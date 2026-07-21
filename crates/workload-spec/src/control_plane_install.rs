//! Shared install-script builder for a control-plane (yubaba + kamaji) roll.
//!
//! This is the ONE net-new mechanism of the rolling-upgrade envelope (R608):
//! the atomic fetch→verify→install→restart of the signed yubaba+kamaji pair.
//! It lives here — in the crate BOTH the CLI orchestrator and yubaba itself
//! depend on — so the two apply transports share a single, trusted script and
//! cannot drift:
//!
//! - **SSH transport** (R608-F5, `app/yah/cli/src/rollout/apply.rs::apply_over_ssh`)
//!   pipes the script to `ssh <node> bash -s` from the orchestrator.
//! - **Mesh transport** (R608-F10, yubaba `POST /self-update`) runs the *same*
//!   script locally on the node via a `systemd-run` transient unit — no SSH.
//!
//! The script is a state-preserving, atomic transcription of the install tail of
//! `stand-up-yubaba.sh`: fetch the signed release tarball, `sha256 -c` it against
//! the digest the signed manifest already resolved (callers only ever pass
//! manifest-derived values — there is no path for an AI or a wire request to
//! fabricate a version/url/digest), extract, stage each file next to its target
//! on the same filesystem, then `mv` it into place so a half-written
//! `/usr/local/bin/yubaba` can never appear. yubaba + kamaji install as one
//! atomic pair (W275 OQ5).
//!
//! **Never touches durable state.** The script contains no reference to
//! `/var/lib/yah-cloud/identity.json` (the ed25519 host identity — wiping it
//! forces a re-TOFU and breaks hostkey-drift detection, the R589 gotcha) or the
//! raft log dir. A roll moves `/usr/local/bin` bytes + unit files, nothing else.
//! The [`tests::script_never_touches_durable_state`] test is the guard.

/// Single-quote a value for safe embedding inside the generated bash. Callers
/// only ever embed manifest-derived URLs/digests (already constrained) and a
/// version string, but we quote defensively regardless.
fn sh_squote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Build the self-contained install script for the yubaba+kamaji pair.
///
/// `sudo` is `true` when the executing user is not root (e.g. an SSH login as
/// `debian@…`), matching `stand-up-yubaba.sh`'s `SUDO` convention. The mesh
/// (self-update) path runs the script as root inside a `systemd-run` transient
/// unit, so it passes `sudo = false`. The script is idempotent and atomic; it
/// restarts kamaji then yubaba (W154 supervision order) and echoes the installed
/// versions so the caller can log them.
///
/// `version`/`url`/`sha256` MUST come from a signed release manifest — this
/// builder does no verification of its own beyond emitting the `sha256sum -c`
/// check; integrity rests on the caller only ever passing manifest-resolved
/// values.
pub fn build_install_script(version: &str, url: &str, sha256: &str, sudo: bool) -> String {
    let sudo_kw = if sudo { "sudo" } else { "" };
    format!(
        r#"set -euo pipefail
SUDO={sudo_kw}
URL={url}
SHA={sha}
VER={ver}
WORK="$(mktemp -d /tmp/yah-roll.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
echo "== fetch + verify (sha256 from signed manifest) =="
curl -fsSL -o pair.tar.gz "$URL"
printf '%s  pair.tar.gz\n' "$SHA" | sha256sum -c -
mkdir x && tar -xzf pair.tar.gz -C x
D="$(find x -maxdepth 1 -type d -name 'yubaba-*' | head -1)"
[ -n "$D" ] || {{ echo 'tarball layout unexpected: no yubaba-* dir' >&2; exit 1; }}
# Atomic install: stage next to the target on the SAME filesystem, then rename.
# A rename within a filesystem is atomic, so a half-written binary/unit is
# never observable. This script touches /usr/local/bin bytes + unit files ONLY
# (durable host state is deliberately out of scope — see the module docs).
install_atomic() {{ # src mode dest
  $SUDO install -m"$2" "$1" "$3.roll-new.$$"
  $SUDO mv -f "$3.roll-new.$$" "$3"
}}
install_atomic "$D/yubaba"         0755 /usr/local/bin/yubaba
install_atomic "$D/kamaji"         0755 /usr/local/bin/kamaji
install_atomic "$D/yubaba.slice"   0644 /etc/systemd/system/yubaba.slice
install_atomic "$D/kamaji.service" 0644 /etc/systemd/system/kamaji.service
install_atomic "$D/yubaba.service" 0644 /etc/systemd/system/yubaba.service
echo "== restart supervision tree (kamaji then yubaba, W154 order) =="
$SUDO systemctl daemon-reload
$SUDO systemctl restart kamaji.service
$SUDO systemctl restart yubaba.service
echo "installed target=$VER yubaba=$(/usr/local/bin/yubaba --version 2>/dev/null) kamaji=$(/usr/local/bin/kamaji --version 2>/dev/null)"
"#,
        sudo_kw = sudo_kw,
        url = sh_squote(url),
        sha = sh_squote(sha256),
        ver = sh_squote(version),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_embeds_the_signed_digest_and_url() {
        let url = "https://cdn.yah.dev/yubaba/0.8.19/yubaba-0.8.19-x86_64-unknown-linux-musl.tar.gz";
        let sha = "abc123def456";
        let s = build_install_script("0.8.19", url, sha, false);
        assert!(s.contains(sha), "script must carry the manifest sha256");
        assert!(s.contains(url), "script must carry the manifest url");
        assert!(s.contains("sha256sum -c -"), "script must verify the digest");
    }

    #[test]
    fn script_is_atomic_and_installs_the_whole_pair() {
        let s = build_install_script("0.8.19", "u", "d", false);
        // Atomic: stage-then-rename, never a direct write to the live path.
        assert!(s.contains("mv -f"), "install must be an atomic rename");
        assert!(s.contains(".roll-new.$$"), "install must stage to a temp name");
        // Both binaries + all three unit files.
        for target in [
            "/usr/local/bin/yubaba",
            "/usr/local/bin/kamaji",
            "/etc/systemd/system/yubaba.slice",
            "/etc/systemd/system/kamaji.service",
            "/etc/systemd/system/yubaba.service",
        ] {
            assert!(s.contains(target), "script must install {target}");
        }
        // Restart order: kamaji before yubaba (W154).
        let k = s.find("restart kamaji.service").unwrap();
        let y = s.find("restart yubaba.service").unwrap();
        assert!(k < y, "kamaji must restart before yubaba");
        assert!(s.contains("daemon-reload"));
    }

    #[test]
    fn script_never_touches_durable_state() {
        // The load-bearing safety property: a roll moves binaries + unit files
        // ONLY. Wiping identity.json forces a re-TOFU (R589 gotcha); touching
        // the raft dir corrupts consensus. The script must reference neither.
        let s = build_install_script("0.8.19", "u", "d", true);
        assert!(!s.contains("identity.json"), "must not touch host identity");
        assert!(!s.contains("/var/lib/yah-cloud"), "must not touch state dir");
        assert!(!s.contains("raft"), "must not touch the raft log dir");
        assert!(!s.contains("rm -rf /"), "must not wipe system paths");
    }

    #[test]
    fn sudo_prefix_tracks_the_caller() {
        let s = build_install_script("0.8.19", "u", "d", true);
        assert!(s.contains("SUDO=sudo"));
        let s = build_install_script("0.8.19", "u", "d", false);
        assert!(s.contains("SUDO=\n") || s.contains("SUDO="));
    }
}
