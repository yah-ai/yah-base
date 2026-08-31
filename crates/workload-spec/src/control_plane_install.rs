//! Shared install-script builder for a control-plane (yubaba + kamaji) roll.
//!
//! This is the ONE net-new mechanism of the rolling-upgrade envelope (R608):
//! the atomic fetch→verify→anchor→install→assert→restart of the signed
//! yubaba+kamaji pair. It lives here — in the crate BOTH the CLI orchestrator
//! and yubaba itself depend on — so the two apply transports share a single,
//! trusted script and cannot drift:
//!
//! - **SSH transport** (R608-F5, `app/yah/cli/src/rollout/apply.rs::apply_over_ssh`)
//!   pipes the script to `ssh <node> bash -s` from the orchestrator.
//! - **Mesh transport** (R608-F10, yubaba `POST /self-update`) runs the *same*
//!   script locally on the node via a `systemd-run` transient unit — no SSH.
//!
//! **The script body is not written here.** It lives beside this file as
//! [`control_plane_install.sh`](./control_plane_install.sh) and is `include_str!`d,
//! because a third caller — `scripts/roll-node.sh`, the one-node operator SSH
//! job (R755-F3) — has to run the identical bytes from bash with no Rust in the
//! loop. This function only prepends the four-variable prologue the template
//! declares (`URL` / `SHA` / `VER` / `SUDO`); `roll-node.sh` prepends the same
//! four. Keeping the body in a `format!` string would have forced that script to
//! become a fourth transcription of the most safety-critical code in the fleet
//! (`stand-up-yubaba.sh`'s install tail is already the second).
//!
//! The script is a state-preserving, atomic transcription of the install tail of
//! `stand-up-yubaba.sh`: fetch the signed release tarball, `sha256 -c` it against
//! the digest the signed manifest already resolved (callers only ever pass
//! manifest-derived values — there is no path for an AI or a wire request to
//! fabricate a version/url/digest), extract, leave a dated rollback anchor beside
//! every file it is about to replace, stage each file next to its target on the
//! same filesystem, then `mv` it into place so a half-written
//! `/usr/local/bin/yubaba` can never appear. yubaba + kamaji install as one
//! atomic pair (W275 OQ5).
//!
//! **Success is proved by content, never by `--version`.** After the rename the
//! script hashes each installed binary against the file it extracted from the
//! manifest-verified tarball. The version string is the workspace version baked
//! in at build time and can be right on a binary that predates the code it
//! claims — us-east-001 reported kamaji 0.8.22 while carrying none of the 0.8.22
//! tree (R746-T3). The hash chain manifest → tarball → extracted → installed has
//! no version string in it.
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

/// The canonical roll script body, shared verbatim with `scripts/roll-node.sh`.
/// Expects the four-variable prologue [`build_install_script`] emits.
pub const INSTALL_SCRIPT_TEMPLATE: &str = include_str!("control_plane_install.sh");

/// Build the self-contained install script for the yubaba+kamaji pair.
///
/// `sudo` is `true` when the executing user is not root (e.g. an SSH login as
/// `debian@…`), matching `stand-up-yubaba.sh`'s `SUDO` convention. The mesh
/// (self-update) path runs the script as root inside a `systemd-run` transient
/// unit, so it passes `sudo = false`. The script is idempotent and atomic; it
/// anchors what it is about to replace, restarts kamaji then yubaba (W154
/// supervision order) and echoes the installed versions so the caller can log
/// them — after having already proved the install by hash, not by those strings.
///
/// `version`/`url`/`sha256` MUST come from a signed release manifest — this
/// builder does no verification of its own beyond emitting the `sha256sum -c`
/// check; integrity rests on the caller only ever passing manifest-resolved
/// values.
pub fn build_install_script(version: &str, url: &str, sha256: &str, sudo: bool) -> String {
    let sudo_kw = if sudo { "sudo" } else { "" };
    format!(
        "SUDO={sudo_kw}\nURL={url}\nSHA={sha}\nVER={ver}\n{body}",
        sudo_kw = sudo_kw,
        url = sh_squote(url),
        sha = sh_squote(sha256),
        ver = sh_squote(version),
        body = INSTALL_SCRIPT_TEMPLATE,
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

    /// The script with every comment line removed — i.e. only the lines bash
    /// will actually execute. The template documents the durable-state rule in
    /// prose *by naming the paths it must not touch*, so the guard below has to
    /// look at commands, not at the whole file, or the doc comment describing
    /// the property would be what breaks the test asserting it.
    fn executable_lines(script: &str) -> String {
        script
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn script_never_touches_durable_state() {
        // The load-bearing safety property: a roll moves binaries + unit files
        // ONLY. Wiping identity.json forces a re-TOFU (R589 gotcha); touching
        // the raft dir corrupts consensus. The script must reference neither.
        let s = executable_lines(&build_install_script("0.8.19", "u", "d", true));
        assert!(!s.contains("identity.json"), "must not touch host identity");
        assert!(!s.contains("/var/lib/yah-cloud"), "must not touch state dir");
        assert!(!s.contains("raft"), "must not touch the raft log dir");
        assert!(!s.contains("rm -rf /"), "must not wipe system paths");
    }

    #[test]
    fn script_anchors_every_file_it_replaces_before_replacing_it() {
        // R755-F3. Every path the script installs must first be copied to a
        // dated `.rollback-YYYYMMDD` sibling — the convention the fleet's boxes
        // already carry — and the anchoring must happen BEFORE the install, or
        // the anchor holds the new build and there is no way back.
        let s = build_install_script("0.8.19", "u", "d", true);
        let first_anchor = s.find("anchor /usr/local/bin/yubaba").expect("anchors");
        let first_install = s.find("install_atomic \"$D/yubaba\"").expect("installs");
        assert!(
            first_anchor < first_install,
            "anchors must be written before anything is replaced"
        );
        assert!(s.contains(r#"STAMP="$(date -u +%Y%m%d)""#));
        for target in [
            "/usr/local/bin/yubaba",
            "/usr/local/bin/kamaji",
            "/etc/systemd/system/yubaba.slice",
            "/etc/systemd/system/kamaji.service",
            "/etc/systemd/system/yubaba.service",
        ] {
            assert!(
                s.contains(&format!("anchor {target}\n")),
                "every installed path needs a rollback anchor, missing {target}"
            );
        }
    }

    #[test]
    fn anchoring_is_idempotent_within_a_day() {
        // The subtle half: a second roll on the same day must NOT re-anchor,
        // or the escape hatch gets overwritten with the build being escaped.
        let s = build_install_script("0.8.19", "u", "d", true);
        assert!(
            s.contains(r#"if [ ! -e "$1.rollback-$STAMP" ]; then"#),
            "anchor must refuse to overwrite an existing same-day anchor"
        );
    }

    #[test]
    fn success_is_asserted_by_content_not_by_version_string() {
        // R746-T3's trap: `--version` reports the workspace version baked in at
        // build time and was right on a binary carrying none of that version's
        // code. The proof has to be a hash of the installed bytes against the
        // bytes extracted from the manifest-verified tarball.
        let s = build_install_script("0.8.19", "u", "d", true);
        for pair in [
            r#"assert_installed_bytes "$D/yubaba" /usr/local/bin/yubaba"#,
            r#"assert_installed_bytes "$D/kamaji" /usr/local/bin/kamaji"#,
        ] {
            assert!(s.contains(pair), "missing content assertion: {pair}");
        }
        // …and a mismatch must fail the roll, not merely print.
        let body = &s[s.find("assert_installed_bytes() {").expect("assert fn")..];
        assert!(
            body.contains("content assertion FAILED") && body.contains("exit 1"),
            "a content mismatch must exit nonzero so the caller sees a failed roll"
        );
        // The assertion must land before the restart — restarting onto bytes
        // you haven't proved is the failure mode this closes.
        assert!(
            s.find("assert_installed_bytes \"$D/yubaba\"").unwrap()
                < s.find("systemctl restart kamaji.service").unwrap(),
            "content must be proved before the supervision tree restarts"
        );
    }

    #[test]
    fn the_template_is_the_only_copy_of_the_body() {
        // scripts/roll-node.sh runs these same bytes with no Rust in the loop,
        // so build_install_script must be a prologue over the template and
        // nothing more. If this drifts, the SSH job and the mesh self-update
        // stop being the same roll.
        let s = build_install_script("0.8.19", "u", "d", false);
        assert!(
            s.ends_with(INSTALL_SCRIPT_TEMPLATE),
            "the built script must be prologue + the shared template, verbatim"
        );
        let prologue = &s[..s.len() - INSTALL_SCRIPT_TEMPLATE.len()];
        assert_eq!(
            prologue.lines().count(),
            4,
            "the prologue is exactly URL/SHA/VER/SUDO — anything else belongs in the template"
        );
    }

    #[test]
    fn sudo_prefix_tracks_the_caller() {
        let s = build_install_script("0.8.19", "u", "d", true);
        assert!(s.contains("SUDO=sudo"));
        let s = build_install_script("0.8.19", "u", "d", false);
        assert!(s.contains("SUDO=\n") || s.contains("SUDO="));
    }
}
