# shellcheck shell=bash
# Canonical control-plane roll: fetch → verify → anchor → install → assert →
# restart. yubaba + kamaji are the supervised pair; yah-scryer (0.8.32) and
# passway + passway-demux (0.8.33) ride the same tarball, each conditional on
# the tarball carrying it so a rollback to an older release still succeeds.
#
# THIS FILE IS THE ONE COPY. Three callers consume these exact bytes:
#   1. `build_install_script` (control_plane_install.rs) include_str!s it for the
#      SSH transport (`rollout::apply::apply_over_ssh`).
#   2. …and for the mesh transport (yubaba `POST /self-update`, run as root in a
#      systemd-run transient unit).
#   3. `scripts/roll-node.sh` reads it off disk and pipes it to `ssh … bash -s`.
# Every caller prepends a prologue setting the four variables below and nothing
# else. Adding a fourth copy of this logic is how the fleet drifts — don't.
#
# Required from the caller's prologue:
#   URL   release tarball URL, from a SIGNED release manifest
#   SHA   that tarball's sha256, from the SAME manifest
#   VER   the version being installed (labels the log line)
#   SUDO  "sudo" when the executing user is not root, empty when it is
#
# Never touches durable state: no /var/lib/yah-cloud/identity.json (wiping the
# ed25519 host identity forces a re-TOFU and breaks hostkey-drift detection —
# the R589 gotcha), no raft log dir. A roll moves /usr/local/bin bytes + unit
# files, nothing else. `script_never_touches_durable_state` is the guard.
set -euo pipefail
: "${URL:?URL must be set from a signed release manifest}"
: "${SHA:?SHA must be set from the same signed release manifest}"
: "${VER:?VER must be set}"
SUDO="${SUDO-}"
STAMP="$(date -u +%Y%m%d)"
WORK="$(mktemp -d /tmp/yah-roll.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

echo "== fetch + verify (sha256 from signed manifest) =="
curl -fsSL -o pair.tar.gz "$URL"
printf '%s  pair.tar.gz\n' "$SHA" | sha256sum -c -
mkdir x && tar -xzf pair.tar.gz -C x
D="$(find x -maxdepth 1 -type d -name 'yubaba-*' | head -1)"
[ -n "$D" ] || { echo 'tarball layout unexpected: no yubaba-* dir' >&2; exit 1; }

echo "== rollback anchors (.rollback-$STAMP) =="
# The convention these boxes already carry: /usr/local/bin/kamaji.rollback-YYYYMMDD,
# the shape both the passway roll and the 2026-07-21 kamaji roll left behind.
# Written BEFORE anything is replaced, so the anchor is the build that was live
# going in.
#
# Never overwritten within the same UTC day, and that is the load-bearing part:
# on a second run the anchor must still hold the build that was live before the
# FIRST roll of the day. Re-anchoring would quietly overwrite the escape hatch
# with the very binary you are trying to escape from.
#
# A missing target is not an error — a first install on a fresh box has nothing
# to anchor. The unit files are anchored alongside the binaries under the same
# stamp: rolling the binaries back while leaving new units in place is not a
# rollback, and the tarball ships all five together.
anchor() { # path
  [ -e "$1" ] || return 0
  if [ ! -e "$1.rollback-$STAMP" ]; then
    $SUDO cp -p "$1" "$1.rollback-$STAMP"
    echo "  anchored $1.rollback-$STAMP"
  else
    echo "  kept existing $1.rollback-$STAMP (pre-roll build for today)"
  fi
}
anchor /usr/local/bin/yubaba
anchor /usr/local/bin/kamaji
anchor /usr/local/bin/yah-scryer
anchor /usr/local/bin/passway
anchor /usr/local/bin/passway-demux
anchor /etc/systemd/system/yubaba.slice
anchor /etc/systemd/system/kamaji.service
anchor /etc/systemd/system/yubaba.service
anchor /etc/systemd/system/yah-scryer.service

echo "== install (atomic, yubaba + kamaji as one pair) =="
# Stage next to the target on the SAME filesystem, then rename. A rename within
# a filesystem is atomic, so a half-written binary/unit is never observable.
install_atomic() { # src mode dest
  $SUDO install -m"$2" "$1" "$3.roll-new.$$"
  $SUDO mv -f "$3.roll-new.$$" "$3"
}
install_atomic "$D/yubaba"         0755 /usr/local/bin/yubaba
install_atomic "$D/kamaji"         0755 /usr/local/bin/kamaji
install_atomic "$D/yubaba.slice"   0644 /etc/systemd/system/yubaba.slice
install_atomic "$D/kamaji.service" 0644 /etc/systemd/system/kamaji.service
install_atomic "$D/yubaba.service" 0644 /etc/systemd/system/yubaba.service
# yah-scryer rides the same tarball from 0.8.32 (R556-F6 gate (b), A049: each
# node runs its own scryer). CONDITIONAL on the tarball actually carrying it so
# a rollback to a pre-scryer release still succeeds — it leaves whatever scryer
# is already installed in place rather than failing on a missing member. The
# scryer's own durable state (/var/lib/yah/scryer, events.db) is never touched
# here; the unit's StateDirectory owns it.
HAS_SCRYER=0
if [ -e "$D/yah-scryer" ]; then
  HAS_SCRYER=1
  install_atomic "$D/yah-scryer"         0755 /usr/local/bin/yah-scryer
  install_atomic "$D/yah-scryer.service" 0644 /etc/systemd/system/yah-scryer.service
fi
# passway + passway-demux ride the same tarball from 0.8.33 (R870-B2). Before
# this they had NO distribution path at all — the live doors were hand-cross-
# built and scp'd (R853-T2) — so a fleet roll could not carry an ingress fix.
# Conditional for the same reason as scryer: a rollback to a pre-0.8.33 release
# must still succeed.
#
# NO UNIT IS INSTALLED AND NOTHING IS RESTARTED, deliberately, and both halves
# matter. The unit name is not knowable from here: the two live origins run
# passway.service (south) and passway-test.service (east) against per-node env
# files, so there is nothing this script could name. And a restart is not free —
# passway cannot hot-swap (tls.rs "The reload gap": TlsSettings is static), so
# `systemctl restart` DROPS IN-FLIGHT CONNECTIONS on a public front door. The
# install is a rename, so a running door keeps serving from its open inode and
# picks the new bytes up on the operator's next restart. Staging bytes without
# cutting live traffic is the correct default for the :443 tier; R870-T3 is
# wiring the graceful PASSWAY_UPGRADE handoff that makes a restart safe.
HAS_PASSWAY=0
if [ -e "$D/passway" ]; then
  HAS_PASSWAY=1
  install_atomic "$D/passway"       0755 /usr/local/bin/passway
  install_atomic "$D/passway-demux" 0755 /usr/local/bin/passway-demux
fi

echo "== assert by CONTENT, not by version string =="
# `--version` prints the workspace version baked in at build time, which says
# nothing about whether the bytes on disk are the ones you just shipped:
# us-east-001 reported kamaji 0.8.22 while carrying none of the 0.8.22 tree's
# code (R746-T3). Hash the installed file against the file extracted from the
# tarball whose sha256 the signed manifest already vouched for, and the chain
# manifest → tarball → extracted → installed closes with no version string in
# it anywhere.
assert_installed_bytes() { # extracted installed
  local want got
  want="$(sha256sum "$1" | awk '{print $1}')"
  got="$(sha256sum "$2" | awk '{print $1}')"
  if [ "$want" != "$got" ]; then
    echo "content assertion FAILED for $2: tarball has $want, installed file has $got" >&2
    exit 1
  fi
  echo "  $2 sha256=$got"
}
assert_installed_bytes "$D/yubaba" /usr/local/bin/yubaba
assert_installed_bytes "$D/kamaji" /usr/local/bin/kamaji
if [ "$HAS_SCRYER" = 1 ]; then
  assert_installed_bytes "$D/yah-scryer" /usr/local/bin/yah-scryer
fi
if [ "$HAS_PASSWAY" = 1 ]; then
  assert_installed_bytes "$D/passway"       /usr/local/bin/passway
  assert_installed_bytes "$D/passway-demux" /usr/local/bin/passway-demux
fi

echo "== restart supervision tree (kamaji then yubaba, W154 order) =="
$SUDO systemctl daemon-reload
$SUDO systemctl restart kamaji.service
$SUDO systemctl restart yubaba.service
# Scryer sits outside the W154 order — it neither drives nor is driven by the
# pair (A049: located by yubaba, not driven by it), so it restarts last.
# `enable` covers the first install; on later rolls it is a no-op.
if [ "$HAS_SCRYER" = 1 ]; then
  $SUDO systemctl enable yah-scryer.service
  $SUDO systemctl restart yah-scryer.service
fi
if [ "$HAS_PASSWAY" = 1 ]; then
  echo "  passway + passway-demux bytes are STAGED, not live — this roll deliberately"
  echo "  does not restart the front door (see the install block above). Restart the"
  echo "  node's own passway unit when a :443 blip is acceptable."
fi
echo "installed target=$VER yubaba=$(/usr/local/bin/yubaba --version 2>/dev/null) kamaji=$(/usr/local/bin/kamaji --version 2>/dev/null)"
