//! Where the machine key (the KEK every `*.enc` file in the store is sealed
//! under) is held.
//!
//! Invariant: on macOS the conventional store's machine key lives in the
//! login Keychain, never in the data directory, so a copy of the directory
//! alone (a backup, a disk image, a sync) holds ciphertext without the key
//! that opens it. Everywhere else, and for any store opened at an explicit
//! non-conventional directory, the key is a 0600 `machine.key` file beside
//! the ciphertext; that directory is marked backup-excluded where the OS has
//! a standard marker (see `mark_backup_excluded`), and the residual risk — a
//! copy that ignores the marker carries the key — is accepted for headless
//! fleet boxes, which have no unlocked user keyring to hold it.
//!
//! A legacy `machine.key` found beside a Keychain-held store is migrated once
//! by `KeysStore::migrate_file_kek`: copied in, read back, proven to open the
//! store's ciphertext, and only then deleted. Any failure leaves the file in
//! place and readable, so a failed migration can never strand the vault.

use anyhow::Result;
use std::sync::Arc;

/// A single secret item that can hold the machine key outside the data dir.
///
/// The trait is the seam: production uses the macOS Keychain, tests use an
/// in-memory slot so no test ever reads or writes a real Keychain item.
pub trait KekSlot: Send + Sync {
    /// `Ok(None)` when the item does not exist.
    fn get(&self) -> Result<Option<Vec<u8>>>;
    /// Create or overwrite the item.
    fn set(&self, key: &[u8]) -> Result<()>;
    /// Human-readable location, for messages.
    fn describe(&self) -> String;
}

/// How a store holds its machine key.
#[derive(Clone)]
pub(crate) enum Kek {
    /// `machine.key` in the store directory.
    File,
    /// An item outside the store directory.
    Held(Arc<dyn KekSlot>),
}

#[cfg(target_os = "macos")]
pub(crate) mod keychain {
    use super::KekSlot;
    use anyhow::{anyhow, Result};
    use security_framework::passwords::{get_generic_password, set_generic_password};

    /// errSecItemNotFound.
    const ITEM_NOT_FOUND: i32 = -25300;

    pub(crate) const SERVICE: &str = "dev.yah.fob.machine-key";

    /// Generic-password item in the user's default (login) Keychain, keyed by
    /// the store directory so two stores never share a key.
    pub(crate) struct Keychain {
        pub(crate) account: String,
    }

    impl KekSlot for Keychain {
        fn get(&self) -> Result<Option<Vec<u8>>> {
            match get_generic_password(SERVICE, &self.account) {
                Ok(v) => Ok(Some(v)),
                Err(e) if e.code() == ITEM_NOT_FOUND => Ok(None),
                Err(e) => Err(anyhow!("read machine key from Keychain: {e}")),
            }
        }

        fn set(&self, key: &[u8]) -> Result<()> {
            set_generic_password(SERVICE, &self.account, key)
                .map_err(|e| anyhow!("write machine key to Keychain: {e}"))
        }

        fn describe(&self) -> String {
            format!("Keychain item {SERVICE} / {}", self.account)
        }
    }
}

/// The key holder for a store at `dir`: the Keychain for the conventional
/// macOS store, the in-directory file otherwise.
pub(crate) fn default_for(dir: &std::path::Path, conventional: Option<&std::path::Path>) -> Kek {
    #[cfg(target_os = "macos")]
    {
        if conventional == Some(dir) {
            return Kek::Held(Arc::new(keychain::Keychain {
                account: dir.to_string_lossy().into_owned(),
            }));
        }
    }
    let _ = (dir, conventional);
    Kek::File
}

/// Whether this process is a test binary: this crate's own `cfg(test)`, or
/// any cargo test harness (which cargo always places in a `deps/` dir). The
/// real store must never be opened from either, since a test that reaches it
/// would read, migrate or overwrite live credentials.
pub(crate) fn under_test_harness() -> bool {
    cfg!(test)
        || std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().and_then(|d| d.file_name()).map(|n| n == "deps"))
            .unwrap_or(false)
}

/// Mark `dir` excluded from OS backups where the OS has a standard marker.
///
/// macOS: the sticky Time Machine exclusion xattr (the same one `tmutil
/// addexclusion` writes, no root needed). Other platforms have no standard
/// per-directory marker; rsync/borg/restic users must exclude the data dir
/// in their own config.
pub(crate) fn mark_backup_excluded(dir: &std::path::Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        use anyhow::anyhow;
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let path = CString::new(dir.as_os_str().as_bytes())?;
        let rc = unsafe {
            libc::setxattr(
                path.as_ptr(),
                BACKUP_EXCLUDE_XATTR.as_ptr().cast(),
                BACKUP_EXCLUDE_VALUE.as_ptr().cast(),
                BACKUP_EXCLUDE_VALUE.len(),
                0,
                0,
            )
        };
        if rc != 0 {
            return Err(anyhow!(
                "mark {} backup-excluded: {}",
                dir.display(),
                std::io::Error::last_os_error()
            ));
        }
    }
    let _ = dir;
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) const BACKUP_EXCLUDE_XATTR: &[u8] = b"com.apple.metadata:com_apple_backup_excludeItem\0";

/// Binary plist of the string `com.apple.backupd`, byte-identical to what
/// `tmutil addexclusion` writes.
#[cfg(target_os = "macos")]
const BACKUP_EXCLUDE_VALUE: &[u8] = &[
    b'b', b'p', b'l', b'i', b's', b't', b'0', b'0', // header
    0x5F, 0x10, 0x11, // ASCII string, length follows as 1-byte int: 17
    b'c', b'o', b'm', b'.', b'a', b'p', b'p', b'l', b'e', b'.', b'b', b'a', b'c', b'k', b'u', b'p',
    b'd', // "com.apple.backupd"
    0x08, // offset table: object 0 at byte 8
    0, 0, 0, 0, 0, 0, // trailer: unused
    1, 1, // offset int size, object ref size
    0, 0, 0, 0, 0, 0, 0, 1, // object count
    0, 0, 0, 0, 0, 0, 0, 0, // top object
    0, 0, 0, 0, 0, 0, 0, 28, // offset table offset
];
