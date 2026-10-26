//! Per-device camp-vault wrap keypair (W374 §3, R975-F13).
//!
//! An X25519 keypair held as the host-scoped fob slot [`WRAP_SLOT`]. The vault
//! key VK is sealed to the public half, one wrap per enrolled device. It is a
//! separate key from the mshr Ed25519 NodeId key: signing and encryption keys
//! stay apart, and a wrap key must be rotatable while a NodeId is not.
//! The slot is `Scope::Host`, so `export_camp_map` never carries it.
//!
//! # VK wrap (`wrap.g<g>.<NodeId>`, R975-F15)
//!
//! ECIES over X25519: the shape of HPKE base mode with DHKEM(X25519,
//! HKDF-SHA256) and AES-256-GCM, though not its exact labels.
//!
//! ```text
//! eph     = fresh X25519 secret, one per wrap
//! shared  = X25519(eph, recipient_pub), refused if non-contributory
//! key     = HKDF-SHA256(salt = eph_pub || recipient_pub, ikm = shared, info = WRAP_INFO)
//!
//! [0..4]    magic  b"YAHW"
//! [4]       version (0x01)
//! [5..37]   eph_pub
//! [37..49]  AES-256-GCM nonce
//! [49..]    ciphertext + tag over the 32 VK bytes
//! ```
//!
//! The 37 header bytes plus the caller's `context` are the GCM associated
//! data. The carrier passes camp, generation and NodeId as `context`, so a
//! wrap cannot be relabelled to another camp, generation or device.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::vault::VaultKey;
use crate::KeysStore;

const WRAP_MAGIC: &[u8; 4] = b"YAHW";
const WRAP_VERSION: u8 = 0x01;
const WRAP_HEADER_LEN: usize = 4 + 1 + 32;
const WRAP_NONCE_LEN: usize = 12;
const WRAP_INFO: &[u8] = b"yah camp-vault wrap v1";

/// Fob slot holding the hex-encoded 32-byte X25519 secret.
pub const WRAP_SLOT: &str = "camp-vault-wrap";

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex32(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 || !s.is_ascii() {
        bail!("{WRAP_SLOT} slot is not 64 hex chars");
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
            .with_context(|| format!("{WRAP_SLOT} slot is not hex"))?;
    }
    Ok(out)
}

impl KeysStore {
    /// This device's wrap secret, generating and persisting it on first use.
    pub fn vault_wrap_secret(&self) -> Result<StaticSecret> {
        if let Some(hex) = self.get(WRAP_SLOT)? {
            return Ok(StaticSecret::from(from_hex32(hex.trim())?));
        }
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        self.set(WRAP_SLOT, &to_hex(&raw))?;
        Ok(StaticSecret::from(raw))
    }

    /// The public half, 32 raw bytes. Stable across reloads once generated.
    pub fn vault_wrap_pub(&self) -> Result<[u8; 32]> {
        Ok(PublicKey::from(&self.vault_wrap_secret()?).to_bytes())
    }

    /// [`Self::vault_wrap_pub`] as lowercase hex, the form the enrollment
    /// ledger stores.
    pub fn vault_wrap_pub_hex(&self) -> Result<String> {
        Ok(to_hex(&self.vault_wrap_pub()?))
    }

    /// Open a VK wrap sealed to this device. Never mints a wrap key: a device
    /// with none was never enrolled, and that is said rather than papered over.
    pub fn open_vault_key_wrap(&self, blob: &[u8], context: &[u8]) -> Result<VaultKey> {
        let Some(hex) = self.get(WRAP_SLOT)? else {
            bail!("this device has no {WRAP_SLOT} key, so no vault wrap can be addressed to it");
        };
        open_vault_key_wrap_with(&StaticSecret::from(from_hex32(hex.trim())?), blob, context)
    }
}

fn wrap_cipher(shared: &[u8; 32], eph_pub: &[u8; 32], recipient_pub: &[u8; 32]) -> Result<Aes256Gcm> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(eph_pub);
    salt[32..].copy_from_slice(recipient_pub);
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), shared)
        .expand(WRAP_INFO, &mut okm)
        .map_err(|e| anyhow!("hkdf expand: {e}"))?;
    Aes256Gcm::new_from_slice(&okm).map_err(|e| anyhow!("cipher init: {e}"))
}

fn wrap_aad(header: &[u8], context: &[u8]) -> Vec<u8> {
    [header, context].concat()
}

/// Seal VK to `recipient_pub` (see the module docs for the construction).
pub fn seal_vault_key_to(key: &VaultKey, recipient_pub: &[u8; 32], context: &[u8]) -> Result<Vec<u8>> {
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let eph = StaticSecret::from(raw);
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&PublicKey::from(*recipient_pub));
    if !shared.was_contributory() {
        bail!("vault wrap: recipient key is a low-order point");
    }
    let cipher = wrap_cipher(shared.as_bytes(), &eph_pub, recipient_pub)?;
    let mut header = [0u8; WRAP_HEADER_LEN];
    header[..4].copy_from_slice(WRAP_MAGIC);
    header[4] = WRAP_VERSION;
    header[5..].copy_from_slice(&eph_pub);
    let mut nonce = [0u8; WRAP_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: key.as_bytes(), aad: &wrap_aad(&header, context) },
        )
        .map_err(|_| anyhow!("vault wrap seal failed"))?;
    Ok([&header[..], &nonce, &ct].concat())
}

/// Open a wrap from [`seal_vault_key_to`] with the recipient's secret.
pub fn open_vault_key_wrap_with(secret: &StaticSecret, blob: &[u8], context: &[u8]) -> Result<VaultKey> {
    if blob.len() != WRAP_HEADER_LEN + WRAP_NONCE_LEN + 32 + 16 {
        bail!("vault wrap blob has the wrong length");
    }
    if &blob[..4] != WRAP_MAGIC {
        bail!("not a vault wrap blob (wrong magic, expected YAHW)");
    }
    if blob[4] != WRAP_VERSION {
        bail!("unsupported vault wrap version {:#04x}", blob[4]);
    }
    let (header, rest) = blob.split_at(WRAP_HEADER_LEN);
    let eph_pub: [u8; 32] = header[5..].try_into().expect("32 bytes");
    let (nonce, ct) = rest.split_at(WRAP_NONCE_LEN);
    let shared = secret.diffie_hellman(&PublicKey::from(eph_pub));
    if !shared.was_contributory() {
        bail!("vault wrap: ephemeral key is a low-order point");
    }
    let cipher = wrap_cipher(shared.as_bytes(), &eph_pub, &PublicKey::from(secret).to_bytes())?;
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &wrap_aad(header, context) })
        .map_err(|_| anyhow!("vault wrap: not addressed to this key, or corrupted"))?;
    let bytes: [u8; 32] = plain.as_slice().try_into().map_err(|_| anyhow!("vault wrap payload is not 32 bytes"))?;
    Ok(VaultKey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{spec, Scope};

    #[test]
    fn generated_once_and_stable_across_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let a = KeysStore::at(dir.path()).unwrap();
        a.init(false).unwrap();
        let p1 = a.vault_wrap_pub().unwrap();
        assert_eq!(p1, a.vault_wrap_pub().unwrap());
        let b = KeysStore::at(dir.path()).unwrap();
        assert_eq!(p1, b.vault_wrap_pub().unwrap());
        assert_eq!(b.vault_wrap_pub_hex().unwrap().len(), 64);
    }

    #[test]
    fn slot_is_host_scoped_and_absent_from_camp_export() {
        assert_eq!(spec(WRAP_SLOT).expect("spec registered").scope, Scope::Host);
        let dir = tempfile::tempdir().unwrap();
        let s = KeysStore::at(dir.path()).unwrap();
        s.init(false).unwrap();
        s.vault_wrap_pub().unwrap();
        assert!(s.get(WRAP_SLOT).unwrap().is_some());
        assert!(!s.export_camp_map().unwrap().contains_key(WRAP_SLOT));
    }

    fn store() -> (tempfile::TempDir, KeysStore) {
        let dir = tempfile::tempdir().unwrap();
        let s = KeysStore::at(dir.path()).unwrap();
        s.init(false).unwrap();
        (dir, s)
    }

    #[test]
    fn vk_wrap_opens_only_for_its_recipient_and_context() {
        let (_a_dir, a) = store();
        let (_b_dir, b) = store();
        let vk = VaultKey::generate();
        let blob = seal_vault_key_to(&vk, &a.vault_wrap_pub().unwrap(), b"camp/1/a").unwrap();
        assert!(!blob.windows(32).any(|w| w == vk.as_bytes()));
        assert_eq!(a.open_vault_key_wrap(&blob, b"camp/1/a").unwrap().as_bytes(), vk.as_bytes());
        b.vault_wrap_pub().unwrap();
        assert!(b.open_vault_key_wrap(&blob, b"camp/1/a").is_err());
        assert!(a.open_vault_key_wrap(&blob, b"camp/2/a").is_err());
        for i in [4, 6, WRAP_HEADER_LEN + 1, blob.len() - 1] {
            let mut bad = blob.clone();
            bad[i] ^= 0x01;
            assert!(a.open_vault_key_wrap(&bad, b"camp/1/a").is_err(), "flip at {i} accepted");
        }
    }

    #[test]
    fn opening_never_mints_a_wrap_key() {
        let (_dir, s) = store();
        let blob = seal_vault_key_to(&VaultKey::generate(), &[9u8; 32], b"").unwrap();
        assert!(s.open_vault_key_wrap(&blob, b"").is_err());
        assert!(s.get(WRAP_SLOT).unwrap().is_none());
    }

    #[test]
    fn low_order_recipient_refused() {
        assert!(seal_vault_key_to(&VaultKey::generate(), &[0u8; 32], b"").is_err());
    }
}
