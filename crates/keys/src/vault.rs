//! Camp vault seal (W374 §3, R975-F12): the camp-scoped slots of a
//! [`KeysStore`], sealed as one map under a random 256-bit vault key VK.
//!
//! This module is only the seal. Wrapping VK per device, the manifest and the
//! carrier are other tickets; nothing here touches the network or `machine.key`.
//!
//! # Wire format (`vault.g<g>.sealed`)
//!
//! ```text
//! [0..4]    magic  b"YAHV"
//! [4]       version (0x01)
//! [5..13]   generation g, u64 big-endian
//! [13..25]  AES-256-GCM nonce (12 bytes, random per seal)
//! [25..]    ciphertext + 16-byte tag over the UTF-8 JSON object of slots
//! ```
//!
//! The 13 header bytes (magic, version, g) are bound as GCM associated data,
//! so a stored blob cannot be relabelled with a different generation without
//! failing `open`. VK is single-use per generation (revocation mints a fresh
//! VK, W374 §5), so a random 96-bit nonce is safe.
//!
//! # Recovery wrap (`wrap.g<g>.recovery`, W374 §6, R975-F15)
//!
//! [`crate::encode_encrypted`]'s KDF and framing, applied to the 32 raw VK
//! bytes instead of a slot map. The KEK is `derive_kek(kit, salt)`, where the
//! kit is a 32-byte random [`RecoverySecret`], not a human passphrase.
//!
//! ```text
//! [0..4]    magic  b"YAHR"
//! [4]       version (0x01)
//! [5..21]   Argon2id salt
//! [21..33]  AES-256-GCM nonce
//! [33..]    ciphertext + tag over the 32 VK bytes
//! ```
//!
//! Magic, version and the caller's `context` are the GCM associated data.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use rand::RngCore;
use serde_json::{Map, Value};

use crate::spec::{spec, Scope};
use crate::KeysStore;

const MAGIC: &[u8; 4] = b"YAHV";
const VERSION: u8 = 0x01;
const HEADER_LEN: usize = 4 + 1 + 8;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// The 256-bit vault key. Deliberately no `Debug`/`Clone`/`Serialize`.
pub struct VaultKey([u8; 32]);

impl VaultKey {
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        Self(k)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The recovery-kit secret (W374 §6): 32 random bytes, shown once to the
/// operator and never stored online. Deliberately no `Debug`/`Clone`/`Serialize`.
pub struct RecoverySecret([u8; 32]);

impl RecoverySecret {
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        Self(k)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

const RECOVERY_MAGIC: &[u8; 4] = b"YAHR";
const RECOVERY_SALT_LEN: usize = 16;

/// Wrap VK under the recovery kit (see the module docs).
pub fn seal_vault_key_with_recovery(
    key: &VaultKey,
    kit: &RecoverySecret,
    context: &[u8],
) -> Result<Vec<u8>> {
    let mut salt = [0u8; RECOVERY_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let kek = crate::derive_kek(&kit.0, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&kek).map_err(|e| anyhow!("cipher init: {e}"))?;
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut hdr = RECOVERY_MAGIC.to_vec();
    hdr.push(VERSION);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: &key.0, aad: &[&hdr[..], context].concat() },
        )
        .map_err(|_| anyhow!("recovery wrap seal failed"))?;
    Ok([&hdr[..], &salt, &nonce, &ct].concat())
}

/// Open a [`seal_vault_key_with_recovery`] blob with the kit.
pub fn open_vault_key_with_recovery(
    blob: &[u8],
    kit: &RecoverySecret,
    context: &[u8],
) -> Result<VaultKey> {
    if blob.len() != 5 + RECOVERY_SALT_LEN + NONCE_LEN + 32 + TAG_LEN {
        bail!("recovery wrap blob has the wrong length");
    }
    if &blob[..4] != RECOVERY_MAGIC {
        bail!("not a recovery wrap blob (wrong magic, expected YAHR)");
    }
    if blob[4] != VERSION {
        bail!("unsupported recovery wrap version {:#04x}", blob[4]);
    }
    let (hdr, rest) = blob.split_at(5);
    let (salt, rest) = rest.split_at(RECOVERY_SALT_LEN);
    let (nonce, ct) = rest.split_at(NONCE_LEN);
    let kek = crate::derive_kek(&kit.0, salt)?;
    let cipher = Aes256Gcm::new_from_slice(&kek).map_err(|e| anyhow!("cipher init: {e}"))?;
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &[hdr, context].concat() })
        .map_err(|_| anyhow!("recovery wrap: wrong kit or corrupted blob"))?;
    let bytes: [u8; 32] = plain.as_slice().try_into().map_err(|_| anyhow!("recovery payload is not 32 bytes"))?;
    Ok(VaultKey(bytes))
}

/// Keep only the slots `is_camp` accepts. Slots with no spec are host-scoped.
pub fn filter_camp_scoped(
    all: Map<String, Value>,
    is_camp: impl Fn(&str) -> bool,
) -> Map<String, Value> {
    all.into_iter().filter(|(k, _)| is_camp(k)).collect()
}

fn spec_is_camp(slot: &str) -> bool {
    spec(slot).is_some_and(|s| s.scope == Scope::Camp)
}

impl KeysStore {
    /// Only the camp-scoped slots (W374 §7); host-scoped slots never appear.
    pub fn export_camp_map(&self) -> Result<Map<String, Value>> {
        Ok(filter_camp_scoped(self.export_map(None)?, spec_is_camp))
    }

    /// [`Self::export_camp_map`] sealed under `key` as generation `generation`.
    pub fn seal_camp_vault(&self, key: &VaultKey, generation: u64) -> Result<Vec<u8>> {
        seal(&self.export_camp_map()?, key, generation)
    }
}

fn header(generation: u64) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..4].copy_from_slice(MAGIC);
    h[4] = VERSION;
    h[5..].copy_from_slice(&generation.to_be_bytes());
    h
}

/// Seal `slots` under `key`, stamping generation `generation`.
pub fn seal(slots: &Map<String, Value>, key: &VaultKey, generation: u64) -> Result<Vec<u8>> {
    let payload = serde_json::to_vec(slots).context("serialize camp vault map")?;
    let cipher =
        Aes256Gcm::new_from_slice(&key.0).map_err(|e| anyhow!("cipher init: {e}"))?;
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let hdr = header(generation);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: &payload, aad: &hdr })
        .map_err(|_| anyhow!("vault seal failed"))?;
    let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a sealed vault, returning `(generation, slots)`. Fails on a wrong key,
/// any tampering (including the generation), truncation or an unknown version.
pub fn open(bytes: &[u8], key: &VaultKey) -> Result<(u64, Map<String, Value>)> {
    if bytes.len() < HEADER_LEN + NONCE_LEN + TAG_LEN {
        bail!("camp vault blob is truncated");
    }
    if &bytes[..4] != MAGIC {
        bail!("not a camp vault blob (wrong magic, expected YAHV)");
    }
    if bytes[4] != VERSION {
        bail!("unsupported camp vault version {:#04x}", bytes[4]);
    }
    let (hdr, rest) = bytes.split_at(HEADER_LEN);
    let generation = u64::from_be_bytes(hdr[5..].try_into().expect("8 bytes"));
    let (nonce, ct) = rest.split_at(NONCE_LEN);
    let cipher =
        Aes256Gcm::new_from_slice(&key.0).map_err(|e| anyhow!("cipher init: {e}"))?;
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: hdr })
        .map_err(|_| anyhow!("camp vault: wrong key or corrupted blob"))?;
    match serde_json::from_slice(&plain).context("camp vault payload is malformed")? {
        Value::Object(m) => Ok((generation, m)),
        _ => bail!("camp vault payload is not a JSON object"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("cluster-kek".into(), json!("kek-secret"));
        m.insert("anthropic".into(), json!("sk-ant-x"));
        m
    }

    #[test]
    fn round_trip_carries_generation_and_slots() {
        let k = VaultKey::generate();
        let blob = seal(&sample(), &k, 7).unwrap();
        let (g, m) = open(&blob, &k).unwrap();
        assert_eq!(g, 7);
        assert_eq!(m, sample());
        assert!(!blob.windows(10).any(|w| w == b"kek-secret"));
    }

    #[test]
    fn wrong_key_rejected() {
        let blob = seal(&sample(), &VaultKey::generate(), 1).unwrap();
        assert!(open(&blob, &VaultKey::generate()).is_err());
    }

    #[test]
    fn tampered_ciphertext_nonce_and_generation_rejected() {
        let k = VaultKey::generate();
        let blob = seal(&sample(), &k, 1).unwrap();
        for i in [HEADER_LEN + NONCE_LEN + 2, HEADER_LEN + 1, 12 /* low byte of g */] {
            let mut bad = blob.clone();
            bad[i] ^= 0x01;
            assert!(open(&bad, &k).is_err(), "flip at {i} accepted");
        }
        let mut bad = blob.clone();
        bad[4] = 0x02;
        assert!(open(&bad, &k).is_err());
        assert!(open(&blob[..20], &k).is_err());
    }

    #[test]
    fn recovery_wrap_opens_only_with_its_kit_and_context() {
        let vk = VaultKey::generate();
        let kit = RecoverySecret::generate();
        let blob = seal_vault_key_with_recovery(&vk, &kit, b"camp/1").unwrap();
        assert!(!blob.windows(32).any(|w| w == vk.as_bytes() || w == kit.as_bytes()));
        let back = open_vault_key_with_recovery(&blob, &kit, b"camp/1").unwrap();
        assert_eq!(back.as_bytes(), vk.as_bytes());
        assert!(open_vault_key_with_recovery(&blob, &RecoverySecret::generate(), b"camp/1").is_err());
        assert!(open_vault_key_with_recovery(&blob, &kit, b"camp/2").is_err());
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(open_vault_key_with_recovery(&bad, &kit, b"camp/1").is_err());
    }

    #[test]
    fn filter_drops_non_camp_slots() {
        let out = filter_camp_scoped(sample(), |s| s == "cluster-kek");
        assert_eq!(out.keys().collect::<Vec<_>>(), vec!["cluster-kek"]);
    }

    #[test]
    fn host_scoped_slots_never_exported_from_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = KeysStore::at(dir.path()).unwrap();
        store.init(false).unwrap();
        store.set("github", "ghp_hostonly").unwrap();
        // every registered spec is Scope::Host today, and unknown slots default to it.
        store.set("not-in-any-spec", "x").unwrap();
        assert!(store.export_camp_map().unwrap().is_empty());
        let k = VaultKey::generate();
        let (_, m) = open(&store.seal_camp_vault(&k, 1).unwrap(), &k).unwrap();
        assert!(m.is_empty());
    }
}
