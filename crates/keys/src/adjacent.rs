//! Slot-adjacent credential store (W337 §6, R856-F9) — values that belong
//! *to* a vault slot without living *in* the slot namespace.
//!
//! # Why this is not `<slot>.next`
//!
//! The obvious shape for an overlap value is a second vault entry named
//! `<slot>.next`, and the operator ruled that out on 2026-09-03 for its mirror
//! image `<slot>.prev`. R856-F1 made `yah keys list` the authority the
//! [`CREDENTIAL_SPECS`](crate::CREDENTIAL_SPECS) registry is diffed against,
//! with the invariant that the registry holds no slot the vault lacks and none
//! it does not list. A dotted sibling entry would read as an *unlisted vault
//! slot*, break that diff, and add a shadow row per rotated credential to the
//! `yah cloud secrets` table.
//!
//! So this store is a **sidecar file**, encrypted with the same machine key,
//! bounded, and invisible to [`KeysStore::list`](crate::KeysStore::list) — the
//! slot namespace is byte-identical whether or not anything is staged here.
//! Consumers resolve current-then-overlap through
//! [`KeysStore::candidates`](crate::KeysStore::candidates), never by mangling a
//! slot string.
//!
//! # Two tenants, one mechanism
//!
//! A record holds both halves of a slot's non-current history, because they are
//! the same primitive pointed in opposite directions in time:
//!
//! - `next` — the *incoming* value staged during an overlap rotation, held
//!   under a lease so a forgotten rotation cannot leave a second live
//!   credential on disk forever.
//! - `previous` — a bounded stack of values this slot used to hold. R856-T11's
//!   clobber-recovery store is exactly this field; nothing writes it on a plain
//!   `set` yet, and wiring that up is T11's job, not this module's.
//!
//! # Secrecy
//!
//! Everything in here is credential material, so unlike the *health* sidecar
//! (plain JSON at 0644, deliberately readable without the machine key) this
//! file is AES-256-GCM under the same `machine.key` at mode 0600. Nothing in
//! this module returns a value in a `Display`/`Debug`-facing string; the CLI
//! prints lease ids and dates, never bytes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// How many superseded values one slot retains. Bounded on purpose: this is a
/// recovery affordance, not an archive, and every retained value is a live
/// secret on disk that the provider may never have been told to revoke.
pub const MAX_PREVIOUS: usize = 3;

/// One value held next to a slot, with the lease vocabulary `vault.lease`
/// (R219) already uses for time-boxed credential grants: a `lease_id`, an
/// `expires_at` horizon, and prune-then-write on every touch.
///
/// The magnitudes differ from `vault.lease`'s and should: that leases a secret
/// into a bash subprocess for minutes, this one spans a rotation an operator
/// has to finish by hand. The *words* are shared so there is one vocabulary for
/// "credential valid until, then gone", not two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdjacentValue {
    /// The credential itself. Encrypted at rest with the rest of the file.
    pub value: String,
    /// Opaque handle the CLI can echo instead of the value.
    pub lease_id: String,
    pub written_at: DateTime<Utc>,
    /// Lease horizon. `None` means no time-box — correct for `previous`
    /// entries, which are bounded by count rather than by clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Most characters of a credential a masked rendering may show.
///
/// Eight, because that is the join key this codebase already uses: npm's
/// `token list --json` publishes each token as `npm_XXXX...YYYY` and
/// `keys_doctor::npm_record_for` matches a vault value to a provider record on
/// its first eight characters (W337 §3.2). Reusing that width means a recovery
/// listing can be read straight across against `npm token list` output instead
/// of needing a second mental mapping — and for npm specifically those eight
/// characters are not a disclosure at all, since npm publishes them itself to
/// anyone holding a read-only token list.
///
/// A *ceiling*, not a width: see [`MASK_MAX_FRACTION`].
const MASK_PREFIX_CHARS: usize = 8;

/// At most one character in this many may be shown.
///
/// The npm rationale above justifies eight characters of a 40-character
/// provider token; it justifies nothing about a 12-character one, where eight
/// characters is two thirds of the secret and the length is the rest of it. The
/// vault is not npm-only and holds whatever an operator puts in a slot, so the
/// bound has to be a ratio rather than a constant width with a floor under it.
///
/// Quarter is the number that leaves real provider tokens (npm and GitHub both
/// mint 40) at the full eight-character join prefix while making anything short
/// enough for the prefix to matter fall off it.
const MASK_MAX_FRACTION: usize = 4;

/// Below this many shown characters there is no join value left, so the prefix
/// is dropped entirely rather than rendered uselessly short.
const MASK_MIN_PREFIX_CHARS: usize = 4;

impl AdjacentValue {
    /// Still inside its lease. An entry with no `expires_at` is always live.
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_none_or(|t| t > now)
    }

    /// A rendering safe to print, log, or paste into a ticket.
    ///
    /// This lives on the type that holds the secret on purpose: the safe way to
    /// show one of these should be the nearest one to hand, so that reaching
    /// for `.value` in display code reads as the deliberate act it is. No
    /// `yah keys recover` verb prints `.value` at all — restoring writes it
    /// into the vault without it ever passing through stdout.
    ///
    /// Never shows a suffix. npm's own masked form has one; there is no join
    /// value in it here and it is strictly more of the secret.
    ///
    /// The exact length rides along with the prefix but not without it: for a
    /// 40-character machine-minted token the length is a provider constant and
    /// discloses nothing, while for a secret short enough to have been chosen by
    /// a human it is the most useful thing an offline guesser could be handed.
    /// So the short form reports the bound it failed rather than the count.
    pub fn masked(&self) -> String {
        let len = self.value.chars().count();
        let show = (len / MASK_MAX_FRACTION).min(MASK_PREFIX_CHARS);
        if show < MASK_MIN_PREFIX_CHARS {
            let bound = MASK_MIN_PREFIX_CHARS * MASK_MAX_FRACTION;
            return format!("<hidden, under {bound} chars>");
        }
        let prefix: String = self.value.chars().take(show).collect();
        format!("{prefix}... ({len} chars)")
    }
}

/// Everything held adjacent to one slot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdjacentRecord {
    /// The staged incoming value of an in-flight overlap rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<AdjacentValue>,
    /// Superseded values, newest first, capped at [`MAX_PREVIOUS`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub previous: Vec<AdjacentValue>,
}

impl AdjacentRecord {
    /// Nothing left worth keeping a record for.
    pub fn is_empty(&self) -> bool {
        self.next.is_none() && self.previous.is_empty()
    }

    /// Push a superseded value, newest first, discarding the oldest past
    /// [`MAX_PREVIOUS`].
    ///
    /// **Deduplicates by value.** A credential that comes back — A -> B -> A,
    /// or a promotion whose value the lease-expiry demote already retained —
    /// must occupy one entry, not two. The ring is only [`MAX_PREVIOUS`] deep,
    /// so a duplicate does not merely look untidy: it evicts a genuinely older
    /// value that is the only remaining copy of something. The re-pushed entry
    /// keeps its new position at the front, since recency is what the recovery
    /// listing orders on.
    pub fn push_previous(&mut self, value: AdjacentValue) {
        self.previous.retain(|v| v.value != value.value);
        self.previous.insert(0, value);
        self.previous.truncate(MAX_PREVIOUS);
    }

    /// Drop every retained copy of `value`. Used when a value stops being
    /// history because it has become current again (a recovery restore).
    pub fn forget_previous(&mut self, value: &str) -> bool {
        let before = self.previous.len();
        self.previous.retain(|v| v.value != value);
        self.previous.len() != before
    }
}

/// The whole sidecar. `version` exists so a format change can be detected
/// rather than mis-parsed; it is the only field a reader may rely on being
/// present in every past and future revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdjacentStore {
    pub version: u32,
    #[serde(default)]
    pub slots: BTreeMap<String, AdjacentRecord>,
}

/// Current on-disk revision.
pub const ADJACENT_VERSION: u32 = 1;

impl Default for AdjacentStore {
    fn default() -> Self {
        Self {
            version: ADJACENT_VERSION,
            slots: BTreeMap::new(),
        }
    }
}

impl AdjacentStore {
    pub fn get(&self, slot: &str) -> Option<&AdjacentRecord> {
        self.slots.get(slot)
    }

    pub fn entry(&mut self, slot: &str) -> &mut AdjacentRecord {
        self.slots.entry(slot.to_string()).or_default()
    }

    /// Drop empty records so a slot that has been through a rotation and back
    /// leaves no trace.
    pub fn compact(&mut self) {
        self.slots.retain(|_, r| !r.is_empty());
    }

    /// Expire staged values whose lease has run out.
    ///
    /// An expired `next` is **demoted to `previous`, not deleted**. It was
    /// staged but never promoted, so it is a credential the provider minted
    /// and nothing else on this machine holds — and a provider that shows a
    /// token exactly once at registration makes deletion permanent. Bounding
    /// by [`MAX_PREVIOUS`] still keeps the file from growing without limit;
    /// the lease's job is to stop `candidates` handing out a stale second
    /// credential, and demotion does that without destroying anything.
    pub fn prune(&mut self, now: DateTime<Utc>) {
        for record in self.slots.values_mut() {
            let expired = match &record.next {
                Some(v) if !v.is_live(now) => record.next.take(),
                _ => None,
            };
            if let Some(v) = expired {
                record.push_previous(AdjacentValue {
                    expires_at: None,
                    ..v
                });
            }
        }
        self.compact();
    }
}

/// Parse the decrypted sidecar. A malformed or truncated body yields an empty
/// store rather than an error: this file is additive to the vault, and a
/// damaged one must not be able to make a credential unreadable.
pub fn parse_adjacent(bytes: &[u8]) -> AdjacentStore {
    serde_json::from_slice(bytes).unwrap_or_default()
}

/// Serialize the sidecar for encryption.
pub fn render_adjacent(store: &AdjacentStore) -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec(store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(h: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 4, h, 0, 0).unwrap()
    }

    fn staged(value: &str, expires: Option<DateTime<Utc>>) -> AdjacentValue {
        AdjacentValue {
            value: value.into(),
            lease_id: "overlap-test".into(),
            written_at: at(0),
            expires_at: expires,
        }
    }

    #[test]
    fn previous_is_newest_first_and_bounded() {
        let mut rec = AdjacentRecord::default();
        for i in 0..(MAX_PREVIOUS + 2) {
            rec.push_previous(staged(&format!("v{i}"), None));
        }
        assert_eq!(rec.previous.len(), MAX_PREVIOUS);
        assert_eq!(rec.previous[0].value, format!("v{}", MAX_PREVIOUS + 1));
    }

    /// The lease stops `next` being handed out, but the value itself is a
    /// possibly-send-once secret — expiry demotes it, never deletes it.
    #[test]
    fn an_expired_lease_demotes_rather_than_destroys() {
        let mut store = AdjacentStore::default();
        store.entry("github-pat").next = Some(staged("incoming", Some(at(1))));

        store.prune(at(2));

        let rec = store.get("github-pat").unwrap();
        assert!(rec.next.is_none(), "an expired lease must not stay staged");
        assert_eq!(rec.previous.len(), 1);
        assert_eq!(rec.previous[0].value, "incoming");
        assert!(
            rec.previous[0].expires_at.is_none(),
            "a demoted value is bounded by count, not by clock"
        );
    }

    #[test]
    fn a_live_lease_survives_a_prune_and_an_emptied_slot_disappears() {
        let mut store = AdjacentStore::default();
        store.entry("github-pat").next = Some(staged("incoming", Some(at(5))));
        store.entry("npm-api-token");

        store.prune(at(2));

        assert!(store.get("github-pat").unwrap().next.is_some());
        assert!(
            store.get("npm-api-token").is_none(),
            "an empty record must not persist"
        );
    }

    #[test]
    fn a_damaged_sidecar_parses_as_empty_rather_than_erroring() {
        assert_eq!(parse_adjacent(b"{ not json"), AdjacentStore::default());
        assert_eq!(parse_adjacent(b""), AdjacentStore::default());
    }

    #[test]
    fn round_trips_through_json() {
        let mut store = AdjacentStore::default();
        store.entry("npm-api-token").next = Some(staged("incoming", Some(at(9))));
        store.entry("npm-api-token").push_previous(staged("old", None));

        let bytes = render_adjacent(&store).unwrap();
        assert_eq!(parse_adjacent(&bytes), store);
    }
}
