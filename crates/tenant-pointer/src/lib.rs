//! The global tenant→cell pointer (W250) — one small object per tenant naming
//! the cell that owns it, carrying its own monotonic generation.
//!
//! A **cell** is one yubaba raft group tagged with a region + jurisdiction.
//! Two cells are independent raft groups that share no epoch counter, so the
//! intra-cell fencing epoch (W245 / R732-F2) cannot fence a hand-off between
//! them by itself. The second fence level is this pointer: a node acts as
//! owner of tenant X only if *(the pointer says X is in my cell at generation
//! G)* **and** *(my local raft epoch is current)*.
//!
//! There is deliberately **no standing global consensus** behind it. Moves are
//! rare, so the whole coordination budget is one linearizable compare-and-swap
//! on a single object — [`ObjectStore::put_if`], shipped in `yah-object-store`
//! as the step-1 prerequisite of W250. This crate is step 2: the record and
//! the read/CAS helpers over that primitive. It is **not** the move protocol
//! (W250 step 5 / R736-F4), the write-path fence (R736-T2) or cell tagging —
//! it is the thing all three call.
//!
//! ```
//! use yah_object_store::InMemoryObjectStore;
//! use yah_tenant_pointer::{commit_cell, read, CasOutcome};
//!
//! let store = InMemoryObjectStore::new();
//! // First registration: generation 1, create-only.
//! commit_cell(&store, "noisetable", "us-east").unwrap();
//! // The move-protocol commit point. Idempotent: replaying it after a crash
//! // reports AlreadyCommitted instead of burning a second generation.
//! match commit_cell(&store, "noisetable", "eu-central").unwrap() {
//!     CasOutcome::Committed(p) => assert_eq!(p.record.generation, 2),
//!     other => panic!("unexpected {other:?}"),
//! }
//! assert!(read(&store, "noisetable").unwrap().unwrap().record.is_in_cell("eu-central"));
//! ```
//!
//! ## Why this crate and not `yah-object-store`
//!
//! `yah-object-store` is a general-purpose storage trait published to
//! crates.io and linked by scryer, the cloud reconciler, kamaji, almanac and
//! the `yah` CLI purely for `put`/`get`. "Tenant" and "cell" are yah's
//! multi-cell topology vocabulary, not storage vocabulary, and none of those
//! consumers has either concept. The CAS *primitive* belongs there (and is
//! there); the domain record that rides on it belongs on its own shelf.
//!
//! @yah:ticket(R736-F1, "Global tenant-to-cell pointer record + read/CAS helpers over the already-shipped ObjectStore::put_if")
//! @yah:at(2026-08-28)
//! @yah:status(review)
//! @yah:parent(R736)
//! @arch:see(.yah/docs/working/W250-multi-cell-tenant-mobility.md)
//! @arch:see(oss/yah-base/crates/object-store/src/lib.rs)
//! @yah:handoff("This crate IS R736-F1's deliverable; the full handoff — home decision and its reasoning, the design calls, the notes for R736-T2 and R736-F4, and the @yah:verify lines — lives in the F1 block at the top of W250, which the board does not index. Read that before extending this. Kept short here so the two records cannot drift into disagreeing.")

use serde::{Deserialize, Serialize};
use yah_object_store::{Error as StoreError, ObjectStore, Precondition};

/// Wire version of the pointer object. Independent of every other schema
/// version in the tree — it versions this one small object and nothing else.
pub const POINTER_SCHEMA_VERSION: u32 = 1;

/// Generation a pointer is created at. Generation `0` is deliberately not used
/// so that "no generation known" (the `0` a fence would default to, exactly as
/// `StreamConfig::epoch = 0` means unfenced) can never be mistaken for a real,
/// currently-owning generation.
pub const FIRST_GENERATION: u64 = 1;

/// How many times [`read`] will re-read to obtain a *consistent* (bytes, etag)
/// pair before giving up. Each retry costs two `etag` calls and one `get`; a
/// pointer that changes four times inside a single read is not a pointer under
/// contention, it is a pointer under attack or a broken backend.
const READ_STABILITY_RETRIES: usize = 4;

/// Failures a pointer operation can report.
#[derive(Debug, thiserror::Error)]
pub enum PointerError {
    /// The backing store failed. Note that a *lost* CAS is **not** this — the
    /// store's `PreconditionFailed` is translated to [`PointerError::Conflict`]
    /// so a caller cannot accidentally treat a lost race as an outage.
    #[error("object store: {0}")]
    Store(#[from] StoreError),

    /// The compare-and-swap lost: the pointer changed since the handle passed
    /// in was read. Re-[`read`] and decide again — never retry blindly, since
    /// the reason it moved may be that the tenant no longer lives here.
    #[error("pointer CAS lost: the pointer moved since it was read")]
    Conflict,

    /// The stored object is not a pointer this build understands.
    #[error("pointer schema version {found} is not the version this build writes")]
    SchemaVersion { found: u32 },

    /// The object at a tenant's key names a *different* tenant. Either a key
    /// was built wrong or two tenants' objects were crossed; both are worth
    /// failing loudly for, because the caller is about to fence on it.
    #[error("pointer at tenant {expected}'s key names tenant {found}")]
    TenantMismatch { expected: String, found: String },

    /// A tenant or cell identifier that cannot be used: empty, or carrying a
    /// character that would change the object key's shape.
    #[error("invalid {what} identifier {value:?}: {why}")]
    InvalidIdentifier {
        what: &'static str,
        value: String,
        why: &'static str,
    },

    /// The object could not be encoded or decoded.
    #[error("pointer codec: {0}")]
    Codec(String),

    /// [`read`] could not obtain a self-consistent view of the object: it kept
    /// changing between the etag read and the body read. Returning a body with
    /// a mismatched etag instead would hand the caller a CAS comparand that
    /// does not describe the bytes it decided on — the exact hole this fence
    /// exists to close.
    #[error("pointer changed under every read attempt; no self-consistent view of it")]
    ReadUnstable,

    /// The generation counter is exhausted (u64). Recorded rather than wrapped:
    /// a wrapped generation silently un-fences every stale owner.
    #[error("generation counter exhausted")]
    GenerationExhausted,
}

/// The pointer object's contents: which cell owns `tenant`, at which
/// generation.
///
/// `generation` is monotonic and bumped on **every** cell change. It is the
/// comparand the write-path fence checks (R736-T2) alongside the intra-cell
/// raft epoch, which is why it lives in the record rather than being inferred
/// from the ETag: an ETag is opaque and unordered, a generation is neither.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointerRecord {
    /// See [`POINTER_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The tenant this record is about. Redundant with the key it is stored
    /// under, and carried anyway: a reader that fences on a record fetched
    /// from the wrong key would fence on the wrong tenant, and only the
    /// record itself can catch that.
    pub tenant: String,
    /// The cell that owns `tenant` as of `generation`.
    pub cell: String,
    /// Monotonic, bumped on every cell change. Starts at [`FIRST_GENERATION`].
    pub generation: u64,
}

impl PointerRecord {
    /// True when this record names `cell` as the owner.
    ///
    /// The first half of the two-level fence rule; the caller supplies the
    /// second half (its local raft epoch). Deliberately a plain comparison
    /// with no normalisation — a cell identifier that differs by case or
    /// whitespace is a different cell, and quietly matching it would fence
    /// nothing.
    pub fn is_in_cell(&self, cell: &str) -> bool {
        self.cell == cell
    }
}

/// A record plus the ETag it was read at — the handle a
/// [`compare_and_swap`] needs.
///
/// The two travel together on purpose. Reading the body and then separately
/// reading the ETag is a time-of-check/time-of-use bug: the CAS would be
/// conditioned on a version that is not the one the caller's decision was made
/// from. [`read`] only ever returns a pair it has confirmed consistent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pointer {
    /// Decoded contents.
    pub record: PointerRecord,
    /// The store's ETag for those exact bytes — the CAS comparand.
    pub etag: String,
}

/// What a pointer-advancing call actually did.
///
/// The distinction between [`Committed`](CasOutcome::Committed) and
/// [`AlreadyCommitted`](CasOutcome::AlreadyCommitted) is what makes the move
/// protocol resumable: a writer that crashed *after* its CAS landed but
/// *before* it observed the acknowledgement replays the same call and is told
/// the world is already as it wanted, rather than burning a second generation
/// on a move that already happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CasOutcome {
    /// This call performed the write. Carries the new pointer.
    Committed(Pointer),
    /// The intended end state was already in place; nothing was written.
    /// Carries what is there.
    AlreadyCommitted(Pointer),
    /// Somebody else moved the pointer first, and not to where this caller
    /// wanted. Carries what is actually there now, so the caller can decide
    /// (usually: stop — the tenant is no longer ours to move).
    Lost(Pointer),
}

impl CasOutcome {
    /// The pointer as it now stands, whichever branch was taken.
    pub fn pointer(&self) -> &Pointer {
        match self {
            CasOutcome::Committed(p) | CasOutcome::AlreadyCommitted(p) | CasOutcome::Lost(p) => p,
        }
    }

    /// True unless the pointer ended up somewhere this caller did not ask for.
    pub fn is_settled_as_asked(&self) -> bool {
        !matches!(self, CasOutcome::Lost(_))
    }
}

/// Object-store key holding `tenant`'s pointer.
///
/// One object per tenant rather than one shared directory object: the CAS is
/// per-object, so a shared object would make every tenant's move contend with
/// every other tenant's move for no benefit at all.
pub fn pointer_key(tenant: &str) -> String {
    format!("tenants/{tenant}/cell.toml")
}

/// Rejects identifiers that would change the shape of the object key (or of a
/// prefix listing over it), and empty ones.
fn check_identifier(what: &'static str, value: &str) -> Result<(), PointerError> {
    let invalid = |why| {
        Err(PointerError::InvalidIdentifier {
            what,
            value: value.to_string(),
            why,
        })
    };
    if value.is_empty() {
        return invalid("empty");
    }
    if value.contains('/') {
        return invalid("contains '/', which would re-shape the object key");
    }
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return invalid("contains whitespace or a control character");
    }
    Ok(())
}

/// Check a tenant identifier against the rule the pointer operations enforce.
///
/// Exposed for callers that need to fail *early*: the cross-cell move protocol
/// (R736-F4) validates its whole plan before it quiesces anything, because
/// discovering a malformed cell id at the step-5 CAS means the source was
/// drained and the WAL shipped for a move that could never have committed.
/// Re-stating the rule in that crate instead would be a rule in two places
/// with nothing keeping them equal.
pub fn validate_tenant(tenant: &str) -> Result<(), PointerError> {
    check_identifier("tenant", tenant)
}

/// Check a cell identifier against the rule the pointer operations enforce.
/// See [`validate_tenant`].
pub fn validate_cell(cell: &str) -> Result<(), PointerError> {
    check_identifier("cell", cell)
}

fn encode(record: &PointerRecord) -> Result<Vec<u8>, PointerError> {
    toml::to_string_pretty(record)
        .map(String::into_bytes)
        .map_err(|e| PointerError::Codec(e.to_string()))
}

fn decode(tenant: &str, bytes: &[u8]) -> Result<PointerRecord, PointerError> {
    let text =
        std::str::from_utf8(bytes).map_err(|e| PointerError::Codec(format!("not utf-8: {e}")))?;
    let record: PointerRecord =
        toml::from_str(text).map_err(|e| PointerError::Codec(e.to_string()))?;
    if record.schema_version != POINTER_SCHEMA_VERSION {
        return Err(PointerError::SchemaVersion {
            found: record.schema_version,
        });
    }
    if record.tenant != tenant {
        return Err(PointerError::TenantMismatch {
            expected: tenant.to_string(),
            found: record.tenant,
        });
    }
    Ok(record)
}

/// Read `tenant`'s pointer, or `None` when the tenant has never been placed.
///
/// Returns the ETag alongside the record so the caller can CAS on exactly the
/// version it read. Because [`ObjectStore`] exposes body and ETag as two
/// calls, this brackets the body read with two ETag reads and retries while
/// they disagree — otherwise a pointer that moved mid-read would yield a body
/// from before the move paired with a comparand from after it, and the
/// resulting CAS would succeed while acting on stale information.
pub fn read(store: &dyn ObjectStore, tenant: &str) -> Result<Option<Pointer>, PointerError> {
    check_identifier("tenant", tenant)?;
    let key = pointer_key(tenant);
    for _ in 0..READ_STABILITY_RETRIES {
        let before = store.etag(&key)?;
        let body = store.get(&key)?;
        let after = store.etag(&key)?;
        if before != after {
            continue;
        }
        return match (body, after) {
            (None, None) => Ok(None),
            (Some(bytes), Some(etag)) => Ok(Some(Pointer {
                record: decode(tenant, &bytes)?,
                etag,
            })),
            // Body and ETag disagree about existence: the object appeared or
            // vanished between the two calls even though the ETags matched
            // (both `None`, or a `get` miss against a live ETag). Retry.
            _ => continue,
        };
    }
    Err(PointerError::ReadUnstable)
}

/// Place `tenant` in `cell` for the first time, at [`FIRST_GENERATION`].
///
/// A create-only write ([`Precondition::IfAbsent`]) — it cannot overwrite an
/// existing placement, so two control-plane nodes racing to register the same
/// new tenant produce one placement, not two. If a pointer already exists this
/// reports [`CasOutcome::AlreadyCommitted`] when it already names `cell` and
/// [`CasOutcome::Lost`] when it names another one; neither writes.
pub fn create_if_absent(
    store: &dyn ObjectStore,
    tenant: &str,
    cell: &str,
) -> Result<CasOutcome, PointerError> {
    check_identifier("tenant", tenant)?;
    check_identifier("cell", cell)?;
    let record = PointerRecord {
        schema_version: POINTER_SCHEMA_VERSION,
        tenant: tenant.to_string(),
        cell: cell.to_string(),
        generation: FIRST_GENERATION,
    };
    match store.put_if(&pointer_key(tenant), encode(&record)?, Precondition::IfAbsent) {
        Ok(etag) => Ok(CasOutcome::Committed(Pointer { record, etag })),
        Err(StoreError::PreconditionFailed(_)) => {
            // Somebody created it first (or we did, before a crash).
            let existing = read(store, tenant)?.ok_or(PointerError::Conflict)?;
            Ok(classify(existing, cell))
        }
        Err(e) => Err(PointerError::Store(e)),
    }
}

/// Repoint `tenant` at `target_cell`, conditioned on `current`.
///
/// The raw primitive — W250 step 5. Writes `current.record.generation + 1` iff
/// the stored object is still exactly the one `current` was read from,
/// returning the new handle. A lost race is [`PointerError::Conflict`], never
/// a silent overwrite: this call is the moment ownership transfers between two
/// raft groups, and the losing side has to learn that it lost.
///
/// This does not check that `target_cell` differs from the current cell —
/// re-pointing a tenant at the cell it is already in is a legitimate (if
/// unusual) generation bump. Callers wanting the idempotent, replay-safe
/// version want [`commit_cell`].
pub fn compare_and_swap(
    store: &dyn ObjectStore,
    current: &Pointer,
    target_cell: &str,
) -> Result<Pointer, PointerError> {
    check_identifier("cell", target_cell)?;
    let generation = current
        .record
        .generation
        .checked_add(1)
        .ok_or(PointerError::GenerationExhausted)?;
    let record = PointerRecord {
        schema_version: POINTER_SCHEMA_VERSION,
        tenant: current.record.tenant.clone(),
        cell: target_cell.to_string(),
        generation,
    };
    match store.put_if(
        &pointer_key(&current.record.tenant),
        encode(&record)?,
        Precondition::IfMatch(current.etag.clone()),
    ) {
        Ok(etag) => Ok(Pointer { record, etag }),
        Err(StoreError::PreconditionFailed(_)) => Err(PointerError::Conflict),
        Err(e) => Err(PointerError::Store(e)),
    }
}

/// Drive `tenant`'s pointer to `cell`, idempotently.
///
/// The resumable form of [`compare_and_swap`], and what a move protocol should
/// call at its commit point:
///
/// * no pointer yet → create it at [`FIRST_GENERATION`];
/// * already in `cell` → [`CasOutcome::AlreadyCommitted`], **no write**, so a
///   replay after a crash costs no generation;
/// * elsewhere → CAS to `cell` at generation + 1;
/// * CAS lost → re-read once and report `AlreadyCommitted` if the winner put
///   it where we wanted anyway, otherwise [`CasOutcome::Lost`].
///
/// Note what it deliberately does *not* do: retry a lost CAS. Losing means
/// somebody else moved this tenant, and the correct response to that is a
/// decision, not a louder attempt.
pub fn commit_cell(
    store: &dyn ObjectStore,
    tenant: &str,
    cell: &str,
) -> Result<CasOutcome, PointerError> {
    check_identifier("tenant", tenant)?;
    check_identifier("cell", cell)?;
    let Some(current) = read(store, tenant)? else {
        return create_if_absent(store, tenant, cell);
    };
    if current.record.is_in_cell(cell) {
        return Ok(CasOutcome::AlreadyCommitted(current));
    }
    match compare_and_swap(store, &current, cell) {
        Ok(p) => Ok(CasOutcome::Committed(p)),
        Err(PointerError::Conflict) => {
            let now = read(store, tenant)?.ok_or(PointerError::Conflict)?;
            Ok(classify(now, cell))
        }
        Err(e) => Err(e),
    }
}

/// Was the pointer we found the end state the caller asked for?
fn classify(found: Pointer, wanted_cell: &str) -> CasOutcome {
    if found.record.is_in_cell(wanted_cell) {
        CasOutcome::AlreadyCommitted(found)
    } else {
        CasOutcome::Lost(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use yah_object_store::InMemoryObjectStore;

    fn committed(o: CasOutcome) -> Pointer {
        match o {
            CasOutcome::Committed(p) => p,
            other => panic!("expected Committed, got {other:?}"),
        }
    }

    // ── key + record shape ──────────────────────────────────────────────────

    #[test]
    fn key_layout_is_stable() {
        // Pinned: the key is the identity of the object across every cell and
        // every release. Changing it orphans every live pointer.
        assert_eq!(pointer_key("noisetable"), "tenants/noisetable/cell.toml");
    }

    #[test]
    fn a_record_round_trips_through_toml() {
        let r = PointerRecord {
            schema_version: POINTER_SCHEMA_VERSION,
            tenant: "noisetable".into(),
            cell: "us-east".into(),
            generation: 7,
        };
        let bytes = encode(&r).unwrap();
        assert_eq!(decode("noisetable", &bytes).unwrap(), r);
    }

    #[test]
    fn is_in_cell_does_not_normalise() {
        let r = PointerRecord {
            schema_version: POINTER_SCHEMA_VERSION,
            tenant: "t".into(),
            cell: "us-east".into(),
            generation: 1,
        };
        assert!(r.is_in_cell("us-east"));
        assert!(!r.is_in_cell("US-EAST"));
        assert!(!r.is_in_cell("us-east "));
    }

    // ── read ────────────────────────────────────────────────────────────────

    #[test]
    fn absent_pointer_reads_as_none() {
        let s = InMemoryObjectStore::new();
        assert_eq!(read(&s, "nobody").unwrap(), None);
    }

    #[test]
    fn read_returns_the_etag_the_cas_needs() {
        let s = InMemoryObjectStore::new();
        create_if_absent(&s, "noisetable", "us-east").unwrap();
        let p = read(&s, "noisetable").unwrap().unwrap();
        assert_eq!(p.record.generation, FIRST_GENERATION);
        assert_eq!(p.record.cell, "us-east");
        // The handle really is the store's current version, not a guess.
        assert_eq!(s.etag(&pointer_key("noisetable")).unwrap(), Some(p.etag));
    }

    #[test]
    fn a_pointer_written_for_another_tenant_is_rejected_not_fenced_on() {
        // Cross-wired keys must fail loudly: the caller is about to decide
        // ownership from this record.
        let s = InMemoryObjectStore::new();
        let foreign = PointerRecord {
            schema_version: POINTER_SCHEMA_VERSION,
            tenant: "someone-else".into(),
            cell: "eu-central".into(),
            generation: 3,
        };
        s.put(&pointer_key("noisetable"), encode(&foreign).unwrap())
            .unwrap();
        let err = read(&s, "noisetable").unwrap_err();
        assert!(
            matches!(err, PointerError::TenantMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn an_unknown_schema_version_is_rejected() {
        let s = InMemoryObjectStore::new();
        s.put(
            &pointer_key("noisetable"),
            b"schema_version = 99\ntenant = \"noisetable\"\ncell = \"us-east\"\ngeneration = 1\n"
                .to_vec(),
        )
        .unwrap();
        let err = read(&s, "noisetable").unwrap_err();
        assert!(
            matches!(err, PointerError::SchemaVersion { found: 99 }),
            "got {err:?}"
        );
    }

    #[test]
    fn identifiers_that_would_reshape_the_key_are_refused() {
        let s = InMemoryObjectStore::new();
        for bad in ["", "a/b", "has space", "nul\u{0}byte"] {
            assert!(
                matches!(
                    read(&s, bad),
                    Err(PointerError::InvalidIdentifier { what: "tenant", .. })
                ),
                "tenant {bad:?} should be refused"
            );
            assert!(
                matches!(
                    create_if_absent(&s, "t", bad),
                    Err(PointerError::InvalidIdentifier { what: "cell", .. })
                ),
                "cell {bad:?} should be refused"
            );
        }
    }

    #[test]
    fn the_public_validators_enforce_exactly_what_the_operations_do() {
        // R736-F4 fails a move plan up front with these rather than restating
        // the rule; this pins the two to the same answer.
        for bad in ["", "a/b", "has space", "nul\u{0}byte"] {
            assert!(validate_tenant(bad).is_err(), "tenant {bad:?}");
            assert!(validate_cell(bad).is_err(), "cell {bad:?}");
        }
        assert!(validate_tenant("noisetable").is_ok());
        assert!(validate_cell("prod-eu").is_ok());
    }

    /// A store whose object changes *between* the ETag read and the body read.
    /// Proves [`read`] never hands back a body paired with an ETag that does
    /// not describe it — the pair a CAS would then act on wrongly.
    struct Interfering {
        inner: InMemoryObjectStore,
        /// Rewrite the object immediately before this many more `get` calls —
        /// a concurrent writer landing inside [`read`]'s etag/body/etag
        /// bracket. Each rewrite writes *distinct* bytes, so the racing writer
        /// is never accidentally idempotent.
        before_get: Mutex<usize>,
        /// Rewrite the object with this record immediately before the next
        /// `put_if` — a third party winning the pointer between our read and
        /// our CAS. Consumed once.
        before_put_if: Mutex<Option<PointerRecord>>,
    }

    impl Interfering {
        fn new() -> Self {
            Self {
                inner: InMemoryObjectStore::new(),
                before_get: Mutex::new(0),
                before_put_if: Mutex::new(None),
            }
        }
    }

    impl ObjectStore for Interfering {
        fn put(&self, key: &str, data: Vec<u8>) -> Result<(), StoreError> {
            self.inner.put(key, data)
        }
        fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
            {
                let mut left = self.before_get.lock().unwrap();
                if *left > 0 {
                    *left -= 1;
                    let moved = PointerRecord {
                        schema_version: POINTER_SCHEMA_VERSION,
                        tenant: "noisetable".into(),
                        cell: "eu-central".into(),
                        // Distinct per disturbance: two identical rewrites
                        // produce the same etag and would look stable.
                        generation: 900 + *left as u64,
                    };
                    self.inner.put(key, encode(&moved).unwrap())?;
                }
            }
            self.inner.get(key)
        }
        fn delete(&self, key: &str) -> Result<(), StoreError> {
            self.inner.delete(key)
        }
        fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
            self.inner.list_prefix(prefix)
        }
        fn etag(&self, key: &str) -> Result<Option<String>, StoreError> {
            self.inner.etag(key)
        }
        fn put_if(
            &self,
            key: &str,
            data: Vec<u8>,
            cond: Precondition,
        ) -> Result<String, StoreError> {
            if let Some(theirs) = self.before_put_if.lock().unwrap().take() {
                self.inner.put(key, encode(&theirs).unwrap())?;
            }
            self.inner.put_if(key, data, cond)
        }
    }

    #[test]
    fn read_retries_until_body_and_etag_describe_the_same_version() {
        let s = Interfering::new();
        create_if_absent(&s.inner, "noisetable", "us-east").unwrap();
        *s.before_get.lock().unwrap() = 1;

        let p = read(&s, "noisetable").unwrap().unwrap();
        // The read that raced saw the move; what it returned must be the
        // post-move body AND the post-move etag, never a mix.
        assert_eq!(p.record.cell, "eu-central");
        assert_eq!(p.record.generation, 900);
        assert_eq!(
            s.inner.etag(&pointer_key("noisetable")).unwrap(),
            Some(p.etag.clone())
        );
        // And the handle it returned is usable: a CAS on it succeeds.
        compare_and_swap(&s.inner, &p, "us-west").unwrap();
    }

    #[test]
    fn read_gives_up_rather_than_returning_an_inconsistent_pair() {
        let s = Interfering::new();
        create_if_absent(&s.inner, "noisetable", "us-east").unwrap();
        *s.before_get.lock().unwrap() = READ_STABILITY_RETRIES + 1;
        let err = read(&s, "noisetable").unwrap_err();
        assert!(matches!(err, PointerError::ReadUnstable), "got {err:?}");
    }

    // ── create ──────────────────────────────────────────────────────────────

    #[test]
    fn create_places_a_tenant_at_the_first_generation() {
        let s = InMemoryObjectStore::new();
        let p = committed(create_if_absent(&s, "noisetable", "us-east").unwrap());
        assert_eq!(p.record.generation, FIRST_GENERATION);
        assert_eq!(p.record.tenant, "noisetable");
        assert_eq!(p.record.cell, "us-east");
        assert_eq!(read(&s, "noisetable").unwrap(), Some(p));
    }

    #[test]
    fn generation_never_starts_at_zero_because_zero_means_unfenced() {
        assert_eq!(FIRST_GENERATION, 1);
    }

    #[test]
    fn a_second_create_for_the_same_cell_is_already_committed_and_writes_nothing() {
        let s = InMemoryObjectStore::new();
        let first = committed(create_if_absent(&s, "noisetable", "us-east").unwrap());
        let again = create_if_absent(&s, "noisetable", "us-east").unwrap();
        assert!(matches!(again, CasOutcome::AlreadyCommitted(_)));
        // Same etag = the object was not rewritten.
        assert_eq!(again.pointer().etag, first.etag);
        assert_eq!(again.pointer().record.generation, FIRST_GENERATION);
    }

    #[test]
    fn a_second_create_for_a_different_cell_loses_and_does_not_overwrite() {
        let s = InMemoryObjectStore::new();
        create_if_absent(&s, "noisetable", "us-east").unwrap();
        let lost = create_if_absent(&s, "noisetable", "eu-central").unwrap();
        assert!(matches!(lost, CasOutcome::Lost(_)), "got {lost:?}");
        assert!(!lost.is_settled_as_asked());
        // The original placement stands.
        assert_eq!(lost.pointer().record.cell, "us-east");
        assert_eq!(read(&s, "noisetable").unwrap().unwrap().record.cell, "us-east");
    }

    #[test]
    fn two_tenants_do_not_alias() {
        let s = InMemoryObjectStore::new();
        create_if_absent(&s, "noisetable", "us-east").unwrap();
        create_if_absent(&s, "yah", "eu-central").unwrap();
        assert_eq!(read(&s, "noisetable").unwrap().unwrap().record.cell, "us-east");
        assert_eq!(read(&s, "yah").unwrap().unwrap().record.cell, "eu-central");
    }

    // ── compare-and-swap ────────────────────────────────────────────────────

    #[test]
    fn cas_repoints_and_bumps_the_generation() {
        let s = InMemoryObjectStore::new();
        let g1 = committed(create_if_absent(&s, "noisetable", "us-east").unwrap());
        let g2 = compare_and_swap(&s, &g1, "eu-central").unwrap();
        assert_eq!(g2.record.generation, 2);
        assert_eq!(g2.record.cell, "eu-central");
        assert_ne!(g1.etag, g2.etag);
        // Chained: the returned handle drives the next hop with no re-read.
        let g3 = compare_and_swap(&s, &g2, "us-west").unwrap();
        assert_eq!(g3.record.generation, 3);
        assert_eq!(read(&s, "noisetable").unwrap().unwrap().record, g3.record);
    }

    #[test]
    fn cas_on_a_stale_handle_conflicts_and_leaves_the_store_untouched() {
        let s = InMemoryObjectStore::new();
        let stale = committed(create_if_absent(&s, "noisetable", "us-east").unwrap());
        let fresh = compare_and_swap(&s, &stale, "eu-central").unwrap();

        let err = compare_and_swap(&s, &stale, "us-west").unwrap_err();
        assert!(matches!(err, PointerError::Conflict), "got {err:?}");
        assert_eq!(read(&s, "noisetable").unwrap().unwrap().record, fresh.record);
    }

    /// The cross-cell fence in miniature: source and target cells both read the
    /// same pointer and both try to commit. Exactly one may win, and the loser
    /// must be told, because it is about to keep appending to the tenant's WAL.
    #[test]
    fn two_writers_contend_and_exactly_one_wins() {
        let s = InMemoryObjectStore::new();
        let shared = committed(create_if_absent(&s, "noisetable", "us-east").unwrap());
        let source_view = shared.clone();
        let target_view = shared;

        let won = compare_and_swap(&s, &source_view, "eu-central").unwrap();
        let lost = compare_and_swap(&s, &target_view, "us-west").unwrap_err();

        assert!(matches!(lost, PointerError::Conflict), "got {lost:?}");
        assert_eq!(won.record.generation, 2);
        let settled = read(&s, "noisetable").unwrap().unwrap();
        assert_eq!(settled.record.cell, "eu-central");
        // The loser's move left no trace at all — no generation was consumed
        // by the attempt.
        assert_eq!(settled.record.generation, 2);
    }

    #[test]
    fn a_conflict_is_not_reported_as_a_store_outage() {
        // Conflict and Store are different decisions for the caller: one means
        // "re-read and think again", the other means "the backend is down".
        let s = InMemoryObjectStore::new();
        let stale = committed(create_if_absent(&s, "t", "a").unwrap());
        compare_and_swap(&s, &stale, "b").unwrap();
        assert!(!matches!(
            compare_and_swap(&s, &stale, "c"),
            Err(PointerError::Store(_))
        ));
    }

    // ── commit_cell: the idempotent / resumable form ────────────────────────

    #[test]
    fn commit_creates_when_the_tenant_has_never_been_placed() {
        let s = InMemoryObjectStore::new();
        let p = committed(commit_cell(&s, "noisetable", "us-east").unwrap());
        assert_eq!(p.record.generation, FIRST_GENERATION);
    }

    #[test]
    fn commit_moves_an_existing_tenant() {
        let s = InMemoryObjectStore::new();
        commit_cell(&s, "noisetable", "us-east").unwrap();
        let p = committed(commit_cell(&s, "noisetable", "eu-central").unwrap());
        assert_eq!(p.record.generation, 2);
        assert_eq!(p.record.cell, "eu-central");
    }

    /// RESUME: the mover crashed after its CAS landed but before it saw the
    /// acknowledgement, then restarted and replayed the same commit. It must
    /// be told the move already happened and must NOT burn generation 3 —
    /// a spurious bump would fence the target cell it just handed ownership to.
    #[test]
    fn replaying_a_commit_after_a_crash_costs_no_generation() {
        let s = InMemoryObjectStore::new();
        commit_cell(&s, "noisetable", "us-east").unwrap();
        let landed = committed(commit_cell(&s, "noisetable", "eu-central").unwrap());
        assert_eq!(landed.record.generation, 2);

        // ---- crash here; the ack was never observed ----

        let replay = commit_cell(&s, "noisetable", "eu-central").unwrap();
        assert!(
            matches!(replay, CasOutcome::AlreadyCommitted(_)),
            "got {replay:?}"
        );
        assert!(replay.is_settled_as_asked());
        assert_eq!(replay.pointer().record.generation, 2);
        // Byte-identical object: no write happened on the replay.
        assert_eq!(replay.pointer().etag, landed.etag);
    }

    /// RESUME, the other crash window: the writer crashed *before* the CAS,
    /// so the replay is the one that actually performs it.
    #[test]
    fn replaying_a_commit_that_never_landed_performs_it() {
        let s = InMemoryObjectStore::new();
        commit_cell(&s, "noisetable", "us-east").unwrap();
        // (crash before the move's CAS)
        let replay = commit_cell(&s, "noisetable", "eu-central").unwrap();
        assert!(matches!(replay, CasOutcome::Committed(_)), "got {replay:?}");
        assert_eq!(replay.pointer().record.generation, 2);
    }

    /// RESUME under contention: a third party wins the pointer in the window
    /// between our read and our CAS, and sends the tenant somewhere we did not
    /// ask for. The commit must report Lost and must not fight for it — the
    /// tenant is no longer ours to move, and a retry loop here is how two cells
    /// end up trading a tenant back and forth.
    #[test]
    fn a_commit_that_loses_the_tenant_to_a_third_party_reports_lost() {
        let s = Interfering::new();
        create_if_absent(&s.inner, "noisetable", "us-east").unwrap();
        *s.before_put_if.lock().unwrap() = Some(PointerRecord {
            schema_version: POINTER_SCHEMA_VERSION,
            tenant: "noisetable".into(),
            cell: "ap-south".into(),
            generation: 2,
        });

        let out = commit_cell(&s, "noisetable", "eu-central").unwrap();
        assert!(matches!(out, CasOutcome::Lost(_)), "got {out:?}");
        assert!(!out.is_settled_as_asked());
        assert_eq!(out.pointer().record.cell, "ap-south");
        assert_eq!(out.pointer().record.generation, 2);
    }

    /// The plain, uncontended case the test above must not be confused with:
    /// a commit that re-reads and finds the tenant somewhere else simply moves
    /// it. "Lost" is about losing a race, not about the tenant having moved.
    #[test]
    fn a_commit_after_someone_elses_completed_move_still_moves_it() {
        let s = InMemoryObjectStore::new();
        commit_cell(&s, "noisetable", "us-east").unwrap();
        commit_cell(&s, "noisetable", "ap-south").unwrap();

        let out = commit_cell(&s, "noisetable", "eu-central").unwrap();
        assert!(matches!(out, CasOutcome::Committed(_)), "got {out:?}");
        assert_eq!(out.pointer().record.generation, 3);
    }

    /// A commit that loses its CAS to a winner heading for the *same* cell is
    /// AlreadyCommitted, not Lost: the end state the caller asked for holds.
    #[test]
    fn losing_a_cas_to_a_writer_going_to_the_same_cell_is_already_committed() {
        let s = InMemoryObjectStore::new();
        let stale = committed(create_if_absent(&s, "noisetable", "us-east").unwrap());
        // Our stale handle is what commit_cell would have read; another writer
        // gets there first, to the very cell we wanted.
        compare_and_swap(&s, &stale, "eu-central").unwrap();

        let out = commit_cell(&s, "noisetable", "eu-central").unwrap();
        assert!(matches!(out, CasOutcome::AlreadyCommitted(_)), "got {out:?}");
        assert_eq!(out.pointer().record.generation, 2);
    }

    // ── backend contract ────────────────────────────────────────────────────

    /// A store without conditional-write support must surface a store error,
    /// not appear to have placed the tenant. `put_if`'s default impl refuses
    /// for exactly this reason and the helpers must not paper over it.
    #[test]
    fn a_backend_without_put_if_cannot_silently_place_a_tenant() {
        struct Minimal;
        impl ObjectStore for Minimal {
            fn put(&self, _k: &str, _d: Vec<u8>) -> Result<(), StoreError> {
                Ok(())
            }
            fn get(&self, _k: &str) -> Result<Option<Vec<u8>>, StoreError> {
                Ok(None)
            }
            fn delete(&self, _k: &str) -> Result<(), StoreError> {
                Ok(())
            }
            fn list_prefix(&self, _p: &str) -> Result<Vec<String>, StoreError> {
                Ok(vec![])
            }
        }
        let err = create_if_absent(&Minimal, "noisetable", "us-east").unwrap_err();
        assert!(matches!(err, PointerError::Store(StoreError::Backend(_))), "got {err:?}");
        // And the read side is just as refused, rather than reporting "unplaced".
        assert!(matches!(
            read(&Minimal, "noisetable"),
            Err(PointerError::Store(StoreError::Backend(_)))
        ));
    }
}
