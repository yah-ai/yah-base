//! The cross-cell tenant move protocol (W250, W252 §5) as an idempotent,
//! resumable state machine.
//!
//! Moving a tenant between cells hands ownership between **two independent
//! raft groups that share no epoch counter**, so the intra-cell fencing epoch
//! (W245 / R732-F2) cannot fence the hand-off by itself. The second fence
//! level is the global tenant→cell pointer and its monotonic generation
//! ([`yah_tenant_pointer`]); this crate is the protocol that advances it.
//!
//! The seven steps, exactly as W252 §5 numbers them, are the [`Phase`] enum:
//!
//! 1. [`Phase::CheckPolicy`] — residency policy permits the destination.
//! 2. [`Phase::QuiesceSource`] — epoch bump → migrating, drain/queue writes.
//! 3. [`Phase::ShipWal`] — final WAL state to a target-reachable R2 location.
//! 4. [`Phase::HydrateTarget`] — apply it in the target cell.
//! 5. [`Phase::CommitPointer`] — **CAS the global pointer**, generation + 1.
//! 6. [`Phase::CommitTargetOwnership`] — commit ownership in the *target*
//!    cell's raft, at the generation the CAS just published.
//! 7. The source is now fenced on a stale generation; its writes bounce.
//!    There is no step-7 phase because step 7 is not an action — it is what
//!    step 5 already made true.
//!
//! # The commit point is step 5, and it is the only thing that matters
//!
//! Every phase before the pointer CAS is undoable: the source still owns the
//! tenant, still has the pointer, and can simply resume. Every phase after it
//! is *not*: the CAS is the instant ownership transfers, and un-doing it would
//! mean racing a target cell that is already entitled to write. So the machine
//! has exactly one rule, and [`run`] enforces it:
//!
//! > **Before the commit point, roll back. After it, roll forward. Never the
//! > other way round.**
//!
//! Which side of that line a resumed move is on is *not* inferred from what
//! the last process remembered doing — it is read from the pointer, which is
//! the only witness that survives a crash. See [`phase_from`], which is pure
//! and exhaustively tested precisely because everything else defers to it.
//!
//! # Deriving the step after a crash
//!
//! W252 says to derive the current step from *(pointer generation, target
//! hydration state)*. This machine reads one more fact — the source's
//! [`SourceState`] — and the distinction is worth stating: the pointer and the
//! target state decide which **side of the commit point** you are on, which is
//! the safety property. The source's quiesce state only distinguishes step 1
//! from step 3, which is a liveness question. An implementation that cannot
//! cheaply tell whether the source is quiesced may always answer
//! [`SourceState::Serving`]; the cost is one redundant (idempotent) quiesce,
//! never a correctness gap.
//!
//! # What this crate does not contain
//!
//! The effects themselves. Quiescing a tenant, shipping WAL, hydrating a
//! replica and committing an epoch in a raft group are all yubaba control-plane
//! work, and this crate deliberately depends on neither yubaba nor turso-backup
//! — that is the [`MoveEffects`] trait, and it exists for the same reason
//! `tenant-streamer`'s `OwnershipSource` does: R736-T5's split-brain test has
//! to fault the protocol at each of the seven steps, and a test that had to
//! stand up two raft clusters to do it would be testing the clusters.
//!
//! Also not here, on purpose: the per-tenant move rate-limit / cool-down of
//! W252 §7. That is a policy over *how often* moves may start, which belongs
//! with the policy gate at step 1, not inside the state machine that executes
//! one.
//!
//! # Driving one
//!
//! ```no_run
//! use yah_object_store::InMemoryObjectStore;
//! use yah_tenant_move::{run, MoveOutcome, MovePlan, MoveEffects};
//!
//! # fn demo(cells: &dyn MoveEffects) -> Result<(), Box<dyn std::error::Error>> {
//! let store = InMemoryObjectStore::new();
//! let plan = MovePlan::new("noisetable", "prod-us", "prod-eu")?;
//!
//! // The same call starts a move, resumes one another process abandoned
//! // mid-flight, and no-ops on one that already finished. Which of those it
//! // is, is derived from the pointer — never declared by the caller.
//! match run(&store, cells, &plan)? {
//!     MoveOutcome::Moved { generation } => println!("prod-eu owns it at {generation}"),
//!     MoveOutcome::AlreadyInTarget { .. } => println!("it was already there"),
//!     MoveOutcome::RolledBack { at, .. } => println!("backed out at {at:?}; prod-us still owns it"),
//!     MoveOutcome::Abandoned { owner_cell, .. } => println!("overtaken; {owner_cell} owns it"),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Blocking, not async
//!
//! [`yah_object_store::ObjectStore`] is a blocking trait and so is
//! [`yah_tenant_pointer`], so this is too. A move is a rare, operator-scale
//! event measured in seconds of WAL shipping; an async surface here would buy
//! nothing and force a runtime on every caller. Call it from a blocking task.
//!
//! @arch:see(.yah/docs/working/W250-multi-cell-tenant-mobility.md)
//! @arch:see(.yah/docs/working/W252-roaming-tenant-mobility.md)
//! @arch:see(oss/yah-base/crates/tenant-pointer/src/lib.rs)

use yah_object_store::ObjectStore;
use yah_tenant_pointer::{
    self as pointer, Pointer, PointerError, PointerRecord, FIRST_GENERATION,
};

/// Ceiling on how many steps one [`run`] may take.
///
/// The protocol is seven steps and every advance must raise the phase rank, so
/// a run that exceeds this has an effects implementation that reports progress
/// it did not make. Bounded rather than trusting the rank check alone: a loop
/// that spins forever against a live control plane is worse than an error.
const MAX_ADVANCES: usize = 12;

/// One cross-cell move, fully specified.
///
/// `source_cell` is an assertion, not a hint: the move refuses to start if the
/// pointer does not name it. A mover that is wrong about where the tenant
/// lives is a mover about to quiesce the wrong cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MovePlan {
    /// The tenant being moved.
    pub tenant: String,
    /// The cell that owns it now.
    pub source_cell: String,
    /// The cell that should own it when this is done.
    pub target_cell: String,
}

impl MovePlan {
    /// Validate a plan before anything is touched.
    ///
    /// The identifier rules are [`yah_tenant_pointer`]'s, called here rather
    /// than restated, so a plan cannot pass this and then fail at the CAS —
    /// which is step 5, by which point the source has been quiesced and the
    /// WAL shipped for nothing.
    pub fn new(
        tenant: impl Into<String>,
        source_cell: impl Into<String>,
        target_cell: impl Into<String>,
    ) -> Result<Self, MoveError> {
        let (tenant, source_cell, target_cell) =
            (tenant.into(), source_cell.into(), target_cell.into());
        pointer::validate_tenant(&tenant)?;
        pointer::validate_cell(&source_cell)?;
        pointer::validate_cell(&target_cell)?;
        if source_cell == target_cell {
            return Err(MoveError::SameCell { cell: source_cell });
        }
        Ok(Self {
            tenant,
            source_cell,
            target_cell,
        })
    }
}

/// A step of the W252 §5 sequence.
///
/// Deliberately not `Ord`: the phases are ordered, but [`Phase::Abandon`] is
/// not on that line — it is a lateral exit from any pre-commit phase — and a
/// derived `Ord` would silently sort it as though it were. [`Phase::rank`] is
/// the ordering, and it says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Phase {
    /// Step 1. Does residency policy permit this destination? The
    /// cross-jurisdiction copy in step 3 *is* the residency event, which is
    /// why this gate is first and not an afterthought.
    CheckPolicy,
    /// Step 2. Epoch bump → migrating; drain or queue writes in the source.
    QuiesceSource,
    /// Step 3. Ship the final WAL state to a target-reachable location.
    ShipWal,
    /// Step 4. Apply it in the target cell.
    HydrateTarget,
    /// Step 5. CAS the global pointer to the target at generation + 1. The
    /// commit point: before it the move is undoable, after it it is not.
    CommitPointer,
    /// Step 6. Commit ownership in the target cell's raft at the published
    /// generation. Roll-forward only — the pointer has already moved.
    CommitTargetOwnership,
    /// The tenant is in the target cell and the target cell knows it.
    Done,
    /// A cell that is neither source nor target owns the tenant. Not an error
    /// and not a rollback: somebody else's move won, this one has nothing left
    /// to do but clear its own residue out of the target cell.
    Abandon,
}

impl Phase {
    /// Position on the seven-step line, `0` for the off-line
    /// [`Phase::Abandon`].
    ///
    /// Every advance must strictly raise this. That is what turns "the effects
    /// implementation silently did nothing" from an infinite loop into
    /// [`MoveError::Stalled`].
    pub fn rank(self) -> u8 {
        match self {
            Phase::Abandon => 0,
            Phase::CheckPolicy => 1,
            Phase::QuiesceSource => 2,
            Phase::ShipWal => 3,
            Phase::HydrateTarget => 4,
            Phase::CommitPointer => 5,
            Phase::CommitTargetOwnership => 6,
            Phase::Done => 7,
        }
    }

    /// True once the pointer CAS has happened, i.e. rollback is no longer a
    /// legal response to a failure.
    ///
    /// A hint for reporting only. The authoritative answer is always a fresh
    /// read of the pointer — see [`abort`], which re-reads rather than
    /// trusting this.
    pub fn is_past_commit_point(self) -> bool {
        matches!(self, Phase::CommitTargetOwnership | Phase::Done)
    }
}

/// Whether the source cell is still serving the tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceState {
    /// Serving normally; step 2 has not happened, or has been undone.
    Serving,
    /// Quiesced for the move: writes drained or queued, epoch bumped.
    Quiesced,
}

/// How far the tenant has been established in the *target* cell.
///
/// A monotone ladder, which is what makes each step idempotent: the step for a
/// given rung is safe to repeat, and repeating it either advances the rung or
/// leaves it where it was (which [`MoveError::Stalled`] catches).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TargetState {
    /// Nothing of this tenant exists in the target cell.
    Absent,
    /// The final WAL state has been shipped somewhere the target can read,
    /// but not applied.
    Shipped,
    /// Applied and ready to serve — but the target's raft has *not* been told
    /// it owns the tenant, so nothing in the target cell will write.
    Hydrated,
    /// The target cell's raft has committed ownership. Step 6 is done.
    Owning,
}

/// What the residency policy said about the destination (W249, R733-T2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyVerdict {
    /// The tenant's policy permits this destination jurisdiction.
    Permitted,
    /// It does not. `reason` is carried into [`MoveError::PolicyDenied`] and
    /// is meant to be shown to a human — "Tier 0 tenant" is an answer, "false"
    /// is not.
    Denied { reason: String },
}

/// A failure inside a [`MoveEffects`] implementation.
///
/// Type-erased on purpose: the state machine has no opinion about how a
/// control plane fails, only about whether the failure happened before or
/// after the commit point. [`MoveError::Effect`] adds the phase.
#[derive(Debug)]
pub struct EffectFailed(Box<dyn std::error::Error + Send + Sync>);

impl EffectFailed {
    /// Wrap any error, or a plain message.
    pub fn new(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self(e.into())
    }
}

impl std::fmt::Display for EffectFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for EffectFailed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

/// The control-plane work one move needs, as the state machine sees it.
///
/// Every mutating method **must be idempotent**: the machine calls them from a
/// derived phase, and after a crash it will derive that phase again and call
/// the same method a second time. "Quiesce an already-quiesced tenant" and
/// "hydrate an already-hydrated one" have to be no-ops that succeed, not
/// errors — an implementation that fails on replay turns every crash into a
/// stuck move.
///
/// The three observers ([`source_state`](MoveEffects::source_state),
/// [`target_state`](MoveEffects::target_state) and the pointer read the
/// machine does itself) are the *only* memory the protocol has. Nothing is
/// carried across a crash in process state, because nothing can be.
pub trait MoveEffects {
    /// Step 1. Does residency policy permit `plan.target_cell` for this
    /// tenant? Consulted on every resume, not only at the start — a policy
    /// that flips to deny mid-move rolls the move back, which is possible only
    /// before the commit point.
    fn policy_permits(&self, plan: &MovePlan) -> Result<PolicyVerdict, EffectFailed>;

    /// Is the source still serving? See [`SourceState`]; answering
    /// [`SourceState::Serving`] when unsure is safe.
    fn source_state(&self, plan: &MovePlan) -> Result<SourceState, EffectFailed>;

    /// How far the tenant has been established in the target cell.
    fn target_state(&self, plan: &MovePlan) -> Result<TargetState, EffectFailed>;

    /// Step 2. Bump the source's intra-cell epoch to migrating and drain or
    /// queue writes. Idempotent.
    fn quiesce_source(&self, plan: &MovePlan) -> Result<(), EffectFailed>;

    /// Step 3. Ship the final WAL state somewhere the target cell can read.
    ///
    /// **This call is the residency event.** The bytes cross a jurisdiction
    /// boundary here and nowhere else, which is why step 1 gates it.
    fn ship_wal(&self, plan: &MovePlan) -> Result<(), EffectFailed>;

    /// Step 4. Apply the shipped state in the target cell. Idempotent.
    fn hydrate_target(&self, plan: &MovePlan) -> Result<(), EffectFailed>;

    /// Step 6. Commit ownership in the target cell's raft at `generation` —
    /// the generation the pointer CAS just published.
    ///
    /// The generation is passed rather than re-read so that the value the
    /// target fences on is provably the one this move committed. A target that
    /// re-read the pointer itself could pick up a *later* move's generation
    /// and fence on a hand-off it was not party to.
    fn commit_target_ownership(
        &self,
        plan: &MovePlan,
        generation: u64,
    ) -> Result<(), EffectFailed>;

    /// Rollback. Un-quiesce the source and let it serve again. Legal only
    /// before the commit point, which the machine guarantees by re-reading the
    /// pointer before it ever calls this. Idempotent.
    fn resume_source(&self, plan: &MovePlan) -> Result<(), EffectFailed>;

    /// Rollback / abandon. Drop whatever this move left in the target cell.
    ///
    /// Not merely tidiness: a half-hydrated copy sitting in the target cell is
    /// tenant data in a jurisdiction that was never authorised to hold it, so
    /// a failure here is reported loudly even when the tenant itself is
    /// serving correctly. Idempotent.
    fn discard_target_residue(&self, plan: &MovePlan) -> Result<(), EffectFailed>;
}

/// Everything the machine knows about a move at one instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The global pointer, or `None` if the tenant was never placed.
    pub pointer: Option<Pointer>,
    /// The source cell's serving state.
    pub source: SourceState,
    /// How far the target cell has got.
    pub target: TargetState,
    /// The step to perform next, derived by [`phase_from`].
    pub phase: Phase,
}

/// How a move ended.
#[derive(Debug)]
pub enum MoveOutcome {
    /// The tenant is in the target cell at `generation`, and the target cell's
    /// raft knows it. This run performed the pointer CAS.
    Moved { generation: u64 },
    /// It was already there before this run started — a replay of a move that
    /// had completed. No generation was burned.
    AlreadyInTarget { generation: u64 },
    /// The move did not happen and the source is serving again. `at` is the
    /// phase that failed; `cause` is `None` when a caller asked for the abort
    /// rather than a step failing.
    RolledBack {
        at: Phase,
        cause: Option<Box<MoveError>>,
    },
    /// A third cell owns the tenant now — someone else's move won. Residue has
    /// been cleared out of this move's target cell.
    Abandoned { owner_cell: String, generation: u64 },
}

/// Everything that can go wrong.
#[derive(Debug, thiserror::Error)]
pub enum MoveError {
    /// The pointer layer failed. A lost CAS is *not* this: it is reported as
    /// [`MoveOutcome::Abandoned`], because losing means the tenant is somebody
    /// else's now, which is a fact rather than a failure.
    #[error("tenant pointer: {0}")]
    Pointer(#[from] PointerError),

    /// A [`MoveEffects`] call failed, at `step`.
    #[error("move step {step:?} failed: {source}")]
    Effect {
        step: Phase,
        #[source]
        source: EffectFailed,
    },

    /// Step 1 said no. Nothing has been touched when this is raised at the
    /// start; on a resume it rolls the move back.
    #[error("residency policy denies the move to {cell}: {reason}")]
    PolicyDenied { cell: String, reason: String },

    /// The tenant has no pointer at all. A move needs a source of truth about
    /// who owns the tenant *before* it starts changing that; placing a tenant
    /// for the first time is [`yah_tenant_pointer::create_if_absent`], not a
    /// move.
    #[error("tenant {tenant} has no pointer; it has never been placed in a cell")]
    Unplaced { tenant: String },

    /// The pointer names a cell that is neither the plan's source nor its
    /// target, so the plan's premise about where the tenant lives is wrong.
    #[error("tenant {tenant} is in cell {found} at generation {generation}, not in the plan's source {source_cell}")]
    NotInSourceCell {
        tenant: String,
        found: String,
        source_cell: String,
        generation: u64,
    },

    /// Source and target are the same cell.
    #[error("source and target are both {cell}; that is not a move")]
    SameCell { cell: String },

    /// The pointer still names the source, but the target cell's raft already
    /// claims ownership.
    ///
    /// This is **not** corruption — the two-level fence still admits exactly
    /// one writer, because the target's claim loses on the pointer generation.
    /// It is residue, most likely from an earlier move in the other direction,
    /// and the machine refuses to build on it rather than clearing it: the
    /// only way to clear it is to delete tenant data in the target cell on the
    /// inference that it is stale, and that inference is not one a state
    /// machine should make unattended.
    #[error("target cell {target_cell} claims ownership of {tenant} but the pointer says {source_cell} at generation {generation}; clear the stale claim before moving")]
    TargetAlreadyClaimsOwnership {
        tenant: String,
        source_cell: String,
        target_cell: String,
        generation: u64,
    },

    /// An advance completed without moving the world forward — the effects
    /// implementation reported success but the observers say nothing changed.
    /// Raised instead of looping.
    #[error("move stalled at {phase:?}: after performing it the state still derives {observed:?}")]
    Stalled { phase: Phase, observed: Phase },

    /// A rollback was asked for after the pointer had already moved. Refused:
    /// the target cell is entitled to write, and taking the tenant back is a
    /// *new* move in the other direction, not an undo of this one.
    #[error("the pointer already moved to {cell} at generation {generation}; roll forward, do not roll back")]
    PastCommitPoint { cell: String, generation: u64 },

    /// A pre-commit step failed *and* the rollback failed too. Both are
    /// carried: the rollback failure is what needs attention, the original is
    /// what caused it.
    #[error("move failed at {at:?} ({cause}) and the rollback failed too ({rollback})")]
    RollbackFailed {
        at: Phase,
        cause: Box<MoveError>,
        rollback: Box<MoveError>,
    },
}

impl MoveError {
    fn effect(step: Phase, source: EffectFailed) -> Self {
        MoveError::Effect { step, source }
    }
}

/// Derive the step to perform next. Pure, total, and the whole safety argument.
///
/// `pointer` is the record as it stands (`None` when the tenant was never
/// placed); `source` and `target` are what the two cells report. Nothing else
/// is consulted — in particular, not what the previous process believed it had
/// done, because after a crash there is no such thing.
///
/// The three pointer cases are the three regions of the protocol:
///
/// * **pointer names the source** — pre-commit. Everything is undoable; the
///   step comes from how far the target has been staged.
/// * **pointer names the target** — post-commit. Roll forward only, even if
///   the target turns out to be under-hydrated (a crash between step 4 and
///   step 5 leaves exactly that, and finishing hydration is the correct
///   response — the alternative is a cell that owns a tenant it cannot serve).
/// * **pointer names a third cell** — [`Phase::Abandon`]. Another move won.
pub fn phase_from(
    plan: &MovePlan,
    pointer: Option<&PointerRecord>,
    source: SourceState,
    target: TargetState,
) -> Result<Phase, MoveError> {
    let Some(record) = pointer else {
        return Err(MoveError::Unplaced {
            tenant: plan.tenant.clone(),
        });
    };

    if record.is_in_cell(&plan.target_cell) {
        // Past the commit point. The pointer has transferred ownership; the
        // only remaining work is making the target cell able to act on it.
        return Ok(match target {
            TargetState::Absent | TargetState::Shipped => Phase::HydrateTarget,
            TargetState::Hydrated => Phase::CommitTargetOwnership,
            TargetState::Owning => Phase::Done,
        });
    }

    if !record.is_in_cell(&plan.source_cell) {
        return Ok(Phase::Abandon);
    }

    // Pre-commit: the source still owns the tenant.
    if target == TargetState::Owning {
        return Err(MoveError::TargetAlreadyClaimsOwnership {
            tenant: plan.tenant.clone(),
            source_cell: plan.source_cell.clone(),
            target_cell: plan.target_cell.clone(),
            generation: record.generation,
        });
    }
    if source == SourceState::Serving {
        // Covers both "nothing has happened yet" and "a partially staged move
        // whose source came back up serving". Re-gating policy and re-quiescing
        // is the right response to both, and step 1 is where that starts.
        return Ok(Phase::CheckPolicy);
    }
    Ok(match target {
        TargetState::Absent => Phase::ShipWal,
        TargetState::Shipped => Phase::HydrateTarget,
        TargetState::Hydrated => Phase::CommitPointer,
        TargetState::Owning => unreachable!("handled above"),
    })
}

/// Read the world and derive the next step.
pub fn observe(
    store: &dyn ObjectStore,
    effects: &dyn MoveEffects,
    plan: &MovePlan,
) -> Result<Observation, MoveError> {
    let pointer = pointer::read(store, &plan.tenant)?;
    let source = effects
        .source_state(plan)
        .map_err(|e| MoveError::effect(Phase::QuiesceSource, e))?;
    let target = effects
        .target_state(plan)
        .map_err(|e| MoveError::effect(Phase::HydrateTarget, e))?;
    let phase = phase_from(plan, pointer.as_ref().map(|p| &p.record), source, target)?;
    Ok(Observation {
        pointer,
        source,
        target,
        phase,
    })
}

/// Perform exactly `phase`, then say what comes next.
///
/// One step per call, so a fault injector can stop the protocol between any
/// two of them (which is what R736-T5 does). Except for the step-1 → step-2
/// transition, the returned phase is *re-derived from a fresh observation*
/// rather than assumed — so a step whose effect did not take is caught here
/// and not three steps later.
///
/// [`Phase::CheckPolicy`] is the exception, and has to be: a policy check is a
/// predicate over policy, not a mutation, so it leaves no trace in the world
/// for a re-derivation to find. It hands straight to
/// [`Phase::QuiesceSource`].
///
/// Terminal phases ([`Phase::Done`], [`Phase::Abandon`]) return themselves and
/// do nothing; the cleanup that [`Phase::Abandon`] implies is [`run`]'s, since
/// it is an ending rather than a step.
pub fn advance(
    store: &dyn ObjectStore,
    effects: &dyn MoveEffects,
    plan: &MovePlan,
    phase: Phase,
) -> Result<Phase, MoveError> {
    match phase {
        Phase::CheckPolicy => {
            match effects
                .policy_permits(plan)
                .map_err(|e| MoveError::effect(Phase::CheckPolicy, e))?
            {
                PolicyVerdict::Permitted => Ok(Phase::QuiesceSource),
                PolicyVerdict::Denied { reason } => Err(MoveError::PolicyDenied {
                    cell: plan.target_cell.clone(),
                    reason,
                }),
            }
        }
        Phase::QuiesceSource => {
            effects
                .quiesce_source(plan)
                .map_err(|e| MoveError::effect(Phase::QuiesceSource, e))?;
            rederive(store, effects, plan, phase)
        }
        Phase::ShipWal => {
            effects
                .ship_wal(plan)
                .map_err(|e| MoveError::effect(Phase::ShipWal, e))?;
            rederive(store, effects, plan, phase)
        }
        Phase::HydrateTarget => {
            effects
                .hydrate_target(plan)
                .map_err(|e| MoveError::effect(Phase::HydrateTarget, e))?;
            rederive(store, effects, plan, phase)
        }
        Phase::CommitPointer => {
            // The commit point. `commit_cell` is the idempotent form: a replay
            // after a crash that landed the CAS reports AlreadyCommitted and
            // burns no generation, and a lost race reports Lost rather than
            // fighting for a tenant that is no longer ours.
            pointer::commit_cell(store, &plan.tenant, &plan.target_cell)?;
            rederive(store, effects, plan, phase)
        }
        Phase::CommitTargetOwnership => {
            // Re-read rather than carrying the generation from the CAS: on a
            // resumed move the CAS happened in a process that is gone, and the
            // pointer is the only place its result survives.
            let current = pointer::read(store, &plan.tenant)?.ok_or_else(|| {
                // The pointer existed a moment ago (this phase is only derived
                // from a pointer that names the target) and now does not.
                MoveError::Unplaced {
                    tenant: plan.tenant.clone(),
                }
            })?;
            if !current.record.is_in_cell(&plan.target_cell) {
                // Somebody moved it out from under us between the derivation
                // and now. Re-derive and let the caller take the Abandon exit
                // rather than committing ownership we no longer hold.
                return rederive(store, effects, plan, phase);
            }
            effects
                .commit_target_ownership(plan, current.record.generation)
                .map_err(|e| MoveError::effect(Phase::CommitTargetOwnership, e))?;
            rederive(store, effects, plan, phase)
        }
        Phase::Done | Phase::Abandon => Ok(phase),
    }
}

/// Re-observe after a step and insist the world actually moved.
fn rederive(
    store: &dyn ObjectStore,
    effects: &dyn MoveEffects,
    plan: &MovePlan,
    performed: Phase,
) -> Result<Phase, MoveError> {
    let observed = observe(store, effects, plan)?.phase;
    // Abandon is a lateral exit rather than a regression: it means the pointer
    // moved to a third cell under us, which is information, not a stall.
    if observed != Phase::Abandon && observed.rank() <= performed.rank() {
        return Err(MoveError::Stalled {
            phase: performed,
            observed,
        });
    }
    Ok(observed)
}

/// Drive a move to a terminal state, resuming or rolling back as the observed
/// state dictates.
///
/// Safe to call on a fresh move, on one another process abandoned mid-flight,
/// and on one that already completed. Which of those it is, is derived rather
/// than declared.
///
/// **Failure handling is the point of this function.** A step that fails
/// *before* the commit point rolls the move back — the source resumes serving
/// and the target's residue is cleared — and returns
/// [`MoveOutcome::RolledBack`], which is a successful, safe ending rather than
/// an `Err`. A step that fails *after* it returns `Err` with the state left
/// resumable, because rolling back would race a target cell that is already
/// entitled to write. Whether the commit point has passed is decided by
/// re-reading the pointer inside [`abort`], never by the phase label.
pub fn run(
    store: &dyn ObjectStore,
    effects: &dyn MoveEffects,
    plan: &MovePlan,
) -> Result<MoveOutcome, MoveError> {
    let entry = observe(store, effects, plan)?;

    if entry.phase == Phase::Done {
        return Ok(MoveOutcome::AlreadyInTarget {
            generation: generation_of(&entry),
        });
    }
    if entry.phase == Phase::Abandon {
        return abandon(effects, plan, &entry);
    }

    // Re-gate policy on resume. When the entry phase is CheckPolicy the gate
    // *is* the first step, so it is not evaluated twice; for any other
    // pre-commit entry this is a move already in flight whose policy nobody has
    // re-read since the process that started it died.
    if entry.phase != Phase::CheckPolicy && !entry.phase.is_past_commit_point() {
        match effects
            .policy_permits(plan)
            .map_err(|e| MoveError::effect(Phase::CheckPolicy, e))?
        {
            PolicyVerdict::Permitted => {}
            PolicyVerdict::Denied { reason } => {
                let cause = MoveError::PolicyDenied {
                    cell: plan.target_cell.clone(),
                    reason,
                };
                return roll_back(store, effects, plan, entry.phase, cause);
            }
        }
    }

    let mut phase = entry.phase;
    for _ in 0..MAX_ADVANCES {
        match advance(store, effects, plan, phase) {
            Ok(Phase::Done) => {
                let settled = observe(store, effects, plan)?;
                return Ok(MoveOutcome::Moved {
                    generation: generation_of(&settled),
                });
            }
            Ok(Phase::Abandon) => {
                let settled = observe(store, effects, plan)?;
                return abandon(effects, plan, &settled);
            }
            Ok(next) => phase = next,
            Err(cause) => return roll_back(store, effects, plan, phase, cause),
        }
    }
    Err(MoveError::Stalled {
        phase,
        observed: phase,
    })
}

/// Give up on a move and put the world back, or explain why that is no longer
/// possible.
///
/// The pointer is re-read first and decides everything: still in the source →
/// resume it and clear the target's residue; already in the target →
/// [`MoveError::PastCommitPoint`], refused; in a third cell → the move was
/// overtaken, clear the residue and report [`MoveOutcome::Abandoned`].
///
/// The source is resumed **before** the target residue is discarded. The
/// source is the legitimate owner and always was, so restoring service is the
/// urgent half; an orphaned copy in the target cell is a residency problem to
/// report loudly, not one to keep the tenant offline for.
pub fn abort(
    store: &dyn ObjectStore,
    effects: &dyn MoveEffects,
    plan: &MovePlan,
) -> Result<MoveOutcome, MoveError> {
    let observation = observe_for_abort(store, effects, plan)?;
    unwind(store, effects, plan, &observation, Phase::CheckPolicy, None)
}

/// Like [`observe`] but tolerant of the states that only an abort can be in.
///
/// [`phase_from`] refuses `TargetAlreadyClaimsOwnership`, which is exactly a
/// state an operator might be trying to abort out of, so the derivation is
/// skipped here and the raw facts are returned.
fn observe_for_abort(
    store: &dyn ObjectStore,
    effects: &dyn MoveEffects,
    plan: &MovePlan,
) -> Result<Observation, MoveError> {
    let pointer = pointer::read(store, &plan.tenant)?;
    let source = effects
        .source_state(plan)
        .map_err(|e| MoveError::effect(Phase::QuiesceSource, e))?;
    let target = effects
        .target_state(plan)
        .map_err(|e| MoveError::effect(Phase::HydrateTarget, e))?;
    Ok(Observation {
        pointer,
        source,
        target,
        // Not derived: the caller is unwinding, and the derivation's job is to
        // decide the next *forward* step.
        phase: Phase::Abandon,
    })
}

fn roll_back(
    store: &dyn ObjectStore,
    effects: &dyn MoveEffects,
    plan: &MovePlan,
    at: Phase,
    cause: MoveError,
) -> Result<MoveOutcome, MoveError> {
    let observation = match observe_for_abort(store, effects, plan) {
        Ok(o) => o,
        Err(rollback) => {
            return Err(MoveError::RollbackFailed {
                at,
                cause: Box::new(cause),
                rollback: Box::new(rollback),
            })
        }
    };
    unwind(store, effects, plan, &observation, at, Some(cause))
}

/// The shared body of [`abort`] and [`roll_back`].
fn unwind(
    store: &dyn ObjectStore,
    effects: &dyn MoveEffects,
    plan: &MovePlan,
    observation: &Observation,
    at: Phase,
    cause: Option<MoveError>,
) -> Result<MoveOutcome, MoveError> {
    let _ = store;
    let Some(current) = observation.pointer.as_ref() else {
        let unplaced = MoveError::Unplaced {
            tenant: plan.tenant.clone(),
        };
        return Err(match cause {
            Some(cause) => MoveError::RollbackFailed {
                at,
                cause: Box::new(cause),
                rollback: Box::new(unplaced),
            },
            None => unplaced,
        });
    };

    if current.record.is_in_cell(&plan.target_cell) {
        let past = MoveError::PastCommitPoint {
            cell: plan.target_cell.clone(),
            generation: current.record.generation,
        };
        // A failure that happened after the commit point is not rollable back,
        // and saying so must not lose the original: the caller needs to retry
        // it forward, and needs to know what it is retrying.
        return Err(match cause {
            Some(cause) => MoveError::RollbackFailed {
                at,
                cause: Box::new(cause),
                rollback: Box::new(past),
            },
            None => past,
        });
    }

    if !current.record.is_in_cell(&plan.source_cell) {
        // Overtaken by another move. The source is fenced by generation
        // already, so resuming it would be wrong; only the residue is ours.
        return abandon(effects, plan, observation);
    }

    let resumed = effects
        .resume_source(plan)
        .map_err(|e| MoveError::effect(Phase::QuiesceSource, e));
    let discarded = effects
        .discard_target_residue(plan)
        .map_err(|e| MoveError::effect(Phase::HydrateTarget, e));

    // Both are attempted before either is reported: leaving the target residue
    // in place because un-quiescing failed would compound a liveness problem
    // with a residency one.
    if let Err(rollback) = resumed.and(discarded) {
        return Err(MoveError::RollbackFailed {
            at,
            cause: Box::new(cause.unwrap_or(MoveError::PolicyDenied {
                cell: plan.target_cell.clone(),
                reason: "abort requested".into(),
            })),
            rollback: Box::new(rollback),
        });
    }

    Ok(MoveOutcome::RolledBack {
        at,
        cause: cause.map(Box::new),
    })
}

/// Clear this move's residue out of a target cell that is not going to own the
/// tenant, and report who does.
fn abandon(
    effects: &dyn MoveEffects,
    plan: &MovePlan,
    observation: &Observation,
) -> Result<MoveOutcome, MoveError> {
    effects
        .discard_target_residue(plan)
        .map_err(|e| MoveError::effect(Phase::HydrateTarget, e))?;
    let (owner_cell, generation) = match observation.pointer.as_ref() {
        Some(p) => (p.record.cell.clone(), p.record.generation),
        None => {
            return Err(MoveError::Unplaced {
                tenant: plan.tenant.clone(),
            })
        }
    };
    Ok(MoveOutcome::Abandoned {
        owner_cell,
        generation,
    })
}

fn generation_of(observation: &Observation) -> u64 {
    observation
        .pointer
        .as_ref()
        .map(|p| p.record.generation)
        .unwrap_or(FIRST_GENERATION)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use yah_object_store::InMemoryObjectStore;

    // ── a fake pair of cells ────────────────────────────────────────────────
    //
    // Enough of a control plane to fault at any step: the two observable
    // states, a call log, and one knob that makes a chosen step fail. The
    // mutating steps are written idempotently, exactly as the trait requires
    // of a real implementation — a fake that was not idempotent would make the
    // resume tests pass for the wrong reason.

    struct FakeCells {
        source: RefCell<SourceState>,
        target: RefCell<TargetState>,
        policy: RefCell<PolicyVerdict>,
        fail_at: RefCell<Option<Phase>>,
        /// Set to make a step succeed while changing nothing — the shape of a
        /// buggy control plane that reports progress it did not make.
        no_op_at: RefCell<Option<Phase>>,
        calls: RefCell<Vec<&'static str>>,
        committed_generation: RefCell<Option<u64>>,
    }

    impl FakeCells {
        fn new() -> Self {
            Self {
                source: RefCell::new(SourceState::Serving),
                target: RefCell::new(TargetState::Absent),
                policy: RefCell::new(PolicyVerdict::Permitted),
                fail_at: RefCell::new(None),
                no_op_at: RefCell::new(None),
                calls: RefCell::new(Vec::new()),
                committed_generation: RefCell::new(None),
            }
        }

        fn log(&self, what: &'static str) {
            self.calls.borrow_mut().push(what);
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls.borrow().clone()
        }

        fn called(&self, what: &str) -> bool {
            self.calls.borrow().contains(&what)
        }

        fn gate(&self, step: Phase) -> Result<bool, EffectFailed> {
            if *self.fail_at.borrow() == Some(step) {
                return Err(EffectFailed::new(format!("injected fault at {step:?}")));
            }
            Ok(*self.no_op_at.borrow() != Some(step))
        }

        fn fault(&self, step: Phase) {
            *self.fail_at.borrow_mut() = Some(step);
        }

        fn clear_fault(&self) {
            *self.fail_at.borrow_mut() = None;
        }

        fn deny(&self, reason: &str) {
            *self.policy.borrow_mut() = PolicyVerdict::Denied {
                reason: reason.to_string(),
            };
        }

        /// Put the fake in the state a crash at `phase` would have left it in.
        fn staged_to(&self, source: SourceState, target: TargetState) {
            *self.source.borrow_mut() = source;
            *self.target.borrow_mut() = target;
        }
    }

    impl MoveEffects for FakeCells {
        fn policy_permits(&self, _plan: &MovePlan) -> Result<PolicyVerdict, EffectFailed> {
            self.log("policy");
            self.gate(Phase::CheckPolicy)?;
            Ok(self.policy.borrow().clone())
        }

        fn source_state(&self, _plan: &MovePlan) -> Result<SourceState, EffectFailed> {
            Ok(*self.source.borrow())
        }

        fn target_state(&self, _plan: &MovePlan) -> Result<TargetState, EffectFailed> {
            Ok(*self.target.borrow())
        }

        fn quiesce_source(&self, _plan: &MovePlan) -> Result<(), EffectFailed> {
            self.log("quiesce");
            if self.gate(Phase::QuiesceSource)? {
                *self.source.borrow_mut() = SourceState::Quiesced;
            }
            Ok(())
        }

        fn ship_wal(&self, _plan: &MovePlan) -> Result<(), EffectFailed> {
            self.log("ship");
            if self.gate(Phase::ShipWal)? {
                let mut target = self.target.borrow_mut();
                *target = (*target).max(TargetState::Shipped);
            }
            Ok(())
        }

        fn hydrate_target(&self, _plan: &MovePlan) -> Result<(), EffectFailed> {
            self.log("hydrate");
            if self.gate(Phase::HydrateTarget)? {
                let mut target = self.target.borrow_mut();
                *target = (*target).max(TargetState::Hydrated);
            }
            Ok(())
        }

        fn commit_target_ownership(
            &self,
            _plan: &MovePlan,
            generation: u64,
        ) -> Result<(), EffectFailed> {
            self.log("commit-target");
            if self.gate(Phase::CommitTargetOwnership)? {
                *self.target.borrow_mut() = TargetState::Owning;
                *self.committed_generation.borrow_mut() = Some(generation);
            }
            Ok(())
        }

        fn resume_source(&self, _plan: &MovePlan) -> Result<(), EffectFailed> {
            self.log("resume");
            *self.source.borrow_mut() = SourceState::Serving;
            Ok(())
        }

        fn discard_target_residue(&self, _plan: &MovePlan) -> Result<(), EffectFailed> {
            self.log("discard");
            *self.target.borrow_mut() = TargetState::Absent;
            Ok(())
        }
    }

    fn plan() -> MovePlan {
        MovePlan::new("noisetable", "prod-us", "prod-eu").unwrap()
    }

    /// A tenant already placed in the source cell, as every move starts.
    fn placed() -> InMemoryObjectStore {
        let store = InMemoryObjectStore::new();
        pointer::create_if_absent(&store, "noisetable", "prod-us").unwrap();
        store
    }

    fn record(store: &InMemoryObjectStore) -> PointerRecord {
        pointer::read(store, "noisetable").unwrap().unwrap().record
    }

    // ── plan validation ─────────────────────────────────────────────────────

    #[test]
    fn a_plan_whose_cells_are_the_same_is_not_a_move() {
        let err = MovePlan::new("t", "prod-us", "prod-us").unwrap_err();
        assert!(matches!(err, MoveError::SameCell { .. }), "{err:?}");
    }

    #[test]
    fn plan_validation_uses_the_pointer_crates_identifier_rules() {
        // The point is failing here rather than at the CAS — by step 5 the
        // source is quiesced and the WAL has been shipped for nothing.
        for bad in ["", "prod/us", "prod us"] {
            assert!(
                MovePlan::new("t", "prod-us", bad).is_err(),
                "{bad:?} should be refused"
            );
            assert!(MovePlan::new(bad, "prod-us", "prod-eu").is_err());
        }
    }

    // ── the derivation table (pure) ─────────────────────────────────────────

    fn rec(cell: &str, generation: u64) -> PointerRecord {
        PointerRecord {
            schema_version: yah_tenant_pointer::POINTER_SCHEMA_VERSION,
            tenant: "noisetable".into(),
            cell: cell.into(),
            generation,
        }
    }

    #[test]
    fn an_unplaced_tenant_cannot_be_moved() {
        let err = phase_from(&plan(), None, SourceState::Serving, TargetState::Absent)
            .unwrap_err();
        assert!(matches!(err, MoveError::Unplaced { .. }), "{err:?}");
    }

    #[test]
    fn pre_commit_the_step_comes_from_how_far_the_target_is_staged() {
        let (p, source) = (plan(), rec("prod-us", 3));
        let at = |s, t| phase_from(&p, Some(&source), s, t).unwrap();
        // A serving source means step 1 whatever the target looks like: the
        // move either has not started or has been backed out from under it.
        assert_eq!(at(SourceState::Serving, TargetState::Absent), Phase::CheckPolicy);
        assert_eq!(at(SourceState::Serving, TargetState::Shipped), Phase::CheckPolicy);
        assert_eq!(at(SourceState::Serving, TargetState::Hydrated), Phase::CheckPolicy);
        assert_eq!(at(SourceState::Quiesced, TargetState::Absent), Phase::ShipWal);
        assert_eq!(at(SourceState::Quiesced, TargetState::Shipped), Phase::HydrateTarget);
        assert_eq!(
            at(SourceState::Quiesced, TargetState::Hydrated),
            Phase::CommitPointer
        );
    }

    #[test]
    fn post_commit_every_state_rolls_forward_and_none_rolls_back() {
        let (p, target) = (plan(), rec("prod-eu", 4));
        let at = |t| phase_from(&p, Some(&target), SourceState::Quiesced, t).unwrap();
        // Under-hydrated *after* the CAS is the crash between step 4 and step
        // 5. Finishing hydration is the only correct answer; the alternative
        // is a cell that owns a tenant it cannot serve.
        assert_eq!(at(TargetState::Absent), Phase::HydrateTarget);
        assert_eq!(at(TargetState::Shipped), Phase::HydrateTarget);
        assert_eq!(at(TargetState::Hydrated), Phase::CommitTargetOwnership);
        assert_eq!(at(TargetState::Owning), Phase::Done);
        // Even a source that came back up serving does not change this: the
        // pointer already moved, so the source's writes bounce on generation.
        assert_eq!(
            phase_from(&p, Some(&target), SourceState::Serving, TargetState::Hydrated).unwrap(),
            Phase::CommitTargetOwnership
        );
    }

    #[test]
    fn a_third_cell_owning_the_tenant_is_abandon_not_an_error() {
        let phase = phase_from(
            &plan(),
            Some(&rec("prod-ap", 9)),
            SourceState::Quiesced,
            TargetState::Hydrated,
        )
        .unwrap();
        assert_eq!(phase, Phase::Abandon);
    }

    #[test]
    fn a_target_claiming_ownership_before_the_cas_is_refused_not_cleared() {
        // Not corruption — the target's claim loses on the pointer generation
        // — but the machine will not delete tenant data on the inference that
        // the claim is stale.
        let err = phase_from(
            &plan(),
            Some(&rec("prod-us", 2)),
            SourceState::Quiesced,
            TargetState::Owning,
        )
        .unwrap_err();
        assert!(
            matches!(err, MoveError::TargetAlreadyClaimsOwnership { .. }),
            "{err:?}"
        );
    }

    // ── the happy path ──────────────────────────────────────────────────────

    #[test]
    fn a_clean_move_walks_all_seven_steps_and_bumps_the_generation() {
        let (store, cells, p) = (placed(), FakeCells::new(), plan());
        assert_eq!(record(&store).generation, FIRST_GENERATION);

        let outcome = run(&store, &cells, &p).unwrap();

        assert!(
            matches!(outcome, MoveOutcome::Moved { generation: 2 }),
            "{outcome:?}"
        );
        assert_eq!(
            cells.calls(),
            vec!["policy", "quiesce", "ship", "hydrate", "commit-target"]
        );
        let settled = record(&store);
        assert!(settled.is_in_cell("prod-eu"));
        assert_eq!(settled.generation, 2);
        assert_eq!(*cells.target.borrow(), TargetState::Owning);
        // Step 7 is not an action: the source is fenced because the generation
        // moved, and nothing un-quiesced it.
        assert_eq!(*cells.source.borrow(), SourceState::Quiesced);
        assert!(!cells.called("resume"));
    }

    #[test]
    fn the_target_cell_fences_on_the_generation_this_move_published() {
        let (store, cells, p) = (placed(), FakeCells::new(), plan());
        run(&store, &cells, &p).unwrap();
        assert_eq!(*cells.committed_generation.borrow(), Some(2));
        assert_eq!(record(&store).generation, 2);
    }

    #[test]
    fn replaying_a_completed_move_costs_no_generation() {
        let (store, cells, p) = (placed(), FakeCells::new(), plan());
        run(&store, &cells, &p).unwrap();
        let after_first = record(&store).generation;

        let again = run(&store, &cells, &p).unwrap();

        assert!(
            matches!(again, MoveOutcome::AlreadyInTarget { generation: 2 }),
            "{again:?}"
        );
        assert_eq!(record(&store).generation, after_first);
    }

    // ── crashes before the commit point roll back ───────────────────────────

    #[test]
    fn a_fault_before_the_commit_point_rolls_back_and_the_source_serves_again() {
        let (store, cells, p) = (placed(), FakeCells::new(), plan());
        cells.fault(Phase::HydrateTarget);

        let outcome = run(&store, &cells, &p).unwrap();

        match outcome {
            MoveOutcome::RolledBack { at, cause } => {
                assert_eq!(at, Phase::HydrateTarget);
                assert!(matches!(
                    cause.as_deref(),
                    Some(MoveError::Effect {
                        step: Phase::HydrateTarget,
                        ..
                    })
                ));
            }
            other => panic!("expected RolledBack, got {other:?}"),
        }
        // Exactly one owner, and it is the source: pointer untouched, source
        // serving, nothing left behind in the target cell.
        assert!(record(&store).is_in_cell("prod-us"));
        assert_eq!(record(&store).generation, FIRST_GENERATION);
        assert_eq!(*cells.source.borrow(), SourceState::Serving);
        assert_eq!(*cells.target.borrow(), TargetState::Absent);
    }

    #[test]
    fn a_rolled_back_move_can_simply_be_run_again() {
        let (store, cells, p) = (placed(), FakeCells::new(), plan());
        cells.fault(Phase::ShipWal);
        assert!(matches!(
            run(&store, &cells, &p).unwrap(),
            MoveOutcome::RolledBack { .. }
        ));

        cells.clear_fault();
        let outcome = run(&store, &cells, &p).unwrap();

        assert!(
            matches!(outcome, MoveOutcome::Moved { generation: 2 }),
            "{outcome:?}"
        );
        assert!(record(&store).is_in_cell("prod-eu"));
    }

    #[test]
    fn rollback_restores_service_before_it_clears_the_target() {
        let (store, cells, p) = (placed(), FakeCells::new(), plan());
        cells.fault(Phase::HydrateTarget);
        run(&store, &cells, &p).unwrap();

        let calls = cells.calls();
        let resume = calls.iter().position(|c| *c == "resume").unwrap();
        let discard = calls.iter().position(|c| *c == "discard").unwrap();
        assert!(
            resume < discard,
            "the source is the legitimate owner; restoring service is the urgent half: {calls:?}"
        );
    }

    #[test]
    fn a_policy_denial_rolls_back_before_anything_is_quiesced() {
        let (store, cells, p) = (placed(), FakeCells::new(), plan());
        cells.deny("tier 0 tenant: no cross-jurisdiction copy is legal");

        let outcome = run(&store, &cells, &p).unwrap();

        match outcome {
            MoveOutcome::RolledBack { at, cause } => {
                assert_eq!(at, Phase::CheckPolicy);
                assert!(matches!(
                    cause.as_deref(),
                    Some(MoveError::PolicyDenied { .. })
                ));
            }
            other => panic!("expected RolledBack, got {other:?}"),
        }
        // Step 3's copy is the residency event, so a denial must stop before
        // step 2, let alone step 3.
        assert!(!cells.called("quiesce"));
        assert!(!cells.called("ship"));
        assert_eq!(*cells.source.borrow(), SourceState::Serving);
    }

    #[test]
    fn a_policy_that_flips_to_deny_mid_move_rolls_the_half_staged_move_back() {
        let (store, cells, p) = (placed(), FakeCells::new(), plan());
        // A move another process left staged at step 4, one step short of the
        // commit point.
        cells.staged_to(SourceState::Quiesced, TargetState::Hydrated);
        cells.deny("residency policy changed while the move was in flight");

        let outcome = run(&store, &cells, &p).unwrap();

        assert!(matches!(outcome, MoveOutcome::RolledBack { .. }), "{outcome:?}");
        assert!(record(&store).is_in_cell("prod-us"));
        assert_eq!(*cells.source.borrow(), SourceState::Serving);
        assert_eq!(*cells.target.borrow(), TargetState::Absent);
    }

    // ── crashes after the commit point roll forward ─────────────────────────

    #[test]
    fn a_crash_after_the_cas_rolls_forward_and_never_back() {
        let (store, cells, p) = (placed(), FakeCells::new(), plan());
        // The world a crash between step 5 and step 6 leaves: pointer moved,
        // target hydrated but not yet owning.
        cells.staged_to(SourceState::Quiesced, TargetState::Hydrated);
        pointer::commit_cell(&store, "noisetable", "prod-eu").unwrap();
        assert_eq!(record(&store).generation, 2);

        let outcome = run(&store, &cells, &p).unwrap();

        assert!(
            matches!(outcome, MoveOutcome::Moved { generation: 2 }),
            "{outcome:?}"
        );
        // The replayed CAS costs no generation, and the source is never
        // resumed — it is fenced, and un-fencing it is what would create two
        // owners.
        assert_eq!(record(&store).generation, 2);
        assert!(!cells.called("resume"));
        assert_eq!(*cells.target.borrow(), TargetState::Owning);
    }

    #[test]
    fn a_crash_between_hydrate_and_the_cas_finishes_hydrating_rather_than_undoing_it() {
        let (store, cells, p) = (placed(), FakeCells::new(), plan());
        // Pointer moved but the target never finished hydrating — the narrow
        // window where the target owns a tenant it cannot yet serve.
        cells.staged_to(SourceState::Quiesced, TargetState::Shipped);
        pointer::commit_cell(&store, "noisetable", "prod-eu").unwrap();

        let outcome = run(&store, &cells, &p).unwrap();

        assert!(matches!(outcome, MoveOutcome::Moved { .. }), "{outcome:?}");
        assert_eq!(*cells.target.borrow(), TargetState::Owning);
        assert!(!cells.called("resume"));
        assert!(!cells.called("discard"));
    }

    #[test]
    fn a_failure_after_the_commit_point_is_an_error_and_leaves_the_move_resumable() {
        let (store, cells, p) = (placed(), FakeCells::new(), plan());
        cells.staged_to(SourceState::Quiesced, TargetState::Hydrated);
        pointer::commit_cell(&store, "noisetable", "prod-eu").unwrap();
        cells.fault(Phase::CommitTargetOwnership);

        let err = run(&store, &cells, &p).unwrap_err();

        // Reported as a failed rollback rather than a rollback: the attempt to
        // unwind hit the commit point and refused, and both halves are carried.
        match err {
            MoveError::RollbackFailed { at, cause, rollback } => {
                assert_eq!(at, Phase::CommitTargetOwnership);
                assert!(matches!(*cause, MoveError::Effect { .. }), "{cause:?}");
                assert!(
                    matches!(*rollback, MoveError::PastCommitPoint { .. }),
                    "{rollback:?}"
                );
            }
            other => panic!("expected RollbackFailed, got {other:?}"),
        }
        assert!(!cells.called("resume"));
        assert!(!cells.called("discard"));
        assert!(record(&store).is_in_cell("prod-eu"));

        // And resuming it finishes the move rather than needing a new one.
        cells.clear_fault();
        assert!(matches!(
            run(&store, &cells, &p).unwrap(),
            MoveOutcome::Moved { generation: 2 }
        ));
    }

    #[test]
    fn abort_after_the_commit_point_is_refused() {
        let (store, cells, p) = (placed(), FakeCells::new(), plan());
        cells.staged_to(SourceState::Quiesced, TargetState::Hydrated);
        pointer::commit_cell(&store, "noisetable", "prod-eu").unwrap();

        let err = abort(&store, &cells, &p).unwrap_err();

        assert!(matches!(err, MoveError::PastCommitPoint { .. }), "{err:?}");
        assert!(!cells.called("resume"));
        assert!(record(&store).is_in_cell("prod-eu"));
    }

    #[test]
    fn abort_before_the_commit_point_puts_the_source_back() {
        let (store, cells, p) = (placed(), FakeCells::new(), plan());
        cells.staged_to(SourceState::Quiesced, TargetState::Hydrated);

        let outcome = abort(&store, &cells, &p).unwrap();

        match outcome {
            MoveOutcome::RolledBack { cause, .. } => assert!(cause.is_none()),
            other => panic!("expected RolledBack, got {other:?}"),
        }
        assert_eq!(*cells.source.borrow(), SourceState::Serving);
        assert_eq!(*cells.target.borrow(), TargetState::Absent);
        assert!(record(&store).is_in_cell("prod-us"));
    }

    // ── being overtaken by somebody else's move ─────────────────────────────

    #[test]
    fn a_third_cell_taking_the_tenant_mid_move_abandons_and_clears_the_residue() {
        let (store, cells, p) = (placed(), FakeCells::new(), plan());
        cells.staged_to(SourceState::Quiesced, TargetState::Hydrated);
        // Somebody else's move landed first.
        pointer::commit_cell(&store, "noisetable", "prod-ap").unwrap();

        let outcome = run(&store, &cells, &p).unwrap();

        match outcome {
            MoveOutcome::Abandoned {
                owner_cell,
                generation,
            } => {
                assert_eq!(owner_cell, "prod-ap");
                assert_eq!(generation, 2);
            }
            other => panic!("expected Abandoned, got {other:?}"),
        }
        // The residue leaves the target cell; the source is NOT resumed, since
        // the pointer fenced it and un-quiescing would invite a second writer.
        assert_eq!(*cells.target.borrow(), TargetState::Absent);
        assert!(!cells.called("resume"));
        assert_eq!(*cells.source.borrow(), SourceState::Quiesced);
    }

    #[test]
    fn losing_the_pointer_cas_abandons_rather_than_retrying() {
        struct Racer<'a> {
            inner: FakeCells,
            store: &'a InMemoryObjectStore,
        }
        impl MoveEffects for Racer<'_> {
            fn policy_permits(&self, p: &MovePlan) -> Result<PolicyVerdict, EffectFailed> {
                self.inner.policy_permits(p)
            }
            fn source_state(&self, p: &MovePlan) -> Result<SourceState, EffectFailed> {
                self.inner.source_state(p)
            }
            fn target_state(&self, p: &MovePlan) -> Result<TargetState, EffectFailed> {
                self.inner.target_state(p)
            }
            fn quiesce_source(&self, p: &MovePlan) -> Result<(), EffectFailed> {
                self.inner.quiesce_source(p)
            }
            fn ship_wal(&self, p: &MovePlan) -> Result<(), EffectFailed> {
                self.inner.ship_wal(p)
            }
            fn hydrate_target(&self, p: &MovePlan) -> Result<(), EffectFailed> {
                // The last instant at which another cell can still win: we are
                // hydrated and about to CAS.
                self.inner.hydrate_target(p)?;
                pointer::commit_cell(self.store, "noisetable", "prod-ap").unwrap();
                Ok(())
            }
            fn commit_target_ownership(
                &self,
                p: &MovePlan,
                g: u64,
            ) -> Result<(), EffectFailed> {
                self.inner.commit_target_ownership(p, g)
            }
            fn resume_source(&self, p: &MovePlan) -> Result<(), EffectFailed> {
                self.inner.resume_source(p)
            }
            fn discard_target_residue(&self, p: &MovePlan) -> Result<(), EffectFailed> {
                self.inner.discard_target_residue(p)
            }
        }

        let (store, p) = (placed(), plan());
        let racer = Racer {
            inner: FakeCells::new(),
            store: &store,
        };

        let outcome = run(&store, &racer, &p).unwrap();

        match outcome {
            MoveOutcome::Abandoned { owner_cell, .. } => assert_eq!(owner_cell, "prod-ap"),
            other => panic!("expected Abandoned, got {other:?}"),
        }
        // We never took ownership in our target cell, and we did not fight for
        // the pointer: exactly one owner, and it is prod-ap.
        assert!(record(&store).is_in_cell("prod-ap"));
        assert!(!racer.inner.called("commit-target"));
    }

    // ── a control plane that lies about progress ────────────────────────────

    #[test]
    fn a_step_that_reports_success_without_doing_anything_stalls_rather_than_looping() {
        let (store, cells, p) = (placed(), FakeCells::new(), plan());
        *cells.no_op_at.borrow_mut() = Some(Phase::ShipWal);

        // The no-op is pre-commit, so it is caught and rolled back rather than
        // spun on: MAX_ADVANCES is the backstop, the rank check is the catch.
        let outcome = run(&store, &cells, &p).unwrap();

        match outcome {
            MoveOutcome::RolledBack { at, cause } => {
                assert_eq!(at, Phase::ShipWal);
                assert!(
                    matches!(
                        cause.as_deref(),
                        Some(MoveError::Stalled {
                            phase: Phase::ShipWal,
                            observed: Phase::ShipWal
                        })
                    ),
                    "{cause:?}"
                );
            }
            other => panic!("expected RolledBack on a stall, got {other:?}"),
        }
        assert!(record(&store).is_in_cell("prod-us"));
        assert_eq!(*cells.source.borrow(), SourceState::Serving);
    }
}
