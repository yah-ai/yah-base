//! The sovereign-group join rule — W305 / R742-F1, extended by R605-F12.
//!
//! One sentence of logic, deliberately given a home of its own because it is
//! asked in two crates that cannot see each other:
//!
//! - **camp-side**, `cloud::judge_join`, which reads two `MachineConfig`s and
//!   answers "may these two boxes be in one quorum" while planning;
//! - **node-side**, `yubaba`'s `POST /raft/add-learner` gate, which reads its
//!   own `--sovereign-group` and asks the joiner for its own, and refuses.
//!
//! `yubaba` deliberately does **not** depend on `cloud` (R374-F3 moved
//! `local-driver` out precisely to avoid that edge), so the rule cannot simply
//! live in one of them. It lives here for the same reason
//! [`PUBLIC_IP_TAINT`](crate::PUBLIC_IP_TAINT) does: this crate is the shared
//! vocabulary both the planner and the daemon already link, and it depends on
//! neither.
//!
//! What is **not** shared is the prose. A camp-side refusal points at
//! `.yah/infra/machines/<name>.toml`; a node-side refusal has no machine name
//! to interpolate and must also name `yubaba serve --sovereign-group`, because
//! editing the TOML alone does not change what the running daemon declares.
//! Two renderings, one predicate — which is the split that keeps them from
//! disagreeing about what counts as a refusal.
//!
//! # Two axes, because membership and eligibility are different questions
//!
//! A [`Membership`] is a group *and* a [`SovereignRole`]. Before R605-F12 it was
//! only the group, so membership was binary and the only way to express "this
//! box is inside prod's blast radius but must never hold a quorum seat" was to
//! leave it out of prod entirely — which says something else, and says it by
//! omission. us-west-003 is the case: a residential-uplink build box that the
//! operator considers part of prod, whose exclusion from the prod raft was
//! enforced by nothing but the absence of a stamp nobody had written. That is
//! the W305 failure mode that produced R742-T4 (`no-voter` sitting inert on
//! three nodes, asserting something no code read), reached by a different road.
//!
//! So the group answers *which blast radius*, and the role answers *may it
//! vote*. Only the second gates a join.
//!
//! # Reading a live cluster against these declarations
//!
//! Because only the role gates a join, **the declared group and the raft
//! membership are different sets, and the gap between them is the rule working
//! rather than drift.** A `non-voter` is never joined, so it is absent from
//! `/raft/status`'s `members` map *by construction*. us-west-003 declaring
//! `sovereign_group = "prod"` while appearing nowhere in prod's membership is
//! the correct and expected observation — it is a prod worker, inside the blast
//! radius, holding no seat.
//!
//! This is written down because the comparison invites a false alarm: the
//! obvious reading of "declared prod" against a three-node `members` map is
//! "declared-vs-actual drift", and it is wrong. Group membership was never a
//! claim about quorum membership. What the two sets share is only the voters.
//!
//! The observations that **are** worth an alarm, none of which the above is:
//!
//! - a **`voter`** in group G absent from G's raft membership — it was declared
//!   quorum-eligible and never joined, so either a join failed or the group
//!   stamp is aspirational;
//! - a **`non-voter`** *present* in a raft membership — the guarantee is broken,
//!   which means a join gate was bypassed rather than merely misconfigured;
//! - a node in a membership whose declared group differs from the cluster's —
//!   the cross-group join [`join_permitted`] exists to refuse.
//!
//! Note also that a node's *running* daemon is the authority on what it
//! declares, not its TOML: `/raft/status` reporting `sovereign_group: null` on a
//! box whose file says `prod` means the binary predates the field, so read it as
//! "this build cannot tell you" rather than as a contradiction.

use serde::{Deserialize, Serialize};

/// Whether a node in a sovereign group may hold a seat in that group's quorum
/// — R605-F12.
///
/// This is **not** a placement input and not a taint. It narrows a
/// [`Membership`], and the single thing that reads it is [`join_permitted`].
///
/// [`Self::Voter`] is the default because it is what every already-stamped node
/// means today: before this enum existed, declaring a group *was* declaring
/// quorum eligibility, so absence has to keep meaning that or the field would
/// silently retire six live voters. The permissiveness is bounded by the group
/// still being mandatory — a box cannot drift into a quorum without an operator
/// naming the group first — and the camp lints the omission at the layer that
/// can see the whole fleet (`cloud::validate::check_unroled_sovereign_members`),
/// rather than here, where refusing to deserialize would break every node that
/// predates the field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum SovereignRole {
    /// Quorum-eligible: may be joined into its group's cluster.
    #[default]
    Voter,
    /// In the group's blast radius — shares its upgrade cadence, its secrets,
    /// its destruction — but never a quorum seat. Refused by [`join_permitted`]
    /// on either side of a join.
    ///
    /// Consequently a node stamped this way is **absent from its group's
    /// `/raft/status` `members` map, and that absence is correct** — see the
    /// module docs' "Reading a live cluster" section before reporting it as
    /// declared-vs-actual drift. A prod worker holding no seat is the whole
    /// point of the variant.
    NonVoter,
}

impl SovereignRole {
    /// The wire/TOML spelling: `"voter"` / `"non-voter"`. Matches the serde
    /// rename so the CLI flag, the TOML value and the `/raft/status` JSON can
    /// never disagree about how the value is written.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Voter => "voter",
            Self::NonVoter => "non-voter",
        }
    }

    /// True for [`Self::Voter`]. Named rather than matched at call sites so the
    /// join rule reads as one predicate.
    pub fn is_voter(&self) -> bool {
        matches!(self, Self::Voter)
    }
}

impl std::fmt::Display for SovereignRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for SovereignRole {
    type Err = String;

    /// Parses the two legal spellings and nothing else. The error names both,
    /// because this is reached from a CLI flag where the operator has a typo in
    /// hand and no schema to consult.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "voter" => Ok(Self::Voter),
            "non-voter" => Ok(Self::NonVoter),
            other => Err(format!(
                "unknown sovereign role {other:?} — expected \"voter\" or \"non-voter\""
            )),
        }
    }
}

/// What one node declares about its place in a sovereign group.
///
/// `group` is `None` for a standalone node — **in no group**, which is a
/// declaration and not a gap; see [`join_permitted`]. `role` only means anything
/// when `group` is `Some`: a standalone box has no quorum to be eligible for,
/// so its role is never consulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Membership<'a> {
    /// The declared group label, or `None` for standalone.
    pub group: Option<&'a str>,
    /// Quorum eligibility within that group.
    pub role: SovereignRole,
}

impl<'a> Membership<'a> {
    /// A declared member of `group` with the given role.
    pub fn new(group: &'a str, role: SovereignRole) -> Self {
        Self {
            group: Some(group),
            role,
        }
    }

    /// A node in no group at all. Distinct from a non-voting member: standalone
    /// asserts no blast-radius relationship to anything, where a non-voter
    /// shares the group's fate and only declines its quorum.
    pub fn standalone() -> Self {
        Self {
            group: None,
            role: SovereignRole::default(),
        }
    }
}

/// May a node declaring `joiner` join a cluster whose nodes declare `target`?
///
/// **Permitted iff both sides declare the same, non-`None` group *and* both are
/// [`SovereignRole::Voter`].** One rule, no special cases.
///
/// The case it exists for is two *different* declared groups — joining a dev Pi
/// into prod is refused rather than trusted, where the only prior guard was a
/// comment in a TOML saying not to. But an undeclared side is refused too, and
/// that is the deliberate half: **`None` means "in no group", not "unknown"**,
/// so growing prod with an unstamped box is exactly as much a cross-group join
/// as the dev case is. Failing open there would leave the operator believing a
/// guarantee that was never evaluated.
///
/// The distinction that word carries matters most at the *node* boundary. A
/// `MachineConfig` with no `sovereign_group` has genuinely declared standalone.
/// A daemon started without `--sovereign-group` has declared nothing — the
/// declaration never reached the box — and a caller that cannot tell those
/// apart must not pass `None` here and read the answer as "standalone". Resolve
/// the unknown first; this function only judges declarations.
///
/// # Why the role is checked on both sides
///
/// A join grows a quorum, and it takes two nodes to do it. Refusing a
/// non-voting *joiner* is the case R605-F12 was opened for. Refusing a
/// non-voting *target* is the same assertion read from the other end: a box
/// declared non-voting should not be holding a raft seat to be joined *into*,
/// so if one is, the operator has a contradiction between the declaration and
/// the running cluster, and a permit here would paper over it. Neither side is
/// a special case — both are asked the one question the role exists to answer.
pub fn join_permitted(joiner: Membership<'_>, target: Membership<'_>) -> bool {
    matches!((joiner.group, target.group), (Some(a), Some(b)) if a == b)
        && joiner.role.is_voter()
        && target.role.is_voter()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn voter(group: &str) -> Membership<'_> {
        Membership::new(group, SovereignRole::Voter)
    }

    fn non_voter(group: &str) -> Membership<'_> {
        Membership::new(group, SovereignRole::NonVoter)
    }

    #[test]
    fn one_group_joins_itself() {
        assert!(join_permitted(voter("dev"), voter("dev")));
        assert!(join_permitted(voter("prod"), voter("prod")));
    }

    /// The refusal the field was added for.
    #[test]
    fn two_groups_do_not_merge() {
        assert!(!join_permitted(voter("dev"), voter("prod")));
    }

    /// `None` is a declaration, not a gap — so it never matches, including
    /// against itself. Two unstamped boxes forming a group nobody declared is
    /// the shape that leaves nothing to reason about later.
    #[test]
    fn undeclared_never_joins_anything() {
        assert!(!join_permitted(Membership::standalone(), voter("prod")));
        assert!(!join_permitted(voter("dev"), Membership::standalone()));
        assert!(!join_permitted(
            Membership::standalone(),
            Membership::standalone()
        ));
    }

    /// Group labels are compared exactly. A `"Dev"`/`"dev"` typo mints a
    /// phantom group rather than silently joining the real one, which is the
    /// safe direction: the refusal names both values, so the typo is visible
    /// at the moment it bites.
    #[test]
    fn labels_are_compared_exactly() {
        assert!(!join_permitted(voter("Dev"), voter("dev")));
        assert!(!join_permitted(voter("dev "), voter("dev")));
    }

    /// R605-F12, the whole point: same group, and still refused. us-west-003 is
    /// *in* prod's blast radius and must never hold a prod raft seat, and this
    /// is the assertion that enforces it — as opposed to the absent stamp that
    /// used to.
    #[test]
    fn a_non_voting_member_does_not_join_its_own_group() {
        assert!(!join_permitted(non_voter("prod"), voter("prod")));
    }

    /// Read from the other end: a box declared non-voting has no quorum seat to
    /// grow, so it cannot be the target of a join either.
    #[test]
    fn a_non_voting_target_has_no_quorum_to_join() {
        assert!(!join_permitted(voter("prod"), non_voter("prod")));
        assert!(!join_permitted(non_voter("prod"), non_voter("prod")));
    }

    /// Absence of the role means what declaring a group has always meant, so
    /// the six nodes already stamped `prod`/`dev` stay joinable across this
    /// change without an edit.
    #[test]
    fn the_default_role_is_the_pre_r605_f12_meaning() {
        assert_eq!(SovereignRole::default(), SovereignRole::Voter);
        assert!(join_permitted(
            Membership::new("prod", SovereignRole::default()),
            Membership::new("prod", SovereignRole::default())
        ));
    }

    /// The TOML value, the CLI flag and the `/raft/status` JSON are all this
    /// one spelling; a round-trip is what keeps them from drifting apart.
    #[test]
    fn roles_round_trip_through_their_one_spelling() {
        for role in [SovereignRole::Voter, SovereignRole::NonVoter] {
            assert_eq!(role.as_str().parse::<SovereignRole>().unwrap(), role);
            assert_eq!(
                serde_json::to_string(&role).unwrap(),
                format!("\"{}\"", role.as_str())
            );
            assert_eq!(
                serde_json::from_str::<SovereignRole>(&format!("\"{}\"", role.as_str())).unwrap(),
                role
            );
        }
    }

    /// `"nonvoter"` / `"no-voter"` are the near-misses an operator actually
    /// types — `no-voter` especially, since that was the retired taint key this
    /// field replaces. Refusing them by name beats accepting one as a synonym
    /// and leaving two spellings in the fleet.
    #[test]
    fn a_near_miss_role_spelling_is_an_error_naming_both_legal_values() {
        for wrong in ["nonvoter", "no-voter", "Voter", "learner", ""] {
            let err = wrong.parse::<SovereignRole>().unwrap_err();
            assert!(err.contains("voter") && err.contains("non-voter"), "{err}");
        }
    }
}
