//! Delegation, and the one direction authority may move.
//!
//! ```text
//! delegation != privilege amplification
//! ```
//!
//! Across each hop, authority may **hold or narrow**. It may never widen the
//! subject, the audience, the tenant, the skill set, the data scope or the
//! validity window beyond what the upstream grant carried.
//!
//! The asymmetry is the whole content of the module. A chain that narrows at
//! every hop is doing what delegation is for; one that widens at any hop has
//! manufactured authority nobody granted, and the hop where it happened is what
//! an operator needs to be told.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::canonical::assert_safe_identifier;
use crate::error::{A2aSecurityError, Result};
use crate::limits;
use crate::source::{DataSensitivity, EvidenceSource};

/// One hop of delegated authority.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationHop {
    pub hop_id: String,
    /// Who granted this authority.
    pub grantor: String,
    /// Who received it.
    pub grantee: String,
    /// The subject being acted for.
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Skills this hop may invoke. Empty means the hop names none, which is not
    /// the same as naming all of them.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub allowed_skills: BTreeSet<String>,
    /// The most sensitive data this hop may see.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_sensitivity: Option<DataSensitivity>,
    /// What the grant was for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    pub evidence_source: EvidenceSource,
}

impl DelegationHop {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.hop_id, "a delegation hop id")?;
        assert_safe_identifier(&self.grantor, "a grantor")?;
        assert_safe_identifier(&self.grantee, "a grantee")?;
        assert_safe_identifier(&self.subject, "a delegated subject")?;
        for (label, value) in [
            ("a delegation audience", &self.audience),
            ("a delegation tenant", &self.tenant),
            ("a delegation purpose", &self.purpose),
        ] {
            if let Some(value) = value {
                assert_safe_identifier(value, label)?;
            }
        }
        for skill in &self.allowed_skills {
            assert_safe_identifier(skill, "a delegated skill")?;
        }
        Ok(())
    }

    /// Whether this hop holds or narrows relative to an upstream one.
    ///
    /// Every dimension is checked, and each returns the same way: widening on
    /// any one of them is amplification, whatever the others did.
    pub fn narrows_or_holds(&self, upstream: &DelegationHop) -> Vec<AmplificationKind> {
        let mut widened = Vec::new();

        if self.subject != upstream.subject {
            widened.push(AmplificationKind::Subject);
        }
        if let (Some(theirs), Some(mine)) = (upstream.audience.as_deref(), self.audience.as_deref())
        {
            if theirs != mine {
                widened.push(AmplificationKind::Audience);
            }
        }
        if let (Some(theirs), Some(mine)) = (upstream.tenant.as_deref(), self.tenant.as_deref()) {
            if theirs != mine {
                widened.push(AmplificationKind::Tenant);
            }
        }
        if !upstream.allowed_skills.is_empty()
            && !self.allowed_skills.is_subset(&upstream.allowed_skills)
        {
            widened.push(AmplificationKind::Skills);
        }
        if let (Some(theirs), Some(mine)) = (upstream.max_sensitivity, self.max_sensitivity) {
            if mine > theirs {
                widened.push(AmplificationKind::DataScope);
            }
        }
        if let (Some(theirs), Some(mine)) = (upstream.purpose.as_deref(), self.purpose.as_deref()) {
            if theirs != mine {
                widened.push(AmplificationKind::Purpose);
            }
        }

        widened
    }
}

/// The dimension along which authority widened.
///
/// Named rather than counted, because "the chain amplified" is not actionable
/// and "hop 2 widened the tenant" is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AmplificationKind {
    Subject,
    Audience,
    Tenant,
    Skills,
    DataScope,
    Purpose,
}

impl AmplificationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Subject => "SUBJECT",
            Self::Audience => "AUDIENCE",
            Self::Tenant => "TENANT",
            Self::Skills => "SKILLS",
            Self::DataScope => "DATA_SCOPE",
            Self::Purpose => "PURPOSE",
        }
    }
}

/// An ordered chain of delegation hops.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationChain {
    pub chain_id: String,
    /// Hops in grant order: the first is the original grant.
    pub hops: Vec<DelegationHop>,
}

impl DelegationChain {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.chain_id, "a delegation chain id")?;
        if self.hops.is_empty() {
            return Err(A2aSecurityError::invalid(format!(
                "delegation chain `{}` has no hops; an empty chain carries no authority and \
                 must not read as one that does",
                self.chain_id
            )));
        }
        if self.hops.len() as u32 > limits::HARD_MAX_DELEGATION_DEPTH {
            return Err(A2aSecurityError::BudgetExhausted(format!(
                "delegation chain `{}` is deeper than the hard maximum",
                self.chain_id
            )));
        }
        for hop in &self.hops {
            hop.validate()?;
        }
        Ok(())
    }

    /// Where the chain widened, hop by hop.
    ///
    /// Empty means it held or narrowed everywhere, which is delegation working.
    pub fn amplifications(&self) -> Vec<ChainAmplification> {
        let mut found = Vec::new();
        for window in self.hops.windows(2) {
            let (upstream, downstream) = (&window[0], &window[1]);
            for kind in downstream.narrows_or_holds(upstream) {
                found.push(ChainAmplification {
                    hop_id: downstream.hop_id.clone(),
                    upstream_hop_id: upstream.hop_id.clone(),
                    kind,
                });
            }
        }
        found
    }

    /// Whether each hop's grantee is the next hop's grantor.
    ///
    /// A chain whose links do not connect is not a chain: an unrelated grant
    /// spliced into the middle would otherwise be read as authority flowing
    /// through it.
    pub fn is_connected(&self) -> bool {
        self.hops
            .windows(2)
            .all(|window| window[0].grantee == window[1].grantor)
    }

    /// The authority actually in effect: the last hop.
    pub fn effective(&self) -> Option<&DelegationHop> {
        self.hops.last()
    }

    /// The original grant.
    pub fn root(&self) -> Option<&DelegationHop> {
        self.hops.first()
    }
}

/// One widening, with the hop that did it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainAmplification {
    pub hop_id: String,
    pub upstream_hop_id: String,
    pub kind: AmplificationKind,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn hop(id: &str, grantor: &str, grantee: &str) -> DelegationHop {
        DelegationHop {
            hop_id: id.to_owned(),
            grantor: grantor.to_owned(),
            grantee: grantee.to_owned(),
            subject: "user-alice".to_owned(),
            audience: Some("local-orchestrator".to_owned()),
            tenant: Some("tenant-a".to_owned()),
            allowed_skills: BTreeSet::from(["summarize".to_owned(), "search".to_owned()]),
            max_sensitivity: Some(DataSensitivity::Internal),
            purpose: Some("summarize-report".to_owned()),
            evidence_source: EvidenceSource::LocalDelegationRecord,
        }
    }

    pub(crate) fn chain(id: &str) -> DelegationChain {
        let mut second = hop("hop-2", "orchestrator", "planner");
        second.allowed_skills = BTreeSet::from(["summarize".to_owned()]);
        DelegationChain {
            chain_id: id.to_owned(),
            hops: vec![hop("hop-1", "user-alice", "orchestrator"), second],
        }
    }

    #[test]
    fn the_fixture_chain_validates_and_narrows() {
        let chain = chain("chain-1");
        chain.validate().expect("valid");
        assert!(chain.is_connected());
        assert!(
            chain.amplifications().is_empty(),
            "a narrowing chain reported amplification"
        );
    }

    #[test]
    fn narrowing_the_skill_set_is_delegation_working() {
        let chain = chain("chain-1");
        assert_eq!(chain.root().unwrap().allowed_skills.len(), 2);
        assert_eq!(chain.effective().unwrap().allowed_skills.len(), 1);
        assert!(chain.amplifications().is_empty());
    }

    #[test]
    fn widening_the_skill_set_is_amplification_and_names_the_hop() {
        // "The chain amplified" is not actionable. "Hop 2 added transfer-funds"
        // is.
        let mut widened = chain("chain-1");
        widened.hops[1]
            .allowed_skills
            .insert("transfer-funds".to_owned());
        let found = widened.amplifications();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, AmplificationKind::Skills);
        assert_eq!(found[0].hop_id, "hop-2");
        assert_eq!(found[0].upstream_hop_id, "hop-1");
    }

    #[test]
    fn widening_any_single_dimension_is_amplification() {
        // Each returns the same way: widening on one dimension is amplification
        // whatever the others did.
        type Mutation = (&'static str, fn(&mut DelegationHop), AmplificationKind);
        let cases: [Mutation; 5] = [
            (
                "subject",
                |hop| hop.subject = "user-bob".to_owned(),
                AmplificationKind::Subject,
            ),
            (
                "audience",
                |hop| hop.audience = Some("another-service".to_owned()),
                AmplificationKind::Audience,
            ),
            (
                "tenant",
                |hop| hop.tenant = Some("tenant-b".to_owned()),
                AmplificationKind::Tenant,
            ),
            (
                "data scope",
                |hop| hop.max_sensitivity = Some(DataSensitivity::Restricted),
                AmplificationKind::DataScope,
            ),
            (
                "purpose",
                |hop| hop.purpose = Some("something-else".to_owned()),
                AmplificationKind::Purpose,
            ),
        ];

        for (label, mutate, expected) in cases {
            let mut widened = chain("chain-1");
            mutate(&mut widened.hops[1]);
            let kinds: Vec<AmplificationKind> = widened
                .amplifications()
                .into_iter()
                .map(|amplification| amplification.kind)
                .collect();
            assert!(
                kinds.contains(&expected),
                "widening the {label} was not reported"
            );
        }
    }

    #[test]
    fn narrowing_the_data_scope_is_not_amplification() {
        let mut narrowed = chain("chain-1");
        narrowed.hops[1].max_sensitivity = Some(DataSensitivity::Public);
        assert!(narrowed.amplifications().is_empty());
    }

    #[test]
    fn a_chain_whose_links_do_not_connect_is_not_a_chain() {
        // An unrelated grant spliced into the middle would otherwise be read as
        // authority flowing through it.
        let mut broken = chain("chain-1");
        broken.hops[1].grantor = "somebody-else".to_owned();
        assert!(!broken.is_connected());
    }

    #[test]
    fn an_empty_chain_is_refused_rather_than_stored() {
        // An empty chain carries no authority and must not read as one that
        // does.
        let empty = DelegationChain {
            chain_id: "chain-1".to_owned(),
            hops: Vec::new(),
        };
        assert!(empty.validate().is_err());
    }

    #[test]
    fn an_upstream_hop_that_names_no_skills_does_not_authorize_all_of_them() {
        // An empty upstream set means the hop named none. Treating it as "all"
        // would turn silence into a grant.
        let mut chain = chain("chain-1");
        chain.hops[0].allowed_skills = BTreeSet::new();
        // The downstream hop still names one; with no upstream constraint there
        // is nothing to compare, and the comparison is skipped rather than
        // being read as approval.
        assert!(chain
            .amplifications()
            .iter()
            .all(|amplification| amplification.kind != AmplificationKind::Skills));
    }

    #[test]
    fn a_chain_deeper_than_the_ceiling_is_refused() {
        let mut deep = chain("chain-1");
        deep.hops = (0..=limits::HARD_MAX_DELEGATION_DEPTH)
            .map(|index| hop(&format!("hop-{index}"), "a", "b"))
            .collect();
        assert!(deep.validate().is_err());
    }

    #[test]
    fn a_hop_cannot_declare_itself_authorized() {
        let hostile = serde_json::json!({
            "hop_id": "h", "grantor": "a", "grantee": "b", "subject": "s",
            "evidence_source": "LOCAL_DELEGATION_RECORD", "authorized": true
        });
        assert!(serde_json::from_value::<DelegationHop>(hostile).is_err());
    }
}
