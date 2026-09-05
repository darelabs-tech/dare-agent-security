//! Canonical digests and identity binding.
//!
//! Reuses the Cycle 009 canonical digest helper so scenario, corpus, objective,
//! policy and tool-surface identities hash the same way as every other DARE
//! artifact: SHA-256 over key-sorted canonical JSON, rendered `sha256:<hex>`.
//!
//! The point is substitution resistance. An approved scenario binds an
//! objective, a policy and a tool surface; if any of them is not the one that
//! was approved, the run is refused rather than silently validating something
//! else.

use dare_adversarial::canonical as cycle009;
use serde::Serialize;

use crate::error::{Result, ToolSecurityError};
use crate::model::{
    ApprovedToolPolicy, ToolCorpusEntry, ToolObjective, ToolSecurityScenario, ToolSurfaceSnapshot,
};

/// Canonical digest of any serializable value.
///
/// Delegates to the Cycle 009 helper: one canonicalization rule for the whole
/// product, not a second competing one.
pub fn digest<T: Serialize>(value: &T) -> Result<String> {
    cycle009::digest(value)
        .map_err(|err| ToolSecurityError::invalid(format!("canonical digest failed: {err}")))
}

pub fn scenario_digest(scenario: &ToolSecurityScenario) -> Result<String> {
    digest(scenario)
}

pub fn objective_digest(objective: &ToolObjective) -> Result<String> {
    digest(objective)
}

pub fn policy_digest(policy: &ApprovedToolPolicy) -> Result<String> {
    digest(policy)
}

pub fn tool_surface_digest(surface: &ToolSurfaceSnapshot) -> Result<String> {
    digest(surface)
}

pub fn corpus_entry_digest(entry: &ToolCorpusEntry) -> Result<String> {
    digest(entry)
}

/// Per-tool digest, so an individual tool entry can be pinned.
pub fn tool_entry_digest(tool: &crate::model::ToolEntry) -> Result<String> {
    // The declared `digest` field is the *claim*; it must not feed the digest
    // of the entry itself, or a substituted tool could restate its own hash.
    let mut copy = tool.clone();
    copy.digest = None;
    digest(&copy)
}

/// Codepoints that make two identifiers look identical but hash differently.
const HOSTILE_CODEPOINTS: [char; 10] = [
    '\u{200b}', // zero width space
    '\u{200c}', // zero width non-joiner
    '\u{200d}', // zero width joiner
    '\u{2060}', // word joiner
    '\u{feff}', // zero width no-break space / BOM
    '\u{202a}', // left-to-right embedding
    '\u{202b}', // right-to-left embedding
    '\u{202d}', // left-to-right override
    '\u{202e}', // right-to-left override
    '\u{00a0}', // no-break space
];

/// Refuse identifiers that are not plain ASCII or carry hostile controls.
pub fn assert_safe_identifier(value: &str, label: &str) -> Result<()> {
    if value.is_empty() {
        return Err(ToolSecurityError::invalid(format!("{label} is empty")));
    }
    if let Some(found) = value.chars().find(|c| HOSTILE_CODEPOINTS.contains(c)) {
        return Err(ToolSecurityError::refusal(format!(
            "{label} contains hostile control codepoint U+{:04X}",
            found as u32
        )));
    }
    if !value.is_ascii() {
        return Err(ToolSecurityError::refusal(format!(
            "{label} must be ASCII; non-ASCII identifiers enable homoglyph substitution"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(ToolSecurityError::refusal(format!(
            "{label} contains a control character"
        )));
    }
    Ok(())
}

/// Verify a claimed digest against a value, failing closed on mismatch.
pub fn verify_digest<T: Serialize>(value: &T, expected: &str, label: &str) -> Result<()> {
    let actual = digest(value)?;
    if actual != expected {
        return Err(ToolSecurityError::DigestMismatch(format!(
            "{label} digest does not match the approved binding"
        )));
    }
    Ok(())
}

/// The verified identity of one scenario run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolIdentityBinding {
    pub scenario_id: String,
    pub scenario_digest: String,
    pub objective_id: String,
    pub objective_digest: String,
    pub policy_id: String,
    pub policy_digest: String,
    pub surface_id: String,
    pub surface_digest: String,
    /// Per-tool digests, in surface order.
    pub tool_digests: Vec<(String, String)>,
}

/// Bind an approved scenario's identities and refuse any substitution.
pub fn bind(scenario: &ToolSecurityScenario) -> Result<ToolIdentityBinding> {
    assert_safe_identifier(&scenario.id, "scenario id")?;
    assert_safe_identifier(&scenario.objective.id, "objective id")?;
    assert_safe_identifier(&scenario.objective.authorized_goal_id, "authorized goal id")?;
    assert_safe_identifier(&scenario.policy.policy_id, "policy id")?;
    assert_safe_identifier(&scenario.tool_surface.surface_id, "tool surface id")?;

    // The policy is bound to an objective. A policy for a different objective
    // is not the authority for this run.
    if scenario.policy.objective_id != scenario.objective.id {
        return Err(ToolSecurityError::DigestMismatch(format!(
            "approved policy is bound to objective `{}` but the scenario declares `{}`",
            scenario.policy.objective_id, scenario.objective.id
        )));
    }

    // Duplicate tool ids make identity ambiguous; refuse rather than guess.
    let mut seen = std::collections::HashSet::new();
    let mut tool_digests = Vec::new();
    for tool in &scenario.tool_surface.tools {
        assert_safe_identifier(&tool.tool_id, "tool id")?;
        if !seen.insert(tool.tool_id.as_str()) {
            return Err(ToolSecurityError::DigestMismatch(format!(
                "tool surface declares duplicate tool id `{}`",
                tool.tool_id
            )));
        }

        let computed = tool_entry_digest(tool)?;
        // A tool that pins its own digest must actually match it.
        if let Some(claimed) = tool.digest.as_deref() {
            if claimed != computed {
                return Err(ToolSecurityError::DigestMismatch(format!(
                    "tool `{}` does not match its declared digest",
                    tool.tool_id
                )));
            }
        }
        // A policy that pins an approved digest binds the tool identity.
        if let Some(approved) = scenario
            .policy
            .approved_tool(&tool.tool_id)
            .and_then(|approved| approved.approved_digest.as_deref())
        {
            if approved != computed {
                return Err(ToolSecurityError::DigestMismatch(format!(
                    "tool `{}` does not match the digest approved by policy",
                    tool.tool_id
                )));
            }
        }
        tool_digests.push((tool.tool_id.clone(), computed));
    }

    // Every approved tool must exist on the surface, or the policy is not
    // describing this surface.
    for approved in &scenario.policy.approved_tools {
        if scenario.tool_surface.get(&approved.tool_id).is_none() {
            return Err(ToolSecurityError::DigestMismatch(format!(
                "approved tool `{}` is absent from the observed tool surface",
                approved.tool_id
            )));
        }
    }

    Ok(ToolIdentityBinding {
        scenario_id: scenario.id.clone(),
        scenario_digest: scenario_digest(scenario)?,
        objective_id: scenario.objective.id.clone(),
        objective_digest: objective_digest(&scenario.objective)?,
        policy_id: scenario.policy.policy_id.clone(),
        policy_digest: policy_digest(&scenario.policy)?,
        surface_id: scenario.tool_surface.surface_id.clone(),
        surface_digest: tool_surface_digest(&scenario.tool_surface)?,
        tool_digests,
    })
}

/// Bind a corpus vector to a scenario, refusing substitution.
pub fn bind_corpus(scenario: &ToolSecurityScenario, entry: &ToolCorpusEntry) -> Result<String> {
    let Some(vector) = scenario.vector.as_ref() else {
        return corpus_entry_digest(entry);
    };
    assert_safe_identifier(&vector.corpus_id, "scenario corpus reference")?;
    assert_safe_identifier(&entry.id, "corpus entry id")?;

    if vector.corpus_id != entry.id {
        return Err(ToolSecurityError::DigestMismatch(format!(
            "scenario {} references corpus vector `{}` but was given `{}`",
            scenario.id, vector.corpus_id, entry.id
        )));
    }
    if entry.property.as_str() != scenario.property.as_str() {
        return Err(ToolSecurityError::DigestMismatch(format!(
            "corpus vector property `{}` contradicts the scenario property `{}`",
            entry.property.as_str(),
            scenario.property.as_str()
        )));
    }

    let computed = corpus_entry_digest(entry)?;
    if let Some(pinned) = vector.corpus_digest.as_deref() {
        if pinned != computed {
            return Err(ToolSecurityError::DigestMismatch(format!(
                "corpus vector `{}` does not match the digest pinned by scenario {}",
                entry.id, scenario.id
            )));
        }
    }
    Ok(computed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scenario() -> ToolSecurityScenario {
        serde_json::from_value(crate::schema::tests::valid_scenario()).unwrap()
    }

    #[test]
    fn digests_are_stable_and_match_the_cycle_009_helper() {
        let scenario = scenario();
        assert_eq!(
            scenario_digest(&scenario).unwrap(),
            scenario_digest(&scenario).unwrap()
        );
        assert_eq!(
            scenario_digest(&scenario).unwrap(),
            dare_adversarial::canonical::digest(&scenario).unwrap()
        );
        assert!(scenario_digest(&scenario).unwrap().starts_with("sha256:"));
    }

    #[test]
    fn each_identity_is_digested_independently() {
        let scenario = scenario();
        let binding = bind(&scenario).expect("binding");
        let digests = [
            &binding.scenario_digest,
            &binding.objective_digest,
            &binding.policy_digest,
            &binding.surface_digest,
        ];
        for digest in digests {
            assert!(digest.starts_with("sha256:"));
        }
        // They are genuinely different values, not one digest reused.
        let unique: std::collections::HashSet<&String> = digests.into_iter().collect();
        assert_eq!(unique.len(), 4);
        assert_eq!(binding.tool_digests.len(), 2);
    }

    #[test]
    fn a_changed_objective_policy_or_surface_changes_its_digest() {
        let scenario = scenario();

        let mut swapped = scenario.clone();
        swapped.objective.authorized_goal_id = "goal-attacker-controlled".to_owned();
        assert_ne!(
            objective_digest(&scenario.objective).unwrap(),
            objective_digest(&swapped.objective).unwrap()
        );

        let mut swapped = scenario.clone();
        swapped.policy.forbidden_operation_classes.clear();
        assert_ne!(
            policy_digest(&scenario.policy).unwrap(),
            policy_digest(&swapped.policy).unwrap()
        );

        let mut swapped = scenario.clone();
        swapped.tool_surface.tools[0].description = "something else".to_owned();
        assert_ne!(
            tool_surface_digest(&scenario.tool_surface).unwrap(),
            tool_surface_digest(&swapped.tool_surface).unwrap()
        );
    }

    #[test]
    fn a_policy_for_another_objective_is_refused() {
        let mut scenario = scenario();
        scenario.policy.objective_id = "objective-something-else".to_owned();
        let err = bind(&scenario).unwrap_err();
        assert!(matches!(err, ToolSecurityError::DigestMismatch(_)));
        assert!(err.is_refusal());
    }

    #[test]
    fn duplicate_tool_ids_are_refused() {
        let mut scenario = scenario();
        let clone = scenario.tool_surface.tools[0].clone();
        scenario.tool_surface.tools.push(clone);
        let err = bind(&scenario).unwrap_err();
        assert!(err.is_refusal());
        assert!(err.to_string().contains("duplicate tool id"));
    }

    #[test]
    fn a_tool_that_misstates_its_own_digest_is_refused() {
        let mut scenario = scenario();
        scenario.tool_surface.tools[0].digest = Some(format!("sha256:{}", "0".repeat(64)));
        let err = bind(&scenario).unwrap_err();
        assert!(err.is_refusal());
        assert!(err.to_string().contains("declared digest"));
    }

    #[test]
    fn a_tool_that_does_not_match_the_policy_pinned_digest_is_refused() {
        let mut scenario = scenario();
        let correct = tool_entry_digest(&scenario.tool_surface.tools[0]).unwrap();
        scenario.policy.approved_tools[0].approved_digest = Some(correct);
        bind(&scenario).expect("matching pin");

        // Now tamper with the tool the policy pinned.
        scenario.tool_surface.tools[0].description = "substituted description".to_owned();
        let err = bind(&scenario).unwrap_err();
        assert!(err.is_refusal());
        assert!(err.to_string().contains("approved by policy"));
    }

    #[test]
    fn a_tool_cannot_restate_its_own_hash_to_avoid_detection() {
        // The declared digest field is excluded from the computed digest, so
        // an attacker cannot substitute a tool and update its self-claim to
        // match.
        let scenario = scenario();
        let tool = &scenario.tool_surface.tools[0];
        let computed = tool_entry_digest(tool).unwrap();

        let mut restated = tool.clone();
        restated.digest = Some(computed.clone());
        assert_eq!(
            tool_entry_digest(&restated).unwrap(),
            computed,
            "the self-claim must not change the computed identity"
        );

        // And changing real content still changes the identity.
        let mut tampered = restated.clone();
        tampered.description = "substituted".to_owned();
        assert_ne!(tool_entry_digest(&tampered).unwrap(), computed);
    }

    #[test]
    fn an_approved_tool_absent_from_the_surface_is_refused() {
        let mut scenario = scenario();
        scenario
            .tool_surface
            .tools
            .retain(|tool| tool.tool_id != "ticket_summarize");
        let err = bind(&scenario).unwrap_err();
        assert!(err.is_refusal());
        assert!(err
            .to_string()
            .contains("absent from the observed tool surface"));
    }

    #[test]
    fn hostile_unicode_identifiers_are_refused() {
        for hostile in [
            "TOOL-LAB-001\u{200b}",
            "TOOL\u{200d}-LAB-001",
            "TOOL-LAB-\u{202e}100",
            "TOOL-LAB-001\u{feff}",
            "TOOL-LAB-001\u{00a0}",
            "\u{0422}OOL-LAB-001",
        ] {
            assert!(
                assert_safe_identifier(hostile, "scenario id").is_err(),
                "{hostile:?} must be refused"
            );
        }
        assert!(assert_safe_identifier("TOOL-LAB-001", "scenario id").is_ok());
        assert!(assert_safe_identifier("", "scenario id").is_err());
    }

    #[test]
    fn binding_rejects_hostile_identifiers_end_to_end() {
        let mut scenario = scenario();
        scenario.id = "TOOL-LAB-001\u{200b}".to_owned();
        assert!(bind(&scenario).unwrap_err().is_refusal());

        let mut scenario = self::scenario();
        scenario.tool_surface.tools[0].tool_id = "ticket\u{202e}_search".to_owned();
        assert!(bind(&scenario).unwrap_err().is_refusal());
    }

    #[test]
    fn verify_digest_detects_substitution() {
        let scenario = scenario();
        let expected = policy_digest(&scenario.policy).unwrap();
        verify_digest(&scenario.policy, &expected, "policy").expect("matching");

        let mut swapped = scenario.policy.clone();
        swapped.forbidden_operation_classes.clear();
        let err = verify_digest(&swapped, &expected, "policy").unwrap_err();
        assert!(matches!(err, ToolSecurityError::DigestMismatch(_)));
    }

    #[test]
    fn digests_are_insensitive_to_key_order_but_not_to_content() {
        let scenario = scenario();
        let forward = serde_json::to_value(&scenario).unwrap();
        let shuffled: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&forward).unwrap()).unwrap();
        assert_eq!(digest(&forward).unwrap(), digest(&shuffled).unwrap());

        let mut changed = forward.clone();
        changed["objective"]["authorized_goal_id"] = json!("goal-other");
        assert_ne!(digest(&forward).unwrap(), digest(&changed).unwrap());
    }
}
