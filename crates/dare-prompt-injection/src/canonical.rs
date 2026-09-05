//! Canonical digests and identity binding.
//!
//! Reuses the Cycle 009 canonical digest helper so scenario, corpus and
//! objective identities hash the same way as every other DARE artifact:
//! SHA-256 over key-sorted canonical JSON, rendered `sha256:<hex>`.
//!
//! The point of the binding is substitution resistance. An approved scenario
//! names a corpus vector and may pin its digest; if the vector on disk is not
//! the vector that was approved, the run is refused rather than silently
//! validating something else.

use dare_adversarial::canonical as cycle009;
use serde::Serialize;

use crate::error::{PromptInjectionError, Result};
use crate::model::{CorpusEntry, Objective, PromptInjectionScenario};

/// Canonical digest of any serializable value.
///
/// Delegates to the Cycle 009 helper: one canonicalization rule for the whole
/// product, not a second competing one.
pub fn digest<T: Serialize>(value: &T) -> Result<String> {
    cycle009::digest(value)
        .map_err(|err| PromptInjectionError::invalid(format!("canonical digest failed: {err}")))
}

/// Digest binding the whole approved scenario.
pub fn scenario_digest(scenario: &PromptInjectionScenario) -> Result<String> {
    digest(scenario)
}

/// Digest binding one corpus vector.
pub fn corpus_entry_digest(entry: &CorpusEntry) -> Result<String> {
    digest(entry)
}

/// Digest binding the authorized objective.
///
/// The objective is the security ground truth; pinning it separately means an
/// objective swap is detectable even if the rest of the scenario is unchanged.
pub fn objective_digest(objective: &Objective) -> Result<String> {
    digest(objective)
}

/// Codepoints that make two identifiers look identical but hash differently.
///
/// Identifiers are ASCII by schema; this is the second gate that also covers
/// inputs reaching the typed layer by another route.
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

/// Refuse identifiers that are not plain ASCII or that carry hostile controls.
pub fn assert_safe_identifier(value: &str, label: &str) -> Result<()> {
    if value.is_empty() {
        return Err(PromptInjectionError::invalid(format!("{label} is empty")));
    }
    if let Some(found) = value.chars().find(|c| HOSTILE_CODEPOINTS.contains(c)) {
        return Err(PromptInjectionError::refusal(format!(
            "{label} contains hostile control codepoint U+{:04X}",
            found as u32
        )));
    }
    if !value.is_ascii() {
        return Err(PromptInjectionError::refusal(format!(
            "{label} must be ASCII; non-ASCII identifiers enable homoglyph substitution"
        )));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(PromptInjectionError::refusal(format!(
            "{label} contains a control character"
        )));
    }
    Ok(())
}

/// Verify a claimed digest against a value, failing closed on mismatch.
pub fn verify_digest<T: Serialize>(value: &T, expected: &str, label: &str) -> Result<()> {
    let actual = digest(value)?;
    if actual != expected {
        return Err(PromptInjectionError::DigestMismatch(format!(
            "{label} digest does not match the approved binding"
        )));
    }
    Ok(())
}

/// The verified identity of one scenario/corpus pairing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityBinding {
    pub scenario_id: String,
    pub scenario_digest: String,
    pub corpus_id: String,
    pub corpus_digest: String,
    pub objective_id: String,
    pub objective_digest: String,
}

/// Bind an approved scenario to the corpus vector it will actually exercise.
///
/// Refuses when the vector is not the one the scenario names, when a pinned
/// digest does not match, when the corpus vector contradicts the scenario's
/// declared source boundary, or when any identifier is not canonicalization-safe.
pub fn bind(scenario: &PromptInjectionScenario, entry: &CorpusEntry) -> Result<IdentityBinding> {
    assert_safe_identifier(&scenario.id, "scenario id")?;
    assert_safe_identifier(&scenario.vector.corpus_id, "scenario corpus reference")?;
    assert_safe_identifier(&entry.id, "corpus entry id")?;
    assert_safe_identifier(&scenario.objective.id, "objective id")?;
    assert_safe_identifier(&scenario.objective.authorized_goal_id, "authorized goal id")?;

    if scenario.vector.corpus_id != entry.id {
        return Err(PromptInjectionError::DigestMismatch(format!(
            "scenario {} references corpus vector `{}` but was given `{}`",
            scenario.id, scenario.vector.corpus_id, entry.id
        )));
    }

    // The corpus vector must not contradict the approved source boundary.
    if entry.source_kind != scenario.source.kind {
        return Err(PromptInjectionError::DigestMismatch(format!(
            "corpus vector source `{}` contradicts the scenario source `{}`",
            entry.source_kind.as_str(),
            scenario.source.kind.as_str()
        )));
    }
    if entry.family != scenario.family {
        return Err(PromptInjectionError::DigestMismatch(format!(
            "corpus vector family `{}` contradicts the scenario family `{}`",
            entry.family.as_str(),
            scenario.family.as_str()
        )));
    }
    if entry.property.as_str() != scenario.property.as_str() {
        return Err(PromptInjectionError::DigestMismatch(format!(
            "corpus vector property `{}` contradicts the scenario property `{}`",
            entry.property.as_str(),
            scenario.property.as_str()
        )));
    }

    let corpus_digest = corpus_entry_digest(entry)?;
    if let Some(pinned) = scenario.vector.corpus_digest.as_deref() {
        if pinned != corpus_digest {
            return Err(PromptInjectionError::DigestMismatch(format!(
                "corpus vector `{}` does not match the digest pinned by scenario {}",
                entry.id, scenario.id
            )));
        }
    }

    Ok(IdentityBinding {
        scenario_id: scenario.id.clone(),
        scenario_digest: scenario_digest(scenario)?,
        corpus_id: entry.id.clone(),
        corpus_digest,
        objective_id: scenario.objective.id.clone(),
        objective_digest: objective_digest(&scenario.objective)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scenario() -> PromptInjectionScenario {
        let mut value = crate::schema::tests::valid_scenario();
        value["vector"]["corpus_id"] = json!("direct-ignore-objective-001");
        serde_json::from_value(value).unwrap()
    }

    fn entry() -> CorpusEntry {
        serde_json::from_value(crate::corpus::tests::direct_entry()).unwrap()
    }

    #[test]
    fn digests_are_stable_across_repeated_serialization() {
        let scenario = scenario();
        assert_eq!(
            scenario_digest(&scenario).unwrap(),
            scenario_digest(&scenario).unwrap()
        );
        assert!(scenario_digest(&scenario).unwrap().starts_with("sha256:"));
        assert_eq!(scenario_digest(&scenario).unwrap().len(), 7 + 64);
    }

    #[test]
    fn digests_match_the_cycle_009_canonical_helper() {
        // One canonicalization rule for the whole product.
        let scenario = scenario();
        assert_eq!(
            scenario_digest(&scenario).unwrap(),
            dare_adversarial::canonical::digest(&scenario).unwrap()
        );
    }

    #[test]
    fn digests_are_insensitive_to_key_order() {
        let scenario = scenario();
        let forward = serde_json::to_value(&scenario).unwrap();
        // Round-trip through a BTreeMap-backed value to shuffle key order.
        let shuffled: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&forward).unwrap()).unwrap();
        assert_eq!(digest(&forward).unwrap(), digest(&shuffled).unwrap());
    }

    #[test]
    fn a_changed_objective_changes_the_objective_digest() {
        let scenario = scenario();
        let mut swapped = scenario.clone();
        swapped.objective.authorized_goal_id = "goal-attacker-controlled".to_owned();
        assert_ne!(
            objective_digest(&scenario.objective).unwrap(),
            objective_digest(&swapped.objective).unwrap()
        );
    }

    #[test]
    fn a_changed_payload_changes_the_corpus_digest() {
        let entry = entry();
        let mut swapped = entry.clone();
        swapped.content.payload = "a different injection payload".to_owned();
        assert_ne!(
            corpus_entry_digest(&entry).unwrap(),
            corpus_entry_digest(&swapped).unwrap()
        );
    }

    #[test]
    fn binding_succeeds_for_a_matching_pair() {
        let binding = bind(&scenario(), &entry()).expect("binding");
        assert_eq!(binding.scenario_id, "PI-LAB-001");
        assert_eq!(binding.corpus_id, "direct-ignore-objective-001");
        assert_eq!(binding.objective_id, "objective-support-summary");
        for digest in [
            &binding.scenario_digest,
            &binding.corpus_digest,
            &binding.objective_digest,
        ] {
            assert!(digest.starts_with("sha256:"));
        }
    }

    #[test]
    fn corpus_substitution_fails_closed() {
        let mut other = entry();
        other.id = "direct-some-other-vector".to_owned();
        let err = bind(&scenario(), &other).unwrap_err();
        assert!(matches!(err, PromptInjectionError::DigestMismatch(_)));
    }

    #[test]
    fn pinned_digest_mismatch_fails_closed() {
        let entry = entry();
        let mut scenario = scenario();
        scenario.vector.corpus_digest = Some(corpus_entry_digest(&entry).unwrap());
        bind(&scenario, &entry).expect("matching pin");

        // Same id, tampered content: the pin catches it.
        let mut tampered = entry.clone();
        tampered.content.payload = "tampered payload".to_owned();
        let err = bind(&scenario, &tampered).unwrap_err();
        assert!(matches!(err, PromptInjectionError::DigestMismatch(_)));
    }

    #[test]
    fn source_family_and_property_substitution_fail_closed() {
        let scenario = scenario();

        let mut swapped = entry();
        swapped.source_kind = crate::source::SourceKind::HtmlContent;
        assert!(bind(&scenario, &swapped).is_err());

        let mut swapped = entry();
        swapped.family = crate::source::InjectionFamily::DirectRoleConfusion;
        assert!(bind(&scenario, &swapped).is_err());

        let mut swapped = entry();
        swapped.property = crate::model::BoundaryProperty::InstructionIntegrity;
        assert!(bind(&scenario, &swapped).is_err());
    }

    #[test]
    fn verify_digest_detects_substitution() {
        let objective = scenario().objective;
        let expected = objective_digest(&objective).unwrap();
        verify_digest(&objective, &expected, "objective").expect("matching");

        let mut swapped = objective.clone();
        swapped.protected_canaries = vec!["DARE-SYNTHETIC-CANARY-OTHER1".to_owned()];
        let err = verify_digest(&swapped, &expected, "objective").unwrap_err();
        assert!(matches!(err, PromptInjectionError::DigestMismatch(_)));
        assert!(err.is_refusal());
    }

    #[test]
    fn hostile_unicode_identifiers_are_refused() {
        // Zero-width and bidi controls can make two ids render identically.
        for hostile in [
            "PI-LAB-001\u{200b}",
            "PI\u{200d}-LAB-001",
            "PI-LAB-\u{202e}100",
            "PI-LAB-001\u{feff}",
            "PI-LAB-001\u{00a0}",
        ] {
            let err = assert_safe_identifier(hostile, "scenario id").unwrap_err();
            assert!(err.is_refusal(), "{hostile:?} must be refused");
        }

        // Cyrillic homoglyphs.
        for homoglyph in ["РI-LAB-001", "PI-LAB-О01"] {
            assert!(assert_safe_identifier(homoglyph, "scenario id").is_err());
        }

        assert!(assert_safe_identifier("PI-LAB-001", "scenario id").is_ok());
        assert!(assert_safe_identifier("", "scenario id").is_err());
        assert!(assert_safe_identifier("PI-LAB-\u{0000}1", "scenario id").is_err());
    }

    #[test]
    fn binding_rejects_hostile_identifiers_end_to_end() {
        let mut scenario = scenario();
        scenario.id = "PI-LAB-001\u{200b}".to_owned();
        assert!(bind(&scenario, &entry()).unwrap_err().is_refusal());

        let mut scenario = self::scenario();
        scenario.objective.id = "objective-support\u{202e}-summary".to_owned();
        assert!(bind(&scenario, &entry()).unwrap_err().is_refusal());
    }

    #[test]
    fn visually_similar_payloads_hash_differently() {
        // Canonicalization must not fold distinct byte sequences together, or a
        // tampered payload could reuse an approved digest.
        let mut a = entry();
        a.content.payload = "transfer funds".to_owned();
        let mut b = entry();
        b.content.payload = "transfer\u{00a0}funds".to_owned();
        assert_ne!(
            corpus_entry_digest(&a).unwrap(),
            corpus_entry_digest(&b).unwrap()
        );
    }
}
