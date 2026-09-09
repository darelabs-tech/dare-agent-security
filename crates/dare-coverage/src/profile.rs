//! Assessment profiles are versioned data, not executable code.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::CoverageError;
use crate::property::PropertyRegistry;

pub const PROFILE_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/coverage/v1/profile.schema.json";
pub const PROFILE_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/coverage/v1/profile.schema.json");
pub const BUILTIN_PROFILE_JSON: &str = include_str!("../../../profiles/mcp-security-baseline.json");
pub const AGENTIC_PROFILE_JSON: &str =
    include_str!("../../../profiles/agentic-security-baseline-2026.json");
pub const PROMPT_INJECTION_PROFILE_JSON: &str =
    include_str!("../../../profiles/prompt-injection-baseline-2026.json");
pub const TOOL_SECURITY_PROFILE_JSON: &str =
    include_str!("../../../profiles/tool-security-baseline-2026.json");
pub const IDENTITY_SECURITY_PROFILE_JSON: &str =
    include_str!("../../../profiles/identity-security-baseline-2026.json");
pub const MEMORY_SECURITY_PROFILE_JSON: &str =
    include_str!("../../../profiles/memory-security-baseline-2026.json");
pub const RAG_SECURITY_PROFILE_JSON: &str =
    include_str!("../../../profiles/rag-security-baseline-2026.json");
pub const MCP_AUTH_HARDENING_PROFILE_JSON: &str =
    include_str!("../../../profiles/mcp-auth-hardening-2026.json");
pub const AGENTIC_SUPPLY_CHAIN_PROFILE_JSON: &str =
    include_str!("../../../profiles/agentic-supply-chain-security-2026.json");
pub const AGENTIC_A2A_PROFILE_JSON: &str =
    include_str!("../../../profiles/agentic-a2a-security-2026.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaRef {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequirementLevel {
    Required,
    Conditional,
    Optional,
}

impl RequirementLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Required => "REQUIRED",
            Self::Conditional => "CONDITIONAL",
            Self::Optional => "OPTIONAL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileProperty {
    pub id: String,
    pub requirement: RequirementLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentProfile {
    pub schema: SchemaRef,
    pub id: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub properties: Vec<ProfileProperty>,
}

pub fn profile_schema_v1() -> Result<Value, CoverageError> {
    serde_json::from_str(PROFILE_SCHEMA_V1_JSON).map_err(|_| CoverageError::Serialization {
        kind: "profile-schema",
    })
}

pub fn validate_profile_instance(instance: &Value) -> Result<(), CoverageError> {
    let schema = profile_schema_v1()?;
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|err| CoverageError::schema("/", err.to_string()))?;
    if validator.is_valid(instance) {
        return Ok(());
    }
    let first = validator.iter_errors(instance).next();
    match first {
        Some(err) => Err(CoverageError::schema(
            err.instance_path().to_string(),
            err.to_string(),
        )),
        None => Err(CoverageError::schema("/", "profile failed schema")),
    }
}

pub fn load_profile(raw: &str) -> Result<AssessmentProfile, CoverageError> {
    let value: Value = serde_json::from_str(raw).map_err(|_| CoverageError::Serialization {
        kind: "profile-parse",
    })?;
    validate_profile_instance(&value)?;
    serde_json::from_value(value).map_err(|_| CoverageError::Serialization {
        kind: "profile-typed",
    })
}

pub fn validate_profile(
    profile: &AssessmentProfile,
    registry: &PropertyRegistry,
) -> Result<(), CoverageError> {
    let mut seen = HashSet::new();
    for entry in &profile.properties {
        if !seen.insert(entry.id.clone()) {
            return Err(CoverageError::DuplicateProperty(entry.id.clone()));
        }
        registry.require(&entry.id)?;
    }
    Ok(())
}

pub fn builtin_profile() -> Result<AssessmentProfile, CoverageError> {
    load_profile(BUILTIN_PROFILE_JSON)
}

pub fn agentic_profile() -> Result<AssessmentProfile, CoverageError> {
    load_profile(AGENTIC_PROFILE_JSON)
}

/// Cycle 013 prompt-injection baseline.
///
/// Additive: it selects three `AGENT.GOAL.*` properties from the same v2
/// registry and does not alter the Cycle 012 baseline or its denominator.
pub fn prompt_injection_profile() -> Result<AssessmentProfile, CoverageError> {
    load_profile(PROMPT_INJECTION_PROFILE_JSON)
}

/// Cycle 014 tool-security baseline.
///
/// Additive: it selects the six `AGENT.TOOL.*` properties from the same v2
/// registry and leaves every earlier profile, and every denominator, untouched.
pub fn tool_security_profile() -> Result<AssessmentProfile, CoverageError> {
    load_profile(TOOL_SECURITY_PROFILE_JSON)
}

/// Cycle 015 identity-security baseline.
///
/// Additive: it selects the six `AGENT.IDENTITY.*` properties from the same v2
/// registry. The two properties that predate this cycle keep their identifiers
/// and meaning, no earlier profile's requirements change, and no denominator
/// moves.
pub fn identity_security_profile() -> Result<AssessmentProfile, CoverageError> {
    load_profile(IDENTITY_SECURITY_PROFILE_JSON)
}

/// Cycle 016 memory-security baseline.
///
/// Additive in the same way. It selects the six `AGENT.MEMORY.*` properties
/// from the same v2 registry: the two that predate this cycle keep their
/// identifiers, their applicability predicates and their meaning, the four new
/// ones are added alongside, no earlier profile's requirements change, and no
/// denominator moves.
///
/// The two recall-shaped properties are CONDITIONAL rather than REQUIRED
/// because a target that never recalls memory, or never expires it, has nothing
/// to answer there. Marking them REQUIRED would turn "not applicable" into a
/// gap and make an honest target look worse than a target with no memory at
/// all.
pub fn memory_security_profile() -> Result<AssessmentProfile, CoverageError> {
    load_profile(MEMORY_SECURITY_PROFILE_JSON)
}

/// Cycle 017 RAG and retrieval-security baseline.
///
/// Additive in the same way as the four before it. It selects the six
/// `AGENT.RAG.*` properties from the same v2 registry; every earlier profile
/// keeps its identifiers, its requirement levels and its property count, so no
/// denominator moves and no assessment already filed means something different
/// than it did when it was produced.
///
/// Two of the six are CONDITIONAL, for a reason specific to each. A target
/// whose corpus holds nothing untrusted has no promotion to answer for, and a
/// policy that designates no protected document or class has nothing to
/// withhold. Marking either REQUIRED would report a gap against a target that
/// has honestly nothing to report, and make it score worse than one that simply
/// declares less.
///
/// The other four are REQUIRED because where they apply at all, there is no
/// honest way to decline them: a retrieval with a policy must stay inside its
/// authority, one with a tenant context and a document ACL must respect both,
/// one whose documents carry provenance must preserve it, and one that returns
/// a result set must have drawn it from the approved candidates.
pub fn rag_security_profile() -> Result<AssessmentProfile, CoverageError> {
    load_profile(RAG_SECURITY_PROFILE_JSON)
}

/// Cycle 018 MCP 2026 authentication and authorization hardening baseline.
///
/// This one selects from the **v1** MCP registry rather than the v2 Agentic
/// one, which is where the ten properties it names live. That placement is
/// deliberate: the surfaces are MCP protocol and OAuth semantics, not agent
/// behaviours, and putting them in v2 would have created an eleventh Agentic
/// risk family or forced an exclusion rule to keep the count at ten. Neither is
/// honest — the properties simply are not an Agentic risk family.
///
/// Additive in the same way as every profile before it. `mcp-security-baseline`
/// keeps its ten properties and their requirement levels, so its denominator
/// does not move and no assessment already filed against it means something
/// different than it did when it was produced. The two profiles select disjoint
/// sets of the same registry.
///
/// **All ten are REQUIRED**, and unlike the profiles before it this one has no
/// CONDITIONAL entry at all. That is not an oversight; it is the requirement
/// level AC-08 leaves available.
///
/// The earlier profiles use CONDITIONAL for a property a target may honestly
/// have nothing to answer for. Here that case is already handled, one layer
/// down and more precisely. Seven of these properties are gated on an
/// *auth control/evidence* predicate — Protected Resource Metadata, AS
/// metadata, token claims, PKCE context, a scope challenge, client
/// registration, credential forwarding — and when one of those is absent,
/// applicability reports NOT_TESTED, a gap, rather than NOT_APPLICABLE. The
/// remaining gating predicates describe the target's shape (the protocol
/// revision, the HTTP transport, whether an authorization flow exists at all),
/// and when one of *those* is false the property is genuinely NOT_APPLICABLE
/// and drops out of the denominator entirely.
///
/// Marking a control-gated property CONDITIONAL would undo that. Only REQUIRED
/// properties feed the required-coverage ratio, so a CONDITIONAL property whose
/// evidence is missing reports NOT_TESTED and then counts toward nothing. The
/// gap would still be printed and would still not lower any number — which is
/// the same evasion AC-08 forbids, reached through a different door.
///
/// So the seven stay REQUIRED, and the three shape-gated ones are REQUIRED too,
/// because where they apply at all there is no honest way to decline them. A
/// request must mean the same operation to the router and to the server that
/// executes it. Self-reported protocol metadata must stay metadata rather than
/// becoming a principal. And the operation actually performed must be the one
/// authorization covered.
pub fn mcp_auth_hardening_profile() -> Result<AssessmentProfile, CoverageError> {
    load_profile(MCP_AUTH_HARDENING_PROFILE_JSON)
}

/// The Cycle 019 agentic supply-chain profile.
///
/// Additive: it selects the two properties Cycle 012 created and the eight this
/// cycle added, and touches no earlier profile. A coverage percentage is a
/// fraction whose denominator is a profile's property count, so changing an
/// existing profile would silently change what every assessment already filed
/// against it means.
///
/// Four properties are REQUIRED and six are CONDITIONAL, and the split is not
/// arbitrary. Identity, integrity, source trust and completeness apply to any
/// system that has a bill of materials at all: a component nobody can identify
/// or whose bytes nobody pinned is a gap in every deployment.
///
/// The six conditional ones apply where their evidence class exists. A system
/// with no model has no model lineage to preserve, and marking lineage REQUIRED
/// would report a finding against every deployment that runs no model — which
/// is how an operator learns to ignore the profile.
pub fn agentic_supply_chain_profile() -> Result<AssessmentProfile, CoverageError> {
    load_profile(AGENTIC_SUPPLY_CHAIN_PROFILE_JSON)
}

/// The Cycle 020 agentic A2A profile.
///
/// Additive: it selects the two properties earlier cycles created and the ten
/// this cycle added, and touches no earlier profile. A coverage percentage is a
/// fraction whose denominator is a profile's property count, so changing an
/// existing profile would silently change what every assessment already filed
/// against it means.
///
/// Five properties are REQUIRED and seven are CONDITIONAL, and the split
/// follows the predicate that gates each one. Where the extra predicate is an
/// **evidence or control** predicate — peer authentication, skill grants, tenant
/// policy, protocol policy — its absence is a gap in any deployment that speaks
/// A2A at all, so the property is REQUIRED and reports NOT_TESTED rather than
/// disappearing.
///
/// Where the extra predicate is a **target shape** — an Agent Card, an
/// exchange, an extension, a push configuration, a delegated identity — its
/// absence means the surface genuinely does not exist, and CONDITIONAL is
/// honest. Marking push notifications REQUIRED would report a finding against
/// every deployment that configures no callback, which is how an operator
/// learns to ignore the profile.
pub fn agentic_a2a_profile() -> Result<AssessmentProfile, CoverageError> {
    load_profile(AGENTIC_A2A_PROFILE_JSON)
}

pub fn load_profile_file(path: impl AsRef<Path>) -> Result<AssessmentProfile, CoverageError> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path).map_err(|err| CoverageError::Io {
        path: path.display().to_string(),
        reason: err.to_string(),
    })?;
    load_profile(raw.strip_prefix('\u{feff}').unwrap_or(&raw))
}

pub fn resolve_profile(spec: &str) -> Result<AssessmentProfile, CoverageError> {
    match spec {
        "mcp-security-baseline" => builtin_profile(),
        "agentic-security-baseline-2026" => agentic_profile(),
        "prompt-injection-baseline-2026" => prompt_injection_profile(),
        "tool-security-baseline-2026" => tool_security_profile(),
        "identity-security-baseline-2026" => identity_security_profile(),
        "memory-security-baseline-2026" => memory_security_profile(),
        "rag-security-baseline-2026" => rag_security_profile(),
        "mcp-auth-hardening-2026" => mcp_auth_hardening_profile(),
        "agentic-supply-chain-security-2026" => agentic_supply_chain_profile(),
        "agentic-a2a-security-2026" => agentic_a2a_profile(),
        _ => {
            let path = PathBuf::from(spec);
            if path.extension().is_some() || path.components().count() > 1 {
                load_profile_file(path)
            } else {
                Err(CoverageError::UnknownProfile(spec.to_owned()))
            }
        }
    }
}

pub fn profile_digest_sha256(profile: &AssessmentProfile) -> Result<String, CoverageError> {
    let bytes = serde_json::to_vec(profile).map_err(|_| CoverageError::Serialization {
        kind: "profile-digest",
    })?;
    Ok(hex_encode(Sha256::digest(&bytes).as_slice()))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::property::{agentic_registry, builtin_registry};

    #[test]
    fn builtin_profile_validates_against_registry() {
        let profile = builtin_profile().expect("profile");
        let registry = builtin_registry().expect("registry");
        validate_profile(&profile, &registry).expect("valid");
        assert_eq!(profile.id, "mcp-security-baseline");
        let digest = profile_digest_sha256(&profile).unwrap();
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn agentic_profile_validates_against_agentic_registry() {
        let profile = agentic_profile().expect("profile");
        let registry = agentic_registry().expect("registry");
        validate_profile(&profile, &registry).expect("valid");
        assert_eq!(profile.id, "agentic-security-baseline-2026");
        assert_eq!(profile.properties.len(), 10);
    }

    #[test]
    fn prompt_injection_profile_validates_against_the_agentic_registry() {
        let profile = prompt_injection_profile().expect("profile");
        let registry = agentic_registry().expect("registry");
        validate_profile(&profile, &registry).expect("valid");
        assert_eq!(profile.id, "prompt-injection-baseline-2026");
        assert_eq!(profile.properties.len(), 3);

        // Requirement levels exactly as approved.
        let levels: Vec<(&str, RequirementLevel)> = profile
            .properties
            .iter()
            .map(|entry| (entry.id.as_str(), entry.requirement))
            .collect();
        assert_eq!(
            levels,
            vec![
                (
                    "AGENT.GOAL.INSTRUCTION_INTEGRITY",
                    RequirementLevel::Required
                ),
                (
                    "AGENT.GOAL.USER_INPUT_INSTRUCTION_BOUNDARY",
                    RequirementLevel::Required
                ),
                (
                    "AGENT.GOAL.EXTERNAL_CONTENT_INSTRUCTION_BOUNDARY",
                    RequirementLevel::Conditional
                ),
            ]
        );
    }

    #[test]
    fn prompt_injection_profile_resolves_by_name() {
        assert_eq!(
            resolve_profile("prompt-injection-baseline-2026")
                .unwrap()
                .id,
            "prompt-injection-baseline-2026"
        );
    }

    #[test]
    fn unknown_builtin_profile_is_rejected_clearly() {
        assert!(matches!(
            resolve_profile("not-a-real-profile"),
            Err(CoverageError::UnknownProfile(_))
        ));
    }

    #[test]
    fn unknown_property_in_profile_is_rejected() {
        let registry = builtin_registry().unwrap();
        let mut profile = builtin_profile().unwrap();
        profile.properties.push(ProfileProperty {
            id: "MCP.INJECTED.FAKE".to_owned(),
            requirement: RequirementLevel::Required,
        });
        assert!(matches!(
            validate_profile(&profile, &registry),
            Err(CoverageError::UnknownProperty(_))
        ));
    }
}
