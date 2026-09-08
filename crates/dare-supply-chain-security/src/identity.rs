//! Canonical identity, and what does not establish one.
//!
//! The distinction this module exists for:
//!
//! ```text
//! component name        != component identity
//! name + version        != immutable artifact
//! mutable reference     != immutable identity
//! same name and version != same artifact
//! ```
//!
//! A name is what something calls itself. Two packages on two registries can
//! share one. A version is a label the publisher chose, and two builds can
//! carry the same label and be different bytes — which is the substitution the
//! whole artifact-integrity property exists to catch.
//!
//! So identity is graded rather than binary. `IdentityStrength` says how far
//! the available evidence goes, and the evaluators ask for the strength the
//! situation needs rather than for "an identity".

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::component::Component;
use crate::error::{Result, SupplyChainError};
use crate::source::ComponentType;

/// How far the evidence for a component's identity actually goes.
///
/// Ordered, so "at least this strong" is a comparison rather than a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityStrength {
    /// A name, and nothing that distinguishes this thing from another with the
    /// same name.
    NameOnly,
    /// A name and a version. Distinguishes releases, not builds.
    NameAndVersion,
    /// A coordinate that names a specific published thing — a purl with a
    /// version, an SPDX id. Still not the bytes.
    Coordinate,
    /// An immutable digest. This is the only strength that identifies bytes.
    ImmutableDigest,
}

impl IdentityStrength {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NameOnly => "NAME_ONLY",
            Self::NameAndVersion => "NAME_AND_VERSION",
            Self::Coordinate => "COORDINATE",
            Self::ImmutableDigest => "IMMUTABLE_DIGEST",
        }
    }

    /// Whether this strength identifies an immutable artifact.
    ///
    /// Only `ImmutableDigest`. A coordinate names a published thing; the
    /// publisher can republish it.
    pub fn is_immutable(self) -> bool {
        matches!(self, Self::ImmutableDigest)
    }
}

/// Reference forms that cannot pin an artifact, however specific they look.
///
/// `latest` is the obvious one. The others matter as much: a branch name
/// resolves to whatever was last pushed, and a semver range resolves to
/// whatever the resolver picked today.
const MUTABLE_VERSION_MARKERS: [&str; 10] = [
    "latest", "main", "master", "head", "dev", "nightly", "stable", "edge", "*", "current",
];

/// Whether a version or reference string is mutable.
///
/// Two families: named moving targets, and range expressions. Both resolve to
/// something different tomorrow, and neither is an identity.
pub fn is_mutable_reference(value: &str) -> bool {
    let lowered = value.trim().to_ascii_lowercase();
    if lowered.is_empty() {
        return true;
    }
    if MUTABLE_VERSION_MARKERS.contains(&lowered.as_str()) {
        return true;
    }
    // Range and wildcard expressions: `^1.2`, `~1.2`, `>=1.0`, `1.x`, `1.*`.
    lowered.starts_with('^')
        || lowered.starts_with('~')
        || lowered.starts_with('>')
        || lowered.starts_with('<')
        || lowered.contains('*')
        || lowered.ends_with(".x")
        || lowered.contains(" || ")
}

/// Whether a coordinate string pins an immutable artifact.
///
/// A purl with a `digest` or `checksum` qualifier does; a purl with only a
/// version does not. The document does not get to declare this — the shape of
/// the value decides it.
fn coordinate_is_immutable(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    lowered.contains("?digest=")
        || lowered.contains("&digest=")
        || lowered.contains("?checksum=")
        || lowered.contains("&checksum=")
        // An OCI reference pinned by digest rather than tag.
        || lowered.contains("@sha256:")
}

/// The identity evidence available for one component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalIdentity {
    pub component_id: String,
    pub strength: IdentityStrength,
    /// Whether the version or reference the document supplied is mutable.
    ///
    /// `None` when no version was supplied at all — a different answer from
    /// "supplied and mutable".
    pub mutable_reference: Option<bool>,
    /// The digest values that pin this component, in wire form.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub pinned_by: BTreeSet<String>,
    /// The semantic key two documents must agree on to describe one component.
    pub semantic_key: String,
}

impl CanonicalIdentity {
    /// Whether this identity satisfies what its component class needs.
    ///
    /// Three answers. `None` means the class expects no immutable artifact, so
    /// the question does not arise — distinct from "expected and unmet", which
    /// the evaluator reports as a finding.
    pub fn satisfies_class(&self, component_type: ComponentType) -> Option<bool> {
        if !component_type.expects_immutable_artifact() {
            return None;
        }
        Some(self.strength.is_immutable())
    }
}

/// Derive canonical identity from a normalized component.
///
/// The semantic key is deliberately **format-independent**: it is built from
/// what the component *is*, never from which document described it. Two
/// documents in different formats describing the same component must produce
/// the same key, or cross-format equivalence would compare parsers.
pub fn resolve_identity(component: &Component) -> CanonicalIdentity {
    let pinned_by: BTreeSet<String> = component
        .digests
        .iter()
        .map(|digest| digest.to_wire())
        .collect();

    let immutable_coordinate = component
        .identifiers
        .iter()
        .any(|identifier| coordinate_is_immutable(&identifier.value));

    let has_coordinate = !component.identifiers.is_empty();

    let strength = if !pinned_by.is_empty() || immutable_coordinate {
        IdentityStrength::ImmutableDigest
    } else if has_coordinate {
        IdentityStrength::Coordinate
    } else if component.version.is_some() {
        IdentityStrength::NameAndVersion
    } else {
        IdentityStrength::NameOnly
    };

    let mutable_reference = component
        .version
        .as_deref()
        .map(is_mutable_reference);

    // The key: type, name, version and the sorted digest set. Not the evidence
    // source, not the document's own identifiers ordering, not any field a
    // format happened to supply.
    let semantic_key = format!(
        "{}|{}|{}|{}",
        component.component_type.as_str(),
        component.name,
        component.version.as_deref().unwrap_or(""),
        pinned_by
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(",")
    );

    CanonicalIdentity {
        component_id: component.component_id.clone(),
        strength,
        mutable_reference,
        pinned_by,
        semantic_key,
    }
}

/// A pair of components whose canonical identity collides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityCollision {
    pub component_id: String,
    pub conflicting_component_id: String,
    pub reason: String,
}

/// Find components that cannot be told apart, or that claim one identity while
/// describing different things.
///
/// Two failures, and they are opposites:
///
/// - **Same id, different semantics.** Two rows claiming to be the same
///   component while describing different artifacts. Whichever the evaluator
///   reads, the other is silently absent from every finding about it.
/// - **Same semantics, different ids.** The same artifact appearing twice under
///   different ids, so a policy approving one leaves the other unapproved while
///   a reader sees the component as covered.
pub fn find_collisions(components: &[Component]) -> Vec<IdentityCollision> {
    let mut collisions = Vec::new();
    let mut by_id: BTreeMap<&str, &Component> = BTreeMap::new();
    let mut by_key: BTreeMap<String, &Component> = BTreeMap::new();

    for component in components {
        let identity = resolve_identity(component);

        if let Some(existing) = by_id.get(component.component_id.as_str()) {
            let existing_key = resolve_identity(existing).semantic_key;
            if existing_key != identity.semantic_key {
                collisions.push(IdentityCollision {
                    component_id: component.component_id.clone(),
                    conflicting_component_id: existing.component_id.clone(),
                    reason: "two components share a canonical id while describing different \
                             artifacts, so a finding about one silently omits the other"
                        .to_owned(),
                });
            }
        } else {
            by_id.insert(component.component_id.as_str(), component);
        }

        if let Some(existing) = by_key.get(&identity.semantic_key) {
            if existing.component_id != component.component_id {
                collisions.push(IdentityCollision {
                    component_id: component.component_id.clone(),
                    conflicting_component_id: existing.component_id.clone(),
                    reason: "one artifact appears under two canonical ids, so approving one \
                             leaves the other unapproved while a reader sees it as covered"
                        .to_owned(),
                });
            }
        } else {
            by_key.insert(identity.semantic_key.clone(), component);
        }
    }

    collisions
}

/// Refuse a component set whose identities cannot be resolved.
pub fn assert_no_collisions(components: &[Component]) -> Result<()> {
    let collisions = find_collisions(components);
    if let Some(first) = collisions.first() {
        return Err(SupplyChainError::BindingMismatch(format!(
            "canonical identity is ambiguous: {}",
            first.reason
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component::tests::{component, digest};
    use crate::component::ComponentIdentifier;
    use crate::source::ComponentType;
    use std::collections::BTreeSet;

    fn without_digest(id: &str) -> Component {
        let mut component = component(id, ComponentType::Package);
        component.digests.clear();
        component
    }

    #[test]
    fn a_name_alone_is_never_an_immutable_identity() {
        // The first distinction the module exists for.
        let mut component = without_digest("react");
        component.version = None;
        let identity = resolve_identity(&component);
        assert_eq!(identity.strength, IdentityStrength::NameOnly);
        assert!(!identity.strength.is_immutable());
    }

    #[test]
    fn a_name_and_version_are_not_an_immutable_artifact() {
        // Two builds can carry the same version and be different bytes. This is
        // the substitution artifact integrity exists to catch, and an engine
        // that accepted name+version would never see it.
        let component = without_digest("react");
        let identity = resolve_identity(&component);
        assert_eq!(identity.strength, IdentityStrength::NameAndVersion);
        assert!(!identity.strength.is_immutable());
        assert_eq!(
            identity.satisfies_class(ComponentType::Package),
            Some(false)
        );
    }

    #[test]
    fn a_digest_is_what_makes_an_identity_immutable() {
        let component = component("react", ComponentType::Package);
        let identity = resolve_identity(&component);
        assert_eq!(identity.strength, IdentityStrength::ImmutableDigest);
        assert!(identity.strength.is_immutable());
        assert_eq!(identity.satisfies_class(ComponentType::Package), Some(true));
        assert_eq!(identity.pinned_by.len(), 1);
    }

    #[test]
    fn a_coordinate_pinned_by_digest_is_immutable_and_one_pinned_by_version_is_not() {
        // The document does not decide this. A purl with a digest qualifier
        // pins bytes; a purl with a version names a release the publisher can
        // republish.
        let mut versioned = without_digest("react");
        versioned.identifiers = BTreeSet::from([ComponentIdentifier {
            kind: "purl".to_owned(),
            value: "pkg:npm/react@18.3.1".to_owned(),
            immutable: false,
        }]);
        assert_eq!(
            resolve_identity(&versioned).strength,
            IdentityStrength::Coordinate
        );

        let mut pinned = without_digest("react");
        pinned.identifiers = BTreeSet::from([ComponentIdentifier {
            kind: "purl".to_owned(),
            value: "pkg:npm/react@18.3.1?digest=sha256%3Aaaaa".to_owned(),
            immutable: false,
        }]);
        assert_eq!(
            resolve_identity(&pinned).strength,
            IdentityStrength::ImmutableDigest,
            "a digest-qualified coordinate pins bytes"
        );

        let mut oci = without_digest("image");
        oci.identifiers = BTreeSet::from([ComponentIdentifier {
            kind: "oci".to_owned(),
            value: "ghcr.io/org/image@sha256:aaaa".to_owned(),
            immutable: false,
        }]);
        assert_eq!(
            resolve_identity(&oci).strength,
            IdentityStrength::ImmutableDigest
        );
    }

    #[test]
    fn a_document_cannot_declare_its_own_coordinate_immutable() {
        // `immutable: true` on the identifier is ignored. The shape of the
        // value decides, because otherwise a document could assert the one
        // thing this module exists to determine.
        let mut component = without_digest("react");
        component.identifiers = BTreeSet::from([ComponentIdentifier {
            kind: "purl".to_owned(),
            value: "pkg:npm/react@latest".to_owned(),
            immutable: true,
        }]);
        assert_eq!(
            resolve_identity(&component).strength,
            IdentityStrength::Coordinate,
            "a document asserted immutability and was believed"
        );
    }

    #[test]
    fn mutable_references_are_recognised_in_both_families() {
        // Named moving targets and range expressions. Both resolve to something
        // different tomorrow.
        for mutable in [
            "latest",
            "main",
            "HEAD",
            "nightly",
            "*",
            "^1.2.0",
            "~1.2",
            ">=1.0",
            "1.x",
            "1.2 || 1.3",
            "",
        ] {
            assert!(
                is_mutable_reference(mutable),
                "`{mutable}` was treated as immutable"
            );
        }
        for pinned in ["1.2.3", "18.3.1", "v2.0.0-rc1", "2026.09.08"] {
            assert!(
                !is_mutable_reference(pinned),
                "`{pinned}` was treated as mutable"
            );
        }
    }

    #[test]
    fn a_mutable_reference_is_recorded_distinctly_from_an_absent_one() {
        // Three answers again. "No version supplied" and "a version that means
        // whatever was pushed last" are different situations.
        let mut floating = without_digest("react");
        floating.version = Some("latest".to_owned());
        assert_eq!(resolve_identity(&floating).mutable_reference, Some(true));

        let pinned = without_digest("react");
        assert_eq!(resolve_identity(&pinned).mutable_reference, Some(false));

        let mut absent = without_digest("react");
        absent.version = None;
        assert_eq!(resolve_identity(&absent).mutable_reference, None);
    }

    #[test]
    fn a_mutable_reference_plus_a_digest_still_identifies_the_artifact() {
        // The benign control. Tagging an image `latest` is not a finding when
        // the digest is also recorded — the tag moves, the digest does not, and
        // an engine that reported this would train readers to ignore it.
        let mut component = component("image", ComponentType::ContainerImage);
        component.version = Some("latest".to_owned());
        let identity = resolve_identity(&component);
        assert_eq!(identity.strength, IdentityStrength::ImmutableDigest);
        assert_eq!(identity.mutable_reference, Some(true));
        assert_eq!(
            identity.satisfies_class(ComponentType::ContainerImage),
            Some(true)
        );
    }

    #[test]
    fn a_class_that_expects_no_artifact_answers_none_rather_than_false() {
        let mut agent = component("planner", ComponentType::Agent);
        agent.digests.clear();
        let identity = resolve_identity(&agent);
        assert_eq!(identity.satisfies_class(ComponentType::Agent), None);
    }

    #[test]
    fn the_semantic_key_is_independent_of_which_format_supplied_it() {
        // The requirement behind cross-format equivalence. If the key included
        // the evidence source, a CycloneDX and an SPDX description of one
        // component would never match, and the equivalence test would be
        // comparing parsers.
        let mut from_cyclonedx = component("react", ComponentType::Package);
        from_cyclonedx.evidence_source = crate::source::EvidenceSource::CycloneDx;

        let mut from_spdx = component("react", ComponentType::Package);
        from_spdx.evidence_source = crate::source::EvidenceSource::Spdx;
        from_spdx.component_id = "spdx-react".to_owned();

        assert_eq!(
            resolve_identity(&from_cyclonedx).semantic_key,
            resolve_identity(&from_spdx).semantic_key
        );
    }

    #[test]
    fn two_components_sharing_an_id_while_describing_different_artifacts_collide() {
        // Whichever the evaluator reads, the other is silently absent from
        // every finding about it.
        let first = component("react", ComponentType::Package);
        let mut second = component("react", ComponentType::Package);
        second.digests = BTreeSet::from([digest("b")]);

        let collisions = find_collisions(&[first, second]);
        assert!(!collisions.is_empty());
        assert!(collisions[0].reason.contains("silently omits"));
        assert!(
            assert_no_collisions(&[component("react", ComponentType::Package), {
                let mut other = component("react", ComponentType::Package);
                other.digests = BTreeSet::from([digest("b")]);
                other
            }])
            .is_err()
        );
    }

    #[test]
    fn one_artifact_under_two_ids_also_collides() {
        // The opposite failure, and the more dangerous one: approving one id
        // leaves the other unapproved while a reader sees the component as
        // covered.
        let first = component("react", ComponentType::Package);
        let mut second = component("react", ComponentType::Package);
        second.component_id = "react-duplicate".to_owned();

        let collisions = find_collisions(&[first, second]);
        assert!(!collisions.is_empty());
        assert!(collisions[0].reason.contains("two canonical ids"));
    }

    #[test]
    fn distinct_components_do_not_collide() {
        // The control. An engine that reported every pair would be useless.
        let react = component("react", ComponentType::Package);
        let mut vue = component("vue", ComponentType::Package);
        vue.digests = BTreeSet::from([digest("b")]);
        assert!(find_collisions(&[react, vue]).is_empty());
    }

    #[test]
    fn the_same_component_listed_twice_identically_is_not_a_collision() {
        // Deduplication must stay deterministic and quiet. Two identical rows
        // describe one thing, and reporting that as ambiguity would fire on
        // every merged document.
        let component = component("react", ComponentType::Package);
        assert!(find_collisions(&[component.clone(), component]).is_empty());
    }

    #[test]
    fn identity_strength_is_ordered_so_requirements_are_comparisons() {
        assert!(IdentityStrength::NameOnly < IdentityStrength::NameAndVersion);
        assert!(IdentityStrength::NameAndVersion < IdentityStrength::Coordinate);
        assert!(IdentityStrength::Coordinate < IdentityStrength::ImmutableDigest);
        assert!(!IdentityStrength::Coordinate.is_immutable());
        assert!(IdentityStrength::ImmutableDigest.is_immutable());
    }
}
