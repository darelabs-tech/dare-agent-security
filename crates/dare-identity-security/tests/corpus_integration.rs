//! The shipped identity-security corpus, loaded and cross-checked.
//!
//! The corpus is the catalogue of what Cycle 015 claims to exercise. These
//! tests hold it to three things: it loads and digest-verifies, it is paired
//! (every attack family has a benign control), and it stays inert — no
//! credential material, no remote target, no executable field, no verdict.

use std::collections::{BTreeMap, BTreeSet};

use dare_identity_security::corpus::{builtin_corpus, builtin_corpus_root};
use dare_identity_security::model::IdentityInvariantType;
use dare_identity_security::source::{CorpusClass, ScenarioClass};

#[test]
fn the_shipped_corpus_loads_and_verifies_every_pinned_digest() {
    // `load_corpus` refuses a mismatched digest, so loading at all is the
    // assertion; the counts guard against a silently emptied corpus.
    let corpus = builtin_corpus().expect("corpus loads");
    assert_eq!(corpus.corpus_id, "identity-security-v1");
    assert_eq!(corpus.version, "1.0.0");
    assert!(
        corpus.entries.len() >= 24,
        "found {} entries",
        corpus.entries.len()
    );

    let ids: BTreeSet<&str> = corpus
        .entries
        .iter()
        .map(|entry| entry.id.as_str())
        .collect();
    assert_eq!(ids.len(), corpus.entries.len(), "entry ids must be unique");
}

#[test]
fn every_surface_carries_both_attacks_and_controls() {
    // A corpus that only attacks proves nothing about false positives; one that
    // only controls proves nothing about detection.
    let corpus = builtin_corpus().expect("corpus loads");
    for surface in ScenarioClass::all() {
        let entries = corpus.by_surface(surface);
        assert!(
            !entries.is_empty(),
            "{} has no corpus entries at all",
            surface.as_str()
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry.class == CorpusClass::IdentityAttack),
            "{} has no attack vector",
            surface.as_str()
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry.class == CorpusClass::BenignControl),
            "{} has no benign control",
            surface.as_str()
        );
    }
}

#[test]
fn every_invariant_is_named_by_both_an_attack_and_a_control() {
    let corpus = builtin_corpus().expect("corpus loads");
    let mut attacked: BTreeSet<IdentityInvariantType> = BTreeSet::new();
    let mut controlled: BTreeSet<IdentityInvariantType> = BTreeSet::new();

    for entry in &corpus.entries {
        match entry.class {
            CorpusClass::IdentityAttack => attacked.insert(entry.expected_invariant),
            CorpusClass::BenignControl => controlled.insert(entry.expected_invariant),
        };
    }

    for invariant in IdentityInvariantType::all() {
        assert!(
            attacked.contains(&invariant),
            "{} has no attack vector",
            invariant.as_str()
        );
        assert!(
            controlled.contains(&invariant),
            "{} has no benign control, so a false positive there would go unnoticed",
            invariant.as_str()
        );
    }
}

#[test]
fn a_benign_control_is_always_compliant_and_an_attack_never_is() {
    use dare_identity_security::model::ReferenceBehavior;
    let corpus = builtin_corpus().expect("corpus loads");
    for entry in &corpus.entries {
        match entry.class {
            CorpusClass::BenignControl => assert_eq!(
                entry.reference_behavior,
                ReferenceBehavior::Compliant,
                "{}",
                entry.id
            ),
            CorpusClass::IdentityAttack => assert_ne!(
                entry.reference_behavior,
                ReferenceBehavior::Compliant,
                "{}",
                entry.id
            ),
        }
    }
}

#[test]
fn every_entry_is_a_synthetic_noop_from_a_synthetic_origin() {
    let corpus = builtin_corpus().expect("corpus loads");
    for entry in &corpus.entries {
        assert_eq!(entry.safety_class, "SYNTHETIC_NOOP", "{}", entry.id);
        assert_eq!(entry.provenance.origin, "DARE_SYNTHETIC", "{}", entry.id);
        assert!(!entry.standards.is_empty(), "{}", entry.id);
    }
}

#[test]
fn a_draft_or_proposal_is_never_recorded_as_a_conformance_claim() {
    // AuthZEN informs the modelling and COAZ is a draft. Neither makes DARE
    // "compliant" with anything, and the corpus must not imply otherwise.
    let corpus = builtin_corpus().expect("corpus loads");
    let allowed: BTreeSet<&str> = [
        "NORMATIVE",
        "FINAL_SPECIFICATION",
        "DRAFT",
        "OPEN_PROPOSAL",
        "INFORMATIVE",
    ]
    .into_iter()
    .collect();

    for entry in &corpus.entries {
        for standard in &entry.standards {
            assert!(
                allowed.contains(standard.status.as_str()),
                "{}: unknown status `{}`",
                entry.id,
                standard.status
            );
            for banned in ["COMPLIANT", "CERTIFIED", "CONFORMS"] {
                assert!(
                    !standard.status.contains(banned) && !standard.reference.contains(banned),
                    "{}: `{banned}` is a conformance claim",
                    entry.id
                );
            }
        }
    }
}

#[test]
fn the_corpus_tree_holds_nothing_but_the_families_it_declares() {
    let root = builtin_corpus_root();
    let mut directories: BTreeSet<String> = BTreeSet::new();
    for entry in std::fs::read_dir(&root).expect("corpus root") {
        let entry = entry.expect("entry");
        if entry.file_type().expect("file type").is_dir() {
            directories.insert(entry.file_name().to_string_lossy().into_owned());
        }
    }

    let expected: BTreeSet<String> = [
        "principal-binding",
        "delegation",
        "privilege",
        "tenant-resource",
        "authorization-binding",
        "benign-controls",
        "adversarial-parser-fixtures",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();

    assert_eq!(directories, expected);
}

#[test]
fn no_shipped_corpus_file_contains_credential_or_remote_material() {
    // Belt and braces: the validator refuses these on load, and this catches a
    // file that never gets loaded because someone forgot to register it.
    let root = builtin_corpus_root();
    for path in walk(&root) {
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("{}: {err}", path.display()))
            .to_lowercase();
        let hostile = path
            .parent()
            .is_some_and(|parent| parent.ends_with("adversarial-parser-fixtures"));
        if hostile {
            // These deliberately carry shapes, never real material.
            for marker in ["ghp_", "xoxb-", "aws_secret_access_key"] {
                assert!(!text.contains(marker), "{}: `{marker}`", path.display());
            }
            continue;
        }
        for marker in [
            "sk-live-",
            "-----begin",
            "ghp_",
            "xoxb-",
            "eyjhbgci",
            "https://",
            "http://",
            "expected_verdict",
        ] {
            assert!(!text.contains(marker), "{}: `{marker}`", path.display());
        }
    }
}

#[test]
fn the_registry_and_the_tree_agree() {
    let corpus = builtin_corpus().expect("corpus loads");
    let root = builtin_corpus_root();

    let mut on_disk: BTreeMap<String, ()> = BTreeMap::new();
    for path in walk(&root) {
        let relative = path
            .strip_prefix(&root)
            .expect("under root")
            .to_string_lossy()
            .replace('\\', "/");
        if relative == "registry.json" || relative.starts_with("adversarial-parser-fixtures/") {
            continue;
        }
        on_disk.insert(relative, ());
    }

    assert_eq!(
        on_disk.len(),
        corpus.entries.len(),
        "a file in the tree that the registry does not list would never be validated"
    );
}

fn walk(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory).expect("readable directory") {
            let entry = entry.expect("entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "json") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}
