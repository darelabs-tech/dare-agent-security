use std::path::PathBuf;

use dare_adversarial::{load_bundle, ControlledRunner, ResultStatus, ValidationMode};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/adversarial")
        .join(name)
}

#[test]
fn controlled_fixture_matrix_is_deterministic_and_offline() {
    let cases = [
        ("confused-deputy.json", ResultStatus::Completed),
        ("tool-mutation.json", ResultStatus::Completed),
        ("argument-mutation.json", ResultStatus::Completed),
        ("tenant-boundary.json", ResultStatus::Completed),
        ("credential-reuse.json", ResultStatus::Completed),
        ("budget-exhausted.json", ResultStatus::Stopped),
        ("kill-switch.json", ResultStatus::Killed),
    ];
    for (name, expected) in cases {
        let bundle = load_bundle(&fixture(name)).expect(name);
        let first = ControlledRunner::new(ValidationMode::LocalSynthetic)
            .run(&bundle)
            .expect(name);
        let second = ControlledRunner::new(ValidationMode::LocalSynthetic)
            .run(&bundle)
            .expect(name);
        assert_eq!(first.status, expected, "{name}");
        assert_eq!(first, second, "{name}");
    }
}

#[test]
fn no_safe_proof_performs_zero_operations() {
    let bundle = load_bundle(&fixture("no-safe-proof.json")).expect("fixture");
    let error = ControlledRunner::new(ValidationMode::LocalSynthetic)
        .run(&bundle)
        .expect_err("unsupported proof must fail closed");
    assert!(error.to_string().contains("no safe proof"));
}

#[test]
fn plan_only_emits_no_operations() {
    let bundle = load_bundle(&fixture("confused-deputy.json")).expect("fixture");
    let result = ControlledRunner::new(ValidationMode::PlanOnly)
        .run(&bundle)
        .expect("plan");
    assert_eq!(result.status, ResultStatus::Planned);
    assert_eq!(result.operations, 0);
}
