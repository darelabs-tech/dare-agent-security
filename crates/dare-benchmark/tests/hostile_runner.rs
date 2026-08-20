use dare_benchmark::{
    builtin_policy, load_corpus_manifest, RunnerMode, RunnerOptions, RunnerSafetyGate,
};

#[test]
fn schema_rejects_unpinned_commit() {
    let raw = r#"{
      "schema": {"id":"https://darelabs.tech/schemas/benchmark/v1/corpus-manifest.schema.json","version":"1.0.0"},
      "corpus": {"id":"bad","version":"1.0.0"},
      "selection": {"source":"x","inclusion":["a"],"exclusion":["b"]},
      "targets": [{
        "id":"mcp-target-000001",
        "repository":"x/y",
        "commit":"notasha",
        "license":"MIT",
        "discovered_at":"2026-08-20T00:00:00Z",
        "lineage":{"type":"CANONICAL"}
      }]
    }"#;
    assert!(load_corpus_manifest(raw).is_err());
}

#[test]
fn authorized_dynamic_disabled_by_default_policy() {
    let policy = builtin_policy().unwrap();
    assert!(!policy.allow_authorized_dynamic);
    let err = RunnerSafetyGate::assert_mode_allowed(
        &RunnerOptions {
            mode: RunnerMode::AuthorizedDynamic,
            authorized_dynamic_roe: true,
        },
        &policy,
    );
    assert!(err.is_err());
}
