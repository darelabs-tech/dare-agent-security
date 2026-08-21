//! Performance baseline smoke — documents v1 limits, no scale subsystem.

use std::time::Instant;

use dare_product::{init_project, run_assessment, AssessOptions, InitOptions};
use tempfile::tempdir;

#[test]
fn assess_empty_project_under_two_seconds() {
    let dir = tempdir().unwrap();
    init_project(dir.path(), &InitOptions::default()).unwrap();
    let started = Instant::now();
    let outcome = run_assessment(&AssessOptions {
        target: dir.path().to_path_buf(),
        config_path: None,
        confidential: false,
        offline: true,
        run_id: Some("run-perf-001".into()),
    })
    .unwrap();
    let elapsed = started.elapsed();
    assert!(
        elapsed.as_secs() < 2,
        "v1 baseline: empty offline assess should finish under 2s, took {elapsed:?}"
    );
    assert!(outcome.duration_ms < 2000);
}
