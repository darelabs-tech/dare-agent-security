//! CLI smoke for product commands.

use std::process::Command;

fn bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dare-agent-security"));
    cmd.env_remove("HTTP_PROXY");
    cmd.env_remove("HTTPS_PROXY");
    cmd.env_remove("ALL_PROXY");
    cmd
}

#[test]
fn init_doctor_assess_report_journey() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();

    let init = bin()
        .args(["init", path.to_str().unwrap()])
        .output()
        .expect("init");
    assert!(init.status.success(), "{:?}", init);

    let doctor = bin()
        .args(["doctor", path.to_str().unwrap(), "--json"])
        .output()
        .expect("doctor");
    assert!(doctor.status.success(), "{:?}", doctor);

    let assess = bin()
        .args([
            "assess",
            path.to_str().unwrap(),
            "--offline",
            "--run",
            "run-cli-001",
        ])
        .output()
        .expect("assess");
    assert!(assess.status.success(), "{:?}", assess);

    let report = bin()
        .args([
            "report",
            "--path",
            path.to_str().unwrap(),
            "--run",
            "run-cli-001",
        ])
        .output()
        .expect("report");
    assert!(report.status.success(), "{:?}", report);
}
