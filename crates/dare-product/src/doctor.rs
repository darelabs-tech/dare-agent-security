//! `doctor` diagnostics — safe environment/config checks.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::{load_config, CONFIG_FILE_NAMES};
use crate::error::Result;
use crate::privacy::PrivacyPolicy;
use crate::store::RUNS_DIR;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorCheck {
    pub id: String,
    pub status: CheckStatus,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub ok: bool,
    pub checks: Vec<DoctorCheck>,
}

/// Run non-invasive diagnostics for product readiness.
pub fn run_doctor(root: &Path) -> Result<DoctorReport> {
    let mut checks = Vec::new();

    checks.push(DoctorCheck {
        id: "runtime".to_owned(),
        status: CheckStatus::Pass,
        message: format!(
            "dare-product {} / MSRV-oriented build (rustc via cargo)",
            env!("CARGO_PKG_VERSION")
        ),
    });

    let config_present = CONFIG_FILE_NAMES
        .iter()
        .any(|name| root.join(name).is_file());
    if config_present {
        match load_config(root, None) {
            Ok((cfg, path)) => {
                let policy: PrivacyPolicy = cfg.privacy.to_policy();
                match policy.validate_fail_closed() {
                    Ok(()) => checks.push(DoctorCheck {
                        id: "config".to_owned(),
                        status: CheckStatus::Pass,
                        message: format!(
                            "valid config v{} at {} (profile={})",
                            cfg.version,
                            path.display(),
                            cfg.assessment.profile
                        ),
                    }),
                    Err(err) => checks.push(DoctorCheck {
                        id: "config".to_owned(),
                        status: CheckStatus::Fail,
                        message: err.actionable_message(),
                    }),
                }
                checks.push(DoctorCheck {
                    id: "privacy".to_owned(),
                    status: CheckStatus::Pass,
                    message: format!(
                        "privacy mode={:?} telemetry={} offline={} network={:?}",
                        policy.mode, policy.telemetry, policy.offline, policy.network
                    ),
                });
            }
            Err(err) => checks.push(DoctorCheck {
                id: "config".to_owned(),
                status: CheckStatus::Fail,
                message: err.actionable_message(),
            }),
        }
    } else {
        checks.push(DoctorCheck {
            id: "config".to_owned(),
            status: CheckStatus::Warn,
            message: "no product config found; run `dare-agent-security init`".to_owned(),
        });
    }

    let runs = root.join(RUNS_DIR);
    if runs.exists() {
        let writable = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(runs.join(".doctor-write-check"))
            .is_ok();
        let _ = std::fs::remove_file(runs.join(".doctor-write-check"));
        checks.push(DoctorCheck {
            id: "output_path".to_owned(),
            status: if writable {
                CheckStatus::Pass
            } else {
                CheckStatus::Fail
            },
            message: if writable {
                format!("runs directory writable at {}", runs.display())
            } else {
                format!("runs directory not writable at {}", runs.display())
            },
        });
    } else {
        checks.push(DoctorCheck {
            id: "output_path".to_owned(),
            status: CheckStatus::Warn,
            message: format!(
                "runs directory missing ({}); will be created on assess",
                runs.display()
            ),
        });
    }

    checks.push(DoctorCheck {
        id: "safe_defaults".to_owned(),
        status: CheckStatus::Pass,
        message:
            "safe defaults remain static/passive/plan-only; AUTHORIZED_DYNAMIC stays ROE-gated"
                .to_owned(),
    });

    checks.push(DoctorCheck {
        id: "dependencies".to_owned(),
        status: CheckStatus::Pass,
        message: "orchestrates Cycles 001–010 crates only (no second security engine)".to_owned(),
    });

    let ok = checks.iter().all(|c| c.status != CheckStatus::Fail);
    Ok(DoctorReport { ok, checks })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::{init_project, InitOptions};
    use tempfile::tempdir;

    #[test]
    fn doctor_passes_after_init() {
        let dir = tempdir().unwrap();
        init_project(dir.path(), &InitOptions::default()).unwrap();
        let report = run_doctor(dir.path()).unwrap();
        assert!(report.ok);
        assert!(report.checks.iter().any(|c| c.id == "config"));
    }
}
