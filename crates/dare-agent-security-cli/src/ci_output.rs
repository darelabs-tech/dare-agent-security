//! CI automation helpers: output directory, evidence collection, ci-result emission.

use std::fs;
use std::path::{Component, Path, PathBuf};

use dare_mcp_discovery::sanitize_stream;

use crate::ci_result::{
    build_ci_result, validate_ci_result, ActionMode, CiResult, CI_RESULT_FILENAME,
    GITHUB_OUTPUT_FILENAME, SUMMARY_FILENAME,
};
use crate::exit_code::SCANNER_ERROR;

/// Resolved CI automation paths from CLI flags.
#[derive(Debug, Clone)]
pub struct CiAutomation {
    pub output_dir: PathBuf,
    pub evidence_dir: PathBuf,
    pub fail_on_inconclusive: bool,
}

impl CiAutomation {
    pub fn from_flags(
        output_dir: Option<PathBuf>,
        evidence_dir: Option<PathBuf>,
        fail_on_inconclusive: bool,
    ) -> Option<Self> {
        let output_dir = output_dir?;
        Some(Self {
            evidence_dir: evidence_dir.unwrap_or_else(|| output_dir.join("evidence")),
            output_dir,
            fail_on_inconclusive,
        })
    }

    pub fn prepare(&self) -> Result<(), String> {
        validate_output_dir(&self.output_dir)?;
        fs::create_dir_all(&self.output_dir).map_err(|err| {
            format!(
                "output directory unavailable ({})",
                sanitize_stream(&err.to_string())
            )
        })?;
        fs::create_dir_all(&self.evidence_dir).map_err(|err| {
            format!(
                "evidence directory unavailable ({})",
                sanitize_stream(&err.to_string())
            )
        })
    }

    pub fn write_ci_result(&self, mode: ActionMode, command_exit: i32) -> Result<i32, String> {
        self.write_ci_result_with_summary(mode, command_exit, None)
    }

    pub fn write_ci_result_with_summary(
        &self,
        mode: ActionMode,
        command_exit: i32,
        target_label: Option<&str>,
    ) -> Result<i32, String> {
        let evidence_paths = collect_evidence_paths(&self.evidence_dir);
        self.write_ci_result_with_summary_and_paths(
            mode,
            command_exit,
            &evidence_paths,
            target_label,
        )
    }

    pub fn write_ci_result_with_summary_and_paths(
        &self,
        mode: ActionMode,
        command_exit: i32,
        evidence_paths: &[PathBuf],
        target_label: Option<&str>,
    ) -> Result<i32, String> {
        let result = build_ci_result(
            mode,
            &self.output_dir,
            evidence_paths,
            self.fail_on_inconclusive,
        );
        validate_ci_result(&result).map_err(|err| err.to_string())?;
        write_ci_result_file(&self.output_dir, &result)?;
        write_job_summary(&self.output_dir, &result, target_label)?;
        write_github_output_env(&self.output_dir, &result)?;
        Ok(map_command_exit(command_exit, &result))
    }

    pub fn write_error_result(&self, mode: ActionMode, command_exit: i32) -> Result<i32, String> {
        self.write_error_result_with_summary(mode, command_exit, None)
    }

    pub fn write_error_result_with_summary(
        &self,
        mode: ActionMode,
        command_exit: i32,
        target_label: Option<&str>,
    ) -> Result<i32, String> {
        let mut result = build_ci_result(mode, &self.output_dir, &[], self.fail_on_inconclusive);
        if command_exit == SCANNER_ERROR || command_exit == UNSUPPORTED_TARGET {
            result.aggregate_verdict = dare_security_evidence::Verdict::Error;
            result.process_exit_code = command_exit as u8;
            result.github_outputs.verdict = dare_security_evidence::Verdict::Error;
        }
        validate_ci_result(&result).map_err(|err| err.to_string())?;
        write_ci_result_file(&self.output_dir, &result)?;
        write_job_summary(&self.output_dir, &result, target_label)?;
        write_github_output_env(&self.output_dir, &result)?;
        Ok(command_exit)
    }
}

fn map_command_exit(command_exit: i32, result: &CiResult) -> i32 {
    if command_exit == UNSUPPORTED_TARGET {
        return UNSUPPORTED_TARGET;
    }
    if command_exit == SCANNER_ERROR
        && result.aggregate_verdict == dare_security_evidence::Verdict::Error
    {
        return SCANNER_ERROR;
    }
    result.process_exit_code as i32
}

use crate::exit_code::UNSUPPORTED_TARGET;

pub fn validate_output_dir(path: &Path) -> Result<(), String> {
    let normalized = normalize_relative_path(path);
    if normalized
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("output directory must not contain parent traversal (..)".to_owned());
    }
    if normalized.as_os_str().is_empty() {
        return Err("output directory must not be empty".to_owned());
    }
    Ok(())
}

fn normalize_relative_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir => normalized.push(".."),
            Component::RootDir | Component::Prefix(_) => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

pub fn collect_evidence_paths(dir: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return paths,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name == CI_RESULT_FILENAME {
            continue;
        }
        if name.ends_with(".result.json") {
            continue;
        }
        if name.ends_with(".json") {
            paths.push(path);
        }
    }
    paths.sort();
    paths
}

fn write_ci_result_file(output_dir: &Path, result: &CiResult) -> Result<(), String> {
    let path = output_dir.join(CI_RESULT_FILENAME);
    let bytes = serde_json::to_vec_pretty(result)
        .map_err(|_| "failed to serialize ci-result.json".to_owned())?;
    fs::write(path, bytes).map_err(|err| {
        format!(
            "ci-result write failed ({})",
            sanitize_stream(&err.to_string())
        )
    })
}

fn write_job_summary(
    output_dir: &Path,
    result: &CiResult,
    target_label: Option<&str>,
) -> Result<(), String> {
    let path = output_dir.join(SUMMARY_FILENAME);
    let target = sanitize_stream(target_label.unwrap_or("NOT PROVIDED"));
    let counts = &result.evidence_counts;
    let summary = format!(
        "# DARE Agent Security\n\n\
         | Field | Value |\n\
         |---|---|\n\
         | Version | {} |\n\
         | Mode | {} |\n\
         | Target | {} |\n\
         | Protocol revision | NOT TESTED (offline vectors) |\n\
         | Aggregate verdict | {} |\n\
         | PASS count | {} |\n\
         | FAIL count | {} |\n\
         | INCONCLUSIVE count | {} |\n\
         | ERROR count | {} |\n\
         | Evidence path | {} |\n\
         | Active adversarial testing | NOT TESTED (out of scope) |\n\
         | Remote production targets | NOT TESTED (synthetic fixtures only) |\n",
        env!("CARGO_PKG_VERSION"),
        result.mode.as_str(),
        target,
        result.aggregate_verdict.as_str(),
        counts.pass,
        counts.fail,
        counts.inconclusive,
        counts.error,
        result.github_outputs.evidence_path,
    );
    assert_summary_secret_safe(&summary)?;
    fs::write(path, summary.as_bytes()).map_err(|err| {
        format!(
            "summary write failed ({})",
            sanitize_stream(&err.to_string())
        )
    })
}

fn write_github_output_env(output_dir: &Path, result: &CiResult) -> Result<(), String> {
    let path = output_dir.join(GITHUB_OUTPUT_FILENAME);
    let body = format!(
        "verdict={}\nevidence-path={}\nsummary-path={}\n",
        result.github_outputs.verdict.as_str(),
        result.github_outputs.evidence_path,
        result.github_outputs.summary_path,
    );
    assert_summary_secret_safe(&body)?;
    fs::write(path, body.as_bytes()).map_err(|err| {
        format!(
            "github output write failed ({})",
            sanitize_stream(&err.to_string())
        )
    })
}

pub fn assert_summary_secret_safe(content: &str) -> Result<(), String> {
    const CANARIES: [&str; 4] = ["Bearer ", "Authorization:", "sk-live-", "password="];
    for canary in CANARIES {
        if content.contains(canary) {
            return Err("refusing to write secret-like content to CI outputs".to_owned());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ci_result::{DEFAULT_OUTPUT_DIR, GITHUB_OUTPUT_FILENAME};
    use crate::exit_code::{PARTIAL, SCANNER_ERROR, SUCCESS};
    use dare_security_evidence::Verdict;

    #[test]
    fn rejects_parent_traversal_in_output_dir() {
        assert!(validate_output_dir(Path::new("../escape")).is_err());
        assert!(validate_output_dir(Path::new(".dare-agent-security")).is_ok());
    }

    #[test]
    fn default_output_dir_constant_matches_contract() {
        assert_eq!(DEFAULT_OUTPUT_DIR, ".dare-agent-security");
    }

    #[test]
    fn collect_evidence_skips_result_and_ci_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("COAZ-INTEGRITY-001.evidence.json"), b"{}").unwrap();
        fs::write(dir.path().join("COAZ-INTEGRITY-001.result.json"), b"{}").unwrap();
        fs::write(dir.path().join(CI_RESULT_FILENAME), b"{}").unwrap();
        let paths = collect_evidence_paths(dir.path());
        assert_eq!(paths.len(), 1);
        assert!(paths[0]
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(".evidence.json"));
    }

    #[test]
    fn write_ci_result_produces_valid_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ci = CiAutomation {
            output_dir: dir.path().to_path_buf(),
            evidence_dir: dir.path().join("evidence"),
            fail_on_inconclusive: true,
        };
        ci.prepare().expect("prepare");
        let exit = ci
            .write_ci_result(ActionMode::Validate, SUCCESS)
            .expect("write");
        assert_eq!(exit, PARTIAL);
        assert!(dir.path().join(CI_RESULT_FILENAME).is_file());
        assert!(dir.path().join(SUMMARY_FILENAME).is_file());
        assert!(dir.path().join(GITHUB_OUTPUT_FILENAME).is_file());
        let raw = fs::read_to_string(dir.path().join(CI_RESULT_FILENAME)).unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(value["aggregate_verdict"], "INCONCLUSIVE");
        assert_ne!(value["aggregate_verdict"], "PASS");
    }

    #[test]
    fn fail_on_inconclusive_false_yields_success_exit_for_inconclusive() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ci = CiAutomation {
            output_dir: dir.path().to_path_buf(),
            evidence_dir: dir.path().join("evidence"),
            fail_on_inconclusive: false,
        };
        ci.prepare().expect("prepare");
        let exit = ci
            .write_ci_result(ActionMode::Discover, SUCCESS)
            .expect("write");
        assert_eq!(exit, SUCCESS);
    }

    #[test]
    fn error_result_marks_aggregate_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ci = CiAutomation {
            output_dir: dir.path().to_path_buf(),
            evidence_dir: dir.path().join("evidence"),
            fail_on_inconclusive: true,
        };
        ci.prepare().expect("prepare");
        let exit = ci
            .write_error_result(ActionMode::Discover, SCANNER_ERROR)
            .expect("write");
        assert_eq!(exit, SCANNER_ERROR);
        let raw = fs::read_to_string(dir.path().join(CI_RESULT_FILENAME)).unwrap();
        assert!(raw.contains("\"ERROR\""));
        let _: Verdict = Verdict::Error;
    }
}
