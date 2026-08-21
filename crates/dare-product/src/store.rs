//! Local artifact store under `.dare-security/runs/<run-id>/`.

use std::fs;
use std::path::{Component, Path, PathBuf};

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error::{ProductError, Result};
use crate::redaction::assert_no_secrets;
use crate::view_model::ProductViewModel;

pub const RUNS_DIR: &str = ".dare-security/runs";

#[derive(Debug, Clone)]
pub struct RunArtifactPaths {
    pub run_dir: PathBuf,
    pub summary: PathBuf,
    pub findings: PathBuf,
    pub coverage: PathBuf,
    pub attack_graph: PathBuf,
    pub validation: PathBuf,
    pub drift: PathBuf,
    pub evidence_dir: PathBuf,
    pub executive_html: PathBuf,
    pub technical_html: PathBuf,
}

impl RunArtifactPaths {
    pub fn for_run(root: &Path, run_id: &str) -> Result<Self> {
        validate_safe_segment(run_id)?;
        let run_dir = root.join(RUNS_DIR).join(run_id);
        Ok(Self {
            summary: run_dir.join("summary.json"),
            findings: run_dir.join("findings.json"),
            coverage: run_dir.join("coverage.json"),
            attack_graph: run_dir.join("attack-graph.json"),
            validation: run_dir.join("validation.json"),
            drift: run_dir.join("drift.json"),
            evidence_dir: run_dir.join("evidence"),
            executive_html: run_dir.join("reports").join("executive.html"),
            technical_html: run_dir.join("reports").join("technical.html"),
            run_dir,
        })
    }

    pub fn prepare(&self) -> Result<()> {
        validate_output_path(&self.run_dir)?;
        fs::create_dir_all(&self.evidence_dir)?;
        fs::create_dir_all(self.run_dir.join("reports"))?;
        Ok(())
    }
}

pub fn new_run_id() -> String {
    let now = OffsetDateTime::now_utc();
    let ts = now
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
    let compact = ts.replace([':', '-'], "").replace('.', "");
    format!("run-{compact}")
}

pub fn resolve_run_dir(root: &Path, run_id: Option<&str>) -> Result<PathBuf> {
    let id = match run_id {
        Some(id) => {
            validate_safe_segment(id)?;
            id.to_owned()
        }
        None => latest_run_id(root)?.ok_or_else(|| {
            ProductError::environment(
                "no assessment runs found; run `dare-agent-security assess` first",
            )
        })?,
    };
    let paths = RunArtifactPaths::for_run(root, &id)?;
    if !paths.run_dir.is_dir() {
        return Err(ProductError::environment(format!(
            "run directory not found: {}",
            paths.run_dir.display()
        )));
    }
    Ok(paths.run_dir)
}

pub fn latest_run_id(root: &Path) -> Result<Option<String>> {
    let runs = root.join(RUNS_DIR);
    if !runs.is_dir() {
        return Ok(None);
    }
    let mut ids: Vec<String> = fs::read_dir(&runs)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| validate_safe_segment(name).is_ok())
        .collect();
    ids.sort();
    Ok(ids.pop())
}

pub fn write_view_model(paths: &RunArtifactPaths, vm: &ProductViewModel) -> Result<()> {
    paths.prepare()?;
    write_json(&paths.summary, &vm.summary)?;
    write_json(&paths.findings, &vm.findings)?;
    write_json(&paths.coverage, &vm.coverage)?;
    write_json(&paths.attack_graph, &vm.attack_graph)?;
    write_json(&paths.validation, &vm.validation)?;
    write_json(&paths.drift, &vm.drift)?;
    Ok(())
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let body = serde_json::to_vec_pretty(value)?;
    let text = String::from_utf8_lossy(&body);
    assert_no_secrets(path.to_string_lossy().as_ref(), &text).map_err(ProductError::internal)?;
    fs::write(path, body)?;
    Ok(())
}

pub fn validate_safe_segment(segment: &str) -> Result<()> {
    if segment.is_empty()
        || segment.contains('/')
        || segment.contains('\\')
        || segment.contains("..")
        || segment.starts_with('.')
    {
        return Err(ProductError::configuration(
            "run id must be a single safe path segment without traversal",
        ));
    }
    if !segment
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ProductError::configuration(
            "run id contains unsupported characters",
        ));
    }
    Ok(())
}

pub fn validate_output_path(path: &Path) -> Result<()> {
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(ProductError::configuration(
            "output path must not contain parent traversal (..)",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_traversal_run_id() {
        assert!(validate_safe_segment("../etc").is_err());
        assert!(validate_safe_segment("run/../../x").is_err());
        assert!(validate_safe_segment("run-ok_01").is_ok());
    }
}
