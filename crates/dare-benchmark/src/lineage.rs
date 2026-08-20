//! Lineage classification for prevalence denominators.

use crate::corpus::{CorpusTarget, LineageType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrevalenceInclusion {
    /// Counts independently in headline prevalence.
    Include,
    /// Visible in corpus stats but excluded from headline prevalence.
    ExcludeFromPrevalence,
}

pub fn classify_for_prevalence(target: &CorpusTarget) -> PrevalenceInclusion {
    match target.lineage.lineage_type {
        LineageType::Canonical | LineageType::MaterialFork => PrevalenceInclusion::Include,
        LineageType::Mirror | LineageType::VendorCopy | LineageType::Example => {
            PrevalenceInclusion::ExcludeFromPrevalence
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::LineageInfo;

    fn target(lineage: LineageType, parent: Option<&str>) -> CorpusTarget {
        CorpusTarget {
            id: "mcp-target-000001".to_owned(),
            repository: "owner/repo".to_owned(),
            commit: "a".repeat(40),
            license: "Apache-2.0".to_owned(),
            discovered_at: "2026-08-20T00:00:00Z".to_owned(),
            lineage: LineageInfo {
                lineage_type: lineage,
                parent_target_id: parent.map(str::to_owned),
            },
            stratification: None,
            fixture_path: None,
        }
    }

    #[test]
    fn mirrors_do_not_inflate_prevalence() {
        assert_eq!(
            classify_for_prevalence(&target(LineageType::Mirror, Some("mcp-target-000001"))),
            PrevalenceInclusion::ExcludeFromPrevalence
        );
        assert_eq!(
            classify_for_prevalence(&target(LineageType::Canonical, None)),
            PrevalenceInclusion::Include
        );
    }
}
