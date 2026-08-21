//! Classification metadata rendered on product reports.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Classification {
    #[serde(default = "default_level")]
    pub level: String,
    #[serde(default)]
    pub distribution: Vec<String>,
    #[serde(default)]
    pub publication_allowed: bool,
}

fn default_level() -> String {
    "INTERNAL".to_owned()
}

impl Default for Classification {
    fn default() -> Self {
        Self {
            level: default_level(),
            distribution: vec!["security-team".to_owned()],
            publication_allowed: false,
        }
    }
}

impl Classification {
    pub fn confidential_default() -> Self {
        Self {
            level: "CONFIDENTIAL".to_owned(),
            distribution: vec!["security-team".to_owned(), "target-owner".to_owned()],
            publication_allowed: false,
        }
    }

    pub fn banner_text(&self) -> String {
        let dist = if self.distribution.is_empty() {
            "restricted".to_owned()
        } else {
            self.distribution.join(", ")
        };
        format!(
            "Classification: {} | Distribution: {} | Publication allowed: {}",
            self.level, dist, self.publication_allowed
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_includes_level() {
        let c = Classification::confidential_default();
        let banner = c.banner_text();
        assert!(banner.contains("CONFIDENTIAL"));
        assert!(banner.contains("false"));
    }
}
