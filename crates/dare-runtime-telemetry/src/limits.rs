//! Hard maxima (DESIGN §4.3). Inputs may only lower them.
use crate::error::Refusal;

pub const MAX_TRACE_FILES: usize = 64;
pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_POLICY_BYTES: u64 = 1024 * 1024;
pub const MAX_JSON_DEPTH: usize = 64;
pub const MAX_SPANS: u64 = 1_000_000;
pub const MAX_ATTRIBUTES_PER_SPAN: usize = 256;
pub const MAX_SCANNED_VALUE_BYTES: usize = 64 * 1024;
pub const MAX_TREE_DEPTH: usize = 256;

/// Bounds of one run. Only the span total can be lowered by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    pub max_spans: u64,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            max_spans: MAX_SPANS,
        }
    }
}

impl Bounds {
    /// Refuses 0 and any value above its maximum; never clamps.
    pub fn validate(&self) -> Result<(), Refusal> {
        check("max_spans", self.max_spans, MAX_SPANS)
    }

    pub fn lower(self, max_spans: Option<u64>) -> Self {
        Self {
            max_spans: max_spans.map_or(self.max_spans, |s| s.min(self.max_spans)),
        }
    }
}

pub fn check(bound: &'static str, value: u64, maximum: u64) -> Result<(), Refusal> {
    if value == 0 {
        return Err(Refusal::BoundZero { bound });
    }
    if value > maximum {
        return Err(Refusal::BoundAboveMaximum { bound });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_maxima_are_the_design_values() {
        assert_eq!(MAX_TRACE_FILES, 64);
        assert_eq!(MAX_FILE_BYTES, 16 << 20);
        assert_eq!(MAX_TOTAL_BYTES, 256 << 20);
        assert_eq!(MAX_JSON_DEPTH, 64);
        assert_eq!(MAX_SPANS, 1_000_000);
        assert_eq!(MAX_ATTRIBUTES_PER_SPAN, 256);
        assert_eq!(MAX_SCANNED_VALUE_BYTES, 64 << 10);
        assert_eq!(MAX_TREE_DEPTH, 256);
        assert_eq!(Bounds::default().validate(), Ok(()));
    }

    #[test]
    fn every_bound_refuses_zero_and_values_above_its_maximum() {
        let spans = |s| Bounds { max_spans: s };
        assert_eq!(
            spans(0).validate(),
            Err(Refusal::BoundZero { bound: "max_spans" })
        );
        assert_eq!(
            spans(MAX_SPANS + 1).validate(),
            Err(Refusal::BoundAboveMaximum { bound: "max_spans" })
        );
        assert_eq!(spans(MAX_SPANS).validate(), Ok(()));
        assert_eq!(spans(1).validate(), Ok(()));
    }

    #[test]
    fn lowering_takes_the_smaller_value() {
        assert_eq!(Bounds::default().lower(Some(10)).max_spans, 10);
        assert_eq!(Bounds { max_spans: 5 }.lower(Some(9)).max_spans, 5);
        assert_eq!(Bounds::default().lower(None), Bounds::default());
    }
}
