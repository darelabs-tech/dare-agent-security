//! Deterministic logical time.
//!
//! Every lifecycle decision in Cycle 016 is made against a scenario-declared
//! logical tick, never against the machine clock. A verdict that depended on
//! when the suite happened to run would not be reproducible, and a memory
//! fixture that expires because CI was slow would be a false finding.

use serde::{Deserialize, Serialize};

/// A synthetic logical instant. Not a wall-clock time and not a duration.
pub type LogicalTime = u64;

/// A half-open validity interval `[valid_from, valid_until)`.
///
/// Half-open so that an item expiring at `t` is already expired *at* `t`. The
/// alternative leaves one tick where an expired item is still usable, which is
/// exactly the off-by-one an attacker would want.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidityWindow {
    pub valid_from: LogicalTime,
    /// `None` means the item does not expire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<LogicalTime>,
}

impl ValidityWindow {
    /// Whether `now` falls inside the window.
    pub fn contains(&self, now: LogicalTime) -> bool {
        if now < self.valid_from {
            return false;
        }
        match self.valid_until {
            Some(until) => now < until,
            None => true,
        }
    }

    /// Why `now` falls outside the window, for evidence.
    ///
    /// Returns `None` when the instant is inside, so the caller cannot
    /// accidentally render an exclusion reason for a valid item.
    pub fn describe_exclusion(&self, now: LogicalTime) -> Option<String> {
        if now < self.valid_from {
            return Some(format!(
                "used at {now}, before it becomes valid at {}",
                self.valid_from
            ));
        }
        match self.valid_until {
            Some(until) if now >= until => {
                Some(format!("used at {now}, after it expired at {until}"))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_is_half_open_at_both_ends() {
        let window = ValidityWindow {
            valid_from: 100,
            valid_until: Some(200),
        };
        assert!(!window.contains(99));
        // Inclusive at the start.
        assert!(window.contains(100));
        assert!(window.contains(199));
        // Exclusive at the end: expiring at 200 means expired at 200, not 201.
        assert!(!window.contains(200));
        assert!(!window.contains(201));
    }

    #[test]
    fn an_open_ended_window_never_expires() {
        let window = ValidityWindow {
            valid_from: 0,
            valid_until: None,
        };
        assert!(window.contains(0));
        assert!(window.contains(u64::MAX));
        assert_eq!(window.describe_exclusion(u64::MAX), None);
    }

    #[test]
    fn an_exclusion_reason_exists_only_when_the_instant_is_outside() {
        let window = ValidityWindow {
            valid_from: 100,
            valid_until: Some(200),
        };
        assert_eq!(window.describe_exclusion(150), None);

        let early = window.describe_exclusion(50).expect("before the window");
        assert!(early.contains("before it becomes valid"));
        assert!(early.contains("100"));

        let late = window.describe_exclusion(250).expect("after the window");
        assert!(late.contains("after it expired"));
        assert!(late.contains("200"));

        // The boundary instant is outside and says so.
        assert!(window
            .describe_exclusion(200)
            .expect("the expiry instant is outside")
            .contains("after it expired"));
    }

    #[test]
    fn a_zero_length_window_contains_nothing() {
        let window = ValidityWindow {
            valid_from: 100,
            valid_until: Some(100),
        };
        assert!(!window.contains(99));
        assert!(!window.contains(100));
        assert!(!window.contains(101));
    }

    #[test]
    fn the_window_round_trips_and_rejects_unknown_fields() {
        let window = ValidityWindow {
            valid_from: 1,
            valid_until: Some(2),
        };
        let json = serde_json::to_string(&window).expect("serializes");
        assert_eq!(
            serde_json::from_str::<ValidityWindow>(&json).expect("round-trips"),
            window
        );
        assert!(serde_json::from_str::<ValidityWindow>(
            r#"{"valid_from":1,"valid_until":2,"timezone":"UTC"}"#
        )
        .is_err());
    }
}
