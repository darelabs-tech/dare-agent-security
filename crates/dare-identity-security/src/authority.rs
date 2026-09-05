//! Declarative authority: ceilings, effective authority and the subset relation.
//!
//! Authority here is data, never code. There is no expression language, no
//! scripting hook and no executable policy; every dimension is a closed
//! constraint over a set of labels, and comparison is deterministic set
//! containment.
//!
//! The relation the cycle rests on:
//!
//! ```text
//! effective_authority <= source_or_delegated_authority_ceiling
//! ```
//!
//! # Why a dimension is explicit rather than implied
//!
//! Every dimension is either explicitly `ANY` or an explicit list. An omitted
//! dimension decodes as the *empty* list, which grants nothing — absence of a
//! rule is never permission. To express "unconstrained" an author must write
//! `ANY` and mean it. That is the difference between a ceiling that forgot to
//! mention audiences and a ceiling that deliberately allows all of them.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::{IdentitySecurityError, Result};

/// Synthetic logical time.
///
/// A tick counter, not a wall clock: validity comparisons must be identical on
/// every machine and in every timezone, and a test that depends on "now" is a
/// test that decides differently tomorrow.
pub type LogicalTime = u64;

/// One dimension of an authority constraint.
///
/// `Any` must be written explicitly. An absent dimension is `Only { values: [] }`,
/// which permits nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "constraint", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityDimension {
    /// Deliberately unconstrained on this dimension.
    Any,
    /// Constrained to exactly these values. An empty list permits nothing.
    Only { values: Vec<String> },
}

impl Default for AuthorityDimension {
    /// The safe default: nothing is permitted until something says otherwise.
    fn default() -> Self {
        Self::Only { values: Vec::new() }
    }
}

impl AuthorityDimension {
    /// Construct a constrained dimension from any iterable of labels.
    pub fn only<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::Only {
            values: values.into_iter().map(Into::into).collect(),
        }
    }

    pub fn is_any(&self) -> bool {
        matches!(self, Self::Any)
    }

    /// True when this dimension permits nothing at all.
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Only { values } if values.is_empty())
    }

    fn value_set(&self) -> BTreeSet<&str> {
        match self {
            Self::Any => BTreeSet::new(),
            Self::Only { values } => values.iter().map(String::as_str).collect(),
        }
    }

    /// Whether this dimension permits a single concrete value.
    pub fn permits(&self, value: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Only { values } => values.iter().any(|allowed| allowed == value),
        }
    }

    /// Whether `self` is within `ceiling`.
    ///
    /// The asymmetry matters: a constrained dimension fits inside `ANY`, but
    /// `ANY` does not fit inside a constrained ceiling. Claiming unconstrained
    /// authority where the ceiling constrains is an expansion, not a match.
    pub fn within(&self, ceiling: &Self) -> bool {
        match (self, ceiling) {
            (_, Self::Any) => true,
            (Self::Any, Self::Only { .. }) => false,
            (Self::Only { .. }, Self::Only { .. }) => {
                self.value_set().is_subset(&ceiling.value_set())
            }
        }
    }

    /// Values present here that the ceiling does not permit.
    ///
    /// Returned so a violation can name what exceeded the ceiling instead of
    /// only reporting that something did.
    pub fn excess_over(&self, ceiling: &Self) -> Vec<String> {
        match (self, ceiling) {
            (_, Self::Any) => Vec::new(),
            (Self::Any, Self::Only { .. }) => vec!["ANY".to_owned()],
            (Self::Only { values }, Self::Only { .. }) => {
                let permitted = ceiling.value_set();
                values
                    .iter()
                    .filter(|value| !permitted.contains(value.as_str()))
                    .cloned()
                    .collect()
            }
        }
    }
}

/// A validity window in synthetic logical time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidityWindow {
    /// Inclusive lower bound.
    pub valid_from: LogicalTime,
    /// Exclusive upper bound.
    pub valid_until: LogicalTime,
}

impl ValidityWindow {
    pub fn new(valid_from: LogicalTime, valid_until: LogicalTime) -> Result<Self> {
        if valid_until <= valid_from {
            return Err(IdentitySecurityError::invalid(format!(
                "validity window ends at {valid_until}, which is not after its start {valid_from}"
            )));
        }
        Ok(Self {
            valid_from,
            valid_until,
        })
    }

    /// Whether `at` falls inside the window.
    ///
    /// Half-open on purpose: an edge that expires at tick 100 is not valid at
    /// tick 100, so a fixture can express expiry without an off-by-one debate.
    pub fn contains(&self, at: LogicalTime) -> bool {
        at >= self.valid_from && at < self.valid_until
    }

    /// Why `at` is outside the window, when it is.
    pub fn describe_exclusion(&self, at: LogicalTime) -> Option<String> {
        if at < self.valid_from {
            Some(format!(
                "not yet valid: use at {at} precedes validity start {}",
                self.valid_from
            ))
        } else if at >= self.valid_until {
            Some(format!(
                "expired: use at {at} is not before validity end {}",
                self.valid_until
            ))
        } else {
            None
        }
    }

    /// Whether this window is entirely inside `ceiling`.
    ///
    /// A delegation may shorten a validity window; it may never extend one.
    pub fn within(&self, ceiling: &Self) -> bool {
        self.valid_from >= ceiling.valid_from && self.valid_until <= ceiling.valid_until
    }
}

/// A declarative authority: what a principal may do, over what, and when.
///
/// Every field is a set constraint. There is deliberately no rule expression,
/// no condition string and no callback — a ceiling is compared, never executed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default)]
    pub actions: AuthorityDimension,
    #[serde(default)]
    pub resource_ids: AuthorityDimension,
    #[serde(default)]
    pub resource_types: AuthorityDimension,
    #[serde(default)]
    pub tenant_ids: AuthorityDimension,
    #[serde(default)]
    pub scopes: AuthorityDimension,
    #[serde(default)]
    pub purposes: AuthorityDimension,
    #[serde(default)]
    pub audiences: AuthorityDimension,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity: Option<ValidityWindow>,
}

/// One named dimension of an authority, for reporting which one exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityAxis {
    Actions,
    ResourceIds,
    ResourceTypes,
    TenantIds,
    Scopes,
    Purposes,
    Audiences,
    Validity,
}

impl AuthorityAxis {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Actions => "ACTIONS",
            Self::ResourceIds => "RESOURCE_IDS",
            Self::ResourceTypes => "RESOURCE_TYPES",
            Self::TenantIds => "TENANT_IDS",
            Self::Scopes => "SCOPES",
            Self::Purposes => "PURPOSES",
            Self::Audiences => "AUDIENCES",
            Self::Validity => "VALIDITY",
        }
    }

    /// Every set-valued axis, in a stable order.
    pub fn set_axes() -> [Self; 7] {
        [
            Self::Actions,
            Self::ResourceIds,
            Self::ResourceTypes,
            Self::TenantIds,
            Self::Scopes,
            Self::Purposes,
            Self::Audiences,
        ]
    }
}

/// One way in which an authority exceeded a ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityExcess {
    pub axis: AuthorityAxis,
    /// The values present beyond the ceiling, or a description for validity.
    pub excess: Vec<String>,
    pub detail: String,
}

impl Authority {
    /// A ceiling that permits nothing. The safe starting point.
    pub fn empty(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            title: None,
            actions: AuthorityDimension::default(),
            resource_ids: AuthorityDimension::default(),
            resource_types: AuthorityDimension::default(),
            tenant_ids: AuthorityDimension::default(),
            scopes: AuthorityDimension::default(),
            purposes: AuthorityDimension::default(),
            audiences: AuthorityDimension::default(),
            validity: None,
        }
    }

    fn dimension(&self, axis: AuthorityAxis) -> &AuthorityDimension {
        match axis {
            AuthorityAxis::Actions => &self.actions,
            AuthorityAxis::ResourceIds => &self.resource_ids,
            AuthorityAxis::ResourceTypes => &self.resource_types,
            AuthorityAxis::TenantIds => &self.tenant_ids,
            AuthorityAxis::Scopes => &self.scopes,
            AuthorityAxis::Purposes => &self.purposes,
            AuthorityAxis::Audiences => &self.audiences,
            // Validity is not a set dimension; callers handle it separately.
            AuthorityAxis::Validity => &self.actions,
        }
    }

    /// Every way in which `self` exceeds `ceiling`.
    ///
    /// A list rather than a first match: an authority can exceed on several
    /// axes at once, and reporting only the first would understate what
    /// happened.
    pub fn excess_over(&self, ceiling: &Self) -> Vec<AuthorityExcess> {
        let mut excesses = Vec::new();

        for axis in AuthorityAxis::set_axes() {
            let mine = self.dimension(axis);
            let theirs = ceiling.dimension(axis);
            if mine.within(theirs) {
                continue;
            }
            let excess = mine.excess_over(theirs);
            let detail = if mine.is_any() {
                format!(
                    "{} claims unconstrained authority while the ceiling constrains it",
                    axis.as_str()
                )
            } else {
                format!(
                    "{} exceeds the ceiling by {} value(s)",
                    axis.as_str(),
                    excess.len()
                )
            };
            excesses.push(AuthorityExcess {
                axis,
                excess,
                detail,
            });
        }

        // Validity: a delegation may shorten a window, never extend it. An
        // authority with no window under a ceiling that has one is unbounded in
        // time, which is an extension.
        match (&self.validity, &ceiling.validity) {
            (Some(mine), Some(theirs)) if !mine.within(theirs) => {
                excesses.push(AuthorityExcess {
                    axis: AuthorityAxis::Validity,
                    excess: vec![format!("{}..{}", mine.valid_from, mine.valid_until)],
                    detail: format!(
                        "validity {}..{} extends beyond the ceiling window {}..{}",
                        mine.valid_from, mine.valid_until, theirs.valid_from, theirs.valid_until
                    ),
                });
            }
            (None, Some(theirs)) => {
                excesses.push(AuthorityExcess {
                    axis: AuthorityAxis::Validity,
                    excess: vec!["UNBOUNDED".to_owned()],
                    detail: format!(
                        "authority declares no validity window while the ceiling is bounded to \
                         {}..{}",
                        theirs.valid_from, theirs.valid_until
                    ),
                });
            }
            _ => {}
        }

        excesses
    }

    /// Whether `self` is entirely within `ceiling`.
    ///
    /// This is the `effective_authority <= ceiling` relation.
    pub fn within(&self, ceiling: &Self) -> bool {
        self.excess_over(ceiling).is_empty()
    }

    /// Whether this authority is valid for use at a logical time.
    pub fn valid_at(&self, at: LogicalTime) -> bool {
        self.validity.is_none_or(|window| window.contains(at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ceiling() -> Authority {
        Authority {
            id: "authority-support-read".to_owned(),
            title: Some("read support documents in tenant A".to_owned()),
            actions: AuthorityDimension::only(["read", "list"]),
            resource_ids: AuthorityDimension::Any,
            resource_types: AuthorityDimension::only(["document"]),
            tenant_ids: AuthorityDimension::only(["tenant-a"]),
            scopes: AuthorityDimension::only(["support.read"]),
            purposes: AuthorityDimension::only(["objective-summarize-ticket"]),
            audiences: AuthorityDimension::only(["api://support"]),
            validity: Some(ValidityWindow::new(100, 200).expect("window")),
        }
    }

    #[test]
    fn an_omitted_dimension_permits_nothing() {
        // The fail-closed default. Absence of a rule is never permission.
        let decoded: Authority =
            serde_json::from_value(serde_json::json!({"id": "authority-empty"})).expect("decodes");
        for axis in AuthorityAxis::set_axes() {
            assert!(
                decoded.dimension(axis).is_empty(),
                "{} should permit nothing when omitted",
                axis.as_str()
            );
            assert!(!decoded.dimension(axis).permits("anything"));
        }
    }

    #[test]
    fn unconstrained_must_be_written_explicitly() {
        let any: AuthorityDimension =
            serde_json::from_value(serde_json::json!({"constraint": "ANY"})).expect("decodes");
        assert!(any.is_any());
        assert!(any.permits("literally anything"));

        // And it round-trips as a tagged value, so `ANY` is visible in a
        // fixture rather than inferred from a missing key.
        assert_eq!(
            serde_json::to_value(&any).expect("serializes"),
            serde_json::json!({"constraint": "ANY"})
        );
    }

    #[test]
    fn a_constrained_dimension_fits_inside_any() {
        let constrained = AuthorityDimension::only(["read"]);
        assert!(constrained.within(&AuthorityDimension::Any));
        assert!(constrained.excess_over(&AuthorityDimension::Any).is_empty());
    }

    #[test]
    fn any_does_not_fit_inside_a_constrained_ceiling() {
        // The asymmetry that makes this a ceiling rather than a comparison.
        // Claiming unconstrained authority under a constrained ceiling is an
        // expansion, however innocuous the claim looks.
        let ceiling = AuthorityDimension::only(["read"]);
        assert!(!AuthorityDimension::Any.within(&ceiling));
        assert_eq!(
            AuthorityDimension::Any.excess_over(&ceiling),
            vec!["ANY".to_owned()]
        );
    }

    #[test]
    fn equal_authority_is_within_the_ceiling() {
        // Authority may remain equal. Only expansion is a violation.
        let ceiling = ceiling();
        assert!(ceiling.within(&ceiling));
        assert!(ceiling.excess_over(&ceiling).is_empty());
    }

    #[test]
    fn narrowed_authority_is_within_the_ceiling() {
        let ceiling = ceiling();
        let narrowed = Authority {
            id: "authority-narrowed".to_owned(),
            actions: AuthorityDimension::only(["read"]),
            resource_types: AuthorityDimension::only(["document"]),
            tenant_ids: AuthorityDimension::only(["tenant-a"]),
            scopes: AuthorityDimension::only(["support.read"]),
            purposes: AuthorityDimension::only(["objective-summarize-ticket"]),
            audiences: AuthorityDimension::only(["api://support"]),
            resource_ids: AuthorityDimension::only(["document-123"]),
            validity: Some(ValidityWindow::new(120, 180).expect("window")),
            title: None,
        };
        assert!(
            narrowed.within(&ceiling),
            "{:?}",
            narrowed.excess_over(&ceiling)
        );
    }

    #[test]
    fn an_added_action_exceeds_the_ceiling_and_is_named() {
        let ceiling = ceiling();
        let mut widened = ceiling.clone();
        widened.actions = AuthorityDimension::only(["read", "list", "delete"]);

        assert!(!widened.within(&ceiling));
        let excess = widened.excess_over(&ceiling);
        assert_eq!(excess.len(), 1);
        assert_eq!(excess[0].axis, AuthorityAxis::Actions);
        assert_eq!(excess[0].excess, vec!["delete".to_owned()]);
    }

    #[test]
    fn several_axes_can_exceed_at_once_and_all_are_reported() {
        // One classification never masks another, at the authority level too.
        let ceiling = ceiling();
        let mut widened = ceiling.clone();
        widened.actions = AuthorityDimension::only(["read", "delete"]);
        widened.tenant_ids = AuthorityDimension::only(["tenant-a", "tenant-b"]);
        widened.scopes = AuthorityDimension::Any;

        let excess = widened.excess_over(&ceiling);
        let axes: Vec<AuthorityAxis> = excess.iter().map(|item| item.axis).collect();
        assert_eq!(
            axes,
            vec![
                AuthorityAxis::Actions,
                AuthorityAxis::TenantIds,
                AuthorityAxis::Scopes
            ]
        );
    }

    #[test]
    fn a_validity_window_may_shorten_but_never_extend() {
        let ceiling = ceiling();

        let mut shortened = ceiling.clone();
        shortened.validity = Some(ValidityWindow::new(120, 180).expect("window"));
        assert!(shortened.within(&ceiling));

        let mut extended = ceiling.clone();
        extended.validity = Some(ValidityWindow::new(100, 500).expect("window"));
        let excess = extended.excess_over(&ceiling);
        assert_eq!(excess.len(), 1);
        assert_eq!(excess[0].axis, AuthorityAxis::Validity);
    }

    #[test]
    fn dropping_a_validity_window_is_an_extension_not_a_simplification() {
        // Unbounded time under a bounded ceiling grants more, not less.
        let ceiling = ceiling();
        let mut unbounded = ceiling.clone();
        unbounded.validity = None;

        assert!(!unbounded.within(&ceiling));
        let excess = unbounded.excess_over(&ceiling);
        assert_eq!(excess[0].axis, AuthorityAxis::Validity);
        assert_eq!(excess[0].excess, vec!["UNBOUNDED".to_owned()]);
    }

    #[test]
    fn a_window_is_half_open_so_expiry_is_unambiguous() {
        let window = ValidityWindow::new(100, 200).expect("window");
        assert!(!window.contains(99));
        assert!(window.contains(100), "the start tick is inside");
        assert!(window.contains(199));
        assert!(!window.contains(200), "the end tick is outside");

        assert!(window.describe_exclusion(150).is_none());
        assert!(window
            .describe_exclusion(50)
            .expect("excluded")
            .contains("not yet valid"));
        assert!(window
            .describe_exclusion(250)
            .expect("excluded")
            .contains("expired"));
    }

    #[test]
    fn an_inverted_or_empty_window_is_refused() {
        assert!(ValidityWindow::new(200, 100).is_err());
        assert!(
            ValidityWindow::new(100, 100).is_err(),
            "a window that contains no tick cannot authorize anything"
        );
    }

    #[test]
    fn an_authority_without_a_window_is_valid_at_any_time() {
        let mut authority = Authority::empty("authority-timeless");
        assert!(authority.valid_at(0));
        assert!(authority.valid_at(u64::MAX));

        authority.validity = Some(ValidityWindow::new(10, 20).expect("window"));
        assert!(!authority.valid_at(9));
        assert!(authority.valid_at(15));
        assert!(!authority.valid_at(20));
    }

    #[test]
    fn an_empty_ceiling_permits_nothing_at_all() {
        let ceiling = Authority::empty("authority-none");
        let mut claiming = Authority::empty("authority-claiming");
        claiming.actions = AuthorityDimension::only(["read"]);

        assert!(!claiming.within(&ceiling));
        assert!(Authority::empty("authority-also-none").within(&ceiling));
    }

    #[test]
    fn authority_carries_no_executable_field() {
        // A ceiling is compared, never executed. If a rule expression could be
        // written here, the comparison would stop being deterministic.
        let encoded = serde_json::to_string(&ceiling()).expect("serializes");
        for forbidden in [
            "condition",
            "expression",
            "script",
            "eval",
            "callback",
            "rule",
            "cel",
            "rego",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "authority declares {forbidden}"
            );
        }
    }

    #[test]
    fn an_unknown_authority_field_fails_closed() {
        let value = serde_json::json!({
            "id": "authority-hostile",
            "condition": "subject.role == 'admin'"
        });
        assert!(serde_json::from_value::<Authority>(value).is_err());
    }

    #[test]
    fn an_unknown_constraint_tag_fails_closed() {
        assert!(serde_json::from_value::<AuthorityDimension>(
            serde_json::json!({"constraint": "EXCEPT", "values": ["delete"]})
        )
        .is_err());
    }

    #[test]
    fn comparison_is_deterministic_regardless_of_value_order() {
        let ceiling = AuthorityDimension::only(["read", "list", "write"]);
        let one = AuthorityDimension::only(["write", "read"]);
        let other = AuthorityDimension::only(["read", "write"]);
        assert!(one.within(&ceiling));
        assert!(other.within(&ceiling));
        assert_eq!(one.excess_over(&ceiling), other.excess_over(&ceiling));
    }
}
