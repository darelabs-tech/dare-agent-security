//! Table-driven conservative classification contract.

use dare_mcp_discovery::classification::{
    classify_tool, ClassificationInput, RATIONALE_ANNOTATION_DESTRUCTIVE,
    RATIONALE_ANNOTATION_READ_ONLY, RATIONALE_ANNOTATION_STATE_CHANGING,
    RATIONALE_CONFLICTING_ANNOTATIONS, RATIONALE_EXPLICIT_CONFIG, RATIONALE_INSUFFICIENT_METADATA,
};
use dare_mcp_discovery::{
    ClassificationSource, OperationClass, ToolAnnotations, ToolClassification,
};

struct Case {
    label: &'static str,
    name: &'static str,
    description: Option<&'static str>,
    annotations: Option<ToolAnnotations>,
    explicit_class: Option<OperationClass>,
    protocol_annotation_class: Option<OperationClass>,
    expected: Expected,
}

struct Expected {
    class: OperationClass,
    source: ClassificationSource,
    rationale_code: &'static str,
    required_indicators: &'static [&'static str],
    forbidden_indicators: &'static [&'static str],
}

fn classify_case(case: &Case) -> ToolClassification {
    classify_tool(&ClassificationInput {
        name: case.name,
        description: case.description,
        annotations: case.annotations.as_ref(),
        explicit_class: case.explicit_class,
        protocol_annotation_class: case.protocol_annotation_class,
    })
}

fn annotations(
    read_only_hint: Option<bool>,
    destructive_hint: Option<bool>,
    idempotent_hint: Option<bool>,
    open_world_hint: Option<bool>,
) -> ToolAnnotations {
    ToolAnnotations {
        read_only_hint,
        destructive_hint,
        idempotent_hint,
        open_world_hint,
    }
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            label: "read_only from protocol annotation",
            name: "customer.lookup",
            description: Some("Read synthetic reservation holder metadata."),
            annotations: Some(annotations(
                Some(true),
                Some(false),
                Some(true),
                Some(false),
            )),
            explicit_class: None,
            protocol_annotation_class: None,
            expected: Expected {
                class: OperationClass::ReadOnly,
                source: ClassificationSource::ProtocolAnnotation,
                rationale_code: RATIONALE_ANNOTATION_READ_ONLY,
                required_indicators: &["read_only_hint"],
                forbidden_indicators: &["conflicting_hints"],
            },
        },
        Case {
            label: "state_changing from read_only_hint false",
            name: "reservation.create",
            description: Some("Create a synthetic booking."),
            annotations: Some(annotations(Some(false), Some(false), None, None)),
            explicit_class: None,
            protocol_annotation_class: None,
            expected: Expected {
                class: OperationClass::StateChanging,
                source: ClassificationSource::ProtocolAnnotation,
                rationale_code: RATIONALE_ANNOTATION_STATE_CHANGING,
                required_indicators: &["read_only_hint_false"],
                forbidden_indicators: &["conflicting_hints"],
            },
        },
        Case {
            label: "destructive from destructive_hint",
            name: "reservation.cancel",
            description: Some("Cancel a synthetic booking."),
            annotations: Some(annotations(Some(false), Some(true), None, None)),
            explicit_class: None,
            protocol_annotation_class: None,
            expected: Expected {
                class: OperationClass::Destructive,
                source: ClassificationSource::ProtocolAnnotation,
                rationale_code: RATIONALE_ANNOTATION_DESTRUCTIVE,
                required_indicators: &["destructive_hint"],
                forbidden_indicators: &[],
            },
        },
        Case {
            label: "unknown without annotations",
            name: "legacy.ambiguous",
            description: Some("Undocumented legacy helper."),
            annotations: None,
            explicit_class: None,
            protocol_annotation_class: None,
            expected: Expected {
                class: OperationClass::Unknown,
                source: ClassificationSource::InsufficientMetadata,
                rationale_code: RATIONALE_INSUFFICIENT_METADATA,
                required_indicators: &[],
                forbidden_indicators: &[],
            },
        },
        Case {
            label: "conflicting read_only and destructive is destructive",
            name: "mixed.hints",
            description: None,
            annotations: Some(annotations(Some(true), Some(true), None, None)),
            explicit_class: None,
            protocol_annotation_class: None,
            expected: Expected {
                class: OperationClass::Destructive,
                source: ClassificationSource::ProtocolAnnotation,
                rationale_code: RATIONALE_ANNOTATION_DESTRUCTIVE,
                required_indicators: &["conflicting_hints", "destructive_hint", "read_only_hint"],
                forbidden_indicators: &[],
            },
        },
        Case {
            label: "tempting get_ name without annotations is unknown",
            name: "get_customer",
            description: None,
            annotations: None,
            explicit_class: None,
            protocol_annotation_class: None,
            expected: Expected {
                class: OperationClass::Unknown,
                source: ClassificationSource::InsufficientMetadata,
                rationale_code: RATIONALE_INSUFFICIENT_METADATA,
                required_indicators: &["name_suggests_read"],
                forbidden_indicators: &[],
            },
        },
        Case {
            label: "tempting list_ name without annotations is unknown",
            name: "list_reservations",
            description: None,
            annotations: None,
            explicit_class: None,
            protocol_annotation_class: None,
            expected: Expected {
                class: OperationClass::Unknown,
                source: ClassificationSource::InsufficientMetadata,
                rationale_code: RATIONALE_INSUFFICIENT_METADATA,
                required_indicators: &["name_suggests_read"],
                forbidden_indicators: &[],
            },
        },
        Case {
            label: "explicit config overrides annotations",
            name: "customer.lookup",
            description: Some("Read synthetic reservation holder metadata."),
            annotations: Some(annotations(Some(true), Some(false), None, None)),
            explicit_class: Some(OperationClass::Destructive),
            protocol_annotation_class: None,
            expected: Expected {
                class: OperationClass::Destructive,
                source: ClassificationSource::ExplicitConfiguration,
                rationale_code: RATIONALE_EXPLICIT_CONFIG,
                required_indicators: &["read_only_hint", "name_suggests_read"],
                forbidden_indicators: &[],
            },
        },
        Case {
            label: "explicit unknown stays unknown",
            name: "delete_customer",
            description: Some("Might delete records."),
            annotations: Some(annotations(Some(true), Some(true), None, None)),
            explicit_class: Some(OperationClass::Unknown),
            protocol_annotation_class: None,
            expected: Expected {
                class: OperationClass::Unknown,
                source: ClassificationSource::ExplicitConfiguration,
                rationale_code: RATIONALE_EXPLICIT_CONFIG,
                required_indicators: &["name_suggests_delete", "description_suggests_delete"],
                forbidden_indicators: &[],
            },
        },
        Case {
            label: "ambiguous description is unknown",
            name: "legacy.helper",
            description: Some("might delete or read"),
            annotations: None,
            explicit_class: None,
            protocol_annotation_class: None,
            expected: Expected {
                class: OperationClass::Unknown,
                source: ClassificationSource::InsufficientMetadata,
                rationale_code: RATIONALE_INSUFFICIENT_METADATA,
                required_indicators: &["description_suggests_delete", "description_suggests_read"],
                forbidden_indicators: &[],
            },
        },
        Case {
            label: "read_only annotation blocked by delete description",
            name: "records.inspect",
            description: Some("might delete or read"),
            annotations: Some(annotations(Some(true), None, None, None)),
            explicit_class: None,
            protocol_annotation_class: None,
            expected: Expected {
                class: OperationClass::Unknown,
                source: ClassificationSource::InsufficientMetadata,
                rationale_code: RATIONALE_CONFLICTING_ANNOTATIONS,
                required_indicators: &[
                    "conflicting_hints",
                    "description_suggests_delete",
                    "read_only_hint",
                ],
                forbidden_indicators: &[],
            },
        },
        Case {
            label: "idempotent_hint alone is not read_only",
            name: "cache.touch",
            description: None,
            annotations: Some(annotations(None, None, Some(true), None)),
            explicit_class: None,
            protocol_annotation_class: None,
            expected: Expected {
                class: OperationClass::Unknown,
                source: ClassificationSource::InsufficientMetadata,
                rationale_code: RATIONALE_INSUFFICIENT_METADATA,
                required_indicators: &["idempotent_hint"],
                forbidden_indicators: &[],
            },
        },
        Case {
            label: "open_world_hint is indicator only",
            name: "catalog.search",
            description: None,
            annotations: Some(annotations(Some(true), Some(false), None, Some(true))),
            explicit_class: None,
            protocol_annotation_class: None,
            expected: Expected {
                class: OperationClass::ReadOnly,
                source: ClassificationSource::ProtocolAnnotation,
                rationale_code: RATIONALE_ANNOTATION_READ_ONLY,
                required_indicators: &["open_world_hint", "read_only_hint"],
                forbidden_indicators: &[],
            },
        },
        Case {
            label: "open_world_hint alone is unknown",
            name: "external.lookup",
            description: None,
            annotations: Some(annotations(None, None, None, Some(true))),
            explicit_class: None,
            protocol_annotation_class: None,
            expected: Expected {
                class: OperationClass::Unknown,
                source: ClassificationSource::InsufficientMetadata,
                rationale_code: RATIONALE_INSUFFICIENT_METADATA,
                required_indicators: &["open_world_hint", "name_suggests_read"],
                forbidden_indicators: &[],
            },
        },
        Case {
            label: "protocol annotation class state changing",
            name: "booking.update",
            description: None,
            annotations: None,
            explicit_class: None,
            protocol_annotation_class: Some(OperationClass::StateChanging),
            expected: Expected {
                class: OperationClass::StateChanging,
                source: ClassificationSource::ProtocolAnnotation,
                rationale_code: RATIONALE_ANNOTATION_STATE_CHANGING,
                required_indicators: &["name_suggests_write"],
                forbidden_indicators: &[],
            },
        },
    ]
}

#[test]
fn table_covers_all_classes_and_contract_edges() {
    let observed_classes: Vec<OperationClass> =
        cases().iter().map(|case| case.expected.class).collect();
    for required in [
        OperationClass::ReadOnly,
        OperationClass::StateChanging,
        OperationClass::Destructive,
        OperationClass::Unknown,
    ] {
        assert!(
            observed_classes.contains(&required),
            "table must cover {required:?}"
        );
    }

    for case in cases() {
        let result = classify_case(&case);
        assert_eq!(result.class, case.expected.class, "{}", case.label);
        assert_eq!(result.source, case.expected.source, "{}", case.label);
        assert_eq!(
            result.rationale_code, case.expected.rationale_code,
            "{}",
            case.label
        );
        assert!(
            is_sorted(&result.heuristic_indicators),
            "{} indicators must be sorted: {:?}",
            case.label,
            result.heuristic_indicators
        );
        for indicator in case.expected.required_indicators {
            assert!(
                result
                    .heuristic_indicators
                    .iter()
                    .any(|observed| observed == indicator),
                "{} missing indicator {indicator}; got {:?}",
                case.label,
                result.heuristic_indicators
            );
        }
        for indicator in case.expected.forbidden_indicators {
            assert!(
                result
                    .heuristic_indicators
                    .iter()
                    .all(|observed| observed != indicator),
                "{} must not include {indicator}; got {:?}",
                case.label,
                result.heuristic_indicators
            );
        }
    }
}

#[test]
fn name_heuristics_cannot_independently_produce_read_only() {
    for name in [
        "get_customer",
        "list_reservations",
        "fetchUser",
        "lookup.record",
    ] {
        let result = classify_tool(&ClassificationInput::new(name));
        assert_eq!(result.class, OperationClass::Unknown, "{name}");
        assert_eq!(
            result.source,
            ClassificationSource::InsufficientMetadata,
            "{name}"
        );
        assert_eq!(
            result.rationale_code, RATIONALE_INSUFFICIENT_METADATA,
            "{name}"
        );
        assert!(
            result
                .heuristic_indicators
                .iter()
                .any(|indicator| indicator == "name_suggests_read"),
            "{name} should record a non-authoritative read heuristic"
        );
    }
}

#[test]
fn shuffled_heuristic_token_order_is_deterministic() {
    let left = classify_tool(&ClassificationInput {
        name: "legacy.helper",
        description: Some("might delete or read extra notes"),
        annotations: None,
        explicit_class: None,
        protocol_annotation_class: None,
    });
    let right = classify_tool(&ClassificationInput {
        name: "legacy.helper",
        description: Some("extra notes might read or delete"),
        annotations: None,
        explicit_class: None,
        protocol_annotation_class: None,
    });

    assert_eq!(left.class, right.class);
    assert_eq!(left.source, right.source);
    assert_eq!(left.rationale_code, right.rationale_code);
    assert_eq!(left.heuristic_indicators, right.heuristic_indicators);
    assert!(is_sorted(&left.heuristic_indicators));
    assert_eq!(left.class, OperationClass::Unknown);
    assert_eq!(left.source, ClassificationSource::InsufficientMetadata);
    assert_eq!(left.rationale_code, RATIONALE_INSUFFICIENT_METADATA);
}

#[test]
fn idempotent_hint_alone_does_not_make_read_only() {
    let annotations = annotations(None, None, Some(true), None);
    let result = classify_tool(&ClassificationInput {
        name: "cache.touch",
        description: None,
        annotations: Some(&annotations),
        explicit_class: None,
        protocol_annotation_class: None,
    });
    assert_eq!(result.class, OperationClass::Unknown);
    assert_eq!(result.source, ClassificationSource::InsufficientMetadata);
    assert_eq!(result.rationale_code, RATIONALE_INSUFFICIENT_METADATA);
    assert!(result
        .heuristic_indicators
        .iter()
        .any(|indicator| indicator == "idempotent_hint"));
}

fn is_sorted(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] <= pair[1])
}
