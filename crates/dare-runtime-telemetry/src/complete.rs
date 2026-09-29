//! Completeness (BLUEPRINT §6.3, DESIGN RS-06).
//!
//! A property may PASS on a trace only when nothing about the trace could be
//! hiding the violation it looks for. [`gaps`] lists every reason, from a
//! closed set, why that cannot be shown. An empty set is the only way to a
//! PASS; a FAIL, by contrast, needs no completeness: a violation seen is real.
use std::collections::BTreeSet;

use serde::Serialize;

use crate::{
    normalize::NSpan,
    semconv::{Mapping, SpanKind},
    trace::{Marker, Trace},
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case", tag = "reason", content = "key")]
pub enum Gap {
    Orphan,
    Conflict,
    Malformed,
    TooDeep,
    MissingRoot,
    TimeInversion,
    DroppedAttributes,
    DroppedEvents,
    DroppedLinks,
    NotSampled,
    /// No span of a kind the property needs appears at all.
    NoObservation,
    /// A span the property reads lacks this key (or every key of a one-of).
    MissingKey(String),
    /// The run stopped at the span bound before this trace was complete.
    SpanBound,
    /// A value longer than the scan bound was fingerprinted, not scanned.
    OversizeValue,
}

/// A key need: all of them, or at least one of a set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyNeed {
    Key(String),
    AnyOf(Vec<String>),
}

/// What one property reads from a trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    /// Span kinds the property reads (and whose defects can hide a violation).
    pub kinds: Vec<SpanKind>,
    /// Kinds that must appear at least once for a positive observation.
    pub observed: Vec<SpanKind>,
    /// Keys every span of `kinds` must carry.
    pub keys: Vec<(SpanKind, KeyNeed)>,
}

/// A trace with each span's kind.
#[derive(Debug, Clone)]
pub struct View<'t> {
    pub trace: &'t Trace,
    pub kinds: Vec<SpanKind>,
}

impl<'t> View<'t> {
    pub fn new(trace: &'t Trace, mapping: &Mapping) -> Self {
        Self {
            trace,
            kinds: trace.spans.iter().map(|s| mapping.classify(s)).collect(),
        }
    }

    pub fn spans(&self) -> impl Iterator<Item = (&'t NSpan, SpanKind)> + '_ {
        self.trace.spans.iter().zip(self.kinds.iter().copied())
    }

    pub fn of(&self, kind: SpanKind) -> impl Iterator<Item = &'t NSpan> + '_ {
        self.spans()
            .filter(move |(_, k)| *k == kind)
            .map(|(s, _)| s)
    }

    pub fn kind_of(&self, span_id: &str) -> Option<SpanKind> {
        self.trace
            .spans
            .iter()
            .position(|s| s.span_id == span_id)
            .map(|i| self.kinds[i])
    }

    /// The nearest ancestor of `kind`, or `None`.
    pub fn nearest(&self, span_id: &str, kind: SpanKind) -> Option<&'t NSpan> {
        self.trace
            .ancestors(span_id)
            .into_iter()
            .find(|a| self.kind_of(&a.span_id) == Some(kind))
    }
}

fn has(span: &NSpan, need: &KeyNeed) -> Result<(), String> {
    match need {
        KeyNeed::Key(key) => span.attr(key).map(|_| ()).ok_or_else(|| key.clone()),
        KeyNeed::AnyOf(keys) => {
            if keys.iter().any(|k| span.attr(k).is_some()) {
                Ok(())
            } else {
                Err(keys.join("|"))
            }
        }
    }
}

/// Every reason `requirement` cannot be shown complete on this trace.
pub fn gaps(view: &View<'_>, requirement: &Requirement, stopped: bool) -> BTreeSet<Gap> {
    let mut out = BTreeSet::new();
    let trace = view.trace;
    for marker in &trace.markers {
        out.insert(match marker {
            Marker::Conflict => Gap::Conflict,
            Marker::Malformed => Gap::Malformed,
            Marker::TooDeep => Gap::TooDeep,
        });
    }
    if !trace.orphans.is_empty() {
        out.insert(Gap::Orphan);
    }
    if trace.roots.is_empty() {
        out.insert(Gap::MissingRoot);
    }
    if trace.time_inversions > 0 {
        out.insert(Gap::TimeInversion);
    }
    if stopped {
        out.insert(Gap::SpanBound);
    }
    // The sampled flag, where recorded, must be set on every span of the trace:
    // an unsampled span anywhere means siblings may be missing.
    if trace.spans.iter().any(|s| s.sampled() == Some(false)) {
        out.insert(Gap::NotSampled);
    }
    for (span, kind) in view.spans() {
        if !requirement.kinds.contains(&kind) {
            continue;
        }
        if span.dropped_attributes > 0 || span.dropped_resource_attributes > 0 {
            out.insert(Gap::DroppedAttributes);
        }
        if span.dropped_events > 0 || span.events.iter().any(|e| e.dropped_attributes > 0) {
            out.insert(Gap::DroppedEvents);
        }
        if span.dropped_links > 0 {
            out.insert(Gap::DroppedLinks);
        }
        for (need_kind, need) in &requirement.keys {
            if *need_kind == kind {
                if let Err(key) = has(span, need) {
                    out.insert(Gap::MissingKey(key));
                }
            }
        }
    }
    if requirement.observed.iter().any(|k| !view.kinds.contains(k)) {
        out.insert(Gap::NoObservation);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        normalize::normalize,
        otlp::{AnyValue, KeyValue, Kind, Span},
        trace::reconstruct,
    };

    const TRACE: &str = "5b8efff798038103d269b633813fc60c";

    fn raw(id: &str, parent: Option<&str>, attrs: &[(&str, &str)]) -> Span {
        Span {
            trace_id: TRACE.into(),
            span_id: id.repeat(16 / id.len()),
            parent_span_id: parent.map(|p| p.repeat(16 / p.len())),
            flags: Some(1),
            name: "s".into(),
            kind: Kind::Internal,
            start: 1,
            end: 2,
            attributes: attrs
                .iter()
                .map(|(k, v)| KeyValue {
                    key: (*k).into(),
                    value: AnyValue::Str((*v).into()),
                })
                .collect(),
            dropped_attributes: 0,
            events: vec![],
            dropped_events: 0,
            links: 0,
            dropped_links: 0,
            status_code: 0,
            resource: vec![],
            resource_dropped_attributes: 0,
            scope_name: None,
        }
    }

    fn tool_requirement() -> Requirement {
        Requirement {
            kinds: vec![SpanKind::AgentInvoke, SpanKind::ToolExec],
            observed: vec![SpanKind::ToolExec],
            keys: vec![
                (SpanKind::ToolExec, KeyNeed::Key("gen_ai.tool.name".into())),
                (
                    SpanKind::AgentInvoke,
                    KeyNeed::Key("gen_ai.agent.name".into()),
                ),
            ],
        }
    }

    fn agent() -> Span {
        raw(
            "a",
            None,
            &[
                ("gen_ai.operation.name", "invoke_agent"),
                ("gen_ai.agent.name", "assistant"),
            ],
        )
    }

    fn tool() -> Span {
        raw(
            "b",
            Some("a"),
            &[
                ("gen_ai.operation.name", "execute_tool"),
                ("gen_ai.tool.name", "search"),
            ],
        )
    }

    fn gaps_of(spans: Vec<Span>, requirement: &Requirement, stopped: bool) -> BTreeSet<Gap> {
        let mapping = Mapping::embedded().unwrap();
        let forest = reconstruct(spans.iter().map(|s| normalize(s, 0)).collect());
        let trace = &forest.traces[TRACE];
        gaps(&View::new(trace, &mapping), requirement, stopped)
    }

    #[test]
    fn a_complete_trace_has_no_gap() {
        assert!(gaps_of(vec![agent(), tool()], &tool_requirement(), false).is_empty());
    }

    #[test]
    fn every_gap_reason_is_found() {
        let r = tool_requirement();
        let one = |spans: Vec<Span>| gaps_of(spans, &r, false);
        assert!(one(vec![tool()]).contains(&Gap::Orphan));
        assert!(one(vec![tool()]).contains(&Gap::MissingRoot));
        let mut dropped = tool();
        dropped.dropped_attributes = 1;
        assert_eq!(
            one(vec![agent(), dropped]),
            BTreeSet::from([Gap::DroppedAttributes])
        );
        let mut resource_dropped = agent();
        resource_dropped.resource_dropped_attributes = 2;
        assert_eq!(
            one(vec![resource_dropped, tool()]),
            BTreeSet::from([Gap::DroppedAttributes])
        );
        let mut events = tool();
        events.dropped_events = 1;
        assert_eq!(
            one(vec![agent(), events]),
            BTreeSet::from([Gap::DroppedEvents])
        );
        let mut links = tool();
        links.dropped_links = 1;
        assert_eq!(
            one(vec![agent(), links]),
            BTreeSet::from([Gap::DroppedLinks])
        );
        let mut unsampled = agent();
        unsampled.flags = Some(0);
        assert_eq!(
            one(vec![unsampled, tool()]),
            BTreeSet::from([Gap::NotSampled])
        );
        let nameless = raw("b", Some("a"), &[("gen_ai.operation.name", "execute_tool")]);
        assert_eq!(
            one(vec![agent(), nameless]),
            BTreeSet::from([Gap::MissingKey("gen_ai.tool.name".into())])
        );
        assert_eq!(one(vec![agent()]), BTreeSet::from([Gap::NoObservation]));
        let mut inverted = tool();
        inverted.end = 0;
        assert_eq!(
            one(vec![agent(), inverted]),
            BTreeSet::from([Gap::TimeInversion])
        );
        assert!(gaps_of(vec![agent(), tool()], &r, true).contains(&Gap::SpanBound));
        let mut conflicting = tool();
        conflicting.start = 9;
        assert!(one(vec![agent(), tool(), conflicting]).contains(&Gap::Conflict));
        let cycle = vec![
            raw(
                "a",
                Some("b"),
                &[
                    ("gen_ai.operation.name", "invoke_agent"),
                    ("gen_ai.agent.name", "x"),
                ],
            ),
            raw(
                "b",
                Some("a"),
                &[
                    ("gen_ai.operation.name", "execute_tool"),
                    ("gen_ai.tool.name", "t"),
                ],
            ),
        ];
        assert!(one(cycle).contains(&Gap::Malformed));
    }

    #[test]
    fn a_one_of_key_need_is_met_by_any_member() {
        let r = Requirement {
            kinds: vec![SpanKind::HttpClient],
            observed: vec![],
            keys: vec![(
                SpanKind::HttpClient,
                KeyNeed::AnyOf(vec!["server.address".into(), "url.full".into()]),
            )],
        };
        let mut client = raw(
            "c",
            None,
            &[("http.request.method", "GET"), ("url.full", "u")],
        );
        client.kind = Kind::Client;
        assert!(gaps_of(vec![client.clone()], &r, false).is_empty());
        client.attributes.pop();
        assert_eq!(
            gaps_of(vec![client], &r, false),
            BTreeSet::from([Gap::MissingKey("server.address|url.full".into())])
        );
    }

    #[test]
    fn defects_on_spans_the_property_does_not_read_do_not_count() {
        let r = Requirement {
            kinds: vec![SpanKind::ToolExec],
            observed: vec![SpanKind::ToolExec],
            keys: vec![],
        };
        let mut agent = agent();
        agent.dropped_attributes = 3;
        assert!(gaps_of(vec![agent, tool()], &r, false).is_empty());
    }
}
