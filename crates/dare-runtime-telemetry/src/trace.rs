//! Trace reconstruction (BLUEPRINT §6.2).
//!
//! Spans are grouped by trace id and linked by parent id. Nothing about the
//! result depends on file or span order: input is sorted by
//! `(trace id, span id, file)` first, and every list below is kept sorted.
use std::collections::{BTreeMap, BTreeSet};

use crate::{limits::MAX_TREE_DEPTH, normalize::NSpan};

/// Structural defects that make every property of a trace INCONCLUSIVE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Marker {
    /// The same span id twice with different content.
    Conflict,
    /// A parent cycle.
    Malformed,
    /// Deeper than `MAX_TREE_DEPTH`.
    TooDeep,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Trace {
    pub trace_id: String,
    /// Sorted by `(start, span id)`.
    pub spans: Vec<NSpan>,
    index: BTreeMap<String, usize>,
    /// Span ids whose parent is not in the trace.
    pub orphans: BTreeSet<String>,
    /// Span ids with no parent at all.
    pub roots: BTreeSet<String>,
    pub markers: BTreeSet<Marker>,
    /// Spans that end before they start.
    pub time_inversions: usize,
}

impl Trace {
    pub fn span(&self, span_id: &str) -> Option<&NSpan> {
        self.index.get(span_id).map(|&i| &self.spans[i])
    }

    /// The parent chain of `span_id`, nearest first, stopping at a missing
    /// parent. Bounded by the trace size, so a cycle cannot loop.
    pub fn ancestors(&self, span_id: &str) -> Vec<&NSpan> {
        let mut out = Vec::new();
        let mut current = self.span(span_id).and_then(|s| s.parent.clone());
        while let Some(id) = current {
            if out.len() > self.spans.len() {
                break;
            }
            let Some(parent) = self.span(&id) else { break };
            out.push(parent);
            current = parent.parent.clone();
        }
        out
    }

    /// True when the trace has a root and no structural marker.
    pub fn structurally_sound(&self) -> bool {
        self.markers.is_empty() && !self.roots.is_empty() && self.orphans.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Forest {
    /// By trace id.
    pub traces: BTreeMap<String, Trace>,
    /// Byte-identical spans seen more than once (for example in two files).
    pub duplicates_removed: usize,
}

/// Content equality ignoring the file a span came from.
fn same_content(a: &NSpan, b: &NSpan) -> bool {
    NSpan {
        file: 0,
        ..a.clone()
    } == NSpan {
        file: 0,
        ..b.clone()
    }
}

fn build(trace_id: String, spans: Vec<NSpan>) -> Trace {
    let mut markers = BTreeSet::new();
    let mut unique: Vec<NSpan> = Vec::with_capacity(spans.len());
    for span in spans {
        match unique.last() {
            Some(last) if last.span_id == span.span_id => {
                if !same_content(last, &span) {
                    markers.insert(Marker::Conflict);
                }
            }
            _ => unique.push(span),
        }
    }
    unique.sort_by(|a, b| (a.start, &a.span_id).cmp(&(b.start, &b.span_id)));
    let index: BTreeMap<String, usize> = unique
        .iter()
        .enumerate()
        .map(|(i, s)| (s.span_id.clone(), i))
        .collect();
    let mut orphans = BTreeSet::new();
    let mut roots = BTreeSet::new();
    let mut time_inversions = 0;
    for span in &unique {
        match &span.parent {
            None => {
                roots.insert(span.span_id.clone());
            }
            Some(parent) if !index.contains_key(parent) => {
                orphans.insert(span.span_id.clone());
            }
            Some(_) => {}
        }
        if span.end < span.start {
            time_inversions += 1;
        }
    }
    // Cycles and depth: walk each span's chain once, bounded.
    for span in &unique {
        let mut seen = BTreeSet::new();
        let mut depth = 0usize;
        let mut current = span.parent.as_deref();
        while let Some(id) = current {
            if !seen.insert(id) {
                markers.insert(Marker::Malformed);
                break;
            }
            depth += 1;
            if depth > MAX_TREE_DEPTH {
                markers.insert(Marker::TooDeep);
                break;
            }
            current = index.get(id).and_then(|&i| unique[i].parent.as_deref());
        }
    }
    Trace {
        trace_id,
        spans: unique,
        index,
        orphans,
        roots,
        markers,
        time_inversions,
    }
}

/// Builds the forest. Byte-identical duplicates are dropped and counted.
pub fn reconstruct(mut spans: Vec<NSpan>) -> Forest {
    spans.sort_by(|a, b| (&a.trace_id, &a.span_id, a.file).cmp(&(&b.trace_id, &b.span_id, b.file)));
    let mut duplicates_removed = 0;
    let mut deduped: Vec<NSpan> = Vec::with_capacity(spans.len());
    for span in spans {
        if let Some(last) = deduped.last() {
            if last.trace_id == span.trace_id
                && last.span_id == span.span_id
                && same_content(last, &span)
            {
                duplicates_removed += 1;
                continue;
            }
        }
        deduped.push(span);
    }
    let mut grouped: BTreeMap<String, Vec<NSpan>> = BTreeMap::new();
    for span in deduped {
        grouped.entry(span.trace_id.clone()).or_default().push(span);
    }
    Forest {
        traces: grouped
            .into_iter()
            .map(|(id, spans)| (id.clone(), build(id, spans)))
            .collect(),
        duplicates_removed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        normalize::normalize,
        otlp::{AnyValue, KeyValue, Kind, Span},
    };

    pub(crate) fn span(
        trace: &str,
        id: &str,
        parent: Option<&str>,
        start: u64,
        file: usize,
    ) -> NSpan {
        normalize(
            &Span {
                trace_id: trace.repeat(32 / trace.len()),
                span_id: id.repeat(16 / id.len()),
                parent_span_id: parent.map(|p| p.repeat(16 / p.len())),
                flags: None,
                name: "s".into(),
                kind: Kind::Internal,
                start,
                end: start + 1,
                attributes: vec![KeyValue {
                    key: "k".into(),
                    value: AnyValue::Str(id.into()),
                }],
                dropped_attributes: 0,
                events: vec![],
                dropped_events: 0,
                links: 0,
                dropped_links: 0,
                status_code: 0,
                resource: vec![],
                resource_dropped_attributes: 0,
                scope_name: None,
            },
            file,
        )
    }

    fn id(x: &str) -> String {
        x.repeat(16 / x.len())
    }

    #[test]
    fn a_tree_links_children_and_orders_by_start_then_id() {
        let forest = reconstruct(vec![
            span("a", "c", Some("b"), 30, 0),
            span("a", "b", None, 10, 0),
            span("a", "d", Some("b"), 20, 1),
        ]);
        let t = &forest.traces[&"a".repeat(32)];
        let order: Vec<&str> = t.spans.iter().map(|s| s.span_id.as_str()).collect();
        assert_eq!(order, [id("b"), id("d"), id("c")]);
        assert!(t.structurally_sound());
        assert_eq!(t.ancestors(&id("c"))[0].span_id, id("b"));
        assert_eq!(t.roots.len(), 1);
    }

    #[test]
    fn orphans_are_found_and_the_trace_is_not_sound() {
        let t = &reconstruct(vec![
            span("a", "b", None, 1, 0),
            span("a", "c", Some("9"), 2, 0),
        ])
        .traces[&"a".repeat(32)];
        assert_eq!(t.orphans.iter().cloned().collect::<Vec<_>>(), [id("c")]);
        assert!(!t.structurally_sound());
        let no_root = &reconstruct(vec![span("a", "c", Some("9"), 2, 0)]).traces[&"a".repeat(32)];
        assert!(no_root.roots.is_empty());
    }

    #[test]
    fn identical_duplicates_across_files_are_removed_and_conflicts_are_marked() {
        let forest = reconstruct(vec![span("a", "b", None, 1, 0), span("a", "b", None, 1, 5)]);
        assert_eq!(forest.duplicates_removed, 1);
        let t = &forest.traces[&"a".repeat(32)];
        assert_eq!(t.spans.len(), 1);
        assert_eq!(t.spans[0].file, 0, "the lowest file index is kept");
        assert!(t.markers.is_empty());
        let mut changed = span("a", "b", None, 1, 1);
        changed.start = 99;
        let conflict = reconstruct(vec![span("a", "b", None, 1, 0), changed]);
        assert!(conflict.traces[&"a".repeat(32)]
            .markers
            .contains(&Marker::Conflict));
        assert_eq!(conflict.duplicates_removed, 0);
    }

    #[test]
    fn cycles_depth_and_time_inversions_are_detected() {
        let cycle = reconstruct(vec![
            span("a", "b", Some("c"), 1, 0),
            span("a", "c", Some("b"), 2, 0),
        ]);
        let t = &cycle.traces[&"a".repeat(32)];
        assert!(t.markers.contains(&Marker::Malformed));
        assert!(
            t.ancestors(&id("b")).len() <= t.spans.len() + 1,
            "bounded walk"
        );
        let mut chain = vec![span("a", "0001", None, 0, 0)];
        for i in 1..=(MAX_TREE_DEPTH + 1) {
            let mut s = span(
                "a",
                &format!("{:016x}", i + 1),
                Some(&format!("{:016x}", i)),
                i as u64,
                0,
            );
            s.span_id = format!("{:016x}", i + 1);
            s.parent = Some(format!("{:016x}", i));
            chain.push(s);
        }
        chain[0].span_id = format!("{:016x}", 1);
        let deep = reconstruct(chain);
        assert!(deep.traces[&"a".repeat(32)]
            .markers
            .contains(&Marker::TooDeep));
        let mut inverted = span("a", "b", None, 10, 0);
        inverted.end = 5;
        assert_eq!(
            reconstruct(vec![inverted]).traces[&"a".repeat(32)].time_inversions,
            1
        );
    }

    #[test]
    fn file_and_span_order_do_not_change_the_forest() {
        let spans = vec![
            span("a", "b", None, 1, 0),
            span("a", "c", Some("b"), 2, 1),
            span("f", "d", None, 3, 0),
            span("a", "c", Some("b"), 2, 2),
        ];
        let mut reversed = spans.clone();
        reversed.reverse();
        assert_eq!(reconstruct(spans), reconstruct(reversed));
    }
}
