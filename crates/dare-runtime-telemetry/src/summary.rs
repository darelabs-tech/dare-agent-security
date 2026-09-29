//! `summary.md` (task-021): counts, per-property verdicts with reasons, and
//! incomplete traces with their gaps. Every name is neutralized (bidi,
//! control, markup). There is no attribute value and no time stamp, and the
//! summary ends with what is not claimed.
use serde::Serialize;

use crate::{
    complete::Gap,
    evaluate::TraceVerdict,
    evidence_bridge::safe_key,
    result::{Run, RuntimeTelemetryResult},
};

/// Rows listed per table; the rest are counted.
pub const ROWS_PER_TABLE: usize = 50;

pub const NOT_CLAIMED: [&str; 4] = [
    "The traces are self-reported: the system under test produced them, and this tool judged only what they record.",
    "No authenticity is claimed: the exports are unsigned, and a forged or edited export cannot be told from a real one.",
    "Absence is not proof: a span, event or attribute missing from a trace is never evidence that the action did not happen.",
    "A PASS covers only the supplied traces, and only those proven complete for the property.",
];

/// Bidi and invisible formatting characters that could reorder or hide text.
fn is_bidi_or_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{061c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2069}'
            | '\u{feff}'
    )
}

/// A name as it may appear in Markdown: at most 80 characters, no control or
/// bidi character, and no markup.
pub fn neutral(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() && !is_bidi_or_invisible(*c))
        .take(80)
        .flat_map(|c| match c {
            '|' => "\\|".chars().collect::<Vec<_>>(),
            '<' => "&lt;".chars().collect(),
            '>' => "&gt;".chars().collect(),
            '&' => "&amp;".chars().collect(),
            '`' | '*' | '_' | '[' | ']' | '#' => vec!['\\', c],
            c => vec![c],
        })
        .collect()
}

/// The serde wire name of a unit enum value.
fn wire<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(s)) => s,
        _ => "?".to_owned(),
    }
}

fn gap_text(gap: &Gap) -> String {
    match gap {
        Gap::MissingKey(key) => format!("missing_key:{}", neutral(&safe_key(key))),
        other => match serde_json::to_value(other) {
            Ok(v) => v["reason"].as_str().unwrap_or("?").to_owned(),
            Err(_) => "?".to_owned(),
        },
    }
}

fn gaps_text<'a>(gaps: impl IntoIterator<Item = &'a Gap>) -> String {
    let text: Vec<String> = gaps.into_iter().map(gap_text).collect();
    if text.is_empty() {
        "-".to_owned()
    } else {
        text.join(", ")
    }
}

fn header(r: &RuntimeTelemetryResult, out: &mut String) {
    out.push_str("# DARE Runtime Telemetry\n\n");
    out.push_str(&format!(
        "Verdict: **{}** ({})\nMode: {}{}\n",
        wire(&r.verdict),
        r.reason,
        wire(&r.mode),
        if r.synthetic {
            " (synthetic traces)"
        } else {
            ""
        },
    ));
    out.push_str(&format!(
        "Semantic conventions: core {}, GenAI {}; mapping `{}`\n",
        neutral(&r.semconv.core_release),
        neutral(&r.semconv.genai_release),
        neutral(&r.semconv.mapping_digest),
    ));
    match (&r.inputs.policy_id, &r.inputs.policy_digest) {
        (Some(id), Some(digest)) => out.push_str(&format!(
            "Runtime policy: {} (`{}`)\n",
            neutral(id),
            neutral(digest)
        )),
        _ => {
            out.push_str("Runtime policy: none. The behaviour rules B-1..B-6 are not applicable.\n")
        }
    }
    let t = &r.traces;
    out.push_str(&format!(
        "Inputs: {} trace file(s), {} trace(s), {} span(s) analysed, {} duplicate span(s) removed, {} unrecognized attribute key(s)\n",
        r.inputs.trace_files.len(),
        t.count,
        t.spans,
        t.duplicates_removed,
        t.unrecognized_keys,
    ));
    out.push_str(&format!("Span bound: {}", r.max_spans));
    match r.stop_reason {
        Some(reason) => out.push_str(&format!(
            " (**reached: {reason}**; spans beyond it were not analysed)\n"
        )),
        None => out.push_str(" (not reached)\n"),
    }
}

fn spans_by_kind(r: &RuntimeTelemetryResult, out: &mut String) {
    out.push_str("\n## Spans by kind\n\n| Kind | Spans |\n|---|---|\n");
    if r.traces.spans_by_kind.is_empty() {
        out.push_str("| (none) | 0 |\n");
    }
    for (kind, n) in &r.traces.spans_by_kind {
        out.push_str(&format!("| {} | {n} |\n", wire(kind)));
    }
}

fn properties(r: &RuntimeTelemetryResult, out: &mut String) {
    out.push_str(
        "\n## Properties\n\n| Rule | Property | Verdict | Coverage | Reason | Traces failed / undecided / passed / not exercised | Gaps | Evidence |\n|---|---|---|---|---|---|---|---|\n",
    );
    for p in &r.properties {
        let t = &p.traces;
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} / {} / {} / {} | {} | {} |\n",
            p.rule.code(),
            p.property_id,
            p.verdict.map_or("-".to_owned(), |v| wire(&v)),
            wire(&p.coverage),
            p.reason,
            t.fail,
            t.inconclusive,
            t.pass,
            t.not_exercised,
            gaps_text(&p.gaps),
            if p.evidence_ids.is_empty() {
                "-".to_owned()
            } else {
                neutral(&p.evidence_ids.join(", "))
            },
        ));
    }
}

fn incomplete(r: &RuntimeTelemetryResult, out: &mut String) {
    out.push_str("\n## Incomplete traces\n\n");
    let list = &r.traces.incomplete;
    if list.is_empty() {
        out.push_str("Every trace is structurally complete.\n");
        return;
    }
    out.push_str("| Trace | Gaps |\n|---|---|\n");
    for trace in list.iter().take(ROWS_PER_TABLE) {
        out.push_str(&format!(
            "| {} | {} |\n",
            neutral(&trace.trace_id),
            gaps_text(&trace.gaps)
        ));
    }
    if list.len() > ROWS_PER_TABLE {
        out.push_str(&format!(
            "\n{} more in runtime-telemetry-result.json.\n",
            list.len() - ROWS_PER_TABLE
        ));
    }
}

fn deciding(run: &Run, out: &mut String) {
    out.push_str("\n## Failing traces\n\n");
    let failing: Vec<_> = run
        .findings
        .iter()
        .filter(|o| o.verdict == TraceVerdict::Fail)
        .collect();
    if failing.is_empty() {
        out.push_str("No trace shows a violation.\n");
        return;
    }
    out.push_str("| Rule | Trace | Reasons | Spans |\n|---|---|---|---|\n");
    for o in failing.iter().take(ROWS_PER_TABLE) {
        let mut reasons: Vec<&str> = o.violations.iter().map(|v| v.reason).collect();
        reasons.sort_unstable();
        reasons.dedup();
        let mut spans: Vec<&str> = o
            .violations
            .iter()
            .flat_map(|v| v.span_ids.iter().map(String::as_str))
            .collect();
        spans.sort_unstable();
        spans.dedup();
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            o.rule.code(),
            neutral(&o.trace_id),
            reasons.join(", "),
            spans.len()
        ));
    }
    if failing.len() > ROWS_PER_TABLE {
        out.push_str(&format!(
            "\n{} more in runtime-telemetry-findings.json.\n",
            failing.len() - ROWS_PER_TABLE
        ));
    }
}

/// The Markdown summary of a run. It is a function of the run alone.
pub fn summary(run: &Run) -> String {
    let r = &run.result;
    let mut out = String::new();
    header(r, &mut out);
    spans_by_kind(r, &mut out);
    properties(r, &mut out);
    incomplete(r, &mut out);
    deciding(run, &mut out);
    out.push_str("\n## Not claimed\n\n");
    for line in NOT_CLAIMED {
        out.push_str(&format!("- {line}\n"));
    }
    out.push_str(&format!("- {}\n", r.bounded_claim));
    out.push_str(
        "\nNo attribute value, prompt, completion or tool argument is copied into this summary: only keys, ids, rule codes and digests.\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_lose_bidi_control_and_markup() {
        let hostile = "a\u{202e}b\u{2066}c\u{0007}d\ne|f<script>`x`*y*[z](u)#h&";
        let n = neutral(hostile);
        for bad in ['\u{202e}', '\u{2066}', '\u{0007}', '\n', '<', '>'] {
            assert!(!n.contains(bad), "{bad:?} in {n}");
        }
        assert!(n.contains("\\|") && n.contains("&lt;script&gt;") && n.contains("&amp;"));
        assert!(n.contains("\\`x\\`") && n.contains("\\*y\\*") && n.contains("\\[z\\]"));
        assert_eq!(neutral(&"a".repeat(200)).len(), 80);
    }

    #[test]
    fn a_hostile_missing_key_is_written_as_a_digest() {
        let text = gap_text(&Gap::MissingKey("Bearer eyJabc".into()));
        assert!(text.starts_with("missing_key:key-"), "{text}");
        assert_eq!(gap_text(&Gap::NotSampled), "not_sampled");
    }
}
