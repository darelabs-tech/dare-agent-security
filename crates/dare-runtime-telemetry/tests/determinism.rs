//! O-06 / RNF-01: the same inputs in any order give the same outputs
//! (task-025).
//!
//! File order: 10 shuffles give byte-identical artifacts. Span order inside
//! a file changes the file's bytes, and so its recorded digest and the ids
//! derived from it (REGRESSION R-8); 10 shuffles give byte-identical
//! findings and an identical result once the input binding is set aside.
use dare_runtime_telemetry::{
    corpus::{file_bytes, run_case, LabCase, LabClass, CORPUS},
    render::artifacts,
    result::Mode,
};
use serde_json::Value;

/// A small deterministic generator (no clock, no global state).
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = (self.next() % (i as u64 + 1)) as usize;
            items.swap(i, j);
        }
    }
}

fn render(case: &LabCase) -> Vec<(&'static str, Vec<u8>)> {
    let mut run = run_case(case, Mode::Replay).expect("runs");
    artifacts(&mut run, None).expect("renders")
}

/// Cases with more than one file or more than one trace, plus every other
/// non-refusal entry: the whole lab, merged into one multi-file input.
fn merged_lab() -> LabCase {
    let mut files = Vec::new();
    for entry in CORPUS.iter().filter(|e| e.class != LabClass::Refusal) {
        files.extend(entry.case().files);
    }
    // Keep within the 64-file maximum by folding files pairwise.
    while files.len() > 64 {
        let b = files.pop().expect("file");
        let a = files.pop().expect("file");
        let mut spans = a["resourceSpans"].as_array().cloned().unwrap_or_default();
        spans.extend(b["resourceSpans"].as_array().cloned().unwrap_or_default());
        files.insert(0, serde_json::json!({ "resourceSpans": spans }));
    }
    LabCase {
        files,
        policy: Some(dare_runtime_telemetry::corpus::lab_policy()),
    }
}

#[test]
fn ten_file_order_shuffles_give_byte_identical_artifacts() {
    let base = merged_lab();
    assert!(base.files.len() > 1);
    let reference = render(&base);
    let mut rng = Lcg(0x5eed_0025);
    for round in 0..10 {
        let mut shuffled = base.clone();
        rng.shuffle(&mut shuffled.files);
        let got = render(&shuffled);
        for ((name, want), (_, bytes)) in reference.iter().zip(&got) {
            assert!(want == bytes, "round {round}: {name} differs");
        }
    }
}

fn spans_of(file: &mut Value) -> Vec<&mut Vec<Value>> {
    let mut out = Vec::new();
    for rs in file["resourceSpans"].as_array_mut().into_iter().flatten() {
        for ss in rs["scopeSpans"].as_array_mut().into_iter().flatten() {
            if let Some(spans) = ss["spans"].as_array_mut() {
                out.push(spans);
            }
        }
    }
    out
}

/// The result without its input binding: file digests, and evidence ids,
/// which are digests over them.
fn unbound(result: &[u8]) -> Value {
    let mut v: Value = serde_json::from_slice(result).expect("json");
    v["inputs"]["trace_files"] = Value::Null;
    for p in v["properties"].as_array_mut().into_iter().flatten() {
        p["evidence_ids"] = Value::Null;
    }
    v
}

#[test]
fn ten_span_order_shuffles_give_the_same_findings_and_verdicts() {
    let base = merged_lab();
    let reference = render(&base);
    let mut rng = Lcg(0x0bad_5eed);
    for round in 0..10 {
        let mut shuffled = base.clone();
        for file in &mut shuffled.files {
            for spans in spans_of(file) {
                rng.shuffle(spans);
            }
        }
        rng.shuffle(&mut shuffled.files);
        // The shuffle did change the input bytes: this is not a no-op.
        let bytes = |files: &[Value]| -> std::collections::BTreeSet<Vec<u8>> {
            files.iter().map(file_bytes).collect()
        };
        assert_ne!(bytes(&base.files), bytes(&shuffled.files), "round {round}");
        let got = render(&shuffled);
        assert_eq!(
            unbound(&reference[0].1),
            unbound(&got[0].1),
            "round {round}: result"
        );
        assert!(reference[2].1 == got[2].1, "round {round}: findings differ");
    }
}
