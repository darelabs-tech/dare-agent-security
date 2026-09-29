//! OTEL-LAB (RF-11, Design §4.4, task-024).
//!
//! Every entry is judged by its class: ATTACK fails its own property and
//! cites the evidence span; CONTROL passes it; GAP leaves it INCONCLUSIVE,
//! never PASS; REFUSAL is refused. The recorded copies of the SIMULATED
//! exports replay to the same result, byte for byte apart from the mode.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use dare_runtime_telemetry::{
    corpus::{file_bytes, run_case, span_id, LabClass, CORPUS},
    evaluate::{Rule, TraceVerdict},
    limits::Bounds,
    policy::load_policy,
    result::{analyze, read_trace_paths, Mode, Run},
    semconv::Mapping,
    TelemetryError,
};
use dare_security_evidence::Verdict;

fn recorded_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/otel-lab")
}

fn verdict(run: &Run, rule: Rule) -> Option<Verdict> {
    run.result
        .properties
        .iter()
        .find(|p| p.rule == rule)
        .and_then(|p| p.verdict)
}

#[test]
fn the_lab_has_at_least_forty_uniquely_numbered_entries() {
    assert!(CORPUS.len() >= 40);
    let ids: BTreeSet<&str> = CORPUS.iter().map(|e| e.id).collect();
    assert_eq!(ids.len(), CORPUS.len());
    for (i, e) in CORPUS.iter().enumerate() {
        assert_eq!(e.id, format!("OTL-{:03}", i + 1));
        assert_eq!(
            e.evidence.is_some(),
            e.class == LabClass::Attack,
            "{}",
            e.id
        );
    }
}

#[test]
fn every_entry_meets_its_class_contract() {
    for entry in &CORPUS {
        let case = entry.case();
        let outcome = run_case(&case, Mode::Simulated);
        if entry.class == LabClass::Refusal {
            assert!(
                matches!(outcome, Err(TelemetryError::Refused(_))),
                "{}: {:?}",
                entry.id,
                outcome.map(|r| r.result.verdict)
            );
            continue;
        }
        let run = outcome.unwrap_or_else(|e| panic!("{}: {e}", entry.id));
        let got = verdict(&run, entry.rule);
        let want = match entry.class {
            LabClass::Attack => Verdict::Fail,
            LabClass::Control => Verdict::Pass,
            LabClass::Gap => Verdict::Inconclusive,
            LabClass::Refusal => unreachable!(),
        };
        assert_eq!(
            got,
            Some(want),
            "{} {} on {:?}: {:#?}",
            entry.id,
            entry.class.as_str(),
            entry.rule,
            run.result.properties.iter().find(|p| p.rule == entry.rule)
        );
        if let Some(label) = entry.evidence {
            // The FAIL cites the span the fixture names as its evidence.
            let wanted = span_id(entry.id, label);
            let cited = run.findings.iter().any(|o| {
                o.rule == entry.rule
                    && o.verdict == TraceVerdict::Fail
                    && o.violations.iter().any(|v| v.span_ids.contains(&wanted))
            });
            assert!(cited, "{}: the finding does not cite {label}", entry.id);
        }
        assert!(run.result.synthetic, "{}", entry.id);
    }
}

#[test]
fn every_attack_theme_has_a_control() {
    let themes = |class: LabClass| -> BTreeSet<&str> {
        CORPUS
            .iter()
            .filter(|e| e.class == class)
            .map(|e| e.theme)
            .collect()
    };
    let attacks = themes(LabClass::Attack);
    let controls = themes(LabClass::Control);
    assert!(
        attacks.is_subset(&controls),
        "attack themes without a control: {:?}",
        attacks.difference(&controls).collect::<Vec<_>>()
    );
}

#[test]
fn every_rule_has_an_attack_and_a_control() {
    let mut by_rule: BTreeMap<Rule, BTreeSet<LabClass>> = BTreeMap::new();
    for e in &CORPUS {
        by_rule.entry(e.rule).or_default().insert(e.class);
    }
    for rule in Rule::ALL {
        let classes = by_rule.get(&rule).cloned().unwrap_or_default();
        assert!(
            classes.contains(&LabClass::Attack) && classes.contains(&LabClass::Control),
            "{rule:?}: {classes:?}"
        );
    }
}

#[test]
fn the_design_themes_are_all_present() {
    let themes: BTreeSet<&str> = CORPUS.iter().map(|e| e.theme).collect();
    for theme in [
        // Completeness (Design §4.4): each gives INCONCLUSIVE, never PASS.
        "sampled-out",
        "dropped-attributes",
        "orphan-subtree",
        "missing-principal",
        // Confidentiality.
        "bearer-token",
        "credential-marker",
        "content-capture",
        "pii",
        // Multi-file.
        "multi-file-split",
        "multi-file-duplicate",
        // Hostile.
        "id-collision",
        "parent-cycle",
        "hostile-names",
        "doctored-export",
    ] {
        assert!(themes.contains(theme), "{theme}");
    }
}

#[test]
fn no_fixture_states_its_own_outcome() {
    for entry in &CORPUS {
        let case = entry.case();
        let mut text = serde_json::to_string(&case.files).unwrap();
        text.push_str(&serde_json::to_string(&case.policy).unwrap());
        let text = text.to_ascii_lowercase();
        for word in [
            "expected",
            "verdict",
            "outcome",
            "should",
            "attack",
            "control",
            "inconclusive",
            "\"pass",
            "\"fail",
        ] {
            assert!(!text.contains(word), "{} states {word}", entry.id);
        }
    }
}

fn recorded_files(id: &str) -> (Vec<PathBuf>, Option<PathBuf>) {
    let dir = recorded_dir().join(id);
    let mut traces: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|_| panic!("{id} has no recorded copy; run the ignored regenerate test"))
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("trace-"))
        })
        .collect();
    traces.sort();
    let policy = dir.join("policy.json");
    (traces, policy.exists().then_some(policy))
}

#[test]
fn the_recorded_copies_match_the_writer_byte_for_byte() {
    for entry in &CORPUS {
        let case = entry.case();
        let (traces, policy) = recorded_files(entry.id);
        assert_eq!(traces.len(), case.files.len(), "{}", entry.id);
        for (path, value) in traces.iter().zip(&case.files) {
            assert_eq!(
                fs::read(path).unwrap(),
                file_bytes(value),
                "{} drifted from the writer",
                path.display()
            );
        }
        match (&policy, &case.policy) {
            (Some(path), Some(value)) => {
                assert_eq!(fs::read(path).unwrap(), file_bytes(value), "{}", entry.id)
            }
            (None, None) => {}
            _ => panic!("{}: recorded policy presence differs", entry.id),
        }
    }
}

#[test]
fn every_recorded_copy_replays_to_the_simulated_result() {
    let mapping = Mapping::embedded().unwrap();
    for entry in &CORPUS {
        let (traces, policy_path) = recorded_files(entry.id);
        let replay = (|| {
            let policy = policy_path
                .as_ref()
                .map(|p| load_policy(p, &mapping))
                .transpose()?;
            let inputs = read_trace_paths(&traces)?;
            analyze(
                &inputs,
                policy.as_ref(),
                &mapping,
                Bounds::default(),
                Mode::Replay,
            )
        })();
        let simulated = run_case(&entry.case(), Mode::Simulated);
        match (replay, simulated) {
            (Ok(replay), Ok(simulated)) => {
                assert!(!replay.result.synthetic);
                let mut replay = serde_json::to_value(&replay.result).unwrap();
                let mut simulated = serde_json::to_value(&simulated.result).unwrap();
                for doc in [&mut replay, &mut simulated] {
                    doc["mode"] = serde_json::Value::Null;
                    doc["synthetic"] = serde_json::Value::Null;
                }
                assert_eq!(replay, simulated, "{}", entry.id);
            }
            (Err(TelemetryError::Refused(_)), Err(TelemetryError::Refused(_))) => {
                assert_eq!(entry.class, LabClass::Refusal, "{}", entry.id);
            }
            (r, s) => panic!(
                "{}: replay {:?} vs simulated {:?}",
                entry.id,
                r.map(|x| x.result.verdict),
                s.map(|x| x.result.verdict)
            ),
        }
    }
}

/// Rewrites the recorded copies from the writer. Run it only when the writer
/// or the corpus changes on purpose, and review the diff:
/// `cargo test -p dare-runtime-telemetry --test otel_lab -- --ignored`.
#[test]
#[ignore = "regenerates tests/fixtures/otel-lab"]
fn regenerate_recorded_copies() {
    let root = recorded_dir();
    let _ = fs::remove_dir_all(&root);
    for entry in &CORPUS {
        let case = entry.case();
        let dir = root.join(entry.id);
        fs::create_dir_all(&dir).unwrap();
        for (i, value) in case.files.iter().enumerate() {
            fs::write(dir.join(format!("trace-{i}.json")), file_bytes(value)).unwrap();
        }
        if let Some(policy) = &case.policy {
            fs::write(dir.join("policy.json"), file_bytes(policy)).unwrap();
        }
    }
}
