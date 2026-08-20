//! Cycle 005 tasks 004–008: corpus scenario families MCP-LAB-001..010.

use dare_mcp_lab::{
    assert_scenario_matrix, load_full_corpus, run_scenario, VariantKind, CORPUS_SCENARIO_IDS,
};
use dare_security_evidence::Verdict;

#[test]
fn full_corpus_loads_ten_scenarios() {
    let corpus = load_full_corpus().expect("load corpus");
    assert_eq!(corpus.len(), 10);
    for (idx, id) in CORPUS_SCENARIO_IDS.iter().enumerate() {
        assert_eq!(corpus[idx].id, *id);
    }
}

#[test]
fn mcp_lab_001_and_002_secure_pass_vulnerable_fail() {
    assert_scenario_matrix("MCP-LAB-001").expect("001");
    assert_scenario_matrix("MCP-LAB-002").expect("002");
}

#[test]
fn mcp_lab_003_confused_deputy_matrix() {
    assert_scenario_matrix("MCP-LAB-003").expect("003");
}

#[test]
fn mcp_lab_004_005_006_integrity_via_coaz_engine() {
    for id in ["MCP-LAB-004", "MCP-LAB-005", "MCP-LAB-006"] {
        let secure = run_scenario(id, VariantKind::Secure).expect("secure");
        assert_eq!(secure.expected_verdict, Verdict::Pass);
        assert_eq!(secure.observed_verdict, Verdict::Pass);
        assert!(secure.assertion_passed);
        assert!(secure.notes.contains("coaz-integrity:"));

        let vulnerable = run_scenario(id, VariantKind::Vulnerable).expect("vulnerable");
        assert_eq!(vulnerable.expected_verdict, Verdict::Fail);
        assert_eq!(vulnerable.observed_verdict, Verdict::Fail);
        assert!(vulnerable.assertion_passed);
        // expected FAIL + observed FAIL = scenario assertion PASS
        assert_ne!(vulnerable.observed_verdict, Verdict::Pass);
    }
}

#[test]
fn mcp_lab_007_008_009_modern_routing_auth() {
    for id in ["MCP-LAB-007", "MCP-LAB-008", "MCP-LAB-009"] {
        assert_scenario_matrix(id).unwrap_or_else(|e| panic!("{id}: {e}"));
    }
}

#[test]
fn mcp_lab_010_mrtr_matrix() {
    assert_scenario_matrix("MCP-LAB-010").expect("010");
}
