//! Adapter tests may inspect Cycle 005 corpus; core coverage types stay independent.

use dare_coverage::{builtin_registry, map_corpus};
use dare_mcp_lab::CORPUS_SCENARIO_IDS;

#[test]
fn adapter_ids_match_lab_corpus_without_changing_coverage_semantics() {
    assert_eq!(&dare_coverage::LAB_SCENARIO_IDS[..], CORPUS_SCENARIO_IDS);
    let registry = builtin_registry().unwrap();
    let (mappings, unmapped) = map_corpus(&registry).unwrap();
    assert_eq!(mappings.len(), 10);
    assert_eq!(unmapped.len(), 4);
}
