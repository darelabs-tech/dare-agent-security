//! Remote projector (Cycle 022, BLUEPRINT §6.9).
//!
//! Each run is projected by its owning engine's projector in result-only
//! mode. The guards come from `remote-evidence.json`, whose records carry
//! the verdict after the transport overlay; a run's verdict can only be
//! lowered by that overlay, never raised.
use crate::{
    bundle::{LoadedBundle, RemoteEngineResult, RemoteRun},
    facts::FactSink,
    guard_table::RunVerdicts,
};

pub fn project(
    bundle: &LoadedBundle,
    runs: &[RemoteRun],
    verdicts: &mut RunVerdicts,
    sink: &mut FactSink,
) {
    for run in runs {
        match &run.engine_result {
            None => sink.unprojected("RemoteRun::no_engine_result"),
            Some(RemoteEngineResult::A2a(result)) => {
                super::a2a::project(bundle, result, None, verdicts, sink)
            }
            Some(RemoteEngineResult::PromptInjection(result)) => {
                super::prompt_injection::project(bundle, result, verdicts, sink)
            }
            Some(RemoteEngineResult::McpAuth(result)) => {
                super::mcp_auth::project(bundle, result, run.mcp_scenario.as_ref(), verdicts, sink)
            }
            Some(RemoteEngineResult::MultiTurn(result)) => {
                super::multi_turn::project(bundle, result, None, verdicts, sink)
            }
        }
    }
}
