# task-003 — Pin the semantic conventions and write the mapping (BQ-2)

**Status:** DONE  
**Complexity:** MED

The upstream was checked on 2026-09-29, through the git proxy:
- **Tags:** `git ls-remote --tags open-telemetry/semantic-conventions` shows the latest
  release as **v1.44.0**.
- **v1.44.0 contents:** at the tag, the `CHANGELOG` (#3696) moves GenAI and MCP to
  `open-telemetry/semantic-conventions-genai`, and `model/gen-ai` and `model/mcp` hold
  only `deprecated/` files.
- **`semantic-conventions-genai`:** it has no tags. A shallow clone of `main`
  (`e57c543`, 2026-09-24) gives the attribute registry (`model/gen-ai/registry.yaml`,
  `model/mcp/registry.yaml`) and the manifest schema URL `gen-ai-dev/1.42.0-dev`.

Every key the mapping uses was grepped in those registry files:
- **GenAI:** `gen_ai.operation.name` with its values (`invoke_agent`, `execute_tool`,
  `chat`, `retrieval`, `search_memory`, …), the agent, tool, content, retrieval and
  memory keys.
- **MCP:** `mcp.method.name`, with `tools/call`.
- **Core:** `server.address`, `url.full`, `http.request.method` and
  `http.request.resend_count` (all stable in v1.44.0), plus `user.id`, `user.name`,
  `enduser.id` and `enduser.pseudo.id`.

Files:
- **`standards/runtime-telemetry/2026/semconv-mapping.json`:**
  - span kinds `AGENT_INVOKE`, `MODEL_CALL`, `TOOL_EXEC`, `RETRIEVAL`, `MEMORY`,
    `MCP_CALL` and `HTTP_CLIENT`, each with its recognition rule and required keys;
  - the content keys that T-1 checks;
  - the principal and tenant key allow-lists (AD-09);
  - notes that APPROVAL and DELEGATION come from the policy, and that `tenant.id` is not
    an OpenTelemetry convention.
- **`standards/runtime-telemetry/2026/provenance.json`:** both sources with commit, date
  and the keys taken from each.

The deviation from "one released version" is REGRESSION R-1. The loader and its tests
arrive with task-009.
