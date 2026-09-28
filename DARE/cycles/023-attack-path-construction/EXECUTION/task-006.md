# task-006 — Implement the v2 Mermaid and DOT renderers

**Status:** DONE  
**Complexity:** LOW

## Change

- `src/v2/render.rs`: `to_mermaid_v2` and `to_dot_v2` validate the graph first.
- Each edge label names the edge type, the evidence status and the control state as
  text, for example `Calls [Observed] {FAIL}`. Colour is not used to carry state.
- Node labels carry the node type.
- Labels are escaped with the v1 `safe_label` (quote, backslash, `<`, `>`, 80-character
  cap).
- Node symbols are positional (`n0`, `n1`, …). v1 derives symbols by filtering an id down
  to its alphanumerics, so two ids that differ only in punctuation (`a.b` and `ab`) would
  collapse into one symbol. That v1 behaviour is unchanged, because v1 output is frozen.

## Tests

- `views_label_state_in_text_and_escape_hostile_labels`: a display name
  `evil"]; click n0 --> <script>` renders as `evil\"]; click n0 --&gt; &lt;script&gt;`
  in both views, and raw `<script>` never appears. `{FAIL}`, `{UNASSESSED}`,
  `{STRUCTURAL}` and `[Observed]` all appear.
- `a_secret_like_label_is_refused_by_the_views`.

## Ralph Loop

Green: fmt, clippy `-D warnings`, `cargo test -p dare-attack-graph`.
