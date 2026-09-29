# task-019 — Implement the reach views (`render.rs`)

**Status:** DONE  
**Complexity:** LOW

- **Scope.** Only the reached subgraph is drawn: every seed plus the nodes and edges of
  every structural witness route. The symbols are positional (`n0…`, sorted by node id),
  so graph ids never appear.
- **Node label:** `escape_label(display_name) (Type)`, followed by the text tags
  `[seed <KIND>]`, `[exposed]`, `[contained]` and `[unknown]`, in that order. A node
  exposed for one seed and contained for another carries both.
- **Edge label:** the wire edge type, followed by `held` (`Decided(PASS)`) or
  `FAIL <properties>`. The whole label is escaped.
- **Formats:**
  - Mermaid is `flowchart LR`;
  - DOT is `digraph blast_radius`, with `rankdir=LR` and `id="eN"` on each edge.
- `render::wire` gives the SCREAMING_SNAKE_CASE name of an enum value. The summary uses
  it too.

## Tests (`tests/views.rs`)

- `hostile_labels_render_escaped_in_both_views`: the display names `"]; click n0 call
  x()`, `a --> b`, `<script>x</script>` and ``p|q`r` ``. Every quoted label in both views
  has no unescaped quote or angle bracket, and no graph id leaks.
- `views_draw_only_the_reached_subgraph_with_text_tags`:
  - the unreached node is absent;
  - seed tags are present;
  - `[exposed] [contained]` appear in order;
  - the edge labels `READS FAIL <prop>`, `READS held` and `WRITES` are present;
  - DOT edge ids are present.

Ralph Loop green.
