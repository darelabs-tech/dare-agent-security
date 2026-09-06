# task-005 — Protected Resource Metadata schema

**Status:** DONE - REVIEW PASS

Define local synthetic evidence for MCP Protected Resource Metadata, including protected-resource identity and allowed authorization-server relationships. No metadata URL is fetched by this cycle.

## Evidence

`src/metadata.rs`. `ProtectedResourceMetadata` carries the resource it describes, the authorization servers it advertises and its own trust class. Metadata is evidence about a resource, never trust in it, so `ResourceContext` keeps the expected resource separate and the binding is a comparison rather than an assumption. No URL is expressible.
