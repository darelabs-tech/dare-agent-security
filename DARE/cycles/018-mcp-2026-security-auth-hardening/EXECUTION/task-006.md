# task-006 — Authorization Server Metadata and issuer schema

**Status:** DONE - REVIEW PASS

Define local evidence for authorization-server identity, metadata issuer and issuer-binding observations. Treat discovery documents as recorded evidence only; no live AS/OIDC discovery.

## Evidence

`src/metadata.rs`. `AuthorizationServerMetadata` with issuer, endpoint identities, advertised challenge methods and trust class. `selected_metadata()` resolves the selected server to its own document; a selection nobody recorded resolves to nothing rather than to some other document.
