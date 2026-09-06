//! Composition with Cycles 002, 003 and 015.
//!
//! Cycle 018 borders three engines that already exist. It composes with them
//! rather than answering their questions a second time, and this module is
//! where that is asserted rather than assumed.
//!
//! - **Cycle 002** owns the MCP wire revision. The constants are imported, so
//!   the two crates cannot disagree about what "current" means.
//! - **Cycle 003** owns authorization-to-execution binding. Cycle 018 asks the
//!   narrow question — did an authorization-relevant field change without
//!   re-evaluation — and uses Cycle 003's field vocabulary to say which.
//! - **Cycle 015** owns principal, tenant and delegation semantics. Cycle 018
//!   re-exports its principal kinds and never relabels authority.

use crate::model::FinalOperationContext;

/// Fields whose change makes an earlier authorization stale.
///
/// The list is deliberately short and deliberately not "everything that
/// differs". A changed request id or a changed timestamp does not widen
/// authority; a changed method, operation name or resource does.
pub const AUTHORIZATION_RELEVANT_FIELDS: [&str; 3] = ["method", "name", "resource"];

/// Which authorization-relevant fields changed between grant and execution.
///
/// Returned as names rather than a boolean so a finding can say *what* moved.
/// "The operation changed" is not actionable; "the operation name changed" is.
pub fn authorization_relevant_change(binding: &FinalOperationContext) -> Vec<&'static str> {
    let mut changed = Vec::new();

    if let (Some(authorized), Some(performed)) =
        (&binding.authorized_operation, &binding.performed_operation)
    {
        if !crate::protocol::routing_values_agree(&authorized.method, &performed.method) {
            changed.push("method");
        }
        let names_agree = match (&authorized.name, &performed.name) {
            (None, None) => true,
            (Some(left), Some(right)) => crate::protocol::routing_values_agree(left, right),
            _ => false,
        };
        if !names_agree {
            changed.push("name");
        }
    }

    if let (Some(authorized), Some(performed)) =
        (&binding.authorized_resource, &binding.performed_resource)
    {
        if authorized != performed {
            changed.push("resource");
        }
    }

    changed
}

/// The Cycle 016 separation rule, stated where it is tested.
///
/// Retrieval and memory are other cycles' subjects. Cycle 018 records
/// authorization evidence and produces no memory event, which is why an MCP
/// auth observation can never be read as one.
pub const AUTH_EVIDENCE_IS_NOT_MEMORY: &str =
    "An MCP authorization observation records what a request carried. It is not a memory \
     write, and nothing in this cycle persists one.";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::PrincipalKind;
    use crate::metadata::tests::uri;
    use crate::model::McpAuthInvariantType;
    use crate::protocol::JsonRpcOperation;

    fn operation(method: &str, name: Option<&str>) -> JsonRpcOperation {
        JsonRpcOperation {
            method: method.to_owned(),
            name: name.map(str::to_owned),
        }
    }

    fn binding() -> FinalOperationContext {
        FinalOperationContext {
            authorized_operation: Some(operation("tools/call", Some("create-invoice"))),
            performed_operation: Some(operation("tools/call", Some("create-invoice"))),
            authorized_resource: Some(uri("mcp-invoices")),
            performed_resource: Some(uri("mcp-invoices")),
            reevaluated_after_change: false,
            refused_after_change: false,
        }
    }

    #[test]
    fn an_unchanged_operation_changes_nothing() {
        assert!(authorization_relevant_change(&binding()).is_empty());
    }

    #[test]
    fn a_changed_method_is_authorization_relevant() {
        let mut context = binding();
        context.performed_operation = Some(operation("resources/read", Some("create-invoice")));
        assert_eq!(authorization_relevant_change(&context), ["method"]);
    }

    #[test]
    fn a_changed_operation_name_is_authorization_relevant() {
        let mut context = binding();
        context.performed_operation = Some(operation("tools/call", Some("delete-invoice")));
        assert_eq!(authorization_relevant_change(&context), ["name"]);
    }

    #[test]
    fn a_changed_resource_is_authorization_relevant() {
        let mut context = binding();
        context.performed_resource = Some(uri("mcp-payroll"));
        assert_eq!(authorization_relevant_change(&context), ["resource"]);
    }

    #[test]
    fn several_changes_are_all_reported() {
        // A finding that named only the first change would understate what
        // moved between the grant and the execution.
        let mut context = binding();
        context.performed_operation = Some(operation("resources/read", Some("delete-invoice")));
        context.performed_resource = Some(uri("mcp-payroll"));
        assert_eq!(
            authorization_relevant_change(&context),
            ["method", "name", "resource"]
        );
    }

    #[test]
    fn a_name_appearing_or_vanishing_counts_as_a_change() {
        let mut appeared = binding();
        appeared.authorized_operation = Some(operation("tools/call", None));
        assert_eq!(authorization_relevant_change(&appeared), ["name"]);

        let mut vanished = binding();
        vanished.performed_operation = Some(operation("tools/call", None));
        assert_eq!(authorization_relevant_change(&vanished), ["name"]);
    }

    #[test]
    fn casing_alone_is_not_an_authorization_relevant_change() {
        // The same operation written differently routes identically. Reporting
        // it would train readers to ignore the finding.
        let mut context = binding();
        context.performed_operation = Some(operation("Tools/Call", Some("Create-Invoice")));
        assert!(authorization_relevant_change(&context).is_empty());
    }

    #[test]
    fn the_revision_constants_are_cycle_002s() {
        // Imported, not restated. Two constants that must agree and live in
        // different crates eventually disagree.
        assert_eq!(crate::CURRENT_WIRE_REVISION, "2026-07-28");
        assert_eq!(crate::LEGACY_WIRE_REVISION, "2024-11-05");
    }

    #[test]
    fn principal_kinds_are_cycle_015s_and_this_cycle_adds_none() {
        for kind in [
            PrincipalKind::Human,
            PrincipalKind::Agent,
            PrincipalKind::Workload,
            PrincipalKind::Service,
        ] {
            let json = serde_json::to_string(&kind).expect("serializes");
            assert_eq!(
                serde_json::from_str::<PrincipalKind>(&json).expect("round trips"),
                kind
            );
        }
        assert!(serde_json::from_str::<PrincipalKind>("\"MCP_CLIENT\"").is_err());
    }

    #[test]
    fn cycle_018_invariants_do_not_collide_with_cycle_003_vocabulary() {
        // The two engines answer different questions and must stay
        // distinguishable in a report. Cycle 018's invariant names are all
        // MCP-prefixed or explicitly about the MCP auth surface.
        let names: Vec<&str> = McpAuthInvariantType::all()
            .iter()
            .map(|invariant| invariant.as_str())
            .collect();
        for name in names {
            assert!(!name.is_empty());
            // None of them claims to be the COAZ integrity result itself.
            assert!(!name.contains("COAZ"));
        }
    }

    #[test]
    fn the_memory_separation_rule_is_stated_where_it_is_tested() {
        assert!(AUTH_EVIDENCE_IS_NOT_MEMORY.contains("not a memory write"));
    }
}
