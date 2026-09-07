//! Composition with Cycles 002, 003 and 015.
//!
//! Cycle 018 borders three engines that already exist. It composes with them
//! rather than answering their questions a second time, and this module is
//! where that is asserted rather than assumed.
//!
//! - **Cycle 002** owns the MCP wire revision. The constants are imported, so
//!   the two crates cannot disagree about what "current" means.
//! - **Cycle 003** owns authorization-to-execution binding. Cycle 018 builds
//!   the projection and asks Cycle 003 whether the two ends are the same
//!   authorization context. It does not decide that itself.
//! - **Cycle 015** owns principal, tenant and delegation semantics. Cycle 018
//!   re-exports its principal kinds and never relabels authority.
//!
//! # What changed here, and why
//!
//! An earlier version of this module compared three fields — method, name and
//! resource — with its own string comparison, while `PROOF.md` claimed the
//! decision came from `compute_authorization_binding` and
//! `changed_operation_fields`. Neither was called.
//!
//! That gap was not cosmetic. It meant a permit issued for
//! `payments.send(amount=100)` covered `payments.send(amount=10000)`: same
//! method, same name, same resource, so the parallel comparison found nothing
//! to report. The same held for a changed principal, a changed tenant and a
//! changed scope set — every dimension where authorization actually lives
//! except the three that happened to be listed.
//!
//! `changed_operation_fields` also turned out to be the wrong function to have
//! claimed. It maps one of Cycle 003's own fixture mutation *kinds* to the
//! field names that kind touches; it is a fixture helper, not a general
//! comparison. The citation was wrong twice over.
//!
//! Now the decision is Cycle 003's: this module assembles a
//! [`BindingMaterialV1`] for each end, calls
//! [`compute_authorization_binding`], and asks [`bindings_equal`]. Cycle 018
//! contributes the projection and the *name* of whichever dimension moved, so a
//! finding can say what changed. It contributes no policy.

use serde_json::{json, Value};

use dare_coaz_integrity::binding::{
    binding_material_v1, bindings_equal, compute_authorization_binding, BindingMaterialV1,
};
use dare_coaz_integrity::canonical::CanonicalValue;
use dare_coaz_integrity::result::{AuthorizationBinding, MappingIdentity};

use crate::error::{McpAuthSecurityError, Result};
use crate::model::FinalOperationContext;

/// The authorization dimensions Cycle 018 projects into Cycle 003's binding.
///
/// Every one of these can change what a permit means while leaving the others
/// untouched, which is why the list is not "method, name, resource".
pub const AUTHORIZATION_RELEVANT_FIELDS: [&str; 6] = [
    "method",
    "name",
    "resource",
    "arguments",
    "principal",
    "tenant",
];

/// Scopes are carried in the trusted half of the projection rather than the
/// mapped half, so they are named separately when they move.
pub const TRUSTED_RELEVANT_FIELDS: [&str; 1] = ["scopes"];

/// The mapping identity Cycle 018 presents to Cycle 003.
///
/// Cycle 003's binding material is versioned by the mapping that produced it,
/// so two projections built by different mappings never compare equal by
/// accident. Cycle 018 has exactly one projection shape, declared here once.
fn mapping_identity() -> MappingIdentity {
    MappingIdentity {
        kind: "mcp-auth-security".to_owned(),
        id: "cycle-018-final-operation".to_owned(),
        revision: Some("1".to_owned()),
        // A stable digest of the projection shape below. It identifies the
        // mapping, not the values, so it is a constant rather than a hash of
        // the data.
        digest: crate::canonical::digest_bytes(
            b"cycle-018-final-operation:method,name,resource,arguments|principal,tenant,scopes",
        )
        .trim_start_matches("sha256:")
        .to_owned(),
    }
}

/// One end of the comparison, as Cycle 018 sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalOperationProjection {
    method: String,
    name: Option<String>,
    resource: Option<String>,
    arguments: Value,
    principal: Option<String>,
    tenant: Option<String>,
    scopes: Vec<String>,
}

impl FinalOperationProjection {
    /// The mapped half: what the operation is and what it operates on.
    fn mapped_inputs(&self) -> Value {
        json!({
            "resource": self.resource,
            "arguments": self.arguments,
        })
    }

    /// The trusted half: the context the decision was made in.
    ///
    /// Principal, tenant and scopes go here because they are properties of the
    /// authorization context rather than of the request payload — the same
    /// split Cycle 003 makes between mapped inputs and trusted inputs.
    fn trusted_inputs(&self) -> Value {
        let mut scopes = self.scopes.clone();
        scopes.sort();
        scopes.dedup();
        json!({
            "principal": self.principal,
            "tenant": self.tenant,
            "scopes": scopes,
        })
    }

    /// Assemble Cycle 003 binding material for this end.
    fn binding_material(&self) -> Result<BindingMaterialV1> {
        let mapped = CanonicalValue::normalize(&self.mapped_inputs())
            .map_err(|err| McpAuthSecurityError::invalid(format!("mapped inputs: {err}")))?;
        let trusted = CanonicalValue::normalize(&self.trusted_inputs())
            .map_err(|err| McpAuthSecurityError::invalid(format!("trusted inputs: {err}")))?;

        // Cycle 003 binds the authorization request digest alongside the
        // inputs. Cycle 018 records no AuthZEN request of its own, so the
        // digest is of the projection's own identity fields — enough to keep
        // two different operations from colliding, and never a claim that an
        // AuthZEN evaluation happened.
        let request_digest = crate::canonical::digest(&json!({
            "method": self.method,
            "name": self.name,
        }))?;

        Ok(binding_material_v1(
            &self.method,
            self.name.as_deref(),
            mapping_identity(),
            mapped,
            trusted,
            request_digest,
        ))
    }

    /// The Cycle 003 binding for this end.
    pub fn binding(&self) -> Result<AuthorizationBinding> {
        Ok(compute_authorization_binding(&self.binding_material()?))
    }
}

/// Project the authorized end of a final-operation context.
fn authorized(context: &FinalOperationContext) -> Option<FinalOperationProjection> {
    let operation = context.authorized_operation.as_ref()?;
    Some(FinalOperationProjection {
        method: operation.method.clone(),
        name: operation.name.clone(),
        resource: context
            .authorized_resource
            .as_ref()
            .map(ToString::to_string),
        arguments: context.authorized_arguments.clone().unwrap_or(Value::Null),
        principal: context.authorized_principal.clone(),
        tenant: context.authorized_tenant.clone(),
        scopes: context.authorized_scopes.clone(),
    })
}

/// Project the performed end of a final-operation context.
fn performed(context: &FinalOperationContext) -> Option<FinalOperationProjection> {
    let operation = context.performed_operation.as_ref()?;
    Some(FinalOperationProjection {
        method: operation.method.clone(),
        name: operation.name.clone(),
        resource: context.performed_resource.as_ref().map(ToString::to_string),
        arguments: context.performed_arguments.clone().unwrap_or(Value::Null),
        principal: context.performed_principal.clone(),
        tenant: context.performed_tenant.clone(),
        scopes: context.performed_scopes.clone(),
    })
}

/// Whether the permit and the execution are the same authorization context.
///
/// **This is Cycle 003's answer, not Cycle 018's.** The projection is built
/// here; the digest and the equality are `compute_authorization_binding` and
/// `bindings_equal`.
///
/// `None` when one end was never observed — nothing to compare, which the
/// evaluator turns into missing coverage rather than agreement.
pub fn binding_preserved(context: &FinalOperationContext) -> Result<Option<bool>> {
    let (Some(left), Some(right)) = (authorized(context), performed(context)) else {
        return Ok(None);
    };
    Ok(Some(bindings_equal(&left.binding()?, &right.binding()?)))
}

/// Which authorization-relevant dimensions moved between grant and execution.
///
/// Reported as names so a finding can say *what* changed — "the operation
/// changed" is not actionable, "the mapped arguments changed" is. The decision
/// that *something* changed is still Cycle 003's, taken by
/// [`binding_preserved`]; this only attributes it.
///
/// Attribution is done by rebuilding the authorized projection with one
/// dimension replaced by the performed value and asking Cycle 003 whether the
/// binding moved. A dimension that changes the binding is a dimension that
/// changed; nothing here re-implements what "different" means.
pub fn authorization_relevant_change(context: &FinalOperationContext) -> Vec<&'static str> {
    let (Some(base), Some(other)) = (authorized(context), performed(context)) else {
        return Vec::new();
    };

    let mut changed = Vec::new();
    for (field, mutate) in dimension_probes() {
        let mut probe = base.clone();
        mutate(&mut probe, &other);
        let moved = match (base.binding(), probe.binding()) {
            (Ok(before), Ok(after)) => !bindings_equal(&before, &after),
            // A projection that cannot be canonicalized is not evidence that
            // nothing changed. Fail closed by naming the dimension.
            _ => true,
        };
        if moved {
            changed.push(field);
        }
    }
    changed
}

/// One probe per authorization dimension.
type Probe = fn(&mut FinalOperationProjection, &FinalOperationProjection);

fn dimension_probes() -> Vec<(&'static str, Probe)> {
    vec![
        ("method", |probe, other| probe.method = other.method.clone()),
        ("name", |probe, other| probe.name = other.name.clone()),
        ("resource", |probe, other| {
            probe.resource = other.resource.clone()
        }),
        ("arguments", |probe, other| {
            probe.arguments = other.arguments.clone()
        }),
        ("principal", |probe, other| {
            probe.principal = other.principal.clone()
        }),
        ("tenant", |probe, other| probe.tenant = other.tenant.clone()),
        ("scopes", |probe, other| probe.scopes = other.scopes.clone()),
    ]
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
            authorized_operation: Some(operation("tools/call", Some("payments.send"))),
            performed_operation: Some(operation("tools/call", Some("payments.send"))),
            authorized_resource: Some(uri("mcp-payments")),
            performed_resource: Some(uri("mcp-payments")),
            authorized_arguments: Some(json!({ "amount": 100, "to": "acct-1" })),
            performed_arguments: Some(json!({ "amount": 100, "to": "acct-1" })),
            authorized_principal: Some("user-A".to_owned()),
            performed_principal: Some("user-A".to_owned()),
            authorized_tenant: Some("tenant-A".to_owned()),
            performed_tenant: Some("tenant-A".to_owned()),
            authorized_scopes: vec!["payments.send".to_owned()],
            performed_scopes: vec!["payments.send".to_owned()],
            reevaluated_after_change: false,
            refused_after_change: false,
        }
    }

    #[test]
    fn an_unchanged_operation_changes_nothing() {
        let context = binding();
        assert_eq!(binding_preserved(&context).expect("binds"), Some(true));
        assert!(authorization_relevant_change(&context).is_empty());
    }

    #[test]
    fn the_decision_comes_from_cycle_003_rather_than_a_local_comparison() {
        // The composition, checked directly: the same projection run through
        // Cycle 003's own primitives must agree with what this module reports.
        let context = binding();
        let left = authorized(&context).expect("authorized end");
        let right = performed(&context).expect("performed end");

        let from_cycle_003 = bindings_equal(
            &compute_authorization_binding(&left.binding_material().expect("material")),
            &compute_authorization_binding(&right.binding_material().expect("material")),
        );
        assert_eq!(
            binding_preserved(&context).expect("binds"),
            Some(from_cycle_003)
        );

        // And a binding is a Cycle 003 artifact, not a local string.
        assert_eq!(
            left.binding().expect("binding").algorithm,
            "coaz-binding-v1"
        );
        assert_eq!(left.binding().expect("binding").digest.len(), 64);
    }

    #[test]
    fn a_changed_method_is_authorization_relevant() {
        let mut context = binding();
        context.performed_operation = Some(operation("resources/read", Some("payments.send")));
        assert_eq!(binding_preserved(&context).expect("binds"), Some(false));
        assert!(authorization_relevant_change(&context).contains(&"method"));
    }

    #[test]
    fn a_changed_operation_name_is_authorization_relevant() {
        let mut context = binding();
        context.performed_operation = Some(operation("tools/call", Some("payments.refund")));
        assert_eq!(binding_preserved(&context).expect("binds"), Some(false));
        assert!(authorization_relevant_change(&context).contains(&"name"));
    }

    #[test]
    fn a_changed_resource_is_authorization_relevant() {
        let mut context = binding();
        context.performed_resource = Some(uri("mcp-payroll"));
        assert_eq!(binding_preserved(&context).expect("binds"), Some(false));
        assert!(authorization_relevant_change(&context).contains(&"resource"));
    }

    #[test]
    fn a_mutated_argument_is_authorization_relevant() {
        // The false PASS this rewrite closes. Same method, same name, same
        // resource; a permit for 100 does not cover 10000, and the three-field
        // comparison this module used to do saw nothing at all.
        let mut context = binding();
        context.performed_arguments = Some(json!({ "amount": 10000, "to": "acct-1" }));

        assert_eq!(
            binding_preserved(&context).expect("binds"),
            Some(false),
            "an argument mutation left the authorization binding intact"
        );
        assert!(authorization_relevant_change(&context).contains(&"arguments"));

        // And the three fields the old comparison looked at are all unchanged,
        // which is exactly why it reported nothing.
        let changed = authorization_relevant_change(&context);
        assert!(!changed.contains(&"method"));
        assert!(!changed.contains(&"name"));
        assert!(!changed.contains(&"resource"));
    }

    #[test]
    fn a_mutated_principal_is_authorization_relevant() {
        let mut context = binding();
        context.performed_principal = Some("user-B".to_owned());
        assert_eq!(binding_preserved(&context).expect("binds"), Some(false));
        assert!(authorization_relevant_change(&context).contains(&"principal"));
    }

    #[test]
    fn a_mutated_tenant_is_authorization_relevant() {
        let mut context = binding();
        context.performed_tenant = Some("tenant-B".to_owned());
        assert_eq!(binding_preserved(&context).expect("binds"), Some(false));
        assert!(authorization_relevant_change(&context).contains(&"tenant"));
    }

    #[test]
    fn a_mutated_scope_set_is_authorization_relevant() {
        let mut context = binding();
        context.performed_scopes = vec!["payments.send".to_owned(), "payments.admin".to_owned()];
        assert_eq!(binding_preserved(&context).expect("binds"), Some(false));
        assert!(authorization_relevant_change(&context).contains(&"scopes"));
    }

    #[test]
    fn a_case_changed_operation_name_is_authorization_relevant() {
        // Replaces `casing_alone_is_not_an_authorization_relevant_change`,
        // which asserted the opposite and was the same defect as F01 one layer
        // up: a permit for `payments.send` was treated as covering
        // `Payments.Send`.
        let mut context = binding();
        context.performed_operation = Some(operation("tools/call", Some("Payments.Send")));
        assert_eq!(
            binding_preserved(&context).expect("binds"),
            Some(false),
            "a case-changed operation name kept the authorization binding"
        );
        assert!(authorization_relevant_change(&context).contains(&"name"));
    }

    #[test]
    fn several_changes_are_all_reported() {
        let mut context = binding();
        context.performed_operation = Some(operation("resources/read", Some("payments.refund")));
        context.performed_resource = Some(uri("mcp-payroll"));
        context.performed_arguments = Some(json!({ "amount": 10000 }));
        context.performed_principal = Some("user-B".to_owned());
        context.performed_tenant = Some("tenant-B".to_owned());

        let changed = authorization_relevant_change(&context);
        for field in [
            "method",
            "name",
            "resource",
            "arguments",
            "principal",
            "tenant",
        ] {
            assert!(changed.contains(&field), "{field} was not reported");
        }
    }

    #[test]
    fn a_name_appearing_or_vanishing_counts_as_a_change() {
        let mut context = binding();
        context.performed_operation = Some(operation("tools/call", None));
        assert_eq!(binding_preserved(&context).expect("binds"), Some(false));
        assert!(authorization_relevant_change(&context).contains(&"name"));
    }

    #[test]
    fn key_order_in_arguments_is_not_a_change() {
        // Cycle 003's canonicalizer decides this, and it should: JSON object
        // key order carries no meaning, and an engine that reported it would
        // train its readers to ignore argument findings.
        let mut context = binding();
        context.performed_arguments = Some(json!({ "to": "acct-1", "amount": 100 }));
        assert_eq!(binding_preserved(&context).expect("binds"), Some(true));
        assert!(authorization_relevant_change(&context).is_empty());
    }

    #[test]
    fn one_end_unobserved_answers_nothing() {
        let mut context = binding();
        context.performed_operation = None;
        assert_eq!(binding_preserved(&context).expect("binds"), None);
        assert!(authorization_relevant_change(&context).is_empty());
    }

    #[test]
    fn the_revision_constants_are_cycle_002s() {
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
        // Cycle 003 keeps its own names. Cycle 018 must not shadow one and
        // quietly mean something else by it.
        for invariant in McpAuthInvariantType::all() {
            assert!(
                !invariant.as_str().starts_with("COAZ_"),
                "{} borrows Cycle 003's namespace",
                invariant.as_str()
            );
        }
    }

    #[test]
    fn the_memory_separation_rule_is_stated_where_it_is_tested() {
        assert!(AUTH_EVIDENCE_IS_NOT_MEMORY.contains("not a memory"));
    }
}
