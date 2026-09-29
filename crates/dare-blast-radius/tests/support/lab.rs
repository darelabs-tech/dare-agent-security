//! One graph that exercises every part of a document: exposed, contained and
//! cross-tenant targets, a privileged credential, a trust boundary, a failed
//! edge for the delta and a held edge for the frontier.
use dare_attack_graph::{
    v2::{AttackGraphV2, EntryClass, TargetClass},
    EdgeType, NodeSecurity, NodeType,
};

use super::{Gd, G};

pub struct Lab {
    pub graph: AttackGraphV2,
    pub user: String,
    pub doc: String,
    pub admin_key: String,
    pub vault: String,
    pub ledger: String,
    pub rows: String,
    pub fail_a: String,
    pub fail_b: String,
    pub held: String,
    /// An access under a principal no seed acquires: never continuous.
    pub foreign: String,
    pub agent: String,
}

pub fn lab() -> Lab {
    let mut g = G::new();
    let user = g.node_with(NodeType::Human, "user", G::tenant("a"));
    let agent = g.node_with(NodeType::Agent, "agent", G::tenant("a"));
    let doc = g.node(NodeType::Data, "doc");
    let admin_key = g.node_with(
        NodeType::Credential,
        "admin",
        NodeSecurity {
            privileged: true,
            ..NodeSecurity::default()
        },
    );
    let vault = g.node(NodeType::Resource, "vault");
    let ledger = g.node(NodeType::Resource, "ledger");
    let rows = g.node_with(NodeType::Data, "rows", G::tenant("b"));
    g.edge(&user, EdgeType::DelegatesTo, &agent, Gd::None);
    g.edge(&doc, EdgeType::TransfersTo, &agent, Gd::Inconclusive);
    g.edge(&agent, EdgeType::UsesCredential, &admin_key, Gd::None);
    let fail_a = g.edge(&admin_key, EdgeType::CanReach, &vault, Gd::Fail);
    let held = g.edge(&admin_key, EdgeType::CanReach, &ledger, Gd::Pass);
    let fail_b = g.edge_full(
        &agent,
        EdgeType::Reads,
        &rows,
        Gd::Fail,
        None,
        &["tenant-boundary"],
    );
    let other = g.node(NodeType::Human, "other");
    let foreign = g.edge_full(
        &agent,
        EdgeType::CanReach,
        &ledger,
        Gd::Fail,
        Some(&other),
        &[],
    );
    g.target(&vault, TargetClass::SensitiveResource);
    g.target(&ledger, TargetClass::SensitiveResource);
    g.target(&admin_key, TargetClass::PrivilegedCredential);
    g.entry(&user, EntryClass::LowPrivilegePrincipal);
    g.entry(&doc, EntryClass::RetrievedDocument);
    Lab {
        graph: g.build(),
        user,
        doc,
        admin_key,
        vault,
        ledger,
        rows,
        fail_a,
        fail_b,
        held,
        foreign,
        agent,
    }
}
