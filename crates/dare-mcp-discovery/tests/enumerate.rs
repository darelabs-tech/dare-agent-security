//! Bounded enumeration engine: pagination, limits, and list-only methods.

use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;
use dare_mcp_discovery::{
    engine_outbound_methods, enumerate_inventory, validate, validate_instance, CollectionKind,
    Completeness, DefaultPolicy, EnumerateError, EnumerationBounds, EnumerationContext,
    EnumerationOutcome, Page, PagingCatalog, PassivePolicy, PolicyProfile, PromptSnapshot,
    ResourceSnapshot, ResourceTemplateSnapshot, TimeoutPhase, ToolSnapshot, WarningCode,
    ENGINE_LIST_METHODS,
};
use serde_json::json;
use time::macros::datetime;

const FORBIDDEN_METHODS: &[&str] = &[
    "tools/call",
    "resources/read",
    "prompts/get",
    "resources/templates/read",
    "ping",
];

struct ScriptedCatalog {
    tools: BTreeMap<Option<String>, Result<Page<ToolSnapshot>, EnumerateError>>,
    resources: BTreeMap<Option<String>, Result<Page<ResourceSnapshot>, EnumerateError>>,
    templates: BTreeMap<Option<String>, Result<Page<ResourceTemplateSnapshot>, EnumerateError>>,
    prompts: BTreeMap<Option<String>, Result<Page<PromptSnapshot>, EnumerateError>>,
    invoked: Vec<String>,
    sleep_on_tools: Option<Duration>,
}

impl ScriptedCatalog {
    fn new() -> Self {
        Self {
            tools: BTreeMap::new(),
            resources: BTreeMap::new(),
            templates: BTreeMap::new(),
            prompts: BTreeMap::new(),
            invoked: Vec::new(),
            sleep_on_tools: None,
        }
    }

    fn with_empty_sidecars(mut self) -> Self {
        self.resources.insert(None, Ok(Page::complete(Vec::new())));
        self.templates.insert(None, Ok(Page::complete(Vec::new())));
        self.prompts.insert(None, Ok(Page::complete(Vec::new())));
        self
    }

    fn tool_page(mut self, cursor: Option<&str>, page: Page<ToolSnapshot>) -> Self {
        self.tools.insert(cursor.map(ToOwned::to_owned), Ok(page));
        self
    }

    fn tool_err(mut self, cursor: Option<&str>, err: EnumerateError) -> Self {
        self.tools.insert(cursor.map(ToOwned::to_owned), Err(err));
        self
    }

    fn sleep_tools(mut self, duration: Duration) -> Self {
        self.sleep_on_tools = Some(duration);
        self
    }
}

fn tool(name: &str) -> ToolSnapshot {
    ToolSnapshot {
        name: name.to_owned(),
        title: None,
        description: None,
        input_schema: None,
        annotations: None,
    }
}

fn resource(uri: &str) -> ResourceSnapshot {
    ResourceSnapshot {
        uri: uri.to_owned(),
        name: Some(uri.to_owned()),
        description: None,
    }
}

fn template(uri_template: &str) -> ResourceTemplateSnapshot {
    ResourceTemplateSnapshot {
        uri_template: uri_template.to_owned(),
        name: None,
        description: None,
    }
}

fn prompt(name: &str) -> PromptSnapshot {
    PromptSnapshot {
        name: name.to_owned(),
        title: None,
        description: None,
    }
}

#[async_trait]
impl PagingCatalog for ScriptedCatalog {
    async fn next_tools_page(
        &mut self,
        cursor: Option<&str>,
    ) -> Result<Page<ToolSnapshot>, EnumerateError> {
        self.invoked.push("tools/list".to_owned());
        if let Some(duration) = self.sleep_on_tools {
            tokio::time::sleep(duration).await;
        }
        take_page(&mut self.tools, cursor)
    }

    async fn next_resources_page(
        &mut self,
        cursor: Option<&str>,
    ) -> Result<Page<ResourceSnapshot>, EnumerateError> {
        self.invoked.push("resources/list".to_owned());
        take_page(&mut self.resources, cursor)
    }

    async fn next_resource_templates_page(
        &mut self,
        cursor: Option<&str>,
    ) -> Result<Page<ResourceTemplateSnapshot>, EnumerateError> {
        self.invoked.push("resources/templates/list".to_owned());
        take_page(&mut self.templates, cursor)
    }

    async fn next_prompts_page(
        &mut self,
        cursor: Option<&str>,
    ) -> Result<Page<PromptSnapshot>, EnumerateError> {
        self.invoked.push("prompts/list".to_owned());
        take_page(&mut self.prompts, cursor)
    }
}

fn take_page<T>(
    pages: &mut BTreeMap<Option<String>, Result<Page<T>, EnumerateError>>,
    cursor: Option<&str>,
) -> Result<Page<T>, EnumerateError> {
    let key = cursor.map(ToOwned::to_owned);
    match pages.remove(&key) {
        Some(result) => result,
        None => Err(EnumerateError::malformed_page(CollectionKind::Tools)),
    }
}

fn bounds() -> EnumerationBounds {
    EnumerationBounds {
        max_pages_per_collection: 8,
        max_items_per_collection: 32,
        max_schema_depth: 8,
        max_response_bytes: 64 * 1024,
        request_timeout: Duration::from_secs(2),
        overall_timeout: Duration::from_secs(5),
    }
}

fn context() -> EnumerationContext {
    EnumerationContext::synthetic(datetime!(2026-08-18 19:00:00 UTC))
}

async fn run(catalog: &mut ScriptedCatalog) -> EnumerationOutcome {
    enumerate_inventory(catalog, &bounds(), context())
        .await
        .expect("enumerate")
}

fn assert_valid_inventory(outcome: &EnumerationOutcome) {
    validate(&outcome.inventory).expect("semantic");
    let value = serde_json::to_value(&outcome.inventory).expect("json");
    validate_instance(&value).expect("schema");
    assert_eq!(outcome.completeness, outcome.inventory.completeness);
}

fn assert_list_methods_only(methods: &[String]) {
    let allow = PolicyProfile::Current2026_07_28
        .allowlisted_methods()
        .to_vec();
    for method in methods {
        assert!(
            ENGINE_LIST_METHODS.contains(&method.as_str()),
            "engine requested {method} which is outside the list-method set"
        );
        assert!(
            allow.contains(&method.as_str()),
            "{method} is not on the current allowlist"
        );
        assert!(
            !FORBIDDEN_METHODS.contains(&method.as_str()),
            "engine requested forbidden method {method}"
        );
    }
}

#[tokio::test]
async fn multi_page_success_is_complete() {
    let mut catalog = ScriptedCatalog::new()
        .tool_page(
            None,
            Page::continuing(vec![tool("alpha.lookup"), tool("bravo.list")], "p2"),
        )
        .tool_page(Some("p2"), Page::complete(vec![tool("charlie.read")]))
        .with_empty_sidecars();
    catalog.resources.insert(
        None,
        Ok(Page::complete(vec![resource("synthetic://fleet")])),
    );
    catalog.templates.insert(
        None,
        Ok(Page::complete(vec![template("synthetic://vehicle/{id}")])),
    );
    catalog
        .prompts
        .insert(None, Ok(Page::complete(vec![prompt("booking-summary")])));

    let outcome = run(&mut catalog).await;
    assert_eq!(outcome.completeness, Completeness::Complete);
    assert!(outcome.inventory.warnings.is_empty());
    let names: Vec<&str> = outcome
        .inventory
        .tools
        .iter()
        .map(|tool| tool.name.as_str())
        .collect();
    assert_eq!(names, vec!["alpha.lookup", "bravo.list", "charlie.read"]);
    assert_valid_inventory(&outcome);
    assert_list_methods_only(&outcome.invoked_methods);
    assert_eq!(catalog.invoked, outcome.invoked_methods);
}

#[tokio::test]
async fn repeated_cursor_is_partial_malformed_metadata() {
    let mut catalog = ScriptedCatalog::new()
        .tool_page(None, Page::continuing(vec![tool("alpha.lookup")], "loop"))
        .tool_page(
            Some("loop"),
            Page::continuing(vec![tool("bravo.list")], "loop"),
        )
        .with_empty_sidecars();

    let outcome = run(&mut catalog).await;
    assert_eq!(outcome.completeness, Completeness::Partial);
    assert!(outcome
        .inventory
        .warnings
        .iter()
        .any(|warning| warning.code == WarningCode::MalformedMetadata));
    assert_eq!(outcome.inventory.tools.len(), 2);
    assert_valid_inventory(&outcome);
    assert_list_methods_only(&outcome.invoked_methods);
}

#[tokio::test]
async fn max_pages_bound_is_partial() {
    let mut catalog = ScriptedCatalog::new()
        .tool_page(None, Page::continuing(vec![tool("t1")], "p2"))
        .tool_page(Some("p2"), Page::continuing(vec![tool("t2")], "p3"))
        .tool_page(Some("p3"), Page::complete(vec![tool("t3")]))
        .with_empty_sidecars();
    let mut tight = bounds();
    tight.max_pages_per_collection = 1;

    let outcome = enumerate_inventory(&mut catalog, &tight, context())
        .await
        .expect("enumerate");
    assert_eq!(outcome.completeness, Completeness::Partial);
    assert!(outcome
        .inventory
        .warnings
        .iter()
        .any(|warning| warning.code == WarningCode::PaginationLimitReached));
    assert_eq!(outcome.inventory.tools.len(), 1);
    assert_valid_inventory(&outcome);
}

#[tokio::test]
async fn max_items_bound_is_partial() {
    let mut catalog = ScriptedCatalog::new()
        .tool_page(
            None,
            Page::complete(vec![tool("t1"), tool("t2"), tool("t3")]),
        )
        .with_empty_sidecars();
    let mut tight = bounds();
    tight.max_items_per_collection = 2;

    let outcome = enumerate_inventory(&mut catalog, &tight, context())
        .await
        .expect("enumerate");
    assert_eq!(outcome.completeness, Completeness::Partial);
    assert!(outcome
        .inventory
        .warnings
        .iter()
        .any(|warning| warning.code == WarningCode::ItemLimitReached));
    assert_eq!(outcome.inventory.tools.len(), 2);
    assert_valid_inventory(&outcome);
}

#[tokio::test]
async fn max_bytes_bound_is_partial() {
    let huge = ToolSnapshot {
        name: "t1".to_owned(),
        title: None,
        description: Some("x".repeat(2048)),
        input_schema: None,
        annotations: None,
    };
    let mut catalog = ScriptedCatalog::new()
        .tool_page(None, Page::complete(vec![huge]))
        .with_empty_sidecars();
    let mut tight = bounds();
    tight.max_response_bytes = 64;

    let outcome = enumerate_inventory(&mut catalog, &tight, context())
        .await
        .expect("enumerate");
    assert_eq!(outcome.completeness, Completeness::Partial);
    assert!(outcome
        .inventory
        .warnings
        .iter()
        .any(|warning| warning.code == WarningCode::ResponseLimitReached));
    assert!(outcome.inventory.tools.is_empty());
    assert_valid_inventory(&outcome);
}

#[tokio::test]
async fn timeout_from_sleeping_fake_is_partial() {
    let mut catalog = ScriptedCatalog::new()
        .tool_page(None, Page::complete(vec![tool("t1")]))
        .sleep_tools(Duration::from_millis(400))
        .with_empty_sidecars();
    let mut tight = bounds();
    tight.request_timeout = Duration::from_millis(20);
    tight.overall_timeout = Duration::from_secs(2);

    let outcome = enumerate_inventory(&mut catalog, &tight, context())
        .await
        .expect("enumerate");
    assert_eq!(outcome.completeness, Completeness::Partial);
    assert!(outcome
        .inventory
        .warnings
        .iter()
        .any(|warning| warning.code == WarningCode::Timeout));
    assert_valid_inventory(&outcome);
}

#[tokio::test]
async fn timeout_error_from_fake_is_partial() {
    let mut catalog = ScriptedCatalog::new()
        .tool_err(
            None,
            EnumerateError::Timeout {
                phase: TimeoutPhase::Request,
            },
        )
        .with_empty_sidecars();

    let outcome = run(&mut catalog).await;
    assert_eq!(outcome.completeness, Completeness::Partial);
    assert!(outcome
        .inventory
        .warnings
        .iter()
        .any(|warning| warning.code == WarningCode::Timeout));
    assert_valid_inventory(&outcome);
}

#[tokio::test]
async fn malformed_page_is_partial_and_still_valid() {
    let mut catalog = ScriptedCatalog::new()
        .tool_page(None, Page::continuing(vec![tool("kept.lookup")], "p2"))
        .tool_err(
            Some("p2"),
            EnumerateError::malformed_page(CollectionKind::Tools),
        )
        .with_empty_sidecars();

    let outcome = run(&mut catalog).await;
    assert_eq!(outcome.completeness, Completeness::Partial);
    assert!(outcome
        .inventory
        .warnings
        .iter()
        .any(|warning| warning.code == WarningCode::MalformedMetadata));
    assert_eq!(outcome.inventory.tools.len(), 1);
    assert_eq!(outcome.inventory.tools[0].name, "kept.lookup");
    assert_valid_inventory(&outcome);
}

#[tokio::test]
async fn normalize_is_deterministic_across_runs() {
    let build = || {
        ScriptedCatalog::new()
            .tool_page(
                None,
                Page::complete(vec![tool("zeta.write"), tool("alpha.lookup")]),
            )
            .with_empty_sidecars()
    };
    let mut first_catalog = build();
    let mut second_catalog = build();
    let first = run(&mut first_catalog).await;
    let second = run(&mut second_catalog).await;
    assert_eq!(first.inventory, second.inventory);
    assert_eq!(first.inventory.tools[0].name, "alpha.lookup");
    assert_valid_inventory(&first);
}

#[tokio::test]
async fn external_schema_ref_is_not_fetched_and_may_complete() {
    let schema = json!({
        "type": "object",
        "properties": {
            "vehicle": { "$ref": "https://schemas.example.test/vehicle.json" }
        }
    })
    .as_object()
    .cloned();
    let tool = ToolSnapshot {
        name: "customer.lookup".to_owned(),
        title: None,
        description: None,
        input_schema: schema,
        annotations: None,
    };
    let mut catalog = ScriptedCatalog::new()
        .tool_page(None, Page::complete(vec![tool]))
        .with_empty_sidecars();

    let outcome = run(&mut catalog).await;
    assert_eq!(outcome.completeness, Completeness::Complete);
    let captured = outcome.inventory.tools[0]
        .input_schema
        .as_ref()
        .expect("schema captured");
    assert_eq!(
        captured["properties"]["vehicle"]["$ref"],
        json!("https://schemas.example.test/vehicle.json")
    );
    assert!(outcome.inventory.tools[0].input_schema_digest.is_some());
    assert_valid_inventory(&outcome);
}

#[tokio::test]
async fn schema_depth_bound_is_partial() {
    let schema = json!({
        "a": { "b": { "c": { "d": { "type": "string" } } } }
    })
    .as_object()
    .cloned();
    let tool = ToolSnapshot {
        name: "deep.schema".to_owned(),
        title: None,
        description: None,
        input_schema: schema,
        annotations: None,
    };
    let mut catalog = ScriptedCatalog::new()
        .tool_page(None, Page::complete(vec![tool]))
        .with_empty_sidecars();
    let mut tight = bounds();
    tight.max_schema_depth = 2;

    let outcome = enumerate_inventory(&mut catalog, &tight, context())
        .await
        .expect("enumerate");
    assert_eq!(outcome.completeness, Completeness::Partial);
    assert!(outcome
        .inventory
        .warnings
        .iter()
        .any(|warning| warning.code == WarningCode::MalformedMetadata));
    assert!(outcome.inventory.tools[0].input_schema.is_none());
    assert_valid_inventory(&outcome);
}

#[test]
fn engine_methods_are_subset_of_every_allowlist() {
    for profile in [
        PolicyProfile::Current2026_07_28,
        PolicyProfile::Legacy2024_11_05,
    ] {
        let requested = engine_outbound_methods(profile);
        assert_eq!(requested, ENGINE_LIST_METHODS);
        for method in requested {
            assert!(profile.allows(method));
            assert!(!FORBIDDEN_METHODS.contains(&method));
        }
    }
}

#[test]
fn default_policy_authorizes_exactly_the_engine_list_methods() {
    let policy = DefaultPolicy::current();
    for method in ENGINE_LIST_METHODS {
        policy
            .authorize(method)
            .unwrap_or_else(|err| panic!("{method} must be allowed: {err}"));
    }
    for method in FORBIDDEN_METHODS {
        assert!(policy.authorize(method).is_err());
    }
}
