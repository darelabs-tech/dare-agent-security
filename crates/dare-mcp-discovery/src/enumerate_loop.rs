//! Cursor-aware pagination loop with typed bound exhaustion.

use std::collections::BTreeSet;
use std::time::Duration;

use serde::Serialize;
use tokio::time::Instant;

use super::enumerate_error::{CollectionKind, EnumerateError};
use super::{EnumerationBounds, Page, PagingCatalog};
use crate::adapter::{PromptSnapshot, ResourceSnapshot, ResourceTemplateSnapshot, ToolSnapshot};
use crate::inventory::{DiscoveryWarning, WarningCode};
use crate::policy::PassivePolicy;

pub(crate) struct CollectionDrain<T> {
    pub items: Vec<T>,
    pub warnings: Vec<DiscoveryWarning>,
    pub invoked_methods: Vec<String>,
}

struct PageState<T> {
    items: Vec<T>,
    warnings: Vec<DiscoveryWarning>,
    invoked_methods: Vec<String>,
    cursor: Option<String>,
    used_cursors: BTreeSet<String>,
    pages: usize,
    stop: bool,
}

impl<T: Serialize> PageState<T> {
    fn new() -> Self {
        Self {
            items: Vec::new(),
            warnings: Vec::new(),
            invoked_methods: Vec::new(),
            cursor: None,
            used_cursors: BTreeSet::new(),
            pages: 0,
            stop: false,
        }
    }

    fn into_drain(self) -> CollectionDrain<T> {
        CollectionDrain {
            items: self.items,
            warnings: self.warnings,
            invoked_methods: self.invoked_methods,
        }
    }

    fn prepare(
        &mut self,
        bounds: &EnumerationBounds,
        deadline: Instant,
        collection: CollectionKind,
    ) -> Result<Duration, EnumerateError> {
        if remaining(deadline).is_none() {
            self.warnings.push(timeout_warning(collection));
            self.stop = true;
            return Ok(Duration::from_millis(1));
        }
        if let Some(current) = self.cursor.as_deref() {
            if !self.used_cursors.insert(current.to_owned()) {
                self.warnings
                    .push(malformed_warning(collection, "repeated pagination cursor"));
                self.stop = true;
            }
        }
        Ok(request_budget(bounds, deadline))
    }

    fn ingest(&mut self, bounds: &EnumerationBounds, collection: CollectionKind, page: Page<T>) {
        if page_exceeds_bytes(&page, bounds.max_response_bytes) {
            self.warnings.push(warning(
                collection,
                WarningCode::ResponseLimitReached,
                "configured response size bound",
            ));
            self.stop = true;
            return;
        }

        let remaining_items = bounds
            .max_items_per_collection
            .saturating_sub(self.items.len());
        if remaining_items == 0 {
            self.warnings.push(warning(
                collection,
                WarningCode::ItemLimitReached,
                "configured item bound",
            ));
            self.stop = true;
            return;
        }

        let take = page.items.len().min(remaining_items);
        let item_limit_hit = page.items.len() > remaining_items;
        self.items.extend(page.items.into_iter().take(take));
        self.pages += 1;

        if item_limit_hit {
            self.warnings.push(warning(
                collection,
                WarningCode::ItemLimitReached,
                "configured item bound",
            ));
            self.stop = true;
            return;
        }

        match normalize_cursor(page.next_cursor) {
            None => self.stop = true,
            Some(next) if self.cursor.as_deref() == Some(next.as_str()) => {
                self.warnings
                    .push(malformed_warning(collection, "repeated pagination cursor"));
                self.stop = true;
            }
            Some(next) if self.used_cursors.contains(&next) => {
                self.warnings
                    .push(malformed_warning(collection, "repeated pagination cursor"));
                self.stop = true;
            }
            Some(next) => {
                if self.pages >= bounds.max_pages_per_collection {
                    self.warnings.push(warning(
                        collection,
                        WarningCode::PaginationLimitReached,
                        "configured page bound",
                    ));
                    self.stop = true;
                } else {
                    self.cursor = Some(next);
                }
            }
        }
    }

    fn on_fetch_error(
        &mut self,
        collection: CollectionKind,
        err: EnumerateError,
    ) -> Result<(), EnumerateError> {
        match err {
            EnumerateError::Policy(_) | EnumerateError::InvalidBounds { .. } => Err(err),
            EnumerateError::Timeout { .. } => {
                self.warnings.push(timeout_warning(collection));
                self.stop = true;
                Ok(())
            }
            EnumerateError::ResponseLimit => {
                self.warnings.push(warning(
                    collection,
                    WarningCode::ResponseLimitReached,
                    "configured response size bound",
                ));
                self.stop = true;
                Ok(())
            }
            EnumerateError::MalformedPage { .. } | EnumerateError::Adapter(_) => {
                self.warnings
                    .push(malformed_warning(collection, "malformed catalog page"));
                self.stop = true;
                Ok(())
            }
        }
    }
}

pub(crate) async fn paginate_tools<C: PagingCatalog>(
    catalog: &mut C,
    bounds: &EnumerationBounds,
    deadline: Instant,
    policy: &impl PassivePolicy,
) -> Result<CollectionDrain<ToolSnapshot>, EnumerateError> {
    let mut state = PageState::new();
    let collection = CollectionKind::Tools;
    while !state.stop {
        let budget = state.prepare(bounds, deadline, collection)?;
        if state.stop {
            break;
        }
        policy
            .authorize(collection.method())
            .map_err(EnumerateError::from)?;
        state.invoked_methods.push(collection.method().to_owned());
        match tokio::time::timeout(budget, catalog.next_tools_page(state.cursor.as_deref())).await {
            Ok(Ok(page)) => state.ingest(bounds, collection, page),
            Ok(Err(err)) => state.on_fetch_error(collection, err)?,
            Err(_) => {
                state.warnings.push(timeout_warning(collection));
                state.stop = true;
            }
        }
    }
    Ok(state.into_drain())
}

pub(crate) async fn paginate_resources<C: PagingCatalog>(
    catalog: &mut C,
    bounds: &EnumerationBounds,
    deadline: Instant,
    policy: &impl PassivePolicy,
) -> Result<CollectionDrain<ResourceSnapshot>, EnumerateError> {
    let mut state = PageState::new();
    let collection = CollectionKind::Resources;
    while !state.stop {
        let budget = state.prepare(bounds, deadline, collection)?;
        if state.stop {
            break;
        }
        policy
            .authorize(collection.method())
            .map_err(EnumerateError::from)?;
        state.invoked_methods.push(collection.method().to_owned());
        match tokio::time::timeout(budget, catalog.next_resources_page(state.cursor.as_deref()))
            .await
        {
            Ok(Ok(page)) => state.ingest(bounds, collection, page),
            Ok(Err(err)) => state.on_fetch_error(collection, err)?,
            Err(_) => {
                state.warnings.push(timeout_warning(collection));
                state.stop = true;
            }
        }
    }
    Ok(state.into_drain())
}

pub(crate) async fn paginate_templates<C: PagingCatalog>(
    catalog: &mut C,
    bounds: &EnumerationBounds,
    deadline: Instant,
    policy: &impl PassivePolicy,
) -> Result<CollectionDrain<ResourceTemplateSnapshot>, EnumerateError> {
    let mut state = PageState::new();
    let collection = CollectionKind::ResourceTemplates;
    while !state.stop {
        let budget = state.prepare(bounds, deadline, collection)?;
        if state.stop {
            break;
        }
        policy
            .authorize(collection.method())
            .map_err(EnumerateError::from)?;
        state.invoked_methods.push(collection.method().to_owned());
        match tokio::time::timeout(
            budget,
            catalog.next_resource_templates_page(state.cursor.as_deref()),
        )
        .await
        {
            Ok(Ok(page)) => state.ingest(bounds, collection, page),
            Ok(Err(err)) => state.on_fetch_error(collection, err)?,
            Err(_) => {
                state.warnings.push(timeout_warning(collection));
                state.stop = true;
            }
        }
    }
    Ok(state.into_drain())
}

pub(crate) async fn paginate_prompts<C: PagingCatalog>(
    catalog: &mut C,
    bounds: &EnumerationBounds,
    deadline: Instant,
    policy: &impl PassivePolicy,
) -> Result<CollectionDrain<PromptSnapshot>, EnumerateError> {
    let mut state = PageState::new();
    let collection = CollectionKind::Prompts;
    while !state.stop {
        let budget = state.prepare(bounds, deadline, collection)?;
        if state.stop {
            break;
        }
        policy
            .authorize(collection.method())
            .map_err(EnumerateError::from)?;
        state.invoked_methods.push(collection.method().to_owned());
        match tokio::time::timeout(budget, catalog.next_prompts_page(state.cursor.as_deref())).await
        {
            Ok(Ok(page)) => state.ingest(bounds, collection, page),
            Ok(Err(err)) => state.on_fetch_error(collection, err)?,
            Err(_) => {
                state.warnings.push(timeout_warning(collection));
                state.stop = true;
            }
        }
    }
    Ok(state.into_drain())
}

fn page_exceeds_bytes<T: Serialize>(page: &Page<T>, max_response_bytes: usize) -> bool {
    match serde_json::to_vec(page) {
        Ok(bytes) => bytes.len() > max_response_bytes,
        Err(_) => true,
    }
}

fn normalize_cursor(cursor: Option<String>) -> Option<String> {
    cursor.filter(|value| !value.is_empty())
}

fn remaining(deadline: Instant) -> Option<Duration> {
    let now = Instant::now();
    if now >= deadline {
        None
    } else {
        Some(deadline - now)
    }
}

fn request_budget(bounds: &EnumerationBounds, deadline: Instant) -> Duration {
    match remaining(deadline) {
        Some(overall) if overall < bounds.request_timeout => overall,
        Some(_) => bounds.request_timeout,
        None => Duration::from_millis(1),
    }
}

fn warning(collection: CollectionKind, code: WarningCode, bound: &'static str) -> DiscoveryWarning {
    DiscoveryWarning {
        code,
        message: format!("{} stopped after the {bound}", collection.as_str()),
    }
}

fn timeout_warning(collection: CollectionKind) -> DiscoveryWarning {
    DiscoveryWarning {
        code: WarningCode::Timeout,
        message: format!(
            "{} stopped after a request or overall timeout",
            collection.as_str()
        ),
    }
}

fn malformed_warning(collection: CollectionKind, reason: &'static str) -> DiscoveryWarning {
    DiscoveryWarning {
        code: WarningCode::MalformedMetadata,
        message: format!("{} stopped after {reason}", collection.as_str()),
    }
}
