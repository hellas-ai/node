use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;

use crate::fetch_policy::{FetchRoute, FetchRoutePolicy};
use crate::fetch_projection::FetchProjectorFactory;
use crate::fetch_provider::FetchProvider;

/// The route table: the single source of fetch dispatch truth.
///
/// A route maps `(service, method)` — the pair a caller commits to in the
/// input transcript — to exactly one provider driver, output projector, and
/// route-wide capability policy. Providers never inspect `service`/`method`;
/// they only receive requests for the route they were registered under.
#[derive(Clone, Default)]
pub struct FetchRouteRegistry {
    routes: HashMap<FetchRoute, FetchRouteEntry>,
}

#[derive(Clone)]
pub struct FetchRouteEntry {
    pub provider: Arc<dyn FetchProvider>,
    pub projector_factory: Arc<dyn FetchProjectorFactory>,
    /// Route-wide self-protection, independent of caller: what this upstream
    /// can safely satisfy. Admission validates against the intersection of
    /// this and the caller's grant.
    pub capabilities: FetchRoutePolicy,
}

impl std::fmt::Debug for FetchRouteRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set()
            .entries(
                self.routes
                    .keys()
                    .map(|route| format!("{}/{}", route.service, route.method)),
            )
            .finish()
    }
}

impl FetchRouteRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &mut self,
        route: FetchRoute,
        entry: FetchRouteEntry,
    ) -> Result<(), DuplicateFetchRoute> {
        match self.routes.entry(route) {
            Entry::Occupied(occupied) => Err(DuplicateFetchRoute {
                service: occupied.key().service.clone(),
                method: occupied.key().method.clone(),
            }),
            Entry::Vacant(vacant) => {
                vacant.insert(entry);
                Ok(())
            }
        }
    }

    pub fn entry(&self, route: &FetchRoute) -> Option<&FetchRouteEntry> {
        self.routes.get(route)
    }

    pub fn contains(&self, route: &FetchRoute) -> bool {
        self.routes.contains_key(route)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("fetch route {service}/{method} is registered twice")]
pub struct DuplicateFetchRoute {
    pub service: String,
    pub method: String,
}
