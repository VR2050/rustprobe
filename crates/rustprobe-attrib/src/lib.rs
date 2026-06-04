use anyhow::Result;
use rustprobe_core::{AppEvent, AppIdentity, AppSelectionMode, FlowKey, FlowOwnerQuery, FlowState};
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Mutex, OnceLock};

static ATTRIBUTION_RUNTIME: OnceLock<Mutex<AttributionActor>> = OnceLock::new();

#[derive(Debug, Clone, Serialize)]
pub struct AttributionStats {
    pub tracked_apps: usize,
    pub cached_flow_owners: usize,
    pub pending_owner_queries: usize,
    pub total_owner_queries_enqueued: u64,
    pub total_owner_queries_drained: u64,
    pub total_owner_queries_skipped: u64,
    pub total_owner_resolutions: u64,
}

#[derive(Debug)]
pub struct AttributionActor {
    selection_mode: AppSelectionMode,
    package_catalog: HashMap<String, AppIdentity>,
    uid_catalog: HashMap<u32, AppIdentity>,
    flow_owner_cache: HashMap<FlowKey, u32>,
    pending_owner_queries: VecDeque<FlowOwnerQuery>,
    pending_owner_keys: HashSet<FlowKey>,
    total_owner_queries_enqueued: u64,
    total_owner_queries_drained: u64,
    total_owner_queries_skipped: u64,
    total_owner_resolutions: u64,
}

impl Default for AttributionActor {
    fn default() -> Self {
        Self {
            selection_mode: AppSelectionMode::Global,
            package_catalog: HashMap::new(),
            uid_catalog: HashMap::new(),
            flow_owner_cache: HashMap::new(),
            pending_owner_queries: VecDeque::new(),
            pending_owner_keys: HashSet::new(),
            total_owner_queries_enqueued: 0,
            total_owner_queries_drained: 0,
            total_owner_queries_skipped: 0,
            total_owner_resolutions: 0,
        }
    }
}

impl AttributionActor {
    pub fn upsert_app(&mut self, app: AppIdentity) {
        self.package_catalog
            .insert(app.package_name.clone(), app.clone());
        self.uid_catalog.insert(app.uid, app);
    }

    pub fn register_apps(&mut self, apps: impl IntoIterator<Item = AppIdentity>) {
        self.package_catalog.clear();
        self.uid_catalog.clear();

        for app in apps {
            self.upsert_app(app);
        }
    }

    pub fn set_selection_mode(&mut self, selection_mode: AppSelectionMode) {
        self.selection_mode = selection_mode;
    }

    pub fn attribute_flow(&self, flow: &FlowState, owning_uid: Option<u32>) -> Option<AppIdentity> {
        let cached_uid = self.flow_owner_cache.get(&flow.key).copied();
        let app = cached_uid
            .or(owning_uid)
            .and_then(|uid| self.uid_catalog.get(&uid).cloned())
            .or_else(|| self.fallback_selected_app());

        if self.selection_mode.matches(app.as_ref()) {
            app
        } else {
            None
        }
    }

    pub fn should_track(&self, app: Option<&AppIdentity>) -> bool {
        self.selection_mode.matches(app)
    }

    pub fn register_flow_owner(&mut self, key: FlowKey, uid: u32) {
        self.pending_owner_keys.remove(&key);
        self.flow_owner_cache.insert(key, uid);
        self.total_owner_resolutions += 1;
    }

    pub fn queue_owner_query(&mut self, key: FlowKey) -> bool {
        if self.flow_owner_cache.contains_key(&key) || self.pending_owner_keys.contains(&key) {
            self.total_owner_queries_skipped += 1;
            return false;
        }

        self.pending_owner_keys.insert(key.clone());
        self.pending_owner_queries.push_back(FlowOwnerQuery { key });
        self.total_owner_queries_enqueued += 1;
        true
    }

    pub fn take_pending_owner_queries(&mut self, limit: usize) -> Vec<FlowOwnerQuery> {
        let mut output = Vec::with_capacity(limit);
        for _ in 0..limit {
            match self.pending_owner_queries.pop_front() {
                Some(query) => output.push(query),
                None => break,
            }
        }
        self.total_owner_queries_drained += output.len() as u64;
        output
    }

    pub fn stats(&self) -> AttributionStats {
        AttributionStats {
            tracked_apps: self.uid_catalog.len(),
            cached_flow_owners: self.flow_owner_cache.len(),
            pending_owner_queries: self.pending_owner_queries.len(),
            total_owner_queries_enqueued: self.total_owner_queries_enqueued,
            total_owner_queries_drained: self.total_owner_queries_drained,
            total_owner_queries_skipped: self.total_owner_queries_skipped,
            total_owner_resolutions: self.total_owner_resolutions,
        }
    }

    pub fn attribute(&self, flow: &FlowState) -> AppEvent {
        let app = flow.app.clone().unwrap_or(AppIdentity {
            uid: 10_001,
            package_name: "com.example.target".into(),
            app_label: "Example Target".into(),
        });

        AppEvent {
            app,
            flow_id: format!(
                "{}:{}-{}:{}-{:?}",
                flow.key.src_addr,
                flow.key.src_port,
                flow.key.dst_addr,
                flow.key.dst_port,
                flow.key.protocol
            ),
        }
    }

    fn fallback_selected_app(&self) -> Option<AppIdentity> {
        match &self.selection_mode {
            AppSelectionMode::Single(package_name) => {
                self.package_catalog.get(package_name).cloned()
            }
            _ => None,
        }
    }
}

fn runtime() -> &'static Mutex<AttributionActor> {
    ATTRIBUTION_RUNTIME.get_or_init(|| Mutex::new(AttributionActor::default()))
}

pub fn sync_installed_apps(apps: Vec<AppIdentity>) -> Result<()> {
    let mut actor = runtime()
        .lock()
        .map_err(|_| anyhow::anyhow!("attribution runtime poisoned"))?;
    actor.register_apps(apps);
    Ok(())
}

pub fn upsert_app_runtime(app: AppIdentity) -> Result<()> {
    let mut actor = runtime()
        .lock()
        .map_err(|_| anyhow::anyhow!("attribution runtime poisoned"))?;
    actor.upsert_app(app);
    Ok(())
}

pub fn set_monitoring_selection(selection_mode: AppSelectionMode) -> Result<()> {
    let mut actor = runtime()
        .lock()
        .map_err(|_| anyhow::anyhow!("attribution runtime poisoned"))?;
    actor.set_selection_mode(selection_mode);
    Ok(())
}

pub fn attribute_flow_runtime(flow: &FlowState, owning_uid: Option<u32>) -> Option<AppIdentity> {
    runtime()
        .lock()
        .ok()
        .and_then(|actor| actor.attribute_flow(flow, owning_uid))
}

pub fn register_flow_owner_runtime(key: FlowKey, uid: u32) -> Result<()> {
    let mut actor = runtime()
        .lock()
        .map_err(|_| anyhow::anyhow!("attribution runtime poisoned"))?;
    actor.register_flow_owner(key, uid);
    Ok(())
}

pub fn queue_owner_query_runtime(key: FlowKey) -> Result<bool> {
    let mut actor = runtime()
        .lock()
        .map_err(|_| anyhow::anyhow!("attribution runtime poisoned"))?;
    Ok(actor.queue_owner_query(key))
}

pub fn take_pending_owner_queries_runtime(limit: usize) -> Result<Vec<FlowOwnerQuery>> {
    let mut actor = runtime()
        .lock()
        .map_err(|_| anyhow::anyhow!("attribution runtime poisoned"))?;
    Ok(actor.take_pending_owner_queries(limit))
}

pub fn selection_summary() -> String {
    runtime()
        .lock()
        .map(|actor| format!("{:?}", actor.selection_mode))
        .unwrap_or_else(|_| "Unavailable".into())
}

pub fn attribution_stats() -> AttributionStats {
    runtime()
        .lock()
        .map(|actor| actor.stats())
        .unwrap_or(AttributionStats {
            tracked_apps: 0,
            cached_flow_owners: 0,
            pending_owner_queries: 0,
            total_owner_queries_enqueued: 0,
            total_owner_queries_drained: 0,
            total_owner_queries_skipped: 0,
            total_owner_resolutions: 0,
        })
}
