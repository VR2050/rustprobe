use rustprobe_core::{
    AppEvent, AppIdentity, AppMetricsSnapshot, AppTrafficAnalyticsSnapshot, AppTrafficView,
    FlowState, ProtocolHint, RankedMetric, TrafficSeriesPoint, now_unix_ms,
};
use std::collections::{BTreeMap, HashMap};

const DEFAULT_BUCKET_SIZE_MS: u64 = 10_000;
const DEFAULT_BUCKET_COUNT: usize = 36;
const TOP_LIMIT: usize = 8;
const OVERALL_SCOPE: &str = "__overall__";
const UNATTRIBUTED_SCOPE: &str = "__unattributed__";

#[derive(Debug, Clone)]
pub struct TrafficObservation {
    pub observed_at_unix_ms: u128,
    pub app: Option<AppIdentity>,
    pub protocol: ProtocolHint,
    pub dst_addr: String,
    pub domain: Option<String>,
    pub dst_port: u16,
    pub bytes: u64,
    pub packets: u64,
}

#[derive(Debug, Default, Clone)]
struct MetricCounter {
    bytes: u64,
    packets: u64,
    hits: u64,
}

impl MetricCounter {
    fn observe(&mut self, bytes: u64, packets: u64) {
        self.bytes += bytes;
        self.packets += packets;
        self.hits += 1;
    }
}

#[derive(Debug, Default, Clone)]
struct BucketStats {
    bytes: u64,
    packets: u64,
    hits: u64,
    protocols: HashMap<String, MetricCounter>,
    ips: HashMap<String, MetricCounter>,
    domains: HashMap<String, MetricCounter>,
    ports: HashMap<String, MetricCounter>,
}

impl BucketStats {
    fn observe(&mut self, observation: &TrafficObservation) {
        self.bytes += observation.bytes;
        self.packets += observation.packets;
        self.hits += 1;
        self.protocols
            .entry(protocol_label(&observation.protocol))
            .or_default()
            .observe(observation.bytes, observation.packets);
        self.ips
            .entry(observation.dst_addr.clone())
            .or_default()
            .observe(observation.bytes, observation.packets);
        self.ports
            .entry(observation.dst_port.to_string())
            .or_default()
            .observe(observation.bytes, observation.packets);
        if let Some(domain) = observation
            .domain
            .as_ref()
            .filter(|value| !value.is_empty())
        {
            self.domains
                .entry(domain.to_lowercase())
                .or_default()
                .observe(observation.bytes, observation.packets);
        }
    }

    fn merge_into(&self, aggregate: &mut AggregateView) {
        aggregate.total_bytes += self.bytes;
        aggregate.total_packets += self.packets;
        merge_map(&mut aggregate.protocols, &self.protocols);
        merge_map(&mut aggregate.ips, &self.ips);
        merge_map(&mut aggregate.domains, &self.domains);
        merge_map(&mut aggregate.ports, &self.ports);
    }
}

#[derive(Debug, Default)]
struct AggregateView {
    total_bytes: u64,
    total_packets: u64,
    protocols: HashMap<String, MetricCounter>,
    ips: HashMap<String, MetricCounter>,
    domains: HashMap<String, MetricCounter>,
    ports: HashMap<String, MetricCounter>,
}

#[derive(Debug, Default)]
struct ScopeState {
    app: Option<AppIdentity>,
    buckets: BTreeMap<u128, BucketStats>,
}

#[derive(Debug)]
pub struct AppTrafficAnalyticsActor {
    bucket_size_ms: u64,
    bucket_count: usize,
    scopes: HashMap<String, ScopeState>,
}

impl Default for AppTrafficAnalyticsActor {
    fn default() -> Self {
        Self::new(DEFAULT_BUCKET_SIZE_MS, DEFAULT_BUCKET_COUNT)
    }
}

impl AppTrafficAnalyticsActor {
    pub fn new(bucket_size_ms: u64, bucket_count: usize) -> Self {
        let bucket_size_ms = bucket_size_ms.max(1);
        let bucket_count = bucket_count.max(1);
        let mut scopes = HashMap::new();
        scopes.insert(
            OVERALL_SCOPE.to_string(),
            ScopeState {
                app: None,
                buckets: BTreeMap::new(),
            },
        );
        Self {
            bucket_size_ms,
            bucket_count,
            scopes,
        }
    }

    pub fn observe(&mut self, observation: TrafficObservation) {
        let bucket_start = bucket_start(observation.observed_at_unix_ms, self.bucket_size_ms);
        let min_bucket_start = bucket_start.saturating_sub(
            self.bucket_size_ms as u128 * self.bucket_count.saturating_sub(1) as u128,
        );

        self.observe_scope(
            OVERALL_SCOPE,
            None,
            bucket_start,
            min_bucket_start,
            &observation,
        );

        let scope = observation
            .app
            .as_ref()
            .map(|app| app.package_name.clone())
            .unwrap_or_else(|| UNATTRIBUTED_SCOPE.to_string());
        self.observe_scope(
            &scope,
            observation.app.clone(),
            bucket_start,
            min_bucket_start,
            &observation,
        );
    }

    pub fn snapshot(&self, active_flows: &[FlowState]) -> AppTrafficAnalyticsSnapshot {
        let generated_at = now_unix_ms();
        let window_end = bucket_start(generated_at, self.bucket_size_ms);
        let window_start = window_end.saturating_sub(
            self.bucket_size_ms as u128 * self.bucket_count.saturating_sub(1) as u128,
        );

        let overall = self.build_scope_view(OVERALL_SCOPE, window_start, active_flows);
        let mut apps = self
            .scopes
            .keys()
            .filter(|scope| scope.as_str() != OVERALL_SCOPE)
            .map(|scope| self.build_scope_view(scope, window_start, active_flows))
            .filter(|view| view.total_bytes > 0 || view.active_flows > 0)
            .collect::<Vec<_>>();

        apps.sort_by(|left, right| {
            right
                .total_bytes
                .cmp(&left.total_bytes)
                .then_with(|| right.total_packets.cmp(&left.total_packets))
                .then_with(|| left.scope.cmp(&right.scope))
        });

        AppTrafficAnalyticsSnapshot {
            generated_at_unix_ms: generated_at,
            window_start_unix_ms: window_start,
            window_end_unix_ms: window_end + self.bucket_size_ms as u128,
            bucket_size_ms: self.bucket_size_ms,
            bucket_count: self.bucket_count,
            overall,
            apps,
        }
    }

    fn observe_scope(
        &mut self,
        scope: &str,
        app: Option<AppIdentity>,
        bucket_start: u128,
        min_bucket_start: u128,
        observation: &TrafficObservation,
    ) {
        let state = self.scopes.entry(scope.to_string()).or_default();
        if state.app.is_none() {
            state.app = app;
        }
        state
            .buckets
            .entry(bucket_start)
            .or_default()
            .observe(observation);
        state.buckets.retain(|start, _| *start >= min_bucket_start);
    }

    fn build_scope_view(
        &self,
        scope: &str,
        window_start: u128,
        active_flows: &[FlowState],
    ) -> AppTrafficView {
        let state = self.scopes.get(scope);
        let mut aggregate = AggregateView::default();
        let mut traffic_series = Vec::with_capacity(self.bucket_count);

        for bucket_index in 0..self.bucket_count {
            let bucket_start = window_start + bucket_index as u128 * self.bucket_size_ms as u128;
            let stats = state.and_then(|scope_state| scope_state.buckets.get(&bucket_start));
            let bytes = stats.map(|value| value.bytes).unwrap_or(0);
            let packets = stats.map(|value| value.packets).unwrap_or(0);
            let hits = stats.map(|value| value.hits).unwrap_or(0);
            if let Some(stats) = stats {
                stats.merge_into(&mut aggregate);
            }
            traffic_series.push(TrafficSeriesPoint {
                bucket_start_unix_ms: bucket_start,
                bytes,
                packets,
                hits,
            });
        }

        let app = state.and_then(|value| value.app.clone());
        AppTrafficView {
            scope: display_scope(scope, app.as_ref()),
            app: app.clone(),
            total_bytes: aggregate.total_bytes,
            total_packets: aggregate.total_packets,
            active_flows: count_active_flows(scope, active_flows),
            protocol_distribution: top_ranked_metrics(aggregate.protocols),
            top_ips: top_ranked_metrics(aggregate.ips),
            top_domains: top_ranked_metrics(aggregate.domains),
            top_ports: top_ranked_metrics(aggregate.ports),
            traffic_series,
        }
    }
}

#[derive(Debug, Default)]
pub struct MetricsActor;

impl MetricsActor {
    pub fn snapshot(&self, event: &AppEvent) -> AppMetricsSnapshot {
        AppMetricsSnapshot {
            app: event.app.clone(),
            active_flows: 1,
            bytes_up: 0,
            bytes_down: 0,
            cpu_percent: 0.0,
            memory_kb: 0,
        }
    }
}

fn protocol_label(protocol: &ProtocolHint) -> String {
    match protocol {
        ProtocolHint::Tcp => "TCP",
        ProtocolHint::Udp => "UDP",
        ProtocolHint::Icmp => "ICMP",
        ProtocolHint::Dns => "DNS",
        ProtocolHint::Tls => "TLS",
        ProtocolHint::Http => "HTTP",
        ProtocolHint::Quic => "QUIC",
        ProtocolHint::Unknown => "Unknown",
    }
    .to_string()
}

fn bucket_start(timestamp_ms: u128, bucket_size_ms: u64) -> u128 {
    let size = bucket_size_ms as u128;
    (timestamp_ms / size) * size
}

fn merge_map(target: &mut HashMap<String, MetricCounter>, source: &HashMap<String, MetricCounter>) {
    for (label, counter) in source {
        let entry = target.entry(label.clone()).or_default();
        entry.bytes += counter.bytes;
        entry.packets += counter.packets;
        entry.hits += counter.hits;
    }
}

fn top_ranked_metrics(map: HashMap<String, MetricCounter>) -> Vec<RankedMetric> {
    let mut items = map
        .into_iter()
        .map(|(label, counter)| RankedMetric {
            label,
            bytes: counter.bytes,
            packets: counter.packets,
            hits: counter.hits,
        })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| {
        right
            .bytes
            .cmp(&left.bytes)
            .then_with(|| right.hits.cmp(&left.hits))
            .then_with(|| left.label.cmp(&right.label))
    });
    items.truncate(TOP_LIMIT);
    items
}

fn display_scope(scope: &str, app: Option<&AppIdentity>) -> String {
    if scope == OVERALL_SCOPE {
        "All Monitored Apps".to_string()
    } else if scope == UNATTRIBUTED_SCOPE {
        "Unattributed".to_string()
    } else if let Some(app) = app {
        app.package_name.clone()
    } else {
        scope.to_string()
    }
}

fn count_active_flows(scope: &str, flows: &[FlowState]) -> usize {
    flows
        .iter()
        .filter(|flow| match scope {
            OVERALL_SCOPE => true,
            UNATTRIBUTED_SCOPE => flow.app.is_none(),
            package_name => flow
                .app
                .as_ref()
                .map(|app| app.package_name.as_str() == package_name)
                .unwrap_or(false),
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::{AppTrafficAnalyticsActor, TrafficObservation};
    use rustprobe_core::{AppIdentity, FlowKey, FlowState, ProtocolHint, now_unix_ms};

    #[test]
    fn aggregates_traffic_by_app_and_rankings() {
        let mut actor = AppTrafficAnalyticsActor::new(10_000, 6);
        let base = now_unix_ms();
        let app = AppIdentity {
            uid: 1001,
            package_name: "com.example.alpha".into(),
            app_label: "Alpha".into(),
        };

        actor.observe(TrafficObservation {
            observed_at_unix_ms: base.saturating_sub(10_000),
            app: Some(app.clone()),
            protocol: ProtocolHint::Tls,
            dst_addr: "1.1.1.1".into(),
            domain: Some("example.com".into()),
            dst_port: 443,
            bytes: 1200,
            packets: 2,
        });
        actor.observe(TrafficObservation {
            observed_at_unix_ms: base.saturating_sub(2_000),
            app: Some(app.clone()),
            protocol: ProtocolHint::Tls,
            dst_addr: "1.1.1.1".into(),
            domain: Some("example.com".into()),
            dst_port: 443,
            bytes: 800,
            packets: 1,
        });

        let mut flow = FlowState::new(
            FlowKey {
                src_addr: "10.0.0.2".into(),
                dst_addr: "1.1.1.1".into(),
                src_port: 50000,
                dst_port: 443,
                protocol: ProtocolHint::Tcp,
            },
            1200,
        );
        flow.set_app(Some(app));

        let snapshot = actor.snapshot(&[flow]);
        assert_eq!(snapshot.apps.len(), 1);
        assert_eq!(snapshot.apps[0].total_bytes, 2000);
        assert_eq!(snapshot.apps[0].active_flows, 1);
        assert_eq!(snapshot.apps[0].top_ips[0].label, "1.1.1.1");
        assert_eq!(snapshot.apps[0].top_domains[0].label, "example.com");
        assert_eq!(snapshot.apps[0].top_ports[0].label, "443");
        assert_eq!(snapshot.apps[0].protocol_distribution[0].label, "TLS");
    }
}
