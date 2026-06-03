use rustprobe_core::{AppEvent, AppMetricsSnapshot};

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
