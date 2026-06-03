use rustprobe_core::{AlertEvent, AlertRecord, AppMetricsSnapshot, RiskLevel};

#[derive(Debug, Default)]
pub struct DetectionActor;

impl DetectionActor {
    pub fn inspect(&self, snapshot: &AppMetricsSnapshot) -> Option<AlertEvent> {
        if snapshot.cpu_percent > 80.0 {
            return Some(AlertEvent {
                alert: AlertRecord {
                    title: "Suspicious CPU usage".into(),
                    summary: "High sustained CPU may indicate mining-like behavior".into(),
                    risk: RiskLevel::High,
                    app: Some(snapshot.app.clone()),
                },
            });
        }

        None
    }
}
