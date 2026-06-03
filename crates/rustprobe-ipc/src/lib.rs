use rustprobe_core::UiEvent;

#[derive(Debug, Default)]
pub struct UiGatewayActor;

impl UiGatewayActor {
    pub fn publish(&self, topic: impl Into<String>, payload: impl Into<String>) -> UiEvent {
        UiEvent {
            topic: topic.into(),
            payload: payload.into(),
        }
    }
}
