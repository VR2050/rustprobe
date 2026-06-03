use async_trait::async_trait;

use crate::event::ControlEvent;

pub type ActorRef = &'static str;

#[async_trait]
pub trait Actor {
    type Message;

    fn name(&self) -> ActorRef;

    async fn handle(&mut self, message: Self::Message) -> anyhow::Result<()>;

    async fn on_control(&mut self, _message: ControlEvent) -> anyhow::Result<()> {
        Ok(())
    }
}
