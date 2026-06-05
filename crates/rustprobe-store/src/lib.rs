use rustprobe_core::{AlertEvent, FlowEvent, FlowState, ObjectState};
use std::fs::{File, OpenOptions, create_dir_all};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
pub struct StorageActor {
    pub stored_flows: usize,
    pub stored_alerts: usize,
}

impl StorageActor {
    pub fn store_flow(&mut self, _event: &FlowEvent) {
        self.stored_flows += 1;
    }

    pub fn store_alert(&mut self, _event: &AlertEvent) {
        self.stored_alerts += 1;
    }
}

pub struct JsonlStore {
    root: PathBuf,
    flow_writer: BufWriter<File>,
    object_writer: BufWriter<File>,
    pending_flow_writes: usize,
    pending_object_writes: usize,
    last_flush_at: Instant,
}

impl JsonlStore {
    const FLUSH_INTERVAL: Duration = Duration::from_millis(750);
    const MAX_PENDING_WRITES: usize = 64;

    pub fn create(root: impl AsRef<Path>) -> anyhow::Result<Self> {
        Self::create_with_mode(root, false)
    }

    pub fn create_fresh(root: impl AsRef<Path>) -> anyhow::Result<Self> {
        Self::create_with_mode(root, true)
    }

    fn create_with_mode(root: impl AsRef<Path>, truncate: bool) -> anyhow::Result<Self> {
        let root = root.as_ref().to_path_buf();
        create_dir_all(&root)?;

        let flow_writer = open_writer(root.join("flows.jsonl"), truncate)?;
        let object_writer = open_writer(root.join("objects.jsonl"), truncate)?;

        Ok(Self {
            root,
            flow_writer,
            object_writer,
            pending_flow_writes: 0,
            pending_object_writes: 0,
            last_flush_at: Instant::now(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn append_flow(&mut self, flow: &FlowState) -> anyhow::Result<()> {
        serde_json::to_writer(&mut self.flow_writer, flow)?;
        self.flow_writer.write_all(b"\n")?;
        self.pending_flow_writes += 1;
        self.flush_if_needed()?;
        Ok(())
    }

    pub fn append_objects(&mut self, objects: &[ObjectState]) -> anyhow::Result<()> {
        for object in objects {
            serde_json::to_writer(&mut self.object_writer, object)?;
            self.object_writer.write_all(b"\n")?;
            self.pending_object_writes += 1;
        }
        self.flush_if_needed()?;
        Ok(())
    }

    pub fn flush(&mut self) -> anyhow::Result<()> {
        self.flow_writer.flush()?;
        self.object_writer.flush()?;
        self.pending_flow_writes = 0;
        self.pending_object_writes = 0;
        self.last_flush_at = Instant::now();
        Ok(())
    }

    pub fn flush_if_due(&mut self) -> anyhow::Result<()> {
        let pending_writes = self.pending_flow_writes + self.pending_object_writes;
        if pending_writes > 0 && self.last_flush_at.elapsed() >= Self::FLUSH_INTERVAL {
            self.flush()?;
        }
        Ok(())
    }

    fn flush_if_needed(&mut self) -> anyhow::Result<()> {
        let pending_writes = self.pending_flow_writes + self.pending_object_writes;
        if pending_writes >= Self::MAX_PENDING_WRITES
            || self.last_flush_at.elapsed() >= Self::FLUSH_INTERVAL
        {
            self.flush()?;
        }
        Ok(())
    }
}

fn open_writer(path: PathBuf, truncate: bool) -> anyhow::Result<BufWriter<File>> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(!truncate)
        .truncate(truncate)
        .open(path)?;
    Ok(BufWriter::new(file))
}
