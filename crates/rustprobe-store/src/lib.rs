use rustprobe_core::{AlertEvent, FlowEvent, FlowState, ObjectState};
use std::fs::{File, OpenOptions, create_dir_all};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

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
}

impl JsonlStore {
    pub fn create(root: impl AsRef<Path>) -> anyhow::Result<Self> {
        let root = root.as_ref().to_path_buf();
        create_dir_all(&root)?;

        let flow_writer = open_append(root.join("flows.jsonl"))?;
        let object_writer = open_append(root.join("objects.jsonl"))?;

        Ok(Self {
            root,
            flow_writer,
            object_writer,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn append_flow(&mut self, flow: &FlowState) -> anyhow::Result<()> {
        serde_json::to_writer(&mut self.flow_writer, flow)?;
        self.flow_writer.write_all(b"\n")?;
        self.flow_writer.flush()?;
        Ok(())
    }

    pub fn append_objects(&mut self, objects: &[ObjectState]) -> anyhow::Result<()> {
        for object in objects {
            serde_json::to_writer(&mut self.object_writer, object)?;
            self.object_writer.write_all(b"\n")?;
        }
        self.object_writer.flush()?;
        Ok(())
    }
}

fn open_append(path: PathBuf) -> anyhow::Result<BufWriter<File>> {
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    Ok(BufWriter::new(file))
}
