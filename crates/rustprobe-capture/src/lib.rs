use async_trait::async_trait;
use rustprobe_attrib::{attribute_flow_runtime, queue_owner_query_runtime};
use rustprobe_core::{Actor, ActorRef, PacketEvent};
use rustprobe_flow::FlowActor;
use rustprobe_parse::ParserStage;
use rustprobe_store::JsonlStore;
use std::io::{ErrorKind, Read};
use std::os::fd::{FromRawFd, RawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

static CAPTURE_RUNNING: AtomicBool = AtomicBool::new(false);
static PACKETS_SEEN: AtomicU64 = AtomicU64::new(0);
static OUTPUT_ROOT: OnceLock<Mutex<PathBuf>> = OnceLock::new();
const LOG_TAG: &str = "rustprobe-capture";

#[cfg(target_os = "android")]
unsafe extern "C" {
    fn __android_log_write(
        prio: i32,
        tag: *const libc::c_char,
        text: *const libc::c_char,
    ) -> i32;
}

fn log_info(message: impl AsRef<str>) {
    log_android(4, message.as_ref());
}

fn log_error(message: impl AsRef<str>) {
    log_android(6, message.as_ref());
}

#[cfg(target_os = "android")]
fn log_android(priority: i32, message: &str) {
    use std::ffi::CString;

    let tag = CString::new(LOG_TAG).expect("valid android log tag");
    let text = CString::new(message).unwrap_or_else(|_| {
        CString::new("rustprobe-capture: invalid log message").expect("fallback cstring")
    });
    unsafe {
        __android_log_write(priority, tag.as_ptr(), text.as_ptr());
    }
}

#[cfg(not(target_os = "android"))]
fn log_android(_priority: i32, message: &str) {
    println!("{LOG_TAG}: {message}");
}

#[derive(Debug, Default)]
pub struct TunCaptureActor;

impl TunCaptureActor {
    pub fn bootstrap_packet(&self) -> PacketEvent {
        PacketEvent {
            source: "tun0".into(),
            raw_len: 0,
            note: "bootstrap packet placeholder".into(),
        }
    }
}

#[async_trait]
impl Actor for TunCaptureActor {
    type Message = PacketEvent;

    fn name(&self) -> ActorRef {
        "TunCaptureActor"
    }

    async fn handle(&mut self, _message: Self::Message) -> anyhow::Result<()> {
        Ok(())
    }
}

fn configured_output_root() -> PathBuf {
    OUTPUT_ROOT
        .get_or_init(|| Mutex::new(PathBuf::from("rustprobe-output")))
        .lock()
        .expect("output root mutex poisoned")
        .clone()
}

pub fn set_output_root(path: impl Into<PathBuf>) {
    let path = path.into();
    let root = OUTPUT_ROOT.get_or_init(|| Mutex::new(PathBuf::from("rustprobe-output")));
    *root.lock().expect("output root mutex poisoned") = path;
}

pub fn start_capture_from_fd(fd: RawFd) -> anyhow::Result<bool> {
    if CAPTURE_RUNNING.swap(true, Ordering::SeqCst) {
        return Ok(false);
    }

    let duplicated_fd = unsafe { libc::dup(fd) };
    if duplicated_fd < 0 {
        CAPTURE_RUNNING.store(false, Ordering::SeqCst);
        return Err(anyhow::anyhow!("failed to dup tun fd"));
    }

    thread::Builder::new()
        .name("rustprobe-tun-reader".into())
        .spawn(move || {
            let mut file = unsafe { std::fs::File::from_raw_fd(duplicated_fd) };
            let mut buffer = [0_u8; 8192];
            let parser = ParserStage;
            let mut flow_actor = FlowActor::default();
            let output_root = configured_output_root();
            log_info("background TUN reader thread started");
            let mut store = match JsonlStore::create(&output_root) {
                Ok(store) => {
                    log_info(format!(
                        "JSONL persistence enabled at {}",
                        store.root().display()
                    ));
                    Some(store)
                }
                Err(err) => {
                    log_error(format!("failed to initialize JSONL store: {err}"));
                    None
                }
            };

            loop {
                if !CAPTURE_RUNNING.load(Ordering::SeqCst) {
                    log_info("capture loop stopping because running flag is false");
                    break;
                }

                log_info("waiting for next TUN packet");
                match file.read(&mut buffer) {
                    Ok(0) => {
                        log_error("TUN read returned EOF");
                        break;
                    }
                    Ok(size) => {
                        let count = PACKETS_SEEN.fetch_add(1, Ordering::SeqCst) + 1;
                        match parser.parse_tun_packet(&buffer[..size]) {
                            Ok(parsed) => {
                                if let Some(mut flow) = flow_actor.ingest_packet(&parsed) {
                                    let app = attribute_flow_runtime(&flow.flow, None);
                                    flow.flow.set_app(app.clone());
                                    if app.is_none() {
                                        if let Err(err) =
                                            queue_owner_query_runtime(flow.flow.key.clone())
                                        {
                                            log_error(format!(
                                                "failed to queue owner query: {err}"
                                            ));
                                        }
                                    }
                                    if let Some(store) = store.as_mut() {
                                        if let Err(err) = store.append_flow(&flow.flow) {
                                            log_error(format!(
                                                "failed to persist flow snapshot: {err}"
                                            ));
                                        }

                                        let objects = flow_actor.object_snapshot();
                                        if let Err(err) = store.append_objects(&objects) {
                                            log_error(format!(
                                                "failed to persist object snapshot: {err}"
                                            ));
                                        }
                                    }

                                    let top_objects = flow
                                        .top_objects
                                        .iter()
                                        .map(|object| {
                                            format!(
                                                "{:?}={} hits={} bytes={}",
                                                object.key.kind, object.key.value, object.hits, object.bytes
                                            )
                                        })
                                        .collect::<Vec<_>>()
                                        .join(", ");
                                    log_info(format!(
                                        "packet #{count} size={size} ip={:?} protocol={:?} {}:{} -> {}:{} payload={} app={} active_flows={} expired_flows={} flow_packets={} flow_bytes={} top_objects=[{}]",
                                        parsed.ip_version,
                                        parsed.protocol,
                                        parsed.src_addr,
                                        parsed.src_port.unwrap_or(0),
                                        parsed.dst_addr,
                                        parsed.dst_port.unwrap_or(0),
                                        parsed.payload_len,
                                        flow
                                            .flow
                                            .app
                                            .as_ref()
                                            .map(|app| app.package_name.as_str())
                                            .unwrap_or("unattributed"),
                                        flow.active_flows,
                                        flow.expired_flows,
                                        flow.flow.packets,
                                        flow.flow.payload_bytes,
                                        top_objects,
                                    ));
                                } else {
                                    log_info(format!(
                                        "packet #{count} size={size} ip={:?} protocol={:?} {} -> {} payload={} (non-flow transport)",
                                        parsed.ip_version,
                                        parsed.protocol,
                                        parsed.src_addr,
                                        parsed.dst_addr,
                                        parsed.payload_len,
                                    ));
                                }
                            }
                            Err(err) => {
                                log_error(format!(
                                    "packet #{count} size={size} parse error: {err}"
                                ));
                            }
                        }
                    }
                    Err(err) => {
                        if err.kind() == ErrorKind::WouldBlock || err.raw_os_error() == Some(11) {
                            log_info("TUN read would block; retrying");
                            thread::sleep(Duration::from_millis(25));
                            continue;
                        }

                        log_error(format!("TUN read error: {err}"));
                        break;
                    }
                }
            }

            CAPTURE_RUNNING.store(false, Ordering::SeqCst);
            log_info("background TUN reader stopped");
        })?;

    Ok(true)
}

pub fn stop_capture() {
    CAPTURE_RUNNING.store(false, Ordering::SeqCst);
}

pub fn is_capture_running() -> bool {
    CAPTURE_RUNNING.load(Ordering::SeqCst)
}

pub fn packets_seen() -> u64 {
    PACKETS_SEEN.load(Ordering::SeqCst)
}
