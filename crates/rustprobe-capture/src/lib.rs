use async_trait::async_trait;
use rustprobe_attrib::{attribute_flow_runtime, attribution_stats, queue_owner_query_runtime};
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
use std::time::{Duration, Instant};

static CAPTURE_RUNNING: AtomicBool = AtomicBool::new(false);
static PACKETS_SEEN: AtomicU64 = AtomicU64::new(0);
static OUTPUT_ROOT: OnceLock<Mutex<PathBuf>> = OnceLock::new();
const LOG_TAG: &str = "rustprobe-capture";

#[cfg(target_os = "android")]
unsafe extern "C" {
    fn __android_log_write(prio: i32, tag: *const libc::c_char, text: *const libc::c_char) -> i32;
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
                        "JSONL persistence enabled at {} (flows.jsonl, objects.jsonl)",
                        store.root().display()
                    ));
                    Some(store)
                }
                Err(err) => {
                    log_error(format!("failed to initialize JSONL store: {err}"));
                    None
                }
            };
            let summary_interval = Duration::from_secs(5);
            let mut last_summary_at = Instant::now();
            let mut parse_errors = 0_u64;
            let mut non_flow_packets = 0_u64;
            let mut would_block_reads = 0_u64;
            let mut attributed_flow_packets = 0_u64;
            let mut unattributed_flow_packets = 0_u64;
            let mut owner_query_requests = 0_u64;
            let mut owner_query_enqueued = 0_u64;

            let log_summary = |flow_actor: &FlowActor,
                               parse_errors: u64,
                               non_flow_packets: u64,
                               would_block_reads: u64,
                               attributed_flow_packets: u64,
                               unattributed_flow_packets: u64,
                               owner_query_requests: u64,
                               owner_query_enqueued: u64| {
                let attrib = attribution_stats();
                log_info(format!(
                    "capture summary packets_seen={} active_flows={} tracked_objects={} parse_errors={} non_flow_packets={} would_block_reads={} attributed_flow_packets={} unattributed_flow_packets={} owner_query_requests={} owner_query_enqueued={} tracked_apps={} cached_flow_owners={} pending_owner_queries={} owner_queries_enqueued_total={} owner_queries_drained={} owner_queries_skipped={} owner_resolutions={}",
                    PACKETS_SEEN.load(Ordering::Relaxed),
                    flow_actor.active_flows(),
                    flow_actor.object_snapshot().len(),
                    parse_errors,
                    non_flow_packets,
                    would_block_reads,
                    attributed_flow_packets,
                    unattributed_flow_packets,
                    owner_query_requests,
                    owner_query_enqueued,
                    attrib.tracked_apps,
                    attrib.cached_flow_owners,
                    attrib.pending_owner_queries,
                    attrib.total_owner_queries_enqueued,
                    attrib.total_owner_queries_drained,
                    attrib.total_owner_queries_skipped,
                    attrib.total_owner_resolutions,
                ));
            };

            loop {
                if !CAPTURE_RUNNING.load(Ordering::SeqCst) {
                    log_info("capture loop stopping because running flag is false");
                    break;
                }

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
                                    if app.is_some() {
                                        let _ = flow_actor
                                            .set_flow_app(&flow.flow.key, flow.flow.app.clone());
                                    }
                                    if let Some(app) = app.as_ref() {
                                        attributed_flow_packets += 1;
                                        if flow.flow.packets == 1 {
                                            log_info(format!(
                                                "flow attributed protocol={:?} {}:{} -> {}:{} app={} uid={}",
                                                flow.flow.key.protocol,
                                                flow.flow.key.src_addr,
                                                flow.flow.key.src_port,
                                                flow.flow.key.dst_addr,
                                                flow.flow.key.dst_port,
                                                app.package_name,
                                                app.uid,
                                            ));
                                        }
                                    } else {
                                        unattributed_flow_packets += 1;
                                        owner_query_requests += 1;
                                        match queue_owner_query_runtime(flow.flow.key.clone()) {
                                            Ok(enqueued) => {
                                                if enqueued {
                                                    owner_query_enqueued += 1;
                                                    log_info(format!(
                                                        "queued owner query protocol={:?} {}:{} -> {}:{}",
                                                        flow.flow.key.protocol,
                                                        flow.flow.key.src_addr,
                                                        flow.flow.key.src_port,
                                                        flow.flow.key.dst_addr,
                                                        flow.flow.key.dst_port,
                                                    ));
                                                }
                                            }
                                            Err(err) => {
                                                log_error(format!(
                                                    "failed to queue owner query: {err}"
                                                ));
                                            }
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
                                        "packet #{count} size={size} ip={:?} protocol={:?} {}:{} -> {}:{} payload={} domain={} sni={} app={} active_flows={} expired_flows={} flow_packets={} flow_bytes={} top_objects=[{}]",
                                        parsed.ip_version,
                                        parsed.protocol,
                                        parsed.src_addr,
                                        parsed.src_port.unwrap_or(0),
                                        parsed.dst_addr,
                                        parsed.dst_port.unwrap_or(0),
                                        parsed.payload_len,
                                        flow
                                            .flow
                                            .domain
                                            .as_deref()
                                            .unwrap_or("-"),
                                        flow
                                            .flow
                                            .tls_server_name
                                            .as_deref()
                                            .unwrap_or("-"),
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
                                    non_flow_packets += 1;
                                    log_info(format!(
                                        "packet #{count} size={size} ip={:?} protocol={:?} {} -> {} payload={} domain={} sni={} (non-flow transport)",
                                        parsed.ip_version,
                                        parsed.protocol,
                                        parsed.src_addr,
                                        parsed.dst_addr,
                                        parsed.payload_len,
                                        parsed.dns_query_name.as_deref().unwrap_or("-"),
                                        parsed.tls_server_name.as_deref().unwrap_or("-"),
                                    ));
                                }
                            }
                            Err(err) => {
                                parse_errors += 1;
                                log_error(format!(
                                    "packet #{count} size={size} parse error: {err}"
                                ));
                            }
                        }
                    }
                    Err(err) => {
                        if err.kind() == ErrorKind::WouldBlock || err.raw_os_error() == Some(11) {
                            would_block_reads += 1;
                            thread::sleep(Duration::from_millis(25));
                        } else {
                            log_error(format!("TUN read error: {err}"));
                            break;
                        }
                    }
                }

                if last_summary_at.elapsed() >= summary_interval {
                    log_summary(
                        &flow_actor,
                        parse_errors,
                        non_flow_packets,
                        would_block_reads,
                        attributed_flow_packets,
                        unattributed_flow_packets,
                        owner_query_requests,
                        owner_query_enqueued,
                    );
                    last_summary_at = Instant::now();
                }
            }

            log_summary(
                &flow_actor,
                parse_errors,
                non_flow_packets,
                would_block_reads,
                attributed_flow_packets,
                unattributed_flow_packets,
                owner_query_requests,
                owner_query_enqueued,
            );
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
