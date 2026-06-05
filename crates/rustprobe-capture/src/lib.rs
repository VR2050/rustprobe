use async_trait::async_trait;
use rustprobe_attrib::{attribute_flow_runtime, attribution_stats, queue_owner_query_runtime};
use rustprobe_core::{Actor, ActorRef, FlowKey, FlowState, PacketEvent, ParsedPacket};
use rustprobe_flow::FlowActor;
use rustprobe_parse::ParserStage;
use rustprobe_store::JsonlStore;
use std::collections::HashMap;
use std::io::{ErrorKind, Read};
use std::os::fd::{FromRawFd, RawFd};
use std::path::PathBuf;
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

static CAPTURE_RUNNING: AtomicBool = AtomicBool::new(false);
static PACKETS_SEEN: AtomicU64 = AtomicU64::new(0);
static MIRRORED_PACKETS_DROPPED: AtomicU64 = AtomicU64::new(0);
static OUTPUT_ROOT: OnceLock<Mutex<PathBuf>> = OnceLock::new();
static MIRRORED_INGEST_SENDER: OnceLock<Mutex<Option<SyncSender<Vec<u8>>>>> = OnceLock::new();
static MIRRORED_INGEST_THREAD: OnceLock<Mutex<Option<JoinHandle<()>>>> = OnceLock::new();

const LOG_TAG: &str = "rustprobe-capture";
const OWNER_QUERY_RETRY_PACKET_INTERVAL: u64 = 16;
const MIRRORED_INGEST_QUEUE_CAPACITY: usize = 2048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeProfile {
    Capture,
    Forward,
}

impl RuntimeProfile {
    fn mode_label(self) -> &'static str {
        match self {
            Self::Capture => "capture",
            Self::Forward => "forward",
        }
    }

    fn summary_interval(self) -> Duration {
        Duration::from_secs(5)
    }

    fn flow_log_interval(self) -> u64 {
        match self {
            Self::Capture => 50,
            Self::Forward => 400,
        }
    }

    fn non_flow_log_interval(self) -> u64 {
        match self {
            Self::Capture => 100,
            Self::Forward => 800,
        }
    }

    fn parse_error_log_interval(self) -> u64 {
        match self {
            Self::Capture => 1,
            Self::Forward => 32,
        }
    }

    fn expire_scan_interval(self) -> Duration {
        match self {
            Self::Capture => Duration::ZERO,
            Self::Forward => Duration::from_secs(2),
        }
    }

    fn persist_every_packet(self) -> bool {
        matches!(self, Self::Capture)
    }

    fn persist_packet_interval(self) -> u64 {
        match self {
            Self::Capture => 1,
            Self::Forward => 32,
        }
    }

    fn log_owner_query_events(self) -> bool {
        matches!(self, Self::Capture)
    }
}

#[derive(Debug, Default)]
struct PersistedFlowMarker {
    last_persisted_packet_count: u64,
    had_app: bool,
    had_domain: bool,
    had_http_host: bool,
    had_tls_server_name: bool,
    had_quic_server_name: bool,
}

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

struct CaptureRuntime {
    parser: ParserStage,
    flow_actor: FlowActor,
    store: Option<JsonlStore>,
    profile: RuntimeProfile,
    summary_interval: Duration,
    last_summary_at: Instant,
    last_expire_scan_at: Instant,
    parse_errors: u64,
    non_flow_packets: u64,
    would_block_reads: u64,
    attributed_flow_packets: u64,
    unattributed_flow_packets: u64,
    owner_query_requests: u64,
    owner_query_enqueued: u64,
    persisted_flows: HashMap<FlowKey, PersistedFlowMarker>,
}

impl CaptureRuntime {
    fn new(profile: RuntimeProfile) -> Self {
        let mode_label = profile.mode_label();
        let output_root = configured_output_root();
        let store = match JsonlStore::create_fresh(&output_root) {
            Ok(store) => {
                log_info(format!(
                    "{mode_label} JSONL persistence enabled at {} (flows.jsonl, objects.jsonl)",
                    store.root().display()
                ));
                Some(store)
            }
            Err(err) => {
                log_error(format!(
                    "{mode_label} failed to initialize JSONL store: {err}"
                ));
                None
            }
        };

        Self {
            parser: ParserStage,
            flow_actor: FlowActor::default(),
            store,
            profile,
            summary_interval: profile.summary_interval(),
            last_summary_at: Instant::now(),
            last_expire_scan_at: Instant::now(),
            parse_errors: 0,
            non_flow_packets: 0,
            would_block_reads: 0,
            attributed_flow_packets: 0,
            unattributed_flow_packets: 0,
            owner_query_requests: 0,
            owner_query_enqueued: 0,
            persisted_flows: HashMap::new(),
        }
    }

    fn ingest_bytes(&mut self, bytes: &[u8]) {
        let size = bytes.len();
        let count = PACKETS_SEEN.fetch_add(1, Ordering::SeqCst) + 1;

        match self.parser.parse_tun_packet(bytes) {
            Ok(parsed) => self.handle_parsed_packet(count, size, parsed),
            Err(err) => {
                self.parse_errors += 1;
                if should_log_parse_error(self.profile, self.parse_errors) {
                    log_error(format!(
                        "{} packet #{count} size={size} parse error: {err}",
                        self.profile.mode_label()
                    ));
                }
            }
        }

        self.flush_and_log_if_due();
    }

    fn note_would_block(&mut self) {
        self.would_block_reads += 1;
        if let Some(store) = self.store.as_mut() {
            let _ = store.flush_if_due();
        }
        self.flush_and_log_if_due();
    }

    fn finish(mut self) {
        self.log_summary();
        if let Some(store) = self.store.as_mut() {
            let _ = store.flush();
        }
    }

    fn flush_and_log_if_due(&mut self) {
        if self.last_summary_at.elapsed() >= self.summary_interval {
            self.log_summary();
            if let Some(store) = self.store.as_mut() {
                let _ = store.flush_if_due();
            }
            self.last_summary_at = Instant::now();
        }
    }

    fn handle_parsed_packet(&mut self, count: u64, size: usize, parsed: ParsedPacket) {
        if let Some(mut flow) = self.flow_actor.ingest_packet(&parsed) {
            let app = if let Some(app) = flow.flow.app.clone() {
                Some(app)
            } else {
                let app = attribute_flow_runtime(&flow.flow, None);
                flow.flow.set_app(app.clone());
                app
            };

            if app.is_some() {
                let _ = self
                    .flow_actor
                    .set_flow_app(&flow.flow.key, flow.flow.app.clone());
            }

            if let Some(app) = app.as_ref() {
                self.attributed_flow_packets += 1;
                if flow.flow.packets == 1 {
                    log_info(format!(
                        "{} flow attributed transport={:?} protocol_hint={:?} {}:{} -> {}:{} app={} uid={}",
                        self.profile.mode_label(),
                        flow.flow.key.protocol,
                        flow.flow.protocol_hint,
                        flow.flow.key.src_addr,
                        flow.flow.key.src_port,
                        flow.flow.key.dst_addr,
                        flow.flow.key.dst_port,
                        app.package_name,
                        app.uid,
                    ));
                }
            } else {
                self.unattributed_flow_packets += 1;
                if should_queue_owner_query(flow.flow.packets) {
                    self.owner_query_requests += 1;
                    match queue_owner_query_runtime(flow.flow.key.clone()) {
                        Ok(enqueued) => {
                            if enqueued {
                                self.owner_query_enqueued += 1;
                                if self.profile.log_owner_query_events() {
                                    log_info(format!(
                                        "{} queued owner query transport={:?} protocol_hint={:?} {}:{} -> {}:{}",
                                        self.profile.mode_label(),
                                        flow.flow.key.protocol,
                                        flow.flow.protocol_hint,
                                        flow.flow.key.src_addr,
                                        flow.flow.key.src_port,
                                        flow.flow.key.dst_addr,
                                        flow.flow.key.dst_port,
                                    ));
                                }
                            }
                        }
                        Err(err) => {
                            log_error(format!(
                                "{} failed to queue owner query: {err}",
                                self.profile.mode_label()
                            ));
                        }
                    }
                }
            }

            let expired_flows = self.expire_flows_if_due();

            if self.should_persist_flow(&flow.flow) {
                self.persist_flow(&flow.flow, &flow.touched_objects);
            }

            if should_log_flow_packet(self.profile, count, &parsed, &flow.flow) {
                let top_objects = self
                    .flow_actor
                    .top_objects(4)
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
                    "{} packet #{count} size={size} ip={:?} transport={:?} protocol={:?} dns_candidate={} tls_candidate={} quic_candidate={} quic_initial_candidate={} doh_candidate={} dot_candidate={} http3_candidate={} domain_source={:?} {}:{} -> {}:{} payload={} domain={} sni={} quic_sni={} http_host={} alpn={} app={} active_flows={} expired_flows={} flow_packets={} flow_bytes={} top_objects=[{}]",
                    self.profile.mode_label(),
                    parsed.ip_version,
                    parsed.transport_protocol,
                    parsed.protocol,
                    parsed.dns_candidate,
                    parsed.tls_candidate,
                    parsed.quic_candidate,
                    parsed.quic_initial_candidate,
                    parsed.doh_candidate,
                    parsed.dot_candidate,
                    parsed.http3_candidate,
                    flow.flow.domain_source,
                    parsed.src_addr,
                    parsed.src_port.unwrap_or(0),
                    parsed.dst_addr,
                    parsed.dst_port.unwrap_or(0),
                    parsed.payload_len,
                    flow.flow.domain.as_deref().unwrap_or("-"),
                    flow.flow.tls_server_name.as_deref().unwrap_or("-"),
                    flow.flow.quic_server_name.as_deref().unwrap_or("-"),
                    flow.flow.http_host.as_deref().unwrap_or("-"),
                    if flow.flow.application_protocols.is_empty() {
                        "-".to_string()
                    } else {
                        flow.flow.application_protocols.join(",")
                    },
                    flow.flow
                        .app
                        .as_ref()
                        .map(|app| app.package_name.as_str())
                        .unwrap_or("unattributed"),
                    flow.active_flows,
                    expired_flows,
                    flow.flow.packets,
                    flow.flow.payload_bytes,
                    top_objects,
                ));
            }
        } else {
            self.non_flow_packets += 1;
            if should_log_non_flow_packet(self.profile, count, &parsed) {
                log_info(format!(
                    "{} packet #{count} size={size} ip={:?} transport={:?} protocol={:?} dns_candidate={} tls_candidate={} quic_candidate={} quic_initial_candidate={} doh_candidate={} dot_candidate={} http3_candidate={} {} -> {} payload={} domain={} sni={} quic_sni={} http_host={} alpn={} (non-flow transport)",
                    self.profile.mode_label(),
                    parsed.ip_version,
                    parsed.transport_protocol,
                    parsed.protocol,
                    parsed.dns_candidate,
                    parsed.tls_candidate,
                    parsed.quic_candidate,
                    parsed.quic_initial_candidate,
                    parsed.doh_candidate,
                    parsed.dot_candidate,
                    parsed.http3_candidate,
                    parsed.src_addr,
                    parsed.dst_addr,
                    parsed.payload_len,
                    parsed.dns_query_name.as_deref().unwrap_or("-"),
                    parsed.tls_server_name.as_deref().unwrap_or("-"),
                    parsed.quic_server_name.as_deref().unwrap_or("-"),
                    parsed.http_host.as_deref().unwrap_or("-"),
                    if parsed.application_protocols.is_empty() {
                        "-".to_string()
                    } else {
                        parsed.application_protocols.join(",")
                    },
                ));
            }
        }
    }

    fn persist_flow(
        &mut self,
        flow: &FlowState,
        touched_objects: &[rustprobe_core::ObjectState],
    ) {
        if let Some(store) = self.store.as_mut() {
            if let Err(err) = store.append_flow(flow) {
                log_error(format!(
                    "{} failed to persist flow snapshot: {err}",
                    self.profile.mode_label()
                ));
            }

            if let Err(err) = store.append_objects(touched_objects) {
                log_error(format!(
                    "{} failed to persist object snapshot: {err}",
                    self.profile.mode_label()
                ));
            }
        }
    }

    fn should_persist_flow(&mut self, flow: &FlowState) -> bool {
        if self.profile.persist_every_packet() {
            return true;
        }

        let marker = self.persisted_flows.entry(flow.key.clone()).or_default();
        let discovered_metadata = (flow.app.is_some() && !marker.had_app)
            || (flow.domain.is_some() && !marker.had_domain)
            || (flow.http_host.is_some() && !marker.had_http_host)
            || (flow.tls_server_name.is_some() && !marker.had_tls_server_name)
            || (flow.quic_server_name.is_some() && !marker.had_quic_server_name);
        let reached_packet_checkpoint = flow.packets == 1
            || flow.packets
                >= marker.last_persisted_packet_count + self.profile.persist_packet_interval();

        if discovered_metadata || reached_packet_checkpoint {
            marker.last_persisted_packet_count = flow.packets;
            marker.had_app = flow.app.is_some();
            marker.had_domain = flow.domain.is_some();
            marker.had_http_host = flow.http_host.is_some();
            marker.had_tls_server_name = flow.tls_server_name.is_some();
            marker.had_quic_server_name = flow.quic_server_name.is_some();
            true
        } else {
            false
        }
    }

    fn expire_flows_if_due(&mut self) -> usize {
        let interval = self.profile.expire_scan_interval();
        if !interval.is_zero() && self.last_expire_scan_at.elapsed() < interval {
            return 0;
        }

        self.last_expire_scan_at = Instant::now();
        let expired = self.flow_actor.expire_idle_flows();
        if expired > 0 {
            self.persisted_flows
                .retain(|key, _| self.flow_actor.has_flow(key));
        }
        expired
    }

    fn log_summary(&self) {
        let attrib = attribution_stats();
        log_info(format!(
            "{} summary packets_seen={} mirrored_packets_dropped={} active_flows={} tracked_objects={} parse_errors={} non_flow_packets={} would_block_reads={} attributed_flow_packets={} unattributed_flow_packets={} owner_query_requests={} owner_query_enqueued={} tracked_apps={} cached_flow_owners={} pending_owner_queries={} owner_queries_enqueued_total={} owner_queries_drained={} owner_queries_skipped={} owner_resolutions={}",
            self.profile.mode_label(),
            PACKETS_SEEN.load(Ordering::Relaxed),
            MIRRORED_PACKETS_DROPPED.load(Ordering::Relaxed),
            self.flow_actor.active_flows(),
            self.flow_actor.object_snapshot().len(),
            self.parse_errors,
            self.non_flow_packets,
            self.would_block_reads,
            self.attributed_flow_packets,
            self.unattributed_flow_packets,
            self.owner_query_requests,
            self.owner_query_enqueued,
            attrib.tracked_apps,
            attrib.cached_flow_owners,
            attrib.pending_owner_queries,
            attrib.total_owner_queries_enqueued,
            attrib.total_owner_queries_drained,
            attrib.total_owner_queries_skipped,
            attrib.total_owner_resolutions,
        ));
    }
}

fn configured_output_root() -> PathBuf {
    OUTPUT_ROOT
        .get_or_init(|| Mutex::new(PathBuf::from("rustprobe-output")))
        .lock()
        .expect("output root mutex poisoned")
        .clone()
}

fn mirrored_ingest_sender_slot() -> &'static Mutex<Option<SyncSender<Vec<u8>>>> {
    MIRRORED_INGEST_SENDER.get_or_init(|| Mutex::new(None))
}

fn mirrored_ingest_thread_slot() -> &'static Mutex<Option<JoinHandle<()>>> {
    MIRRORED_INGEST_THREAD.get_or_init(|| Mutex::new(None))
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
    PACKETS_SEEN.store(0, Ordering::SeqCst);
    MIRRORED_PACKETS_DROPPED.store(0, Ordering::SeqCst);
    clear_mirrored_runtime();

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
            let mut runtime = CaptureRuntime::new(RuntimeProfile::Capture);
            log_info("background TUN reader thread started");

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
                    Ok(size) => runtime.ingest_bytes(&buffer[..size]),
                    Err(err) => {
                        if err.kind() == ErrorKind::WouldBlock || err.raw_os_error() == Some(11) {
                            runtime.note_would_block();
                            thread::sleep(Duration::from_millis(25));
                        } else {
                            log_error(format!("TUN read error: {err}"));
                            break;
                        }
                    }
                }
            }

            runtime.finish();
            CAPTURE_RUNNING.store(false, Ordering::SeqCst);
            log_info("background TUN reader stopped");
        })?;

    Ok(true)
}

pub fn start_mirrored_capture() -> anyhow::Result<bool> {
    if CAPTURE_RUNNING.swap(true, Ordering::SeqCst) {
        return Ok(false);
    }

    PACKETS_SEEN.store(0, Ordering::SeqCst);
    MIRRORED_PACKETS_DROPPED.store(0, Ordering::SeqCst);
    clear_mirrored_runtime();

    let (sender, receiver) = mpsc::sync_channel::<Vec<u8>>(MIRRORED_INGEST_QUEUE_CAPACITY);
    {
        let mut slot = mirrored_ingest_sender_slot()
            .lock()
            .expect("mirrored ingest sender mutex poisoned");
        *slot = Some(sender);
    }

    let handle = thread::Builder::new()
        .name("rustprobe-forward-reader".into())
        .spawn(move || {
            let mut runtime = CaptureRuntime::new(RuntimeProfile::Forward);
            log_info("forward shared runtime started");

            loop {
                match receiver.recv_timeout(Duration::from_millis(100)) {
                    Ok(bytes) => runtime.ingest_bytes(&bytes),
                    Err(RecvTimeoutError::Timeout) => {
                        if !CAPTURE_RUNNING.load(Ordering::SeqCst) {
                            break;
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }

            runtime.finish();
            log_info("forward shared runtime stopped");
        })?;

    {
        let mut slot = mirrored_ingest_thread_slot()
            .lock()
            .expect("mirrored ingest thread mutex poisoned");
        *slot = Some(handle);
    }

    log_info("mirrored capture bridge armed");
    Ok(true)
}

pub fn ingest_mirrored_packet(bytes: &[u8]) -> bool {
    if !CAPTURE_RUNNING.load(Ordering::SeqCst) || bytes.is_empty() {
        return false;
    }

    let sender = mirrored_ingest_sender_slot()
        .lock()
        .expect("mirrored ingest sender mutex poisoned")
        .clone();
    let Some(sender) = sender else {
        return false;
    };

    match sender.try_send(bytes.to_vec()) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) => {
            MIRRORED_PACKETS_DROPPED.fetch_add(1, Ordering::Relaxed);
            false
        }
        Err(TrySendError::Disconnected(_)) => false,
    }
}

pub fn stop_capture() {
    CAPTURE_RUNNING.store(false, Ordering::SeqCst);
    clear_mirrored_runtime();
}

pub fn is_capture_running() -> bool {
    CAPTURE_RUNNING.load(Ordering::SeqCst)
}

pub fn packets_seen() -> u64 {
    PACKETS_SEEN.load(Ordering::SeqCst)
}

fn clear_mirrored_runtime() {
    let sender = mirrored_ingest_sender_slot()
        .lock()
        .expect("mirrored ingest sender mutex poisoned")
        .take();
    drop(sender);

    let handle = mirrored_ingest_thread_slot()
        .lock()
        .expect("mirrored ingest thread mutex poisoned")
        .take();
    if let Some(handle) = handle {
        let _ = handle.join();
    }
}

fn should_log_parse_error(profile: RuntimeProfile, parse_errors: u64) -> bool {
    parse_errors <= 4 || parse_errors.is_multiple_of(profile.parse_error_log_interval())
}

fn should_log_flow_packet(
    profile: RuntimeProfile,
    count: u64,
    parsed: &ParsedPacket,
    flow: &FlowState,
) -> bool {
    let early_packet_limit = match profile {
        RuntimeProfile::Capture => 12,
        RuntimeProfile::Forward => 4,
    };

    count <= early_packet_limit
        || count.is_multiple_of(profile.flow_log_interval())
        || flow.packets == 1
        || (profile == RuntimeProfile::Capture && flow.domain.is_some())
        || (profile == RuntimeProfile::Capture && flow.tls_server_name.is_some())
        || (profile == RuntimeProfile::Capture && flow.quic_server_name.is_some())
        || (profile == RuntimeProfile::Capture && flow.http_host.is_some())
        || parsed.doh_candidate
        || parsed.dot_candidate
        || parsed.http3_candidate
}

fn should_log_non_flow_packet(profile: RuntimeProfile, count: u64, parsed: &ParsedPacket) -> bool {
    let early_packet_limit = match profile {
        RuntimeProfile::Capture => 8,
        RuntimeProfile::Forward => 2,
    };

    count <= early_packet_limit
        || count.is_multiple_of(profile.non_flow_log_interval())
        || parsed.dns_candidate
        || parsed.tls_candidate
        || parsed.quic_candidate
        || parsed.doh_candidate
        || parsed.dot_candidate
        || parsed.http3_candidate
}

fn should_queue_owner_query(flow_packets: u64) -> bool {
    flow_packets == 1 || flow_packets.is_multiple_of(OWNER_QUERY_RETRY_PACKET_INTERVAL)
}
