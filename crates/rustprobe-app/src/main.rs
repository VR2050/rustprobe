use rustprobe_attrib::AttributionActor;
use rustprobe_capture::TunCaptureActor;
use rustprobe_core::{
    AppIdentity, AppSelectionMode, IpVersion, ParsedPacket, TrafficDispositionMode,
};
use rustprobe_detect::DetectionActor;
use rustprobe_flow::FlowActor;
use rustprobe_ipc::UiGatewayActor;
use rustprobe_metrics::MetricsActor;
use rustprobe_parse::ParserStage;
use rustprobe_store::StorageActor;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let capture = TunCaptureActor;
    let parser = ParserStage;
    let runtime_config = rustprobe_core::RuntimeConfig {
        disposition_mode: TrafficDispositionMode::Forward,
        ..Default::default()
    };
    let mut attrib = AttributionActor::default();
    attrib.register_apps([AppIdentity {
        uid: 10_001,
        package_name: "com.example.target".into(),
        app_label: "Example Target".into(),
    }]);
    attrib.set_selection_mode(AppSelectionMode::Global);
    let metrics = MetricsActor;
    let detector = DetectionActor;
    let gateway = UiGatewayActor;

    let packet = capture.bootstrap_packet();
    let flow = parser.parse(&packet);

    let mut flow_actor = FlowActor::default();
    let parsed = ParsedPacket {
        ip_version: IpVersion::V4,
        protocol: flow.flow.protocol.clone(),
        transport_protocol: flow.flow.protocol.clone(),
        src_addr: flow.flow.src.host.clone(),
        dst_addr: flow.flow.dst.host.clone(),
        src_port: Some(flow.flow.src.port),
        dst_port: Some(flow.flow.dst.port),
        tcp_sequence: None,
        payload_len: 0,
        dns_query_name: None,
        tls_server_name: None,
        quic_server_name: None,
        http_host: None,
        http_request_target: None,
        application_protocols: Vec::new(),
        quic_destination_connection_id: None,
        dns_candidate: false,
        tls_candidate: false,
        quic_candidate: false,
        quic_initial_candidate: false,
        doh_candidate: false,
        dot_candidate: false,
        http3_candidate: false,
        transport_payload: Vec::new(),
    };
    let ingested = flow_actor
        .ingest_packet(&parsed)
        .expect("flow should be created");

    let mut flow_state = ingested.flow.clone();
    flow_state.set_app(Some(AppIdentity {
        uid: 10_001,
        package_name: "com.example.target".into(),
        app_label: "Example Target".into(),
    }));
    let app_event = attrib.attribute(&flow_state);
    let snapshot = metrics.snapshot(&app_event);

    let mut store = StorageActor::default();
    store.store_flow(&flow);

    if let Some(alert) = detector.inspect(&snapshot) {
        store.store_alert(&alert);
        let ui_event = gateway.publish("alerts", serde_json::to_string(&alert)?);
        println!("published ui event: {}", ui_event.topic);
    } else {
        let ui_event = gateway.publish("flows", serde_json::to_string(&flow)?);
        println!("published ui event: {}", ui_event.topic);
    }

    println!(
        "workspace bootstrap complete ({})",
        runtime_config.disposition_mode.as_str()
    );
    Ok(())
}
