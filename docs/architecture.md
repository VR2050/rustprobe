# RustProbe Architecture

This document turns the high-level design in [README.md](../README.md) into an implementation-facing blueprint.

## 1. Scope

RustProbe is a non-root Android traffic analysis probe built around `VPNService`, a Rust analysis core, and a lightweight Android/UI shell.

This document covers:

- runtime topology
- crate boundaries
- actor responsibilities
- event and data models
- Android integration
- storage and export boundaries

## 2. Runtime Topology

The runtime is split into four layers:

1. Android shell layer
2. transport and VPN layer
3. Rust analysis layer
4. presentation layer

### 2.1 Android shell layer

Responsibilities:

- request VPN authorization
- host `MainActivity`
- own `RustProbeVpnService`
- manage app selection mode
- sync installed apps and monitoring selection into Rust runtime
- choose between `capture mode` and `forwarding mode`
- pass TUN file descriptor to Rust or native forwarding components

### 2.2 Transport and VPN layer

Responsibilities:

- create TUN interface
- support direct Rust capture from TUN
- support `hev-socks5-server + hev-socks5-tunnel` forwarding for real connectivity
- maintain Android-compatible network access while traffic is inspected
- emit minimal forwarding-side observability when Rust is not reading raw TUN packets

### 2.3 Rust analysis layer

Responsibilities:

- ingest packets from TUN
- parse IP packets with `pnet`
- assemble flows
- attribute flows to applications
- aggregate objects such as domain, URL, IP, port, and `MAC` metadata
- compute metrics and detect suspicious behavior
- emit records for UI and storage

### 2.4 Presentation layer

Responsibilities:

- display app-centric views
- display object-centric views
- display alerts, metrics, and exports

## 3. Workspace Layout

### 3.1 Crates

- `rustprobe-core`: shared actor traits, config, events, and models
- `rustprobe-capture`: TUN read/write and capture actor entry
- `rustprobe-parse`: `pnet`-based packet parsing
- `rustprobe-flow`: flow table and session lifecycle
- `rustprobe-attrib`: UID/package attribution
- `rustprobe-metrics`: app metrics and aggregation logic
- `rustprobe-detect`: security detection rules and scoring
- `rustprobe-store`: storage and export interfaces
- `rustprobe-ipc`: UI-facing IPC event formatting
- `rustprobe-app`: bootstrap binary used for local integration testing

### 3.2 Non-Rust directories

- `android/`: Android host application
- `ui/`: frontend shell
- `samples/`: fixtures and exported analysis samples
- `docs/`: design and implementation documents

## 4. Actor Model

The project uses `Actor + Pipeline` together:

- actors isolate mutable state
- stages preserve ordered packet-to-analysis transformation

### 4.1 Actor list

- `SessionCtlActor`
- `TunCaptureActor`
- `RelayActor`
- `FlowActor`
- `AttributionActor`
- `MetricsActor`
- `DetectionActor`
- `AlertActor`
- `StorageActor`
- `UiGatewayActor`

### 4.2 Ownership rules

- the flow table is owned by `FlowActor`
- app attribution caches are owned by `AttributionActor`
- aggregated app metrics are owned by `MetricsActor`
- alert suppression state is owned by `AlertActor`
- no UI component reads mutable Rust state directly

## 5. Event Model

Current shared event types live in `rustprobe-core/src/event.rs`.

### 5.1 Current core events

- `PacketEvent`
- `FlowEvent`
- `AppEvent`
- `AlertEvent`
- `UiEvent`
- `ControlEvent`
- `PipelineEvent`

### 5.2 Planned extensions

The next iteration should add:

- `ObjectEvent`
- `MetricsEvent`
- `StorageEvent`
- `RelayEvent`
- `SessionEvent`

### 5.3 Current forwarding-side event output

When `forwarding mode` is enabled, the app currently emits a lightweight JSONL stream derived from native forwarding logs.

Current fields include:

- `event_seq`
- `session_id`
- `session_started_at_ms`
- `observed_at_ms`
- `timestamp`
- `source`
- `transport`
- `host`
- `port`
- `object_kind`
- `selection_mode`
- `monitored_packages`
- optional single-app attribution fields when running in single-app mode

This output is intentionally smaller than the Rust flow/object snapshots. It exists to preserve basic observability while forwarding is active.

## 6. Data Model

Current shared models live in `rustprobe-core/src/model.rs`.

### 6.1 Current core models

- `FlowRecord`
- `AppIdentity`
- `ObjectRecord`
- `AppMetricsSnapshot`
- `AlertRecord`
- `NetworkEndpoint`

### 6.2 Object model expectations

Objects should be modeled as first-class records with:

- kind
- value
- first seen
- last seen
- hit count
- related app count
- related flow count
- bytes up/down
- risk label

### 6.3 `MAC` constraints

In non-root TUN mode, `MAC` should be treated as metadata with constrained visibility.

Expected sources:

- local interface metadata
- gateway-side metadata when available
- future inferred metadata

Not guaranteed:

- stable remote layer-2 `MAC` capture

## 7. End-to-End Processing Path

The project currently has two real runtime paths.

### 7.1 Capture mode

1. Android requests VPN permission.
2. `RustProbeVpnService` creates TUN.
3. TUN fd is passed through JNI into Rust.
4. `TunCaptureActor` / capture thread ingests packets.
5. `rustprobe-parse` parses IPv4/IPv6/TCP/UDP and extracts DNS/TLS hints.
6. `FlowActor` creates or updates flow state.
7. attribution runtime maps to UID/package/app and may enqueue Android owner queries.
8. object aggregation extracts IP/port/domain metadata.
9. JSONL storage writes flow and object snapshots.

### 7.2 Forwarding mode

1. Android requests VPN permission.
2. `RustProbeVpnService` creates TUN.
3. `LocalSocks5Service` starts local `hev-socks5-server`.
4. native `hev-socks5-tunnel` binds to the TUN fd and forwards traffic through the local SOCKS5 server.
5. Android keeps outbound connectivity while VPN interception stays active.
6. `ForwardingObservationRecorder` tails forwarding logs and emits `forwarding-events.jsonl`.

The main architectural gap is that these two paths are not yet merged into one unified "forward + full Rust analysis" pipeline.

## 8. Android Integration Status

### 8.1 Implemented now

Current Android host already provides:

- Gradle APK packaging with Rust JNI build hooks
- launcher activity
- `RustProbeVpnService`
- app inventory sync into Rust
- single-app / multi-app VPN selection
- owner UID resolution via `getConnectionOwnerUid(...)`
- local SOCKS5 service startup and shutdown
- forwarding-mode status polling and minimal forwarding event recording

### 8.2 Next implementation steps

1. merge forwarding and Rust analysis into one primary path
2. expose runtime mode and health in a real UI instead of a text placeholder
3. add explicit service start/stop and mode-switch controls
4. make forwarding-side events and Rust-side events share a more uniform schema

## 9. UI Integration Plan

### 9.1 Current skeleton

Current UI shell provides:

- Vite + TypeScript placeholder
- HTML entry point
- dashboard placeholder content

The Android activity is also still a placeholder text view. There is no production UI flow yet for browsing flows, objects, or alerts.

### 9.2 Next implementation steps

1. add local transport for UI events
2. render flow list
3. render object aggregation panels
4. render alert stream
5. render app metrics trends

## 10. Storage and Export Plan

Initial export surfaces:

- JSONL flow records
- JSONL alert records
- object aggregation exports
- reconstructed PCAP artifacts

Planned backing stores:

- in-memory caches
- rolling flat files
- optional SQLite index

## 11. Gaps Remaining

The project is no longer just a scaffold. The main remaining gaps are:

- `capture mode` and `forwarding mode` are still split
- forwarding mode does not yet emit full Rust flow/object analysis
- UI transport and UI screens are still mostly placeholder-level
- test coverage is still extremely thin
- storage output is usable JSONL, but not yet a stable long-term event contract across all modes

The dominant work now is integration and stabilization rather than repository scaffolding.
