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
- pass TUN file descriptor to Rust via JNI later

### 2.2 Transport and VPN layer

Responsibilities:

- create TUN interface
- exclude relay sockets with `protect()`
- maintain Android-compatible network access while traffic is inspected

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

1. Android requests VPN permission.
2. `RustProbeVpnService` creates TUN.
3. TUN fd is passed to Rust core.
4. `TunCaptureActor` ingests packets.
5. `rustprobe-parse` parses IPv4/IPv6/TCP/UDP.
6. `FlowActor` creates or updates flow state.
7. `AttributionActor` maps to UID/package/app.
8. object aggregation extracts domain/URL/IP/port/`MAC` metadata.
9. `MetricsActor` computes app-level load signals.
10. `DetectionActor` checks malicious outbound and mining indicators.
11. `StorageActor` records exportable artifacts.
12. `UiGatewayActor` pushes summaries to UI.

## 8. Android Integration Plan

### 8.1 Current skeleton

Current Android host provides:

- Gradle project layout
- launcher activity
- placeholder VPN service
- manifest and theme files

### 8.2 Next implementation steps

1. add JNI bridge for Rust startup
2. hand TUN file descriptor to Rust
3. add app allow/deny configuration
4. add runtime status display
5. add service start/stop controls

## 9. UI Integration Plan

### 9.1 Current skeleton

Current UI shell provides:

- Vite + TypeScript placeholder
- HTML entry point
- dashboard placeholder content

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

The scaffold is now structurally complete for early development, but still missing:

- real TUN fd handoff
- real `pnet` packet parsing
- real attribution on Android
- real UI transport
- real persistence format implementation

Those gaps are now implementation gaps, not layout gaps.
