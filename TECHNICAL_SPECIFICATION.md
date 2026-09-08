# ss-zapret2: technical specification for an optimized successor

## 1. Agent assignment and evidence rules

Build a maintainable, secure, observable successor to ss-zapret2 while retaining its proxy, strategy-management, adaptive pool, diagnostics, and operator workflows. This document specifies behavior, not a line-for-line rewrite. Do not preserve defects merely for compatibility.

Baseline reviewed: Git commit `b53dccbe8f7a72bf8efaadfab9753fede40b65df`.

Repository root: `C:\Users\Admin\Documents\GitHub\ss-zapret2`.

Evidence labels:

- **Implemented:** present in the application execution path; not a claim of successful Linux integration testing.
- **Partial:** supporting code exists, but integration, correctness, or completeness is missing.
- **Historical/documented:** described in documentation, fixtures, tests, or obsolete configuration, but not implemented in the current execution path.
- **Target:** a requirement for the successor, including explicitly proposed corrections.

Use executable code to establish current behavior. Use documentation and tests to recover intent. Resolve contradictions explicitly. Never describe simulated results, traffic estimates, or suspected interference as measured facts. The application provides heuristic DPI-interference detection; it does not prove the identity or capabilities of a network middlebox.

### Evidence map

All repository source references below are absolute paths:

| Source | Responsibility |
|---|---|
| `C:\Users\Admin\Documents\GitHub\ss-zapret2\README.md` | Deployment, scanning tools, extensions, proxy integration, historical cut/intel features |
| `C:\Users\Admin\Documents\GitHub\ss-zapret2\Dockerfile` | Dependencies, supported CPU architectures, bundled upstream resources |
| `C:\Users\Admin\Documents\GitHub\ss-zapret2\docker-compose.yml` | Runtime topology, mounts, capabilities, ports, health check |
| `C:\Users\Admin\Documents\GitHub\ss-zapret2\entrypoint.sh` | Validation, default synchronization, daemon startup and shutdown |
| `C:\Users\Admin\Documents\GitHub\ss-zapret2\config.default` | Reference upstream configuration |
| `C:\Users\Admin\Documents\GitHub\ss-zapret2\config` | Checked-in deployment-specific configuration; differs from defaults |
| `C:\Users\Admin\Documents\GitHub\ss-zapret2\.env.example` | Example operator settings |
| `C:\Users\Admin\Documents\GitHub\ss-zapret2\panel\server.py` | HTTP API, configuration/presets/import, reset monitor, pool switching |
| `C:\Users\Admin\Documents\GitHub\ss-zapret2\panel\pool_manager.py` | Processes, queues, firewall, traffic counters, flow attribution |
| `C:\Users\Admin\Documents\GitHub\ss-zapret2\panel\conn_tracker.py` | HTTPS socket/session and idle tracking |
| `C:\Users\Admin\Documents\GitHub\ss-zapret2\panel\strategy_vectors.py` | Technique classification, scoring, diversified selection |
| `C:\Users\Admin\Documents\GitHub\ss-zapret2\panel\tspu_log.py` | Active unified JSONL event journal |
| `C:\Users\Admin\Documents\GitHub\ss-zapret2\panel\cut_logger.py` | Disconnected detailed-cut journal utility |
| `C:\Users\Admin\Documents\GitHub\ss-zapret2\panel\tspu_intel.py` | Disconnected active/simulated reconnaissance engine |
| `C:\Users\Admin\Documents\GitHub\ss-zapret2\panel\index.html` | Browser dashboard and settings |
| `C:\Users\Admin\Documents\GitHub\ss-zapret2\scripts\custom.d\10-pool-fw.sh` | Legacy alternative firewall owner |
| `C:\Users\Admin\Documents\GitHub\ss-zapret2\strategies\schema.json` | Legacy field-oriented schema, not active API validation |
| `C:\Users\Admin\Documents\GitHub\ss-zapret2\.github\workflows\docker-build.yml` | Multi-architecture image publication |

## 2. Product purpose, users, and scope

### Purpose

Expose Shadowsocks and SOCKS5 access to an isolated Linux container whose outbound traffic is processed by upstream zapret2/nfqws2. Allow operators to choose strategies, run multiple strategies concurrently, observe degradation, and replace ineffective strategies. Support local/home-server and VPS deployments and integration with sing-box, Xray, or equivalent clients.

### Roles

- **Operator:** deploys and configures the service; changes strategies and pool policy; runs permitted diagnostics; inspects and exports events.
- **Proxy client:** uses Shadowsocks or SOCKS5; never needs administrative API access.
- **Automation agent:** manages the service through documented, authenticated API contracts.

### Scope boundaries

- Production packet interception requires Linux NFQUEUE/netfilter support. Windows development is suitable for pure logic and simulated tests only.
- Preserve both TCP and UDP proxy support, HTTP/TLS/QUIC strategy profiles, and user-supplied upstream Lua/fake resources.
- Do not reimplement Shadowsocks cryptography or the upstream nfqws2 packet engine.
- Do not promise universal bypass, seamless recovery of already-reset TCP connections, guaranteed provider identification, or a trained ML model. The existing ML-related feature exports a dataset; it does not train or serve a model.
- HTTP forward proxy support, schema-driven `DESYNC_*` configuration, and generic non-Linux packet interception are not confirmed product capabilities.
- Active diagnostics must be operator-controlled, bounded, and limited to configured/authorized destinations.

## 3. Baseline architecture and lifecycle

Current stack: Python standard library (`ThreadingHTTPServer`, threading, subprocess, JSON, sockets), vanilla JavaScript/CSS/HTML with Canvas, POSIX-style shell scripts, Alpine Linux, Docker Compose. No Python web framework, frontend framework, database service, or package manifest is established in this repository.

Current image defaults: Alpine 3.21; zapret2 v1.0.2; static curl 8.13.0; blockcheckw v0.9.0. Builds support `linux/amd64` and `linux/arm64`. Runtime tools include ipset, iptables/ip6tables, nftables, netcat, conntrack-tools, libcap, Python, and shadowsocks-libev. Installed nftables does not mean the custom pool has an nftables backend.

Traffic path:

1. External SOCKS5 client -> `ss-local` -> loopback Shadowsocks `ss-server` -> destination.
2. Shadowsocks client -> `ss-server` -> destination.
3. Selected outbound traffic -> netfilter/NFQUEUE -> nfqws2 strategy processing.
4. In pool mode, connections are assigned queue marks and related incoming traffic is sent to the corresponding queue.

Startup currently validates five required environment variables, copies missing top-level Lua/fake/example resources without overwriting existing entries, starts upstream zapret2, launches the panel, then launches both proxy processes with UDP enabled. It tails server output into a runtime file and prefixes logs. Shutdown attempts to stop zapret2 and children. The panel auto-starts a pool when it finds `NFQWS2_ENABLE=0` in configuration.

**Target lifecycle:** validate configuration and capabilities before mutation; reconcile exactly one operating mode; start and verify owned child processes; install verified firewall rules; publish readiness only after usable proxy and strategy state exists. Handle SIGTERM/SIGINT, reap descendants, bound shutdown, and clean only owned resources. Missing optional diagnostics must produce degraded diagnostics, not a false healthy state or a proxy outage.

## 4. Functional requirements

### FR-01 — Deployment and proxy service

- Preserve configurable Shadowsocks port, password, encryption method, socket timeout, verbosity, and SOCKS5 port.
- Examples currently use ports 8388/1080 and `chacha20-ietf-poly1305`; the example password is not a safe production default.
- Keep TCP and UDP bindings explicit. Bind proxy and administrative host ports to loopback by default; document opt-in exposure and authenticated remote administration.
- Preserve Docker bridge isolation. An external application network must be optional, not a prerequisite for a fresh installation.
- Preserve extension mounts and operator host-name overrides through Compose `extra_hosts`.
- Health must distinguish process liveness, local listener readiness, firewall/queue readiness, and external connectivity. Internet test failure alone must not cause an uncontrolled container restart loop.

### FR-02 — Configuration and classic mode

**Implemented:** read raw config and extract `NFQWS2_OPT`; replace that block while retaining other lines; back up the previous config to `.bak`; optionally restart daemons; apply a named preset; retrieve backup text; restart upstream daemons.

**Target:**

- Accept existing single-line quoted, multiline quoted, and repository preset-style blocks through a tested parser. Preserve unrelated settings and comments.
- Validate before saving; serialize concurrent writes; use atomic replacement where supported by the deployment layout; explicitly handle single-file bind mounts where rename replacement is unsuitable.
- Distinguish saved configuration from successfully applied configuration. Return restart failures accurately; support rollback to the last known-good revision.
- Treat upstream shell-sourced configuration and Lua as privileged operator content. Never source untrusted import text. Safely serialize allowed values; reject shell expansions, escaping errors, and unexpected executable constructs.
- Classic mode uses one upstream-managed daemon. Pool mode disables the upstream daemon and conflicting custom hooks. Switching modes is transactional and restores the prior mode on failure.
- `mode="single"` is accepted as a setting in current code but is not a demonstrated separate control path. Define single-slot pool semantics explicitly rather than silently accepting ineffective settings.

### FR-03 — Strategy catalog and import

**Implemented:** sorted discovery of `.conf` files; name from filename; description from first comment; raw options and `has_nfqws`; import JSON into generated preset files. Empty/legacy option blocks are excluded from automatic pool selection.

Import contract:

```json
{
  "domain": "example.com",
  "name_prefix": "example",
  "strategies": [
    {
      "args": "--filter-tcp=443 --filter-l7=tls --lua-desync=multisplit:pos=2",
      "protocol": "tcp",
      "success_rate": 0.95,
      "median_latency_ms": 120,
      "median_speed_kbps": 5000
    }
  ]
}
```

Legacy input aliases: top-level `prefix`; per-strategy `nfqws_opt`. Missing prefix falls back to domain with dots replaced by underscores, then `imported`. Current naming is `<prefix>_001.conf`, etc. Current import prepends TCP/443 and TLS filters if neither TCP nor UDP filter is present, and places metadata in a comment. Return saved names and per-item errors.

**Target corrections:** validate types, size, counts, names, path containment, numeric metadata, supported engine syntax, and conflicting filenames. Never overwrite silently. Keep import validation separate from activation. Do not infer TCP for explicitly UDP strategies. Retain metadata as structured data and raw options as lossless text. Reject or clearly flag unsupported legacy presets; do not invent a translation from `DESYNC_*`.

Bundled catalog: `disorder.conf` uses obsolete fields without `NFQWS2_OPT`; `nfqws-youtube.conf` contains HTTP, YouTube TLS, Discord-update TLS, generic TLS, and QUIC profiles. The latter is the only bundled pool-eligible preset. A default pool size of three therefore does not mean three useful bundled strategies exist.

### FR-04 — Pool and worker management

- Maintain up to 10 ordinary slots, each with stable slot ID, queue number, strategy, options, PID, start time, health (`unknown/healthy/unhealthy`), process liveness, and routing inclusion state.
- Compatibility queue allocation starts at 300; ordinary slots conventionally use `300 + index`. Temporary candidates use unused queues within the reserved range. Reject exhaustion and collisions.
- Support enable/disable, add/remove, manual slot strategy replacement, background checking, and watchdog recovery.
- Current default target size is three, limited by available eligible strategies and maximum slots. Target must reconcile desired size after settings change and allocate free IDs correctly after removals.
- Start nfqws2 with explicit argument arrays, queue, fwmark, unprivileged worker user (`nobody` currently), and the upstream library/antidpi/auto Lua initialization scripts. Preserve `NFQWS2_EXTRA_ARGS`, but validate reserved-option overrides.
- Capture bounded per-slot stdout/stderr and lifecycle events. Existing startup retries three times with short delays; replacement and watchdog need bounded backoff and observable failure states.
- A process that merely survives startup is not a verified effective strategy. Avoid unconditional debug logging in production.

### FR-05 — Firewall and connection affinity

**Implemented intention:** a `ZAPRET_POOL` mangle chain restores the low 16 connmark bits; already-assigned traffic is routed to its queue; unassigned traffic is randomly distributed with equal expected share and its queue mark saved. Incoming TCP/UDP restores the same mark. All matching packets, not just the first N, are eligible for processing. `DESYNC_MARK` prevents loops. ipset sets determine eligible TCP/UDP destinations and `nozapret` exclusions. Queue rules use `--queue-bypass`.

**Target invariants:**

1. One component owns pool rules. Retire or explicitly isolate the legacy custom hook, whose rules differ from the Python implementation.
2. Update rules atomically or with a verified rollback plan. Check command errors and use bounded timeouts/lock waits.
3. Never flush built-in INPUT or delete unrelated queues/rules. Use owned chains and tagged jump rules for both directions.
4. Preserve marks outside the allocated mask; keep probe/anti-loop bits separate from queue identity.
5. Never route to an unready queue. Explicitly define behavior when every candidate fails: configurable direct fail-open or fail-closed, visibly reported; do not silently re-admit a known-bad strategy.
6. Removing a slot or replacing its process must specify what happens to existing marked flows. Prefer draining old workers for established flows with a bounded deadline and new queue generation for new flows. Do not promise preservation when the old worker/state cannot be retained.
7. IPv6 routing must respect the configured IPv6 policy. Missing ipsets must not silently broaden interception or bypass required exclusions.
8. Probe isolation must select only diagnostic flows, never redirect all client traffic to a test queue.

### FR-06 — Connectivity checks, selection, and rotation

**Current behavior:** periodic watchdog/check loop; default interval 60 seconds; failure threshold two; nominal settle setting six seconds; default test URL `https://www.youtube.com`. Whole-pool checks run curl HEAD via `socks5h` and accept HTTP 2xx/3xx with successful exit. On success, all live slots are marked healthy. On failure, only already-suspect slots are tested. The isolated test temporarily redirects broad POSTROUTING traffic. A replacement excludes the old slot, tries up to three shadow candidates, then replaces/re-enables it. A shadow currently passes after two observed packets or one successful general-pool curl; neither establishes candidate-specific success. If all fail, the old unhealthy strategy is restored to routing.

**Target:**

- Implement explicit `disabled/starting/idle/checking/replacing/healthy/degraded/stopping/error` transitions and one serialized mutation coordinator.
- Whole-pool reachability is not evidence that every member works. Maintain per-slot evidence with timestamp, scope, destination, and reason.
- Test candidates using traffic pinned to that candidate; validate application-level response and optionally sustained transfer. Packet arrival alone is not success.
- When a pool test fails without pre-existing suspects, schedule bounded slot diagnosis rather than return healthy.
- Separate crash recovery, connectivity failure, suspected cut, and operator-directed rotation.
- Preserve healthy slots during diagnosis, avoid overlapping checks/rotations, and cap concurrency and deadlines.
- On a confirmed unhealthy slot, exclude new assignments promptly; choose diversified candidates and publish a degraded state until a replacement passes. Optional fast replacement may use an already-validated standby, not an untested candidate labeled healthy.
- Keep default cut-triggered rotation enabled, 30-second rotation cooldown, configurable lifetime window, and reset confirmation. Record why a trigger was skipped, suppressed, or acted on.
- No guaranteed zero-downtime claim for existing sessions. Measure new-connection recovery separately from existing-flow survival.

### FR-07 — Strategy families and adaptive scores

**Implemented:** heuristic classification of legacy `--dpi-desync` modes into segmentation, fake, IP fragmentation, IPv6 extensions, and TCP-state families; optional fooling, TTL, fake-payload, split-position and L7 components. Unknowns fall back to `other`. Scores clamp to [-20, 20]; success +1, failure -2, selection decay x0.98; a suspected live-cut family receives -3 and 600-second default cooldown. Rank non-implicated families first, then family score, then strategy score. Diversify batches across families before picking siblings. Hazard is observed failures/cuts divided by total outcomes, not a calibrated probability.

**Target:** classify current `--lua-desync` syntax and multiple profiles, not just legacy syntax. A strategy may contain several techniques and destination scopes. Return canonical server-side classification to the UI; remove competing browser classification. Persist event IDs and scoring revisions; deterministic replay must reproduce live scores, cooldowns, and decay. Keep raw evidence and scope; do not penalize an entire family on a weakly attributed idle observation. No-history must differ from a measured zero score.

### FR-08 — Reset monitor and session-cut detection

**Implemented reset monitor:** tail the Shadowsocks server log, count `Connection reset by peer` versus `close a connection`, use a 60-second window, minimum five events, and degradation ratio >=0.4. Maintain totals and last reset time; trigger on transition into degradation; pass reset timestamps to the tracker. Buffer is limited to 500 events.

**Implemented tracker:** poll `/proc/net/tcp` and `/proc/net/tcp6` every two seconds for non-loopback ESTABLISHED outbound remote port 443, excluding service local ports. Despite `yt_active` naming, it does not identify YouTube domains. It tracks an aggregate period during which any eligible socket exists. After five seconds without eligible sockets, it checks a 30–60-second session-duration window and optional recent reset confirmation (10-second window plus polling slack). Idle detection compares socket tx/rx queue occupancy, with five unchanged ticks, at least 15 seconds lifetime, and nominal ten-second idle threshold.

**Historical:** per-flow FIN-vs-RST classification and epidemic detection (four short reset deaths in 60 seconds) are described in the README but not implemented by this tracker. Fail-fast rotation is expected by stale tests but conflicts with current shadow replacement.

**Target:**

- Track stable per-flow identity and actual forward progress using available byte/packet counters; retain source and confidence. Socket queue occupancy is not transferred-byte volume.
- Do not interpret idle keepalive, empty socket queues, normal FIN, missing procfs, clock adjustment, or one unrelated reset as definitive interference.
- Use monotonic timing for durations and UTC timestamps for records. Recover from log truncation/rotation and unavailable procfs without inventing events.
- Support separate suspected reset-cut, stalled-flow, and optional epidemic detector policies; implement the documented epidemic workflow as an explicit feature with its own thresholds and tests.
- Emit a structured event carrying flow tuple, time, lifetime, termination evidence, counters, slot attribution, monitor snapshot, and confidence. Suppress duplicates and keep diagnostic collection independent of whether rotation is enabled.
- Prefer exact conntrack mark attribution and its CLI fallback. Label unresolved attribution and most-active-slot fallback; never present the latter as exact.

### FR-09 — Traffic and connection observability

Preserve queue totals/deltas, bytes, packets, pps, throughput, activity/share, and measurement source. Current sources are iptables chain counters and nfnetlink queue data; when bytes are absent, a 1500-byte-per-packet approximation is used and flagged. Validate the actual kernel field semantics before treating an nfnetlink field as a cumulative packet counter.

Preserve Shadowsocks/SOCKS connected-client summaries and tracker connection counts, but name each metric by its real scope. Support IPv4/IPv6 parsing and conntrack original/reply per-flow counters. Do not label all HTTPS sockets as YouTube sessions or queue-level counts as per-flow traffic.

**Target:** sample counters once per fixed interval and publish immutable snapshots. HTTP reads, log enrichment, and rotation decisions must not advance/reset shared delta baselines. Include sample timestamp, interval, units, stale state, counter reset, and estimated/unavailable flags.

### FR-10 — Journals and persistence

**Implemented active journal:** unified JSONL events `cut`, `idle`, `degraded`, `info`, `test_ok`, `test_fail`, `rotation`; timestamp and contextual payload; bounded 10,000-event memory buffer; recent-event API. Pool panel log separately retains 300 messages. Slot tails retain 300 lines.

**Partial:** detailed cut logger supports record/list/export/clear and 500 buffered entries but is not instantiated by the current server. README cut endpoints are absent. Score restoration calls recent in-memory journal events after startup, but journal initialization counts disk lines without loading their contents, so persistence does not actually restore historical scores.

**Target:**

- One versioned event schema with stable IDs; correlated cuts, probes, tests, and rotations. Provide filtered recent records, cursor pagination, NDJSON export, and authorized explicit clearing.
- Preserve full diagnostic context: flow/slot/strategy, counters and confidence, monitor state, bounded panel/worker/proxy log tails, and fallback reasons. Redact credentials and configure sensitive endpoint retention.
- Use durable append, bounded queues/buffers, configurable retention and actual deletion of expired backups. Baseline defaults intend 2 MiB files and three backups; current rotation loops can leave an additional stale backup.
- Restore valid retained events and/or checkpoints at startup; handle partial/malformed final lines. Never silently claim disk persistence when writes fail.
- Specify whether export/clear includes rotated history; target defaults should cover the requested journal's retained history, not only the current file.
- Persist pool policy and desired assignments separately from engine configuration, plus validated scoring state. Current UI settings are primarily in memory and should not be mistaken for durable configuration.

### FR-11 — TSPU reconnaissance and dataset export

**Partial/disconnected:** a substantial `TspuIntel` module exists, but current server startup does not create it, cut callbacks do not invoke it, and the documented intel routes are absent.

Preserve its intended optional asynchronous workflow: accepted cut -> bounded probe job -> independent dataset JSONL -> correlated companion journal record. Support manual one-shot probe, status, list, export, clear, runtime configuration, cooldown, and one-running-job limit. Defaults: enabled in the module, 30-second cooldown, 1800 ms nominal budget, max TTL 30, SNI `youtube.com`, dry run false. Lack of raw capability currently enables a deterministic simulator; target must clearly label it and separate simulated datasets from production evidence.

Dataset blocks to preserve and version:

| Block | Required contents |
|---|---|
| `environment` | ASN/name with lookup provenance, connection-type and target-host classification, uncertainty |
| `session_profile` | Session lifetime, sent/received bytes, sent packets, termination type; unknown counters remain null |
| `tspu_network_metrics` | Estimated interference hop, destination hop, distance delta, ingress TTL estimate, TTL map and summary |
| `tspu_l7_vulnerabilities` | Split-position 2/5 results, overlap/reorder outcomes, fake-TLS/random validation, QUIC/control observations, per-probe connection/RST/ServerHello evidence, confidence, RTT, RST fingerprint, TCP anomaly and channel-quality results |
| `strategy_context` | Strategy name/raw options, pre-event score and whether score was known |

Metadata includes dataset version, cut ID, target and SNI actually used, UTC timestamp/time-of-week, elapsed time, mode, partial/degraded reasons, and context-field availability.

Target controls: restrict destinations; bound DNS, socket, sniffer and worker lifetimes under one deadline; exclude marked probes from pool processing and cut detection; cancel/clean up jobs on shutdown. Prefer real per-flow counters, not aggregate queue traffic assigned to one session. Distinguish target ASN from access-provider ASN—the current lookup uses destination IP even though fields are named `isp_*`. No-response, failed handshake, no raw capability, and confirmed negative probe outcomes must remain distinct. Validate that protocol probes are valid enough to support their advertised conclusions, especially QUIC. DNS resolver failover/cache and ASN lookup fallback must expose provenance, not fabricated provider identity.

### FR-12 — Browser panel

**Implemented:** Russian-language dark dashboard titled “Evasion Landscape”; Landscape and Settings tabs; live strategy/cut/health/connection totals; pool/monitor indicators; enable/disable/check/add controls; Canvas graph of strategy attributes, relationships and status; zoom/reset/pan, hover information, selection/detail, vector focus and score/hazard display; activity/event view and client-side log clearing; pool and detector configuration; curl URL/port test and command preview; raw config view; JSON import with prefix; strategy list.

Current polling: pool/monitor every 3 s, traffic every 2 s, vectors/log every 4 s, catalog every 15 s. Some JavaScript functions are defined twice; later definitions replace earlier ones. Current visual classifications are heuristic, not a measured network topology.

**Target:** retain operator workflows, not exact pixel layout. Add accessible table alternatives, keyboard navigation, responsive sizing, loading/error/stale states, explicit unknown/simulated indicators, durable-save feedback, and confirmations for disruptive/destructive actions. Expose manual slot set/remove and classic-mode editing/backup workflows already available through the API. Restore cut/intel views only when their backend is actually integrated. Client-side clear must be labeled separately from journal deletion. Escape untrusted strategy/log text; never inject it into HTML unsafely. Pause/reduce polling and animation in hidden tabs, prevent overlapping requests, and use one canonical server classification.

### FR-13 — External tools and extensions

Preserve access to upstream `blockcheck2.sh`, bundled blockcheckw, static curl, custom scripts, Lua resources, and fake payload files. Document parameterized domain/protocol scanning (HTTP, TLS 1.2/1.3, QUIC), result import, independent proxy connectivity checks, and sustained video-like transfer tests.

Scanning is a CLI/operator workflow, not currently an integrated web scanner. Provide a maintenance procedure that suspends pool auto-recovery and conflicting interception for the duration of upstream scanning, then restores the prior state. Stopping upstream zapret2 alone is insufficient when the independent pool controller is active. Do not automatically execute downloaded scripts or arbitrary user commands from the panel.

## 5. API compatibility inventory

The following routes are implemented in `C:\Users\Admin\Documents\GitHub\ss-zapret2\panel\server.py`. Keep compatibility adapters or document a versioned migration. Current responses have inconsistent error handling; target validation/authentication takes precedence over retaining unsafe behavior.

| Method/path | Request | Current result/purpose |
|---|---|---|
| GET `/` | — | HTML panel |
| GET `/api/config` | — | `path`, `raw`, `nfqws_opt` |
| GET `/api/strategies` | — | `strategies[]`: name, file, description, options, eligibility |
| GET `/api/connections` | — | Proxy client connection summary |
| GET `/api/pool/status` | — | Policy, state, slots, tracker, scores, hazard, health totals |
| GET `/api/pool/log` | — | `log[]` of panel events |
| GET `/api/pool/vectors` | — | `vectors[]`: families, member names, score, hazard, implicated |
| GET `/api/pool/traffic` | — | Queue-keyed traffic measurements |
| GET `/api/monitor/status` | — | Reset/close statistics and thresholds |
| GET `/api/tspu-log` | `n=200`, optional `event` | `events[]`; current ad-hoc query parsing needs replacement |
| POST `/api/apply` | `preset` | Apply options, backup, restart, return raw/options/restart result |
| POST `/api/pool/enable` | `enabled` (currently defaults true) | Change operating mode; return status |
| POST `/api/pool/configure` | Pool settings | Update policy and synchronize tracker lifetime/reset settings |
| POST `/api/pool/slot/set` | `index`, `strategy` | Replace slot strategy |
| POST `/api/pool/slot/add` | `{}` | Add selected strategy |
| POST `/api/pool/slot/remove` | `index` | Stop/remove slot |
| POST `/api/pool/check` | `{}` | Schedule background check |
| POST `/api/monitor/configure` | `window_sec`, `threshold`, `min_events` | Configure reset monitor |
| POST `/api/save-nfqws` | `value`, `restart=false` | Save options, optionally restart |
| POST `/api/restart` | `{}` | Restart command rc/stdout/stderr |
| POST `/api/test-curl` | `url`, `socks_port` | `ok`, `rc`, `output` |
| POST `/api/import-json` | FR-03 object | `ok`, `saved[]`, `errors[]`, message |
| POST `/api/backup` | `{}` | Retrieve backup text; **not** restore |

Accepted pool-setting keys: `mode`, `pool_size`, `check_interval`, `fail_threshold`, `settle_time`, `test_url`, `cut_rotate_enabled`, `cut_min_sec`, `cut_max_sec`, `cut_cooldown`, `cut_require_reset`, `vector_cooldown_sec`. Current acceptance is not evidence that every setting has operational effect.

**Documented but absent:** GET `/api/cuts`, GET `/api/cuts/export`, POST `/api/cuts/clear`; GET `/api/intel/status`, GET `/api/intel/list?limit=50`, GET `/api/intel/export`, GET `/api/intel/clear`, POST `/api/intel/probe`.

**Target additions:** implement the missing cut/intel workflows; make all destructive operations POST/DELETE, never GET. Add authenticated readiness/capability and job-status endpoints. Publish machine-readable versioned request/response schemas with bounds, enums, timestamps, units, pagination and error codes. Long jobs return job IDs, not blocking HTTP requests. Validate JSON content type/body limits; use 400/401/403/404/409/413/422/503 consistently as appropriate. Never report success when activation or durable writing failed.

## 6. Configuration and storage contract

| Setting/group | Existing default or purpose | Successor requirement |
|---|---|---|
| `SS_PORT`, `SOCKS_PORT` | Required; examples 8388/1080 | Validate 1–65535 and collisions |
| `SS_PASSWORD` | Required | Secret input; no logging or unsafe default |
| `SS_ENCRYPT_METHOD`, `SS_TIMEOUT` | Required; examples chacha20-ietf-poly1305 / 300 | Validate against installed engine |
| `SS_VERBOSE` | 0 | Expose observability impact |
| `PANEL_PORT` | 1888 | Add explicit secure bind/auth policy |
| `NFQWS2_EXTRA_ARGS` | Empty | Validated privileged options |
| `NF_CONNTRACK_PROC` | Module defaults `/proc/net/nf_conntrack` | Must point to connection entries, not a capacity sysctl |
| `DESYNC_MARK` | `0x40000000` | Single source of truth for config, workers and firewall |
| `CUT_LOG_PATH` | Historical detailed-cut path | Retain migration support; currently not wired to server |
| `TSPU_LOG_PATH`, `CUT_LOG_DIR` | Unified journal location selection | Document precedence and persistence |
| `TSPU_INTEL_ENABLE/COOLDOWN/BUDGET_MS/TTL_MAX/SNI/DRY_RUN` | true/30/1800/30/youtube.com/false in module/example | Explicitly pass into container and integrate |
| `TSPU_INTEL_DNS` | Module default 1.1.1.1 | One validated configurable resolver policy |
| `TSPU_INTEL_MARK`, `SCANNER_FWMARK` | Probe marks; selection differs across helpers | Unify precedence and isolation |

Preserve container data locations or supply migrations: `/opt/zapret2/config`, `/opt/zapret2/strategies`, `/opt/zapret2/lua`, `/opt/zapret2/files/fake`, upstream custom/example script directories, `/opt/zapret2/logs`. Runtime-only PID/slot/queue/server-log state belongs under `/run/zapret-pool` and must be reconstructible. Container paths are Linux absolute paths, distinct from repository paths.

Retain passthrough of upstream ipset sizing, hostlist thresholds, resolver threading, list compression, packet-selection settings, filter mode, IPv6 policy, flow-offload policy and firewall application flags. Clearly distinguish classic-mode packet limits from pool rules that currently do not use those limits. Never overwrite a deployment's current `config` with `config.default` without explicit migration approval.

## 7. Confirmed gaps and prioritized corrections

| Priority | Evidence and issue | Required action |
|---|---|---|
| P0 | Panel listens on all interfaces; Compose publishes panel publicly; no authentication in handler | Secure default exposure, authenticated administration and audit |
| P0 | Preset names/import prefixes are used in filesystem paths without containment; shell-sourced options are writable | Block traversal, validate/serialize privileged content, bound input |
| P0 | Firewall rebuild flushes entire mangle INPUT; rule construction is non-transactional | Dedicated owned chains, verified atomic reconciliation |
| P0 | Shadow packet count/general curl can approve wrong worker; all-failed restores old bad strategy | Candidate-pinned checks and explicit fail-open/closed policy |
| P1 | Diagnosis compares `bad_slots + good_slots < len(suspects)` | Correct list-versus-integer error and exercise multi-suspect branch |
| P1 | Whole-pool success marks every worker healthy; fresh failure can have no suspects | Per-slot evidence and meaningful degraded state |
| P1 | Cut/intel routes and wiring missing; tracker `pool_ref`/`monitor_ref` not assigned in startup | Integrate structured event pipeline and test end-to-end |
| P1 | Journal startup counts lines but does not reload event buffer | Durable scoring replay/checkpoint recovery |
| P1 | Reset/session and idle heuristics overclaim individual cuts/YouTube identification | Per-flow evidence, uncertainty, better false-positive controls |
| P1 | Server-side classifier targets legacy syntax while bundled strategies use Lua desync | Canonical version-aware classification |
| P1 | Traffic reads mutate a shared delta baseline | Scheduled sampler and immutable snapshots |
| P1 | Compose sets conntrack source to `/host/proc/sys/net/netfilter/nf_conntrack_max` | Use actual connection data and namespace-aware fallback |
| P1 | Duplicate DNS entries, hard-coded private resolver and required external network | Portable default topology and explicit overrides |
| P1 | Most intel example variables are not forwarded by Compose | Test effective environment; `.env` substitution alone is not forwarding |
| P1 | Background shell pipelines obscure actual child PIDs; settings mostly volatile | Reliable supervision and durable desired state |
| P2 | Duplicate browser functions, repeated polling/parsing, unconditional worker debug | Simplify frontend and reduce idle/log overhead |
| P2 | CI path filter covers only Dockerfile/entrypoint, not panel or tests | Test/build on all relevant source changes |
| P2 | Dependency archives lack explicit integrity checks; runtime package uses edge/testing | Pin and verify artifacts; document supply-chain dependencies |

## 8. Target architecture and optimization objectives

Prefer the proven existing stack initially: standard-library Python, vanilla browser code, upstream tools, Docker. Any new framework/library requires an explicit dependency decision and measured benefit. A rewrite into another language is not required.

Separate interfaces for configuration/strategy repository, process supervisor, firewall adapter, telemetry sampler, detector, scoring policy, pool coordinator, diagnostic job runner, journal, and HTTP/UI. Inject clocks, filesystem/process adapters and network capabilities so unit tests do not need privileged execution. Remove import-time global initialization of runtime directories/loggers.

Use one serialized control-plane mutation queue; bounded background work; immutable status snapshots; explicit capability reporting. Cache parsed strategies by revision/content hash and eliminate redundant per-request iptables/procfs scans. Decouple journaling and diagnostic work from rotation latency without silently dropping critical events. Keep pure scoring/detection independent from subprocesses.

Proposed measurable acceptance targets (engineering goals, not measured baseline claims):

- Status reads never execute firewall mutation or external network probes; p95 <=200 ms under 10 concurrent readers on a documented reference host.
- At most one telemetry collection cycle per configured interval regardless of browser count; no overlapping identical polls/jobs.
- At most one pool mutation transaction and one intel job at a time by default; bounded queued requests.
- Nominal intel deadline 1800 ms, hard completion/cleanup envelope <=2000 ms for controlled test cases; partial results include timeout reasons. If infeasible, revise the budget explicitly rather than silently exceed it.
- Warm operator UI reflects state within one sampling/poll interval plus request latency; no fabricated healthy fallback on fetch errors.
- No unbounded memory, thread, file-descriptor, log-disk or queue growth during a 24-hour soak.
- Compare baseline/new CPU, RSS, startup time, API latency, firewall update duration, packet drops, throughput and recovery time for 1/3/10 slots. Publish hardware/workload/results; do not claim an arbitrary optimization percentage before measuring.

## 9. Security and operational requirements

- Authenticate and authorize administrative reads/writes; support TLS termination and CSRF protection appropriate to the authentication mechanism. Reject browser-origin misuse; restrict CORS.
- Proxy credentials and arbitrary diagnostic destinations must not become an unauthenticated API surface. Restrict test URLs, protocols, redirects and resolved destinations according to operator policy to prevent SSRF/local-service access.
- Run UI/API without unnecessary packet privileges where practical; isolate privileged firewall/raw-socket operations. Do not blanket-grant capabilities to a general Python interpreter without an explicit threat model.
- Validate all subprocess inputs; no user-provided shell commands. Redact secrets from command lines/log exports where feasible.
- Limit request sizes, import sizes, history/export sizes and diagnostic rate; record destructive actions and policy changes.
- Honor existing license and upstream attribution in the successor. Keep extension execution an explicit privileged feature.

## 10. Validation baseline and acceptance plan

### Audit results

Executed on Windows with Python 3.14.7:

```powershell
python -m unittest discover -s "C:\Users\Admin\Documents\GitHub\ss-zapret2\panel" -p "test_*.py"
```

Result: **77 tests run, 5 failures, 7 errors** (65 passed). The audit redirected the unified journal to a temporary path and used UTF-8 output. Seven fail-fast test errors reference missing `server.cut_logger`. Four failures concern conntrack slot attribution/fallback; one concerns TCP URG-pointer parsing (`0` instead of `513`). Tests encode mixed historical and current expectations and are not an unquestionable source of truth. Classify each failure before updating tests; do not delete coverage to obtain green results.

Docker was not available on the audit host. No Linux firewall, raw-packet, real proxy traffic, image build, or browser end-to-end validation is claimed by this specification.

### Required test matrix

1. **Configuration/catalog:** all existing preset formats; malformed quotes; preserved unrelated lines; safe serialization; traversal/symlink escape; duplicate names; import collisions and limits; invalid types; backup/apply rollback; single-file bind mount behavior.
2. **Workers/pool:** zero eligible strategies; fewer strategies than requested slots; 1/3/10 workers; crash/retry; queue conflicts/exhaustion; non-contiguous IDs; size changes; concurrent enable/disable/set/check; shutdown during replacement.
3. **Firewall in isolated Linux namespace:** correct TCP/UDP and IPv4/IPv6 policy; sticky queue marks; upper-bit preservation; exclusions; incoming symmetry; unchanged unrelated rules; crash/rollback; no ready queues; old-flow drain; no interception loop; probe-only routing.
4. **Health/rotation:** healthy pool with one bad member; no initial suspects; candidate-pinned positive/negative tests; multi-suspect path; all-candidates fail; cooldown and overlapping triggers; maintenance mode; sustained transfer rather than HEAD-only evidence.
5. **Detection:** actual progress versus empty queues; normal FIN; unrelated reset; short reset epidemics; polling gaps; disappearing procfs; log rotation/truncation; IPv6/mapped addresses; per-flow attribution; false-positive suppression and unknown state.
6. **Scoring:** Lua/legacy/multi-profile parsing; unknown families; deterministic tie order; diversification; clamping/decay/cooldown; historical replay equal to live state; missing/renamed strategy; no duplicate scoring for one correlated cut.
7. **Logs/data:** concurrent record IDs; bounded retention; restart replay; rotated history export/clear; malformed final record; disk full/read-only; redaction; measurements versus estimates/null/simulation.
8. **Intel:** no privileged/network side effects in simulator; capability fallback; DNS/ASN provenance; target/SNI correlation; timeout cancellation; socket/thread cleanup; raw packet checksum/URG fields; valid TLS/QUIC controls; cut-to-job-to-journal correlation.
9. **API/UI:** every implemented/added route; auth and unauthorized mutation; validation/errors; body limits; job lifecycle; XSS/CSRF/SSRF cases; both tabs and all actions; inaccessible backend; stale state; hidden-tab throttling; multiple browsers do not change telemetry deltas.
10. **Deployment/soak:** clean clone without external networks; persistent volumes; missing secrets; both CPU architectures; signal handling; readiness; dependency integrity; 24-hour load/retention run; upgrade/rollback with existing user resources.

All privileged tests must run in disposable Linux containers/namespaces, never against the developer host firewall. External probing must use controlled fixtures or explicitly configured test endpoints.

## 11. Implementation sequence and delivery gates

1. **Characterize:** freeze API fixtures, configuration examples and baseline metrics; classify current failures and historical contracts. Produce capability and threat-model decisions.
2. **Secure foundation:** safe configuration/catalog operations, authentication and loopback defaults, portable deployment, supervisor and structured error model.
3. **Correct data plane:** single firewall owner, transactional updates, stable allocation/affinity and process lifecycle; prove isolated namespace invariants before enabling adaptive behavior.
4. **Reliable telemetry/control:** fixed-interval sampler, per-flow detector events, deterministic scoring and serialized pool coordinator; candidate-pinned testing and explicit failure policy.
5. **Durability/diagnostics:** unified journal, score/policy recovery, correlated cut records and optional bounded reconnaissance; versioned API/export schemas.
6. **UI and performance:** consolidated frontend, complete workflows and accessibility, measured resource improvements, multi-browser and soak testing.
7. **Release:** migration/rollback guide, configuration reference, architecture/runbook, CI tests and multi-architecture builds; documented limitations and benchmark report.

Required agent deliverables: complete runnable source; tests and fixtures; versioned API/data schemas; safe example environment and Compose deployment; migration tooling or explicitly documented manual migration; operator runbook; test/benchmark report; inventory of preserved, corrected, deprecated and deferred features. No placeholders presented as completed features.

### Product decisions to confirm before finalizing behavior

- Default all-strategies-failed policy:  Fallback policy upon total strategy failure: fail-closed.
- Whether production active reconnaissance is opt-in (recommended) or enabled by default; authorized destination policy.
- Preferred rotation policy: Preferred rotation policy: rapid replacement with a warm/proven standby. Upon exhaustion of all verified standby strategies, the system must not cyclically reinstate legacy, known-bad strategies. Instead, it must immediately activate the global fail-closed policy, completely isolating the queue traffic until manual intervention occurs..
- Administration authentication method: a simple token/password specified via environment variables. A strict rate-limiting mechanism must be implemented on the API side to mitigate token brute-force vectors..
- Epidemic detection and cut/intel route recovery are included in the initial release. Epidemic detection (triggering at 4+ resets within 60 seconds) must operate at the per-flow conntrack isolation layer (FR-08). An "outbreak" event must initially spawn an isolated, non-blocking connectivity check, and trigger firewall reconfiguration only after explicit confirmation to mitigate false-positive mass rotations.
- Full IPv6 (Dual-Stack) support is required at the pool and conntrack layers. The firewall backend must strictly utilize nftables; no iptables rules shall be generated..