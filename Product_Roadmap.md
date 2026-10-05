# Advanced open-source NetCut alternative — recommended design

After reviewing NetCut’s own documentation, relevant RFCs, current router APIs, and actively maintained open-source networking projects, I would **not** build a modern NetCut clone around ARP spoofing**.** I would build a **network-observability + policy-control platform** where ARP is one discovery/security signal, while actual blocking, quarantine, VLAN movement, ACLs, and rate limiting happen at legitimate enforcement points.

The resulting product would be closer to **“NetCut + lightweight NAC + bandwidth monitor + LAN IDS + multi-vendor router controller.”**

## 1. What NetCut actually does

### Verified facts

Arcai’s own NetCut documentation explicitly says NetCut manages networks “based only on ARP protocol,” discovers IP/device-name/MAC mappings, can turn LAN devices on/off, and includes protection against ARP spoofing. Current Arcai pages also advertise unknown-device detection, speed control, access blocking, scheduling, network locking and historical records. [arcai.com](https://arcai.com/?p=18)

Its defensive mode is documented in more detail: NetCut says it tries to preserve correct ARP mappings for the gateway and protected host, watches for spoofed ARP traffic, and responds with corrective ARP information. [arcai.com](https://arcai.com/category/support-documents/page/4/)

ARP itself is simply the IPv4 mechanism for resolving network-layer addresses to Ethernet addresses; it predates modern authenticated LAN security. RFC 5227 later added IPv4 conflict probing/detection behavior but does not turn ARP into an authenticated protocol. [RFC Editor](https://www.rfc-editor.org/info/rfc826/)

### What is inference, not verified NetCut implementation

Arcai does **not** publicly document enough packet-level detail to prove exactly how every current NetCut “cut” or speed-control mode works.

Open-source NetCut-like implementations commonly perform bidirectional ARP manipulation so that the monitoring machine becomes involved in the victim↔gateway path, but that should be considered evidence of the **traditional NetCut-style technique**, not source-level proof of Arcai’s current implementation. [Go Packages](https://pkg.go.dev/github.com/kevinantoniowiyonolauw/netcut/internal/arp)

That distinction is important.

For this new system:

> **ARP spoofing should never be a normal enforcement mechanism.**

Use it for research, simulation in a lab, detection signatures, and defensive validation only.

---

# 2. Recommended architecture

```text
                       ┌───────────────────────────────┐
                       │       React + TypeScript      │
                       │                               │
                       │ Dashboard / Devices / Alerts  │
                       │ Traffic / Topology / Policies │
                       └───────────────┬───────────────┘
                                       │
                              REST + WebSocket
                                       │
                 ┌─────────────────────▼────────────────────┐
                 │          Go Control Plane / API          │
                 │                                          │
                 │ Device Identity       Policy Engine      │
                 │ Alert Engine          Topology Engine    │
                 │ Adapter Manager       Audit / RBAC       │
                 │ Capability Manager    Realtime Hub       │
                 └──────┬─────────┬─────────────┬───────────┘
                        │         │             │
                        │         │             └──────────────┐
                        │         │                            │
              ┌─────────▼───┐ ┌──▼────────────┐     ┌────────▼─────────┐
              │ PostgreSQL  │ │ Linux Agents  │     │ Router/AP adapters│
              │             │ │               │     │                  │
              │ Inventory   │ │ ARP/DHCP      │     │ OpenWrt          │
              │ Alerts      │ │ mDNS/SSDP     │     │ MikroTik         │
              │ Policies    │ │ eBPF          │     │ UniFi            │
              │ Audit       │ │ libpcap       │     │ OPNsense         │
              │ Traffic     │ │ nftables/tc   │     │ pfSense Plus     │
              └──────┬──────┘ └──────┬────────┘     │ Cisco IOS XE     │
                     │                │              └──────────────────┘
            optional │                │
              ┌──────▼───────┐ ┌──────▼──────────┐
              │ TimescaleDB  │ │ IPFIX/NetFlow/  │
              │ Apache ed.   │ │ sFlow Collector │
              └──────────────┘ └─────────────────┘
```

The most important architectural decision is to split **privileged network sensing/enforcement** from the normal application backend.

The `lan-agent` runs close to the traffic—ideally the gateway, Linux bridge, router, or dedicated monitoring host. The API/UI service remains unprivileged.

That substantially reduces the consequences of a web/API vulnerability.

---

# 3. Discovery strategy

Don't choose one discovery mechanism. **Fuse evidence.**

| Source | Best use | Scope | Recommendation |
|---|---|---|---|
| ARP | Fast IPv4 L2 presence/IP↔MAC | Same broadcast domain | **Core** |
| DHCP | Hostname/client ID/lease history | DHCP-visible networks | **Core** |
| mDNS/DNS-SD | Friendly names/services, Apple/IoT/printers | Local link | **Core enrichment** |
| SSDP | UPnP/TV/media/IoT identification | Local multicast | **Core enrichment** |
| SNMPv3 | Switch ports, FDB, interfaces, AP infrastructure | Managed equipment | **Strongly recommended** |
| Nmap | Ports/services/OS enrichment | Routed/L2 | **Optional/manual** |
| arp-scan | Fast external ARP scan | Local IPv4 | **Optional fallback** |
| Router APIs | Client/AP/VLAN/association truth | Vendor dependent | **Preferred authority** |

Nmap itself confirms that on local Ethernet it normally chooses ARP/Neighbor Discovery because this is faster and more effective than IP probes. [Nmap](https://nmap.org/book/man-host-discovery.html)

DHCP contributes excellent identity information, but DHCP observations must not automatically be trusted. RFC 2131 explicitly warns that unauthorized DHCP servers can easily deliver incorrect addresses, gateways and DNS information. [RFC Editor](https://www.rfc-editor.org/info/rfc2131/)

mDNS and DNS-SD are useful for discovering local-link names and advertised services rather than deciding whether a device is trustworthy. [RFC Editor](https://www.rfc-editor.org/info/rfc6762/)

Use **SNMPv3 only** where possible. Its USM security architecture adds message authentication/integrity and privacy mechanisms that older SNMP versions lack. [RFC Editor](https://www.rfc-editor.org/info/rfc3414/)

### Device identity model

Do **not** make:

```text
device == MAC address
```

Instead:

```text
Device
 ├─ observed MAC addresses
 ├─ observed IPv4/IPv6 addresses
 ├─ DHCP client identifiers
 ├─ hostnames
 ├─ mDNS services
 ├─ vendor/OUI
 ├─ AP/switch-port attachment
 ├─ router client identifier
 ├─ historical observations
 └─ confidence score
```

Modern phones frequently use randomized/private MAC addresses, so MAC should be an identifier, not the entire identity model.

---

# 4. Traffic monitoring

My preferred hierarchy is:

### Linux gateway: eBPF first

Use eBPF maps to maintain counters such as:

```text
device
source/destination
protocol
bytes
packets
direction
interface
flow start/last seen
```

`cilium/ebpf` is a pure-Go loader/library, MIT licensed, supports ring buffers, BTF and common Linux eBPF facilities, and remains actively maintained. [GitHub](https://github.com/cilium/ebpf/blob/main/LICENSE)

This gives excellent performance without copying every full packet into userspace.

### Routers/switches: IPFIX/NetFlow/sFlow

IPFIX is specifically standardized for transmitting flow information from exporters/observation points to collectors. [RFC Editor](https://www.rfc-editor.org/rfc/rfc7011.html)

Use this when the product isn't physically in the forwarding path.

Recommended collector:

**netsampler/goflow2**

It handles IPFIX/NetFlow/sFlow and explicitly recommends protobuf rather than JSON for high-volume workloads. Its project remains active in 2026. [GitHub](https://github.com/netsampler/goflow2)

### nftables counters

Excellent for:

- bytes matching a quarantine/rate policy;
- dropped packet counts;
- per-device rule counters;
- confirming that enforcement actually occurred.

Don't make nftables your high-resolution analytics engine.

### libpcap

Use only where packet visibility is genuinely required:

- ARP;
- DHCP;
- mDNS;
- SSDP;
- unusual discovery protocols;
- packet debugging.

Apply tight capture filters and small snapshot lengths.

Important current security detail: as of September 2026, libpcap 1.10.7 contains several security fixes. A new implementation should therefore require **1.10.7 or newer**, rather than shipping an older distro copy blindly. [GitHub](https://github.com/the-tcpdump-group/tcpdump-htdocs/blob/master/index.html)

Also, libpcap's own documentation notes that it does not expose Linux's various eBPF mechanisms in the same way as native eBPF tooling. [GitHub](https://github.com/the-tcpdump-group/libpcap)

---

# 5. Security detection engine

A useful alert should contain:

```text
type
severity
confidence
device(s)
segment/VLAN
first_seen
last_seen
evidence[]
recommended_action
automatic_action?
```

### ARP spoof detection

Don't alert simply because an IP↔MAC pair changes.

Combine:

```text
ARP claims
+
DHCP lease database
+
router neighbor table
+
switch forwarding table
+
known gateway MAC
+
historical bindings
```

Examples:

```text
CRITICAL:
Gateway IP suddenly advertised by an unknown MAC

HIGH:
One MAC claims 12 active IP addresses within 3 seconds

HIGH:
Known device IP moves to a different MAC while original remains active

MEDIUM:
ARP mapping disagrees with DHCP/router state

LOW:
Expected ARP change during DHCP reassignment
```

Selective active validation can be used when contradictory claims exist; don't continuously blast the LAN.

### Rogue DHCP

Maintain approved DHCP server identities:

```text
VLAN 20:
  DHCP server:
    IP = 10.20.0.1
    MAC = aa:bb:cc:...
    switch-port = Gi1/0/48
```

Raise an immediate alert if an unexpected device emits server-side DHCP responses.

On supported enterprise switches, **DHCP snooping** should remain the authoritative network control rather than relying solely on passive detection.

### Duplicate IP

RFC 5227 gives you a standards-based foundation for IPv4 conflict detection. [RFC Editor](https://www.rfc-editor.org/rfc/rfc5227.html)

Track:

```text
IP X
  MAC A observed
  MAC B observed simultaneously
```

Then distinguish:

- static configuration mistake;
- DHCP conflict;
- HA/VRRP-like legitimate behavior;
- virtualization;
- possible spoofing.

### Unknown device

Avoid immediately quarantining every unfamiliar MAC.

Instead:

```text
new_device
   ↓
identity enrichment
   ↓
risk scoring
   ↓
policy
   ├─ permit
   ├─ alert
   ├─ restricted VLAN
   └─ quarantine
```

### Anomaly detection

For the first versions, use transparent heuristics rather than ML:

- ARP claims/minute;
- DHCP server appearance;
- unusual IP/MAC churn;
- first-seen vendor;
- unexpected VLAN;
- gateway MAC changes;
- newly opened services;
- bandwidth baseline deviation;
- unusually large number of destinations;
- sudden upload spikes.

ML can come later when the system has enough historical/labeled observations.

---

# 6. Network control

This is where the project should be fundamentally safer than NetCut.

## Preferred enforcement order

**1. Switch/router/AP native control**

Best options:

```text
Firewall rule
ACL
VLAN reassignment
AP client block
client isolation
switch port policy
vendor QoS
```

**2. Linux gateway**

Use:

```text
nftables    filtering/quarantine/classification
tc          real bandwidth shaping
CAKE/HTB    queueing/shaping where appropriate
```

A key distinction:

> **nftables is excellent at filtering/policing, but proper bandwidth shaping belongs to Linux traffic-control/qdiscs.**

Don't implement a “1 Mbps limiter” by deliberately losing connectivity or manipulating ARP timing.

### Example normalized enforcement abstraction

```text
Policy:
  selector:
    device_id: 71...
  action:
    type: rate_limit
    download: 10Mbps
    upload: 2Mbps

Compiler:
  MikroTik -> Simple Queue
  OPNsense -> pipe/queue
  Linux    -> tc qdisc/class/filter
  OpenWrt  -> native firewall/QoS integration
```

That means the UI doesn't need vendor-specific policy logic.

---

# 7. Router/platform support

## OpenWrt — Tier 1

Excellent first target.

OpenWrt 22.03+ uses firewall4 with nftables, and OpenWrt explicitly recommends making firewall changes through its UCI/firewall model instead of dropping arbitrary nftables commands into a ruleset that firewall4 manages. firewall4 is actively maintained. [OpenWrt](https://openwrt.org/docs/guide-user/firewall/firewall_configuration?s%5B%5D=1)

**Use:**

```text
ubus/rpcd
UCI
firewall4
native OpenWrt service hooks
```

Rating: **5/5**

---

## MikroTik RouterOS — Tier 1

Very good second target.

RouterOS exposes a REST API covering RouterOS configuration/commands. MikroTik warns against exposing the HTTP version because credentials can be observed; use HTTPS and strict management ACLs. [MikroTik Help](https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST%2BAPI)

Its queue system directly supports per-client and hierarchical rate limiting. [MikroTik Help](https://help.mikrotik.com/docs/spaces/ROS/pages/328088/Queues?src=contextnavpagetreemode)

Rating: **5/5**

---

## UniFi — Tier 1/2

UniFi now has official APIs, including local Network APIs. Ubiquiti says these expose devices, client activity, usage statistics and traffic insights, with version-specific API documentation available from UniFi Network itself. [Ubiquiti Help Center](https://help.ui.com/hc/en-us/articles/30076656117655-Getting-Started-with-the-Official-UniFi-API)

Use capability discovery because supported mutation endpoints vary by Network version/product.

Rating: **4/5**

---

## OPNsense — Tier 1/2

Strong integration target.

The firewall API is part of OPNsense core, and its API supports machine-to-machine rule/alias management. OPNsense also exposes traffic-shaping functionality; its shaper uses pipes, queues and rules. [OPNsense Documentation](https://docs.opnsense.org/development/api/core/firewall.html)

Rating: **4.5/5**

---

## pfSense — Tier 2

Be precise here.

Netgate now provides a REST API through **Netgate Nexus**, available in **pfSense Plus 25.07+**. That does not mean you should promise equivalent official REST functionality for every pfSense CE installation. [Netgate Documentation](https://docs.netgate.com/pfsense/en/latest/nexus/index.html)

So expose:

```text
pfSense Plus / Nexus   Supported
pfSense CE             Limited/experimental
```

Rating: **3/5**

---

## Cisco IOS XE — Tier 2/Enterprise

Powerful but more complicated.

Current IOS XE supports RESTCONF/YANG over HTTPS with structured JSON/XML operations. [Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/1718/b-1718-programmability-cg/restconf_protocol.html)

Cisco also recommends layered controls such as DHCP snooping, Dynamic ARP Inspection, IP Source Guard and ACLs to defend against spoofing/client-isolation bypasses. [Cisco](https://www.cisco.com/c/en/us/support/docs/wireless/catalyst-9800-series-wireless-controllers/225587-review-and-recommendations-for.html)

Rating: **4/5 capability, 3/5 implementation ease**.

---

# 8. Core tool/library decision matrix

The **Performance**, **Security**, and **Difficulty** columns below are my engineering assessments, not vendor benchmarks.

| Tool/library | GitHub | License | Maintenance | Performance | Security consideration | Difficulty |
|---|---|---|---|---|---|---|
| ebpf-go | `cilium/ebpf` | MIT | **High** | **Excellent** | privileged kernel programs; minimize hooks/maps | High |
| ARP | `mdlayher/arp` | MIT | Good/current | Excellent for L2 | raw socket capability; treat claims as untrusted | Low-Med |
| DHCP | `insomniacslk/dhcp` | BSD-3 | Active | Good | use capture filters; project has a 2026 CPU issue around unfiltered traffic | Med |
| mDNS | `grandcat/zeroconf` | MIT | Medium | Good | advertised data is unauthenticated enrichment | Low |
| SSDP/UPnP | `huin/goupnp` | BSD-2 | Medium | Good | parse device XML/URLs as hostile input | Low |
| SNMP | `gosnmp/gosnmp` | BSD-style | Active; 2026 release | Good | **SNMPv3 only** when possible | Med |
| libpcap | `the-tcpdump-group/libpcap` | BSD | **High** | Very good | require ≥1.10.7; least-privilege capture | Med |
| Flow collector | `netsampler/goflow2` | BSD-3 | Active | **Excellent** | exporters/UDP input untrusted; limit buffers | Med |
| nftables API | `google/nftables` | Apache-2.0 | Active | Excellent | atomic changes; protect management access | Med-High |
| PostgreSQL driver | `jackc/pgx` | MIT | **High** | Excellent | TLS, parameterized SQL, bounded pools | Low |
| SQL generation | `sqlc-dev/sqlc` | MIT | **High** | No meaningful runtime penalty | reduces hand-written mapping errors | Low |
| WebSocket | `coder/websocket` | ISC | Good | Excellent | enforce auth/origin/backpressure/message caps | Low |
| React | `react/react` | MIT | **High** | Excellent UI | ordinary browser/XSS controls | Low |
| TanStack Query | `TanStack/query` | MIT | **High**; updated Oct. 5 2026 | Excellent | avoid caching privileged secrets | Low |
| Apache ECharts | `apache/echarts` | Apache-2.0 | **High** | Excellent charts | sanitize user-controlled labels/tooltips | Low |
| React Flow | `xyflow/xyflow` | MIT core | **High** | Very good topology UI | sanitize node metadata | Low |

Supporting evidence for the main library choices includes current GitHub repositories/releases for ebpf-go, DHCP, GoSNMP, GoFlow2, React, TanStack Query, ECharts and React Flow. [GitHub](https://github.com/cilium/ebpf)

One notable issue: `google/nftables` calls its API relatively early-stage and warns that breaking changes may occur. Hide it behind your own internal `FirewallDriver` abstraction rather than letting the library's types leak through the whole application. [GitHub](https://github.com/google/nftables)

### Nmap and arp-scan

| Tool | Decision |
|---|---|
| **Nmap** | Excellent optional enrichment tool, but **do not make it an embedded mandatory dependency**. Its NPSL is not equivalent to a normal permissive OSS license and specifically imposes redistribution/commercial-product considerations. [GitHub](https://github.com/nmap/nmap/blob/master/nmap.h) |
| **arp-scan** | Excellent diagnostic/external discovery option; GPL-3.0. Your Go agent already has enough capability to implement narrowly scoped ARP discovery internally, so it needn't be a core runtime dependency. [GitHub](https://github.com/royhills/arp-scan) |

That Nmap licensing issue is easy to overlook and is one reason a native discovery engine is preferable.

---

# 9. Backend decision: Go vs Rust vs Node/TypeScript

| Requirement | Go | Rust | Node/TS |
|---|---:|---:|---:|
| Networking libraries | **5** | 4 | 3 |
| eBPF integration | **5** | **5** | 2 |
| Raw sockets/netlink | **5** | 5 | 2 |
| Development speed | **5** | 3 | 5 |
| Memory safety | 4 | **5** | 4 |
| Simple deployment | **5** | **5** | 3 |
| Router APIs | **5** | 4 | 5 |
| Concurrency | **5** | 5 | 4 |
| Team accessibility | **5** | 3 | 5 |
| Overall for this project | **47/50** | 39/50 | 33/50 |

### Decision

**Go wins for v1.**

Recommended layout:

```text
Go
 ├── control-plane
 ├── Linux network agent
 ├── router adapters
 ├── discovery
 ├── flow ingestion
 └── policy engine

Rust
 └── optional future ultra-hardened/high-performance sensor

TypeScript
 └── frontend only
```

The big advantage is ecosystem alignment: `cilium/ebpf`, `mdlayher/arp`, Go DHCP libraries, GoSNMP, GoFlow2, `pgx`, and native concurrent networking all live comfortably in one backend language. [GitHub](https://github.com/cilium/ebpf)

---

# 10. Database design

Use standard PostgreSQL first.

```sql
sites
segments
sensors

devices
device_addresses
device_observations
device_services
device_attachments

network_nodes
network_interfaces
network_links

flow_samples
metric_buckets

alerts
alert_evidence

policies
policy_versions
enforcements

integrations
integration_capabilities

audit_logs
```

Useful PostgreSQL native types:

```text
inet
cidr
macaddr
uuid
jsonb
timestamptz
```

Example conceptual `devices` record:

```text
id
site_id
display_name
vendor
trust_state
risk_score

first_seen
last_seen

labels JSONB
metadata JSONB
```

Keep addresses separately because a device can have many:

```text
device_addresses
----------------
device_id
segment_id
mac
ip
source
confidence
first_seen
last_seen
```

### Traffic storage

Don't write one DB row for every packet.

Aggregate in-agent:

```text
1-second memory counters
       ↓
5/10-second realtime event
       ↓
1-minute DB bucket
       ↓
hour/day rollups
```

Raw IPFIX flows can have separate retention:

```text
raw flows       1-7 days
1-min metrics   30-90 days
hourly metrics  1+ year
```

### TimescaleDB

Optional.

PostgreSQL itself is permissively licensed and extremely mature. [GitHub](https://github.com/postgres/postgres/blob/master/COPYRIGHT)

TimescaleDB requires more licensing care: files outside its `tsl` directory are generally Apache-2.0, while TSL components use the Timescale License. Timescale documents a separate Apache-2 edition as classic open-source software. [GitHub](https://github.com/timescale/timescaledb/blob/main/LICENSE)

For a project advertising itself as fully open source:

> Use PostgreSQL by default and support **TimescaleDB Apache-2 edition** as an optional accelerator.

---

# 11. API design

Use versioned REST as the authoritative API.

```text
GET    /api/v1/sites
GET    /api/v1/devices
GET    /api/v1/devices/{id}
GET    /api/v1/devices/{id}/traffic
GET    /api/v1/devices/{id}/observations

GET    /api/v1/topology

GET    /api/v1/alerts
POST   /api/v1/alerts/{id}/ack

GET    /api/v1/policies
POST   /api/v1/policies
PATCH  /api/v1/policies/{id}

POST   /api/v1/devices/{id}/quarantine
DELETE /api/v1/devices/{id}/quarantine

PUT    /api/v1/devices/{id}/rate-limit

GET    /api/v1/integrations
POST   /api/v1/integrations
GET    /api/v1/integrations/{id}/capabilities

GET    /api/v1/audit
```

Realtime:

```text
WS /api/v1/events
```

Events:

```text
device.seen
device.updated
device.offline

traffic.sample

alert.created
alert.updated

enforcement.requested
enforcement.applied
enforcement.failed

topology.changed

integration.online
integration.offline
```

Every WebSocket message should have:

```json
{
  "sequence": 2938201,
  "time": "...",
  "type": "device.updated",
  "site_id": "...",
  "data": {}
}
```

If sequence numbers are missed, the UI refetches from REST.

That makes WebSocket an acceleration mechanism rather than your source of truth.

---

# 12. Product screens

Your requested navigation translates cleanly to:

### Dashboard

Show:

- online/known/unknown devices;
- total bandwidth;
- top talkers;
- high-severity alerts;
- quarantined clients;
- integration health;
- network risk score.

### Devices

```text
Status
Name
IPv4/IPv6
MAC
Vendor
VLAN
AP/Switch port
Rx/Tx
Trust
Risk
Last seen
```

### Device Details

A particularly important screen:

```text
Identity
Address history
DHCP history
mDNS/SSDP services
Current attachment
Historical AP/port movement
Traffic
Flows
Open services
Alerts
Applied policies
Audit history
```

### Bandwidth Monitoring

ECharts:

```text
total throughput
device throughput
top talkers
protocol breakdown
historical usage
drops
```

### Network Topology

React Flow.

Edges should distinguish:

```text
━━ Verified physical/logical attachment
--- Inferred relationship
```

Never present guesses as fact.

### Security Alerts

Show the actual evidence that triggered an alert.

### Quarantine

Include:

```text
Device
Reason
Actor
Method
Applied at
Expiration
Adapter
Desired state
Actual state
```

### Policies

Rules such as:

```text
WHEN:
  trust_state == unknown
  AND segment == "Employees"

THEN:
  alert high

OPTIONALLY:
  move_to_vlan "Quarantine"
```

---

# 13. MVP

I would keep v1 surprisingly focused:

1. **Linux agent**, IPv4 ARP + DHCP + mDNS + SSDP discovery.
2. Device inventory with identity history and unknown-device detection.
3. eBPF-based per-device counters when installed on a Linux gateway.
4. ARP-spoof/gateway-MAC-change detection.
5. Rogue DHCP detection.
6. Duplicate IPv4 detection.
7. PostgreSQL storage.
8. React dashboard/devices/details/alerts/traffic.
9. Linux nftables quarantine when the agent is actually the gateway/bridge.
10. OpenWrt integration.
11. MikroTik integration.
12. WebSocket live updates.
13. Complete audit logging.

Notice what isn't in MVP:

```text
No ML
No packet-content archive
No ARP-poison enforcement
No automatic Nmap scanning
No six-vendor integration at once
```

That keeps the security boundary manageable.

---

# 14. Advanced features

After the core works:

- IPv6 Neighbor Discovery support;
- rogue IPv6 Router Advertisement detection;
- DHCPv6;
- SNMPv3 switch discovery;
- LLDP/CDP topology;
- IPFIX/NetFlow/sFlow;
- UniFi integration;
- OPNsense integration;
- Cisco RESTCONF;
- pfSense Plus/Nexus;
- VLAN-based quarantine;
- router-native client isolation;
- proper `tc`/CAKE/HTB shaping;
- scheduled policies;
- RBAC;
- OIDC/SAML;
- multi-site agents;
- HA control plane;
- webhook/Slack/email alerts;
- policy-as-code;
- topology history;
- per-device behavioral baselines;
- automated switch-port quarantine;
- anomaly scoring/ML;
- REST/webhook plugin SDK.

IPv6 should not be ignored permanently: ARP is IPv4-specific, so a “modern NetCut” that only understands ARP will eventually give administrators a misleading view of their LAN.

---

# 15. Development roadmap

### Phase 0 — security architecture

Define:

```text
privilege boundary
device identity model
event schema
adapter interface
policy model
audit model
threat model
```

This should happen before UI polish.

### Phase 1 — discovery

Implement:

```text
ARP
DHCP
mDNS
SSDP
identity fusion
online/offline state
```

### Phase 2 — observability

Add:

```text
eBPF counters
traffic aggregation
WebSocket
charts
retention
```

### Phase 3 — detection

Implement:

```text
ARP spoof
gateway impersonation
duplicate IP
rogue DHCP
unknown devices
basic anomaly rules
```

### Phase 4 — enforcement

Start with:

```text
Linux nftables
Linux tc
OpenWrt
MikroTik
```

Every operation needs dry-run/desired-state/rollback semantics.

### Phase 5 — infrastructure

Add:

```text
SNMPv3
LLDP/FDB topology
UniFi
OPNsense
Cisco
pfSense Plus
IPFIX
```

### Phase 6 — production hardening

Add:

```text
RBAC
OIDC
mTLS agents
secret encryption
rate limits
HA
backup/restore
SBOM
signed releases
container hardening
security documentation
```

---

# 16. Deployment model

I recommend two supported modes.

## Native Linux — preferred sensor

```text
systemd
lan-agent
```

Give the agent only the capabilities needed for the selected modules rather than permanent unrestricted root access.

This is the best choice for eBPF/raw networking.

## Docker — control plane

```text
docker compose

api
ui
postgres
optional-timescaledb
optional-flow-collector
```

Avoid the tempting design:

```text
network_mode: host
privileged: true
```

for the whole stack.

If the sensor must be containerized, isolate it into a separate container and grant only the narrowly required kernel capabilities.

The web server and PostgreSQL should never require raw-network privileges.

---

# 17. Critical safety mechanisms

This part is essential for a real administration product.

Every enforcement action should be **desired state**, not a fire-and-forget command:

```text
requested
↓
planned
↓
adapter accepted
↓
verified
↓
active
```

Or:

```text
requested
↓
adapter error
↓
rollback
↓
failed
```

Add a protected **management allowlist**:

```text
gateway
controller
admin workstation
management VLAN
DNS/DHCP infrastructure
```

Policies should not be able to quarantine these without an explicit break-glass procedure.

Also add enforcement TTL:

```text
Quarantine device for:
[ 15 min ▼ ]
```

A temporary network-control mistake is much safer than a permanent lockout.

---

# 18. Security/legal considerations

The software should display an explicit authorization statement during initial setup:

> Deploy this software only on networks and devices you own or are explicitly authorized to administer.

Network monitoring can expose metadata such as device identities, destinations, service advertisements and usage patterns. Organizations should establish appropriate retention, access controls and employee/user notification according to applicable law and organizational policy.

Avoid collecting packet payloads by default.

Store:

```text
flow metadata       yes
byte counters       yes
ARP/DHCP metadata   yes
service metadata    yes

full HTTP payload   no
TLS contents        no
credentials         no
arbitrary PCAP      no by default
```

Credentials for routers/APs need:

- encryption at rest;
- redaction from logs;
- minimum privileges;
- HTTPS/mTLS;
- rotation;
- separate credential per integration.

For SNMP, default to SNMPv3 rather than v2c community strings. [RFC Editor](https://www.rfc-editor.org/info/rfc3414/)

For router-side security, prefer native anti-spoof controls such as DHCP snooping and Dynamic ARP Inspection when available rather than trying to “fight” spoofed ARPs from another LAN host. Cisco's current security guidance explicitly recommends this layered infrastructure approach. [Cisco](https://www.cisco.com/c/en/us/support/docs/wireless/catalyst-9800-series-wireless-controllers/225587-review-and-recommendations-for.html)

---

# 19. Final technology decision matrix

| Component | Final decision | Score |
|---|---|---:|
| Backend | **Go** | ★★★★★ |
| Privileged agent | **Go + cilium/ebpf** | ★★★★★ |
| ARP | **mdlayher/arp** | ★★★★★ |
| DHCP | **insomniacslk/dhcp** | ★★★★☆ |
| mDNS | **grandcat/zeroconf** | ★★★★☆ |
| SSDP | **huin/goupnp/ssdp** | ★★★★☆ |
| SNMP | **gosnmp, SNMPv3** | ★★★★★ |
| Heavy discovery | **Nmap optional/user-installed** | ★★★★☆ |
| Basic external scan | **arp-scan optional** | ★★★☆☆ |
| Linux traffic | **eBPF** | ★★★★★ |
| Router traffic | **IPFIX/NetFlow/sFlow** | ★★★★★ |
| Flow collector | **GoFlow2** | ★★★★★ |
| Packet capture | **libpcap fallback** | ★★★★☆ |
| Firewall | **nftables** | ★★★★★ |
| Bandwidth shaping | **tc/CAKE/HTB + router QoS** | ★★★★★ |
| DB | **PostgreSQL** | ★★★★★ |
| Time series | **TimescaleDB Apache edition optional** | ★★★★☆ |
| DB Go driver | **pgx** | ★★★★★ |
| SQL layer | **sqlc** | ★★★★★ |
| Frontend | **React + TypeScript** | ★★★★★ |
| Server state | **TanStack Query** | ★★★★★ |
| Charts | **Apache ECharts** | ★★★★★ |
| Topology | **React Flow** | ★★★★★ |
| Realtime UI | **WebSocket** | ★★★★★ |
| Linux distribution | **systemd/native agent** | ★★★★★ |
| App deployment | **Docker Compose** | ★★★★★ |
| First router | **OpenWrt** | ★★★★★ |
| Second router | **MikroTik** | ★★★★★ |
| Third | **UniFi** | ★★★★☆ |
| Fourth | **OPNsense** | ★★★★☆ |
| pfSense | **Plus/Nexus first** | ★★★☆☆ |
| Enterprise | **Cisco RESTCONF/YANG** | ★★★★☆ |
| ARP spoofing for blocking | **Do not implement in production core** | ❌ |

## Final stack I would build

```text
Frontend
  React + TypeScript
  TanStack Query
  Apache ECharts
  React Flow

Control Plane
  Go
  net/http
  coder/websocket
  pgx + sqlc

Sensor
  Go
  cilium/ebpf
  mdlayher/arp
  insomniacslk/dhcp
  zeroconf
  goupnp SSDP
  gosnmp
  libpcap fallback

Flow Telemetry
  GoFlow2 / IPFIX / NetFlow / sFlow

Enforcement
  nftables
  tc
  router/AP/switch adapters

Storage
  PostgreSQL
  optional TimescaleDB Apache-2 edition

Integrations
  OpenWrt
  MikroTik
  UniFi
  OPNsense
  pfSense Plus
  Cisco IOS XE

Deployment
  Native Linux agent
  Docker control plane
```

The architectural principle I would make non-negotiable is:

> **Discover locally, observe passively, correlate multiple sources, detect ARP attacks, and enforce policy through infrastructure you legitimately control.**

That gives you the useful parts of NetCut—instant device inventory, live bandwidth, unknown-device detection, quarantine, speed controls, schedules and visibility—without making ARP cache manipulation the foundation of the product. It also scales from a home OpenWrt router to MikroTik/UniFi deployments and eventually managed Cisco networks.
