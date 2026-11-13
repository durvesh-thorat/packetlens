# PacketLens Controlled Pilot Protocol & Verification Framework

This document defines the formal operational protocol, comparative evaluation methodology,
operator workload constraints, and governance checklists for running a controlled pilot of
PacketLens on an authorized Windows 11 workstation.

---

## 1. Alert-Only Observation Protocol

### 1.1 Scope and Operational Boundaries
PacketLens is strictly scoped as an **alert-only, passive analysis and observation tool**:
- **Deployment Target:** Exactly one Windows 11 workstation running local offline classic-PCAP
  analysis and loopback dashboard replay (`http://127.0.0.1:8000/`).
- **Passive Replay Only:** The engine ingests recorded capture files. It does **not** inject
  packets, modify Windows firewall rules, alter network routing tables, drop packets, or
  execute active countermeasures.
- **Loopback HTTP Boundary:** The web management console binds strictly to `127.0.0.1`. Remote
  network access is disabled by default to prevent exposure across the local area network.
- **Data Access:** Ingestion is restricted to authorized offline PCAP files (`version 2.4`,
  Ethernet linktype `1` or Linux cooked linktype `113`). Raw capture payloads containing
  sensitive credentials or user data must be sanitized or stored on encrypted local media.

### 1.2 Observation Mode vs Active Enforcement
| Capability | Pilot Status | Justification |
|---|---|---|
| Passive PCAP Ingestion | **ENABLED** | Ingests offline packet captures for anomaly and signature detection. |
| Alerting & Incident Grouping | **ENABLED** | Correlates alerts into manageable incident records in SQLite store. |
| Loopback Web Console | **ENABLED** | Provides operator visualization, timeline charts, and incident management. |
| Offline HTML Reporting | **ENABLED** | Generates CSP-isolated forensic reports (`script-src 'none'`). |
| In-line Packet Dropping | **PROHIBITED** | Not supported by architecture; prevents disruptive network outages. |
| Firewall Rule Modification | **PROHIBITED** | Active blocking is outside M0 target scope and threat model. |
| Remote Network Binding | **PROHIBITED** | Dashboard unauthenticated over LAN; strictly bound to loopback. |

---

## 2. Section 6 Safety & Non-Fabrication Boundary

> [!IMPORTANT]
> **MANDATORY INTEGRITY REQUIREMENT (PRODUCTION ROADMAP SECTION 6)**
> Under Section 6 safety rules, AI agents are strictly prohibited from fabricating live pilot
> execution records, inventing fictitious network logs, generating simulated operator triage
> timestamps, or self-approving maintainer decisions.
>
> All live pilot runs, human operator evaluations, and sign-offs must be conducted by actual
> human maintainers and authorized network administrators on real systems. AI agents prepare
> test harnesses, evaluation scripts, documentation, and decision proposals; only the human
> maintainer has authority to record live pilot execution and approve milestone gates.

---

## 3. Independent Source Comparison Methodology

To validate detection accuracy and ensure PacketLens alerts correspond to genuine network
phenomena, pilot observations must be corroborated against independent, industry-standard
network inspection tools (`Wireshark` and `tshark`).

```
                              ┌────────────────────────────────────────┐
                              │     Authorized PCAP Capture File       │
                              └──────────────────┬─────────────────────┘
                                                 │
                        ┌────────────────────────┴────────────────────────┐
                        ▼                                                 ▼
        ┌───────────────────────────────┐                 ┌───────────────────────────────┐
        │      PacketLens Engine        │                 │    Independent Tool (tshark)  │
        │  (Offline Analysis & Replay)  │                 │   (Protocol Decode & Filters) │
        └───────────────┬───────────────┘                 └───────────────┬───────────────┘
                        │                                                 │
                        ▼                                                 ▼
             [PacketLens Alerts]                                 [tshark Flow Evidence]
                        │                                                 │
                        └────────────────────────┬────────────────────────┘
                                                 │
                                                 ▼
                                     [Cross-Tool Reconciliation]
                                                 │
                      ┌──────────────────────────┼──────────────────────────┐
                      ▼                          ▼                          ▼
               [True Detection]          [False Positive]           [False Negative]
             Both tools corroborate.  PacketLens alerted; tshark  tshark shows attack;
                                      shows benign traffic.       PacketLens missed.
```

### 3.1 Tool Configuration for Independent Baseline
Use `tshark` (Wireshark command-line interface) to generate ground-truth flow summaries and
protocol statistics:

```powershell
# 1. Summary of TCP flags and packet rates
tshark -r capture.pcap -q -z conv,ip -z io,stat,1,"COUNT(tcp.flags.syn==1 and tcp.flags.ack==0)SYN","COUNT(tcp.flags.reset==1)RST"

# 2. Extract ARP traffic to detect address conflicts/spoofing
tshark -r capture.pcap -Y "arp.opcode == 2" -T fields -e frame.time -e arp.src.proto_ipv4 -e arp.src.hw_mac

# 3. Extract DNS query patterns and high-entropy domain names
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e frame.time -e ip.src -e dns.qry.name
```

### 3.2 Comparison Parameters & Corroboration Protocol
For each incident generated by PacketLens, the operator extracts:
1. **Timestamp Range:** Start and end timestamps of the incident window.
2. **IP 5-Tuple:** Source IP, Destination IP, Protocol, Source Port, Destination Port.
3. **Triggering Signature:** Rule name (`port-scan`, `syn-flood`, `dns-tunnel`, `arp-spoof`, `horizontal-scan`).

The operator then queries `tshark` using equivalent Wireshark display filters:
- **Port Scan:** `ip.src == <src_ip> && tcp.flags.syn == 1 && tcp.flags.ack == 0` (verify whether > 20 distinct destination ports were contacted within 10 seconds).
- **SYN Flood:** `ip.dst == <target_ip> && tcp.flags.syn == 1 && tcp.flags.ack == 0` (verify SYN packet rate > 100 pkts/s).
- **ARP Spoof:** `arp.opcode == 2 && arp.src.proto_ipv4 == <ip>` (verify multiple distinct MAC addresses claiming the same IPv4 address).
- **DNS Tunnel:** `ip.src == <src_ip> && dns.qry.name` (inspect subdomain label lengths > 30 chars or Shannon entropy > 3.8).
- **Horizontal Scan:** `ip.src == <src_ip> && tcp.dstport == <target_port>` (verify multiple distinct destination hosts probed on the same port).

### 3.3 Discrepancy Reconciliation Matrix

| Comparison Finding | Classification | Action Required |
|---|---|---|
| PacketLens alerted; `tshark` confirms attack pattern. | **True Positive (TP)** | Acknowledge incident; follow incident triage SOP; export HTML report. |
| PacketLens alerted; `tshark` confirms legitimate traffic (e.g. standard vulnerability scan or busy DNS resolver). | **False Positive (FP)** | Record incident ID and flow parameters; close incident; log for policy tuning. |
| PacketLens produced no alert; `tshark` shows obvious attack (e.g. UDP flood or Xmas scan). | **False Negative (FN)** | Note rule coverage boundary (e.g. UDP and FIN/Xmas scans are out of scope for default TCP rules per `docs/DETECTION_VALIDATION.md`). |
| Timestamp or packet count mismatch between tools. | **Timing Drift / Boundary Discrepancy** | Check for microsecond timestamp rounding or dropped packets in capture file. |

---

## 4. Operator Workload and Resource Usage Review

### 4.1 Operator Workload Bounds
To prevent alert fatigue and maintain operational readiness:
- **Triage Time Target:** Average **< 3 minutes per incident** from discovery to acknowledgment and initial triage.
- **Alert Rate Limit:** **<= 1.0 false alarm per hour per enabled rule** under normal benign background traffic.
- **Incident Aggregation:** PacketLens correlates related alerts on the same IP tuple into a single incident, bounding total open tickets.
- **Experimental Rule Isolation:** Rules with elevated false-alarm rates (such as `volumetric` EWMA Z-score) must be marked `"experimental": true` in policy configurations and reviewed separately so production triage queues remain clean.

### 4.2 System Resource Usage Thresholds

| Metric | Target / Healthy Bound | Degraded Warning Threshold | Critical Alert Limit | Remediation Action |
|---|---|---|---|---|
| **Process RSS Memory** | < 75 MB | >= 100 MB | >= 150 MB | Prune historical records older than 30 days (`packetlens store prune`). |
| **Engine Ingestion Rate** | > 50,000 pkts/s | < 25,000 pkts/s | < 10,000 pkts/s | Check disk I/O bottlenecks; ensure PCAP is on local SSD. |
| **Per-Packet Latency** | < 25 µs avg | > 50 µs avg | > 100 µs avg | Investigate active rule complexity or flow table depth. |
| **Store Queue Depth** | < 1,000 items | >= 5,000 items | >= 8,000 items | SQLite write contention; run batch analysis via `packetlens analyze`. |
| **Store Write Drops** | 0 drops | > 0 drops | > 100 drops | Switch from real-time replay to batch ingestion. |

---

## 5. Operational Checklists

### 5.1 Pre-Pilot Readiness Checklist
Before initiating a pilot observation run, the human operator must verify each item:

- [ ] **Workstation Environment:** Windows 11 workstation running Python 3.10+ in an isolated virtual environment (`.venv`).
- [ ] **Test Suite Status:** Full unit test suite passes with zero failures (`python -m unittest discover -s tests -v`).
- [ ] **Network Interface Binding:** Verified that `packetlens serve` binds strictly to `127.0.0.1` (`--allow-remote` is NOT enabled).
- [ ] **Capture Source Authorization:** All PCAP files are authorized, recorded from permitted test segments, and confirmed as classic PCAP v2.4 (linktype 1 or 113).
- [ ] **Policy Configuration:** Active policy (`packetlens/policies/default.json`) verified; `volumetric` rule is marked `"experimental": true`.
- [ ] **Storage Preparation:** SQLite database initialized, disk space verified (> 5 GB free), and WAL mode confirmed active.
- [ ] **Operator Access:** Operator has access to terminal, browser on loopback, and access token printed during startup.

### 5.2 Daily Observation Checklist
During each day of the pilot observation period:

- [ ] **Service Health Check:** Query `http://127.0.0.1:8000/api/health` and verify `service_status == "healthy"`.
- [ ] **Memory Inspection:** Check `memory_rss_bytes` to ensure process memory remains well below 150 MB.
- [ ] **Incident Queue Review:** Execute `packetlens incidents list --status open` and triage all pending items.
- [ ] **Triage Timing:** Verify that average operator triage time remains under 3 minutes per incident.
- [ ] **Independent Corroboration:** Cross-check at least 2 sample incidents against `tshark` ground truth.
- [ ] **Database Backup:** Run `python -m packetlens store backup --out backups\pilot_daily.db` and verify integrity.

### 5.3 Pilot Exit Criteria Checklist
At the conclusion of the agreed pilot observation window:

- [ ] **Observation Duration:** Minimum agreed observation period (e.g. 5 business days or designated capture replay volume) completed.
- [ ] **Zero Data Loss:** `store_drops == 0` and SQLite database integrity verified with `PRAGMA integrity_check`.
- [ ] **Zero Unhandled Crashes:** No unhandled engine crashes, unhandled HTTP server exceptions, or storage writer deadlocks.
- [ ] **False Alarm Compliance:** Non-experimental signature rules demonstrated <= 1.0 false alarm per hour under benign traffic.
- [ ] **Operator Review:** Operator confirms triage workflow is clear, usable, and manageable (< 3 min SLA).
- [ ] **Maintainer Governance:** Maintainer decision `DEC-2026-11-12-m6-pilot-readiness` reviewed and signed off in `PRODUCTION_ROADMAP.md` Section 10.
