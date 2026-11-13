# PacketLens Controlled Pilot Evaluation Results (M6)

This document records the empirical results, triage classification, throughput metrics,
and operational boundaries of the Milestone 6 controlled pilot capture conducted on
2026-11-13 by the project maintainer.

---

## 1. Pilot Environment & Capture Conditions

### 1.1 Capture Setup
- **Workstation:** Single laptop workstation running Windows 11.
- **Network Interface:** Wi-Fi interface connected to a 4G/5G mobile hotspot.
- **Capture Mechanism:** Captured live via `dumpcap` in classic PCAP format (`version 2.4`,
  Ethernet linktype `1`).
- **Capture File:** `C:\packetlens\captures\hotspot-1h.pcap` (412,199,330 bytes, local only,
  strictly gitignored and never committed).
- **Duration:** 3,572.99 seconds (~59.55 minutes, approximately 1 hour).
- **Network Stability:** No Wi-Fi disconnects or interface renegotiations noticed or recorded.
- **Packet Loss at Capture:** `0` packets dropped by `dumpcap`.

### 1.2 User Activity During Capture Window
- **Primary Activity:** Streamed one YouTube video in High Definition (HD).
- **Interaction:** Paused and resumed playback 2 to 3 times; video was not finished.
- **Adversarial / Security Activity:** **Zero.** No port scans, SYN floods, ARP spoofing,
  DNS tunneling, or synthetic attacks were conducted during the capture.
- **Observed Behavior:** Bursts of high packet and byte rates occurred immediately after
  resuming playback as video segments buffered over HTTPS/QUIC.

---

## 2. Quantitative Results & Verification

All figures below were verified directly against `C:\packetlens\captures\pilot-analyze.txt`
and SQLite database `C:\packetlens\captures\pilot.db`:

### 2.1 Packet & Protocol Distribution
| Metric | Value | Notes |
|---|---|---|
| **Total Packets Ingested** | **391,244** | Zero parser crashes or unhandled frame exceptions |
| **Total Bytes Ingested** | **405,939,402** | ~406 MB total wire data (~54.5 KB/s avg wire rate) |
| **Dumpcap Drops** | **0** | Clean capture capture-card handoff |
| **PacketLens Malformed Frames** | **0** | All 391,244 frames parsed cleanly |
| **UDP Packets** | 259,503 (66.3%) | Predominantly QUIC / YouTube media streaming |
| **TCP Packets** | 129,319 (33.1%) | TLS sessions, web control plane, background apps |
| **DNS Packets** | 1,586 (0.4%) | Standard client domain name resolutions |
| **ICMP Packets** | 385 (< 0.1%) | Routine path MTU and diagnostics |
| **ARP Packets** | 375 (< 0.1%) | Routine local hotspot gateway resolution |
| **Other Protocol Frames** | 76 (< 0.1%) | Local link-layer multicast / IPv6 discovery |

### 2.2 Top Talkers (Masked per Section 6 Safety Rules)
- `[MASKED_IPV6_A]` (172,904,667 B) — External Video Streaming CDN (Google/YouTube)
- `[MASKED_IPV6_B]` (75,335,172 B) — Local Client / Hotspot Gateway IPv6
- `[MASKED_IPV4_A]` (34,483,021 B) — External Cloud CDN IPv4
- `[MASKED_IPV6_C]` (15,860,322 B) — External CDN IPv6
- `[MASKED_IPV6_D]` (15,532,667 B) — External Application Cloud IPv6

---

## 3. Alerts, Incidents, and Classification

### 3.1 Alert Summary by Rule
| Detector / Rule | Alert Count | Production Target (M0) | Pilot Result | Status |
|---|:---:|:---:|:---:|:---:|
| `port-scan` | 0 | <= 1.0 FP/hr | 0.0 FP/hr | **PASS** |
| `syn-flood` | 0 | <= 1.0 FP/hr | 0.0 FP/hr | **PASS** |
| `dns-tunnel` | 0 | <= 1.0 FP/hr | 0.0 FP/hr | **PASS** |
| `arp-spoof` | 0 | <= 1.0 FP/hr | 0.0 FP/hr | **PASS** |
| `horizontal-scan` | 0 | <= 1.0 FP/hr | 0.0 FP/hr | **PASS** |
| `volumetric` (*experimental*) | 59 | N/A (quarantined) | 59.4 alerts/hr | **CONFIRMS EXPERIMENTAL** |
| **Total Alerts** | **59** | | | |

### 3.2 Incident Grouping
PacketLens groups alerts sharing the same rule and flow context occurring within the
policy gap threshold (`gap_seconds: 30`):
- **Total Correlated Incidents:** **49 incidents** (all `kind: volumetric`, severity `medium`, status `open`).
- **Single-Alert Incidents:** 42 incidents.
- **Multi-Alert Incidents:** 7 incidents grouped multiple related alerts:
  - 4 incidents grouped 2 alerts each.
  - 3 incidents grouped 3 alerts each.
- **Alert Metrics Triggering Volumetric Flags:**
  - Packet rate bursts: 35 alerts (z-scores from 7.1 to 26.5; peak 5,894 pkts/s vs baseline 215).
  - Byte rate bursts: 42 alerts (z-scores from 7.1 to 26.7; peak 6.90 MB/s vs baseline 236 KB/s).
  - DNS query rate bursts: 3 alerts (z=12.6, peak 13 DNS pkts/s vs baseline 0).
  - TCP SYN rate bursts: 3 alerts (z=9.8 to 23.4, peak 24 SYN pkts/s vs baseline 1).

### 3.3 Triage Classification
Classification based exclusively on the maintainer's account of activity during the capture:

| Classification | Incident Count | Alert Count | Justification |
|---|:---:|:---:|---|
| **Confirmed Attack / Incident** | **0** | **0** | No scans, floods, or attacks occurred during the capture session. |
| **False Alarm** | **49** | **59** | 100% of alerts were triggered by benign HD YouTube video buffering bursts and pause/resume playback cycles causing the statistical EWMA Z-Score detector to flag temporary rate surges. |
| **Unclear** | **0** | **0** | Complete and unambiguous account of user activity available. |

---

## 4. Relevance to Governance & Detector Decisions

### 4.1 Corroboration of `DEC-2026-11-12-m5-detection-quality`
The pilot findings **directly corroborate and justify** the maintainer decision to mark
`volumetric` (`EwmaZScoreDetector`) as `"experimental": true` in `packetlens/policies/default.json`:
1. **Signature Reliability:** All five core signature detectors (`port-scan`, `syn-flood`,
   `dns-tunnel`, `arp-spoof`, `horizontal-scan`) generated **zero false alarms** (0.0 FP/hr)
   across ~391k packets of real-world Wi-Fi and mobile hotspot traffic, satisfying the M0
   target of <= 1.0 FP/hr.
2. **Volumetric Noise:** The statistical EWMA Z-Score detector generated **59 alerts / 49 incidents**
   in a single hour of benign YouTube streaming (~59.4 FP/hr). Had `volumetric` remained an
   active production alerting rule, it would have generated catastrophic operator alert fatigue.
   Its quarantine as `"experimental": true` protects operator triage queues while retaining
   visibility for offline research.

---

## 5. Performance and Throughput Analysis

| Benchmark / Evaluation | Ingestion Speed | Store Queue Drops | Notes |
|---|:---:|:---:|---|
| **M0 Pipeline Target** | >= 50,000 pkts/s | 0 drops | Minimum acceptance threshold |
| **Synthetic PCAP Benchmark** | 99,874 pkts/s | 0 drops | Clean synthetic traffic baseline |
| **M6 Pilot (Real Hotspot Wi-Fi)** | **64,097 pkts/s** | **0 drops** | **+28.2% above 50,000 pps target** |

- **Pipeline Efficiency:** The offline analysis pipeline sustained **64,097 packets per second**,
  completing analysis of the entire 391,244-packet (406 MB) capture in approximately **6.1 seconds**.
- **Storage Queue Stability:** The asynchronous SQLite writer queue handled the bursty arrival
  rate with **0 dropped writes** (`store_drops = 0`), confirming that the writer thread and
  WAL journaling perform reliably under real-world traffic volume on Windows 11.

---

## 6. Known Limitations & Non-Generalization Boundaries

In strict compliance with Section 6 safety rules:
1. **Single Workstation:** Capture was performed on exactly one laptop workstation.
2. **Single Network Environment:** One 1-hour session over a mobile hotspot Wi-Fi link. Performance
   and traffic profiles on enterprise wired networks, multi-VLAN trunks, or datacenter links
   may differ significantly.
3. **Single Activity:** Normal HD YouTube video streaming with pause/resume cycles. Other activities
   (P2P torrenting, video conferencing, bulk cloud backups, software builds) were not evaluated.
4. **False Alarm Measurement Only:** Because no attacks or penetration testing tools were run during
   this capture, **this pilot measures false-alarm resistance and pipeline throughput only, not
   detection recall or sensitivity on live traffic.**
5. **No Live Live-Capture Driver:** Capture was performed using external `dumpcap`; PacketLens
   operates purely as an offline parser and replayer.
6. **Governance Status:** M6 is **READY FOR REVIEW**; maintainer decision
   `DEC-2026-11-12-m6-pilot-readiness` remains `PROPOSED` awaiting formal maintainer review
   and sign-off.
