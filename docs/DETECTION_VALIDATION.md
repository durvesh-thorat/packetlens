# PacketLens Detection Quality Validation Report (M5)

**Date:** 2026-11-12
**Target scope:** Section 2 Windows 11 workstation (offline classic-PCAP analysis + loopback dashboard, alert-only)
**Policy under test:** [`packetlens/policies/default.json`](../packetlens/policies/default.json)

## 1. Scope & Held-Out Discipline

PacketLens separates **live packet/bin detectors** (which inspect decoded packets in `packetlens/engine.py`) from **offline flow/ML experiments** (`packetlens/flows.py`, `packetlens/flowmodel.py`, optional `packetlens/granite.py` operating only on CIC-IDS2017 CSV flow exports).

To keep tuning data out of validation:
- `packetlens/evaluate.py` default `evaluate()` uses `benign_seed=7` and `attack_seed=8` (and `benchmark()` uses `seed=3`).
- `packetlens evaluate --rules` evaluates each policy rule across **disjoint held-out seeds**: `benign_seeds=(101, 102, 103, 104, 105, 106)` (6 x 600s = `1.0` hour, `60` one-minute bins) and `attack_seeds=(201, 202, 203, 204, 205, 206)` (6 x 300s = `42` scripted attacks, `7` per seed). No detector thresholds were tuned on seeds `101..106` or `201..206`.
- Offline CIC-IDS2017 validation uses chronological 60%/40% splits (`train_frac=0.6`) and diagnostic held-out source-IP machine splits.

---

## 2. Live Packet Engine: Per-Rule Synthetic Evaluation

Measured via `python -m packetlens evaluate --rules` (circular block bootstrap over `60` clean 1-minute bins, `block_length=5`, `resamples=1000`, seed `42`):

| Rule ID | Detector | Experimental | TP | FN | Outside-Window FP | Precision | Recall | Clean FP/hr (95% CI) | Max Delay (s) | M0 Synthetic Target |
|---|---|---|---:|---:|---:|---:|---:|---|---:|---|
| `port-scan` | `port_scan` | `False` | 12 | 0 | 0 | 1.000 | 1.000 | `0.0 [0.0, 0.0]` | 59.0 | **PASS** |
| `syn-flood` | `syn_flood` | `False` | 6 | 0 | 0 | 1.000 | 1.000 | `0.0 [0.0, 0.0]` | 0.15 | **PASS** |
| `dns-tunnel` | `dns_tunnel` | `False` | 6 | 0 | 0 | 1.000 | 1.000 | `0.0 [0.0, 0.0]` | 3.60 | **PASS** |
| `arp-spoof` | `arp_spoof` | `False` | 6 | 0 | 0 | 1.000 | 1.000 | `0.0 [0.0, 0.0]` | 0.00 | **PASS** |
| `horizontal-scan` | `horizontal_scan` | `False` | 6 | 0 | 0 | 1.000 | 1.000 | `0.0 [0.0, 0.0]` | 0.29 | **PASS** |
| `volumetric` | `volumetric` | **`True`** | 6 | 0 | 6 | 0.500 | 1.000 | **`7.0 [4.0, 10.0]`** | 0.00 | **FAIL -> EXPERIMENTAL** |

### Per-Rule Findings, Misses, and Delay Behavior
- **`port-scan` (`windows=[[10, 20], [300, 60]]`):** Detects both fast (`0.0s` delay) and slow (`59.0s` delay across the 60-second probe build-up; mean delay across 12 attacks was `29.53s`) scans with `0` misses and `0` false positives across 1.0 hour of clean synthetic traffic.
- **`syn-flood`, `dns-tunnel`, `arp-spoof`, `horizontal-scan`:** All detect `6/6` held-out attacks in `0.0s` to `3.6s` with `0` misses and `0.0` clean false positives/hour.
- **`volumetric` (`alpha=0.05`, `z=6.0`, `warmup=30`, `rearm=5`):** Raises `7` false alerts during `1.0h` of clean synthetic traffic (`7.0/hr`, 95% CI `[4.0, 10.0]`, exceeding M0 `<= 1.0/hr`) plus `6` false alerts outside attack windows (`precision=0.500`). Benign traffic bursts at `t=90s` into capture routinely exceed `z=6.0` (observed `z=6.3` to `16.2`). Per M5 exit criteria, `volumetric` is now marked `"experimental": true` in `packetlens/policies/default.json` and fails the M0 false-alarm gate.

---

## 3. Offline Real-Data Validation (CIC-IDS2017 Flow CSVs)

Verified via `.venv-ci\Scripts\python.exe -m packetlens reproduce --data-dir cicids2017_traffic_label` (dry-run against `cicids2017_traffic_label/*.csv`).

### 3.1 Minute-Bin Volume Detectors (`results/flows_real.json`, `292` train / `195` clean hold-out / `484` attack bins)

| Method | Precision (95% CI) | Recall (95% CI) | F1 (95% CI) | Clean FA/hr (95% CI) | Bot Recall | DDoS Recall | PortScan Recall |
|---|---|---|---|---|---:|---:|---:|
| `zscore_adaptive` (live baseline algorithm) | `0.522 [0.19, 0.833]` | `0.079 [0.02, 0.157]` | `0.137 [0.037, 0.255]` | **`1.23 [0.0, 2.77]`** | `0.0` | `0.095` | `0.5` |
| `zscore_frozen` (offline reference) | `0.623 [0.378, 0.8]` | `0.217 [0.102, 0.342]` | `0.322 [0.164, 0.465]` | **`1.54 [0.31, 3.08]`** | `0.027` | `0.905` | `0.55` |
| `isolation_forest` (offline sklearn) | `1.0 [1.0, 1.0]` | `0.171 [0.065, 0.288]` | `0.292 [0.122, 0.448]` | `0.0 [0.0, 0.0]` | `0.0` | `0.905` | `0.35` |

*Note on Granite forecaster:* `torch` / `tsfm_public` are not installed in `.venv-ci`; saved `results/flows_real.json` previously recorded `precision=0.714 [0.464, 0.9]`, `recall=0.132 [0.056, 0.221]`, and `1.23 [0.0, 2.77]` clean FA/hr (unverified in this session without the optional `granite` extra).

Both Z-score variants exceed `1.0` clean false alarm/hour on real Monday CIC-IDS2017 traffic, reinforcing why `volumetric` stays **experimental**.

### 3.2 Per-Flow Classifiers (`flowmodel`, Friday CIC-IDS2017 CSVs)

- **Friday Bot (`191,033` rows; `667` Bot / `75,747` BENIGN test):** Random Forest achieves precision `0.6604 [0.4192, 0.8041]`, recall `0.2624 [0.1155, 0.4108]`, F1 `0.3755`, PR-AUC `0.2682`, and **`41.54 [29.08, 54.97]` false alarms/hour** (`90` FPs). Logistic Regression (`0.1536` precision, `0.9955` recall, `3,659` FPs under numpy `2.5.4`/pandas `3.1.1`) and BENIGN-only Isolation Forest (`0.0000` precision/recall, `5,792` FPs) are unsuitable as operational detectors.
- **Friday PortScan (`286,467` rows; `77,096` PortScan / `37,491` BENIGN test):** Random Forest reaches precision `1.0000 [1.0000, 1.0000]`, recall `0.9992 [0.9968, 0.9998]`, `0.0` FA/hr, but **98.96% (`76,292 / 77,096`) of test PortScan vectors are exact duplicates of training feature vectors**. On duplicate-free test rows (`n=34,755`), recall drops to `0.9204`.
- **Friday DDoS (`225,745` rows; `41,298` DDoS / `49,000` BENIGN test):** Low test duplicate rate (`0.01%` DDoS, `4.36%` BENIGN). Random Forest reaches precision `0.9997 [0.9990, 0.9999]`, recall `0.9988 [0.9948, 1.0000]`, F1 `0.9992`, yet still emits `13` FPs = **`14.44 [4.97, 26.67]` false alarms/hour**, exceeding the M0 `<= 1.0/hr` gate.

---

## 4. Known Leakage, Shortcut, and Label Risks (`results/flowmodel_audit.json`)

1. **Duplicate feature-vector leakage:** Chronological splits share identical flow-stat vectors between train and test (`98.96%` for PortScan, `12.14%` for Bot, `7.79%`–`9.44%` for BENIGN).
2. **Label-window discrepancy & misses on Bot traffic:** In Friday morning Bot labels, all `175` Random Forest true positives fell **inside** the documented attack window (`175/175`), while `0` of `492` outside-window `Bot` rows were detected (`0/492`). Furthermore, external attacker `205.174.165.73` has `0` `BENIGN` flows after the window in `flowmodel_audit.json`.
3. **Host/source-IP overfitting:** Under `cleaner_machine_split`, Random Forest hits `0.9881` precision / `0.9565` recall across held-out internal hosts (`192.168.10.*`), but removing external attack source IPs (`cleaner_without_external_sources`) leaves `0` training attack rows and yields `0.0` recall.
4. **Protocol/port shortcut risk:** Including `Destination Port` raises Bot PR-AUC from `0.2682` to `0.4224`, demonstrating shortcut memorization rather than general payload/behavior modeling.

---

## 5. Remaining Blockers Before Passing M5

Per Section 5 M5 exit criteria (*"Synthetic evaluation alone does not pass this milestone"* and *"Have a human review alert usefulness"*):
1. **No raw real-world labeled PCAPs in workspace:** `cicids2017_traffic_label/` contains flow CSVs only, not raw `.pcap` captures. Live packet rules (`port_scan`, `syn_flood`, `dns_tunnel`, `arp_spoof`, `horizontal_scan`) have **not** yet been run against real benign enterprise/workstation `.pcap` traffic to verify `<= 1.0` false alarm/hour on real non-synthetic packets.
2. **Human alert-usefulness review:** A project maintainer / operator must inspect real-capture alerts and incidents and record approval in Section 10 (`DEC-2026-11-12-m5-detection-quality`) before advancing to M6 pilot deployment.
