# PacketLens

A network traffic analyzer written from scratch in Python (standard library only for the core).
It reads raw bytes, decodes protocols itself, detects network attacks, watches traffic volume
for anomalies, and shows everything on a live dashboard.

No scapy, no dpkt, no pyshark: every header field is decoded with `struct` from its byte offset.

```
raw bytes ──► pcap reader / live socket ──► parsers ──► engine ──┬─► packet detectors ──► alerts
                                                                 ├─► per-second bins ──► volume detector ──► alerts
                                                                 └─► statistics ──► HTTP snapshot ──► dashboard
```

## Quick start

```bash
python -m unittest discover -s tests
python -m packetlens generate demo.pcap
python -m packetlens analyze demo.pcap
python -m packetlens serve --pcap demo.pcap --loop
python -m packetlens evaluate
python -m packetlens bench
sudo python -m packetlens serve --iface eth0
pip install scikit-learn numpy pandas
```

The core uses only the Python standard library. Live capture needs Linux (`AF_PACKET`) and root.
The machine-learning and real-data commands use the optional packages shown above.

## GitHub large-file protection

Local Python environments are ignored. The pre-push hook also blocks outgoing files at or above
GitHub's 100 MiB file limit. Enable it in a clone with:

```bash
git config core.hooksPath .githooks
```

## What it detects

| Detector | Signal | Key design choice |
|---|---|---|
| Port scan | One source sends bare SYNs to many different ports of one host | Separate short and long windows catch fast and slow scans |
| SYN flood | A high rate of bare SYNs to one address and port | Keyed on the port, so a scan does not look like a flood |
| DNS tunnelling | Many unique, long, high-entropy subdomains of one domain | Count, length, and Shannon entropy constrain false positives |
| ARP spoofing | An IP address suddenly claimed by a different hardware address | DHCP and failover can cause the same pattern |
| Volume anomaly | Packets, bytes, SYNs or DNS queries far above an adaptive baseline | EWMA mean and variance, spike clipping, one alert per anomalous run |

## Results

Reproduce and refresh [`results/evaluation.json`](results/evaluation.json) with
`python -m packetlens evaluate --save results/evaluation.json`. That file records the run duration,
packet counts, event detections, delays, alert precision, false alarms, and volume-detector metrics.

| Event | Detector | Detected | Delay (s) |
|---|---|---|---:|
| port_scan_fast | port_scan | yes | 0.0 |
| port_scan_slow | port_scan | yes | 59.0 |
| dns_tunnel | dns_tunnel | yes | 3.6 |
| syn_flood | syn_flood | yes | 0.1 |
| udp_flood | volumetric | yes | 0.0 |
| arp_spoof | arp_spoof | yes | 0.0 |

The recorded alert precision is 0.889, with 8 of 9 alerts inside attack windows.

| Method | Precision | Recall | F1 |
|---|---:|---:|---:|
| EWMA z-score | 0.762 | 0.762 | 0.762 |
| Isolation Forest | 0.867 | 0.619 | 0.722 |

Each value in these tables is from `results/evaluation.json`, produced by the command above.
The throughput values in [`results/benchmark.json`](results/benchmark.json) are from
`python -m packetlens bench`:

| Measurement | Packets/s |
|---|---:|
| Parse only | 400,084 |
| Full pipeline | 165,768 |

## Design decisions worth explaining in an interview

* **Bounded memory.** Every window is a deque with a hard cap and periodic cleanup, so a flood cannot exhaust RAM.
* **Malformed input never crashes.** Truncated frames are exercised by the parser tests.
* **Timestamps decide time, not the wall clock.** Replaying a capture at a different speed gives the same alerts.
* **One alert per anomaly, not one per second.** Cooldowns and re-arm logic keep the alert stream usable.
* **Ground truth first.** Synthetic traffic carries exact labels, so recorded measurements are reproducible.
* **Localhost by default.** The dashboard exposes captured network data, so it binds to localhost.

## Limitations (read before quoting results)

* The evaluation traffic is synthetic and written by the same author as the detectors, so the numbers are optimistic.
* Some Bot test flows fall outside the documented attack window. Their labels are unverified, so time-split recall is
  not purely a model property.
* Horizontal scans (one port across many hosts) are not flagged, on purpose: they look like a normal client.
* IPv6 extension headers are not followed; pcapng files must be converted (`editcap -F pcap in.pcapng out.pcap`).
* Detection thresholds are tuned for a small office-sized network. Other networks need other numbers.
* Live capture sees only traffic that reaches the capturing machine. Capture only networks you own or are authorised to monitor.

## Granite feasibility status

Gate failed: the documented IBM `granite-tsfm` install rejects the only installed Python interpreter as outside its
supported range. No compatible alternate interpreter is installed, so the Granite detector phase was skipped.
The Hugging Face model repository was reachable, but that does not make the unsupported package installation
reproducible on this machine.

## Real-data experiment (CIC flow files)

The public dataset ships labelled flow files (one row per connection) and, separately, multi-gigabyte packet captures.
The flow files cannot feed the packet parser, but they can feed the volume detectors. Reproduce and save the recorded
comparison with:

```bash
python -m packetlens flows --benign cicids2017_traffic_label/Monday-WorkingHours.pcap_ISCX.csv \
    --attack cicids2017_traffic_label/Friday-WorkingHours-Morning.pcap_ISCX.csv \
             cicids2017_traffic_label/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv \
             cicids2017_traffic_label/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv \
    --save results/flows_real.json
```

[`results/flows_real.json`](results/flows_real.json) records the training fraction, bin width, counts, and
per-method metrics. The methods are adaptive EWMA z-score, frozen EWMA z-score, and Isolation Forest.
Adaptive EWMA updates as it scores the hold-out and attack data; frozen EWMA retains its Monday training baseline.
`flows.py` handles stray header spaces, repeated header rows, `Infinity` values, a non-UTF-8 label,
and timestamps with no am/pm marker.

## Per-flow Bot detection

Run `python -m packetlens flowmodel --save results/flowmodel_real.json` for the per-flow classifier and BENIGN-only
Isolation Forest comparison on the Friday morning file. The saved metrics use a chronological split; IPs, flow IDs,
ports, and timestamps are excluded from the main feature set. Imputation and scaling are fitted on training rows only.
Evaluation uses default model thresholds without tuning on test labels; a separate Random Forest sensitivity row adds
Destination Port as a possible shortcut feature.

| Model | Precision | Recall | F1 | Average precision |
|---|---:|---:|---:|---:|
| Random forest | 0.6604 | 0.2624 | 0.3755 | 0.2682 |

Those measurements are from [`results/flowmodel_real.json`](results/flowmodel_real.json), produced by the command
above. `python -m packetlens flowmodel --audit-labels --save results/flowmodel_audit.json` adds the label-window
counts and the same Random Forest threshold recall split.

Pass `--extended` to additionally report thresholds selected against training-only validation alarm budgets,
and a held-out-machine experiment that groups by Source IP without using it as a feature. The extended report also
measures performance after removing test rows duplicated from training, and compares feature ablations on the
original time split. No extended experiment selects thresholds using test labels.
Grouping by Source IP alone can leak when the other side of a conversation remains in training.

## Layout

```
packetlens/pcap.py        pcap file format reader and writer
packetlens/parsers.py     Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP, DNS decoding
packetlens/detectors.py   port scan, SYN flood, DNS tunnel, ARP spoof
packetlens/timeseries.py  per-second bins, EWMA z-score volume detector
packetlens/ml.py          optional Isolation Forest, plug-in point for other models
packetlens/engine.py      pipeline and live statistics
packetlens/synth.py       labelled synthetic traffic with byte-exact packet builders
packetlens/evaluate.py    precision / recall / benchmark
packetlens/flows.py       CIC-IDS2017 flow files to per-minute series and detector comparison
packetlens/dashboard.py   HTTP server, static/index.html the live page
packetlens/capture.py     live capture (AF_PACKET)
docs/LEARNING.md          learn-test-implement path through the code
```
