# PacketLens evaluation results

## benchmark.json

### Provenance

| Field | Value |
| --- | --- |
| Command line | python -m packetlens reproduce --write |
| UTC time | 2026-11-11T07:52:34Z |
| Version: python | 3.12.10 |
| Version: numpy | 1.26.4 |
| Version: pandas | 3.0.6 |
| Version: scikit-learn | 1.9.1 |
| Seed: benign_traffic | 3 |

### Throughput benchmark

| Measurement | Value |
| --- | --- |
| packets | 102773 |
| parse_only_pps | 395536 |
| full_pipeline_pps | 140644 |

### Caveats

Throughput varies with hardware, Python build, and system load. See [the evaluation protocol](EVALUATION_PROTOCOL.md) and [limitations](LIMITATIONS.md).

## evaluation.json

### Provenance

| Field | Value |
| --- | --- |
| Command line | python -m packetlens reproduce --write |
| UTC time | 2026-11-11T07:52:32Z |
| Version: python | 3.12.10 |
| Version: numpy | 1.26.4 |
| Version: pandas | 3.0.6 |
| Version: scikit-learn | 1.9.1 |
| Seed: benign_traffic | 7 |
| Seed: attack_traffic | 8 |

### Event detection

| Event | Detector | Detected | Delay (s) |
| --- | --- | --- | --- |
| port_scan_fast | port_scan | yes | 0 |
| port_scan_slow | port_scan | yes | 59 |
| dns_tunnel | dns_tunnel | yes | 3.6 |
| syn_flood | syn_flood | yes | 0.1 |
| udp_flood | volumetric | yes | 0 |
| arp_spoof | arp_spoof | yes | 0 |
| horizontal_scan | horizontal_scan | yes | 0.3 |

### Alert and traffic totals

| Measure | Value |
| --- | --- |
| duration_s | 300 |
| packets_benign | 55291 |
| packets_attack | 92964 |
| alerts_total | 11 |
| alerts_in_attack_windows | 10 |
| alert_precision | 0.909 |
| false_positives_per_hour | 12 |

### Clean-traffic false positives

| Detector | Count |
| --- | --- |
| volumetric | 1 |

### Bin-level volume detectors

| Method | Precision | Recall | F1 | TP | FP | FN |
| --- | --- | --- | --- | --- | --- | --- |
| zscore_adaptive | 0.792 | 0.731 | 0.76 | 19 | 5 | 7 |
| isolation_forest | 0.867 | 0.5 | 0.634 | 13 | 2 | 13 |

### False-positive details

| Detail |
| --- |
| packets 523/s vs baseline 192 (z=7.4); bytes 435250/s vs baseline 88360 (z=15.1) |

### Caveats

Synthetic traffic and labels are generated together; these results are optimistic and are not an estimate of field performance. See [the evaluation protocol](EVALUATION_PROTOCOL.md) and [limitations](LIMITATIONS.md).

## flowmodel_audit.json

### Provenance

| Field | Value |
| --- | --- |
| Command line | python -m packetlens reproduce --write |
| UTC time | 2026-11-11T07:53:10Z |
| Version: python | 3.12.10 |
| Version: numpy | 1.26.4 |
| Version: pandas | 3.0.6 |
| Version: scikit-learn | 1.9.1 |
| Seed: random_forest | 42 |
| Seed: isolation_forest | 42 |
| Seed: bootstrap | 42 |
| Dataset file | Friday-WorkingHours-Morning.pcap_ISCX.csv — available; 75386737 bytes; SHA-256 c061cd98f39d8054aeaed6244a5129a20b3985983d0d022b860ae8aa07fe8d21 |

### Train/test counts

| Split | Class | Flows |
| --- | --- | --- |
| train | Bot | 1299 |
| train | BENIGN | 113320 |
| test | Bot | 667 |
| test | BENIGN | 75747 |

### Model results

| Model | Precision | Recall | F1 | Average precision | FP | FN | False alarms/hour |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Dummy stratified | 0.0068 | 0.009 | 0.0078 | 0.0087 | 870 | 661 | — |
| Logistic regression | 0.1537 | 0.9955 | 0.2663 | 0.1229 | 3656 | 3 | — |
| Random forest | 0.6604 [0.41915, 0.804072] (n=130) | 0.2624 [0.115463, 0.410833] (n=130) | 0.3755 [0.181544, 0.540465] (n=130) | 0.2682 | 90 | 492 | 41.5385 [29.0769, 54.9692] (n=130) |
| Isolation Forest (BENIGN-only) | 0 | 0 | 0 | 0.0171 | 5792 | 667 | — |
| with Destination Port (shortcut risk) | 0.7085 | 0.2624 | 0.3829 | 0.4224 | 72 | 492 | — |

### Exact train/test feature duplicates

| Class | Test rows | Exact duplicates | Rate | Duplicate-free rows |
| --- | --- | --- | --- | --- |
| Bot | 667 | 81 | 0.121439 | 586 |
| BENIGN | 75747 | 5902 | 0.077917 | 69845 |

### Duplicate-free test metrics

| Rows | Precision | Recall | F1 | False positives |
| --- | --- | --- | --- | --- |
| 70431 | 0.5595 | 0.1604 | 0.2493 | 74 |

### Top feature importances

| Feature | Importance |
| --- | --- |
| Init_Win_bytes_backward | 0.152139 |
| Avg Bwd Segment Size | 0.100833 |
| Bwd Packet Length Mean | 0.099925 |
| Init_Win_bytes_forward | 0.092373 |
| Average Packet Size | 0.048578 |
| Subflow Bwd Bytes | 0.041136 |
| Packet Length Mean | 0.031303 |
| Flow Bytes/s | 0.030698 |
| Total Length of Bwd Packets | 0.030423 |
| Bwd Packet Length Max | 0.030164 |

### Label-window audit

| Field | Value |
| --- | --- |
| attacker_ips[0] | 205.174.165.73 |
| h1_bot_flows_per_30min[0].slot | 2017-07-07 09:30 |
| h1_bot_flows_per_30min[0].inside | 0 |
| h1_bot_flows_per_30min[0].outside | 2 |
| h1_bot_flows_per_30min[1].slot | 2017-07-07 10:00 |
| h1_bot_flows_per_30min[1].inside | 318 |
| h1_bot_flows_per_30min[1].outside | 0 |
| h1_bot_flows_per_30min[2].slot | 2017-07-07 10:30 |
| h1_bot_flows_per_30min[2].inside | 1130 |
| h1_bot_flows_per_30min[2].outside | 0 |
| h1_bot_flows_per_30min[3].slot | 2017-07-07 11:00 |
| h1_bot_flows_per_30min[3].inside | 24 |
| h1_bot_flows_per_30min[3].outside | 114 |
| h1_bot_flows_per_30min[4].slot | 2017-07-07 11:30 |
| h1_bot_flows_per_30min[4].inside | 0 |
| h1_bot_flows_per_30min[4].outside | 126 |
| h1_bot_flows_per_30min[5].slot | 2017-07-07 12:00 |
| h1_bot_flows_per_30min[5].inside | 0 |
| h1_bot_flows_per_30min[5].outside | 126 |
| h1_bot_flows_per_30min[6].slot | 2017-07-07 12:30 |
| h1_bot_flows_per_30min[6].inside | 0 |
| h1_bot_flows_per_30min[6].outside | 126 |
| h2_attacker_flows_after_window.205.174.165.73.slots[0].slot | 2017-07-07 11:00 |
| h2_attacker_flows_after_window.205.174.165.73.slots[0].BENIGN | 0 |
| h2_attacker_flows_after_window.205.174.165.73.slots[0].Bot | 112 |
| h2_attacker_flows_after_window.205.174.165.73.slots[1].slot | 2017-07-07 11:30 |
| h2_attacker_flows_after_window.205.174.165.73.slots[1].BENIGN | 0 |
| h2_attacker_flows_after_window.205.174.165.73.slots[1].Bot | 126 |
| h2_attacker_flows_after_window.205.174.165.73.slots[2].slot | 2017-07-07 12:00 |
| h2_attacker_flows_after_window.205.174.165.73.slots[2].BENIGN | 0 |
| h2_attacker_flows_after_window.205.174.165.73.slots[2].Bot | 126 |
| h2_attacker_flows_after_window.205.174.165.73.slots[3].slot | 2017-07-07 12:30 |
| h2_attacker_flows_after_window.205.174.165.73.slots[3].BENIGN | 0 |
| h2_attacker_flows_after_window.205.174.165.73.slots[3].Bot | 126 |
| h2_attacker_flows_after_window.205.174.165.73.BENIGN_after_window | 0 |
| h2_attacker_flows_after_window.205.174.165.73.any_BENIGN_after_window | no |
| h3_destination_pairs.distinct_outside_pairs | 3 |
| h3_destination_pairs.pairs_also_inside | 1 |
| h3_destination_pairs.fraction_also_inside | 0.333333 |
| h4_test_bot.model | Random forest |
| h4_test_bot.threshold | 0.5 |
| h4_test_bot.precision | 0.6604 |
| h4_test_bot.inside.tp | 175 |
| h4_test_bot.inside.fn | 0 |
| h4_test_bot.outside.tp | 0 |
| h4_test_bot.outside.fn | 492 |

### Cleaner split diagnostics

| Field | Value |
| --- | --- |
| cleaner_machine_split.held_out_source_ips[0] | 192.168.10.12 |
| cleaner_machine_split.held_out_source_ips[1] | 192.168.10.15 |
| cleaner_machine_split.held_out_source_ips[2] | 192.168.10.17 |
| cleaner_machine_split.held_out_source_ips[3] | 192.168.10.5 |
| cleaner_machine_split.held_out_source_ips[4] | 192.168.10.9 |
| cleaner_machine_split.counts.train.attack | 722 |
| cleaner_machine_split.counts.train.BENIGN | 95752 |
| cleaner_machine_split.counts.test.attack | 781 |
| cleaner_machine_split.counts.test.BENIGN | 76229 |
| cleaner_machine_split.random_forest.precision | 0.9881 |
| cleaner_machine_split.random_forest.recall | 0.9565 |
| cleaner_machine_split.random_forest.f1 | 0.972 |
| cleaner_machine_split.random_forest.average_precision | 0.991 |
| cleaner_machine_split.random_forest.tn | 76220 |
| cleaner_machine_split.random_forest.fp | 9 |
| cleaner_machine_split.random_forest.fn | 34 |
| cleaner_machine_split.random_forest.tp | 747 |
| cleaner_machine_split.random_forest.fp_per_1000_benign | 0.12 |
| cleaner_without_external_sources.held_out_source_ips[0] | 192.168.10.12 |
| cleaner_without_external_sources.held_out_source_ips[1] | 192.168.10.15 |
| cleaner_without_external_sources.held_out_source_ips[2] | 192.168.10.17 |
| cleaner_without_external_sources.held_out_source_ips[3] | 192.168.10.5 |
| cleaner_without_external_sources.held_out_source_ips[4] | 192.168.10.9 |
| cleaner_without_external_sources.counts.train.attack | 0 |
| cleaner_without_external_sources.counts.train.BENIGN | 95752 |
| cleaner_without_external_sources.counts.test.attack | 781 |
| cleaner_without_external_sources.counts.test.BENIGN | 76229 |
| cleaner_without_external_sources.random_forest.precision | 0 |
| cleaner_without_external_sources.random_forest.recall | 0 |
| cleaner_without_external_sources.random_forest.f1 | 0 |
| cleaner_without_external_sources.random_forest.average_precision | 0.0101 |
| cleaner_without_external_sources.random_forest.tn | 76229 |
| cleaner_without_external_sources.random_forest.fp | 0 |
| cleaner_without_external_sources.random_forest.fn | 781 |
| cleaner_without_external_sources.random_forest.tp | 0 |
| cleaner_without_external_sources.random_forest.fp_per_1000_benign | 0 |

### Caveats

Per-flow results use a chronological split and can reflect dataset label artifacts and exact feature duplicates; see the duplicate check and label-window audit. See [the evaluation protocol](EVALUATION_PROTOCOL.md) and [limitations](LIMITATIONS.md).

## flowmodel_ddos.json

### Provenance

| Field | Value |
| --- | --- |
| Command line | python -m packetlens reproduce --write |
| UTC time | 2026-11-11T07:54:18Z |
| Version: python | 3.12.10 |
| Version: numpy | 1.26.4 |
| Version: pandas | 3.0.6 |
| Version: scikit-learn | 1.9.1 |
| Seed: random_forest | 42 |
| Seed: isolation_forest | 42 |
| Seed: bootstrap | 42 |
| Dataset file | Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv — available; 96101069 bytes; SHA-256 1f779b4f0d78f9225554c4de53b5a2c07912b60dcd136ee4c5c1d0d2496b7cc4 |

### Train/test counts

| Split | Class | Flows |
| --- | --- | --- |
| train | DDoS | 86729 |
| train | BENIGN | 48718 |
| test | DDoS | 41298 |
| test | BENIGN | 49000 |

### Model results

| Model | Precision | Recall | F1 | Average precision | FP | FN | False alarms/hour |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Dummy stratified | 0.4587 | 0.642 | 0.5351 | 0.4582 | 31280 | 14786 | — |
| Logistic regression | 0.9978 | 0.998 | 0.9979 | 0.9991 | 92 | 83 | — |
| Random forest | 0.9997 [0.999048, 0.999886] (n=54) | 0.9988 [0.994816, 0.999952] (n=54) | 0.9992 [0.997058, 0.999844] (n=54) | 0.9997 | 13 | 50 | 14.4444 [4.97222, 26.6667] (n=54) |
| Isolation Forest (BENIGN-only) | 0.7827 | 0.5472 | 0.6441 | 0.6814 | 6275 | 18698 | — |
| with Destination Port (shortcut risk) | 0.9979 | 0.9992 | 0.9985 | 0.9998 | 88 | 32 | — |

### Exact train/test feature duplicates

| Class | Test rows | Exact duplicates | Rate | Duplicate-free rows |
| --- | --- | --- | --- | --- |
| DDoS | 41298 | 5 | 0.000121 | 41293 |
| BENIGN | 49000 | 2135 | 0.043571 | 46865 |

### Duplicate-free test metrics

| Rows | Precision | Recall | F1 | False positives |
| --- | --- | --- | --- | --- |
| 88158 | 0.9997 | 0.9988 | 0.9992 | 13 |

### Top feature importances

| Feature | Importance |
| --- | --- |
| Fwd Packet Length Max | 0.102262 |
| Avg Fwd Segment Size | 0.066658 |
| Fwd Packet Length Mean | 0.066089 |
| Init_Win_bytes_forward | 0.065737 |
| act_data_pkt_fwd | 0.051538 |
| Bwd Packet Length Std | 0.043893 |
| Subflow Fwd Packets | 0.041985 |
| Avg Bwd Segment Size | 0.038089 |
| Subflow Fwd Bytes | 0.038065 |
| Total Fwd Packets | 0.03414 |

### Caveats

Per-flow results use a chronological split and can reflect dataset label artifacts and exact feature duplicates; see the duplicate check and label-window audit. See [the evaluation protocol](EVALUATION_PROTOCOL.md) and [limitations](LIMITATIONS.md).

## flowmodel_portscan.json

### Provenance

| Field | Value |
| --- | --- |
| Command line | python -m packetlens reproduce --write |
| UTC time | 2026-11-11T07:53:48Z |
| Version: python | 3.12.10 |
| Version: numpy | 1.26.4 |
| Version: pandas | 3.0.6 |
| Version: scikit-learn | 1.9.1 |
| Seed: random_forest | 42 |
| Seed: isolation_forest | 42 |
| Seed: bootstrap | 42 |
| Dataset file | Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv — available; 101874777 bytes; SHA-256 7e2ddaa80a5849ba629463296b6128436c161b4a32e8034bb5beae06b0c45e08 |

### Train/test counts

| Split | Class | Flows |
| --- | --- | --- |
| train | PortScan | 81834 |
| train | BENIGN | 90046 |
| test | PortScan | 77096 |
| test | BENIGN | 37491 |

### Model results

| Model | Precision | Recall | F1 | Average precision | FP | FN | False alarms/hour |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Dummy stratified | 0.6721 | 0.4758 | 0.5572 | 0.6725 | 17900 | 40412 | — |
| Logistic regression | 0.9997 | 0.9982 | 0.999 | 0.9999 | 20 | 140 | — |
| Random forest | 1 [1, 1] (n=36) | 0.9992 [0.996834, 0.99975] (n=36) | 0.9996 [0.998415, 0.999875] (n=36) | 0.9999 | 0 | 64 | 0 [0, 0] (n=36) |
| Isolation Forest (BENIGN-only) | 0.03 | 0.0013 | 0.0025 | 0.6777 | 3206 | 76997 | — |
| with Destination Port (shortcut risk) | 1 | 0.9992 | 0.9996 | 0.9999 | 0 | 64 | — |

### Exact train/test feature duplicates

| Class | Test rows | Exact duplicates | Rate | Duplicate-free rows |
| --- | --- | --- | --- | --- |
| PortScan | 77096 | 76292 | 0.989571 | 804 |
| BENIGN | 37491 | 3540 | 0.094423 | 33951 |

### Duplicate-free test metrics

| Rows | Precision | Recall | F1 | False positives |
| --- | --- | --- | --- | --- |
| 34755 | 1 | 0.9204 | 0.9585 | 0 |

### Top feature importances

| Feature | Importance |
| --- | --- |
| Fwd Packet Length Max | 0.110568 |
| Total Length of Fwd Packets | 0.102669 |
| Subflow Fwd Bytes | 0.088035 |
| Fwd Packet Length Mean | 0.082515 |
| PSH Flag Count | 0.057023 |
| Packet Length Mean | 0.052743 |
| Avg Fwd Segment Size | 0.050631 |
| Bwd Packets/s | 0.04437 |
| Average Packet Size | 0.04418 |
| Flow IAT Max | 0.031303 |

### Caveats

Per-flow results use a chronological split and can reflect dataset label artifacts and exact feature duplicates; see the duplicate check and label-window audit. See [the evaluation protocol](EVALUATION_PROTOCOL.md) and [limitations](LIMITATIONS.md).

## flowmodel_real.json

### Provenance

| Field | Value |
| --- | --- |
| Command line | python -m packetlens reproduce --write |
| UTC time | 2026-11-11T07:53:10Z |
| Version: python | 3.12.10 |
| Version: numpy | 1.26.4 |
| Version: pandas | 3.0.6 |
| Version: scikit-learn | 1.9.1 |
| Seed: random_forest | 42 |
| Seed: isolation_forest | 42 |
| Seed: bootstrap | 42 |
| Dataset file | Friday-WorkingHours-Morning.pcap_ISCX.csv — available; 75386737 bytes; SHA-256 c061cd98f39d8054aeaed6244a5129a20b3985983d0d022b860ae8aa07fe8d21 |

### Train/test counts

| Split | Class | Flows |
| --- | --- | --- |
| train | Bot | 1299 |
| train | BENIGN | 113320 |
| test | Bot | 667 |
| test | BENIGN | 75747 |

### Model results

| Model | Precision | Recall | F1 | Average precision | FP | FN | False alarms/hour |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Dummy stratified | 0.0068 | 0.009 | 0.0078 | 0.0087 | 870 | 661 | — |
| Logistic regression | 0.1537 | 0.9955 | 0.2663 | 0.1229 | 3656 | 3 | — |
| Random forest | 0.6604 [0.41915, 0.804072] (n=130) | 0.2624 [0.115463, 0.410833] (n=130) | 0.3755 [0.181544, 0.540465] (n=130) | 0.2682 | 90 | 492 | 41.5385 [29.0769, 54.9692] (n=130) |
| Isolation Forest (BENIGN-only) | 0 | 0 | 0 | 0.0171 | 5792 | 667 | — |
| with Destination Port (shortcut risk) | 0.7085 | 0.2624 | 0.3829 | 0.4224 | 72 | 492 | — |

### Exact train/test feature duplicates

| Class | Test rows | Exact duplicates | Rate | Duplicate-free rows |
| --- | --- | --- | --- | --- |
| Bot | 667 | 81 | 0.121439 | 586 |
| BENIGN | 75747 | 5902 | 0.077917 | 69845 |

### Duplicate-free test metrics

| Rows | Precision | Recall | F1 | False positives |
| --- | --- | --- | --- | --- |
| 70431 | 0.5595 | 0.1604 | 0.2493 | 74 |

### Top feature importances

| Feature | Importance |
| --- | --- |
| Init_Win_bytes_backward | 0.152139 |
| Avg Bwd Segment Size | 0.100833 |
| Bwd Packet Length Mean | 0.099925 |
| Init_Win_bytes_forward | 0.092373 |
| Average Packet Size | 0.048578 |
| Subflow Bwd Bytes | 0.041136 |
| Packet Length Mean | 0.031303 |
| Flow Bytes/s | 0.030698 |
| Total Length of Bwd Packets | 0.030423 |
| Bwd Packet Length Max | 0.030164 |

### Cleaner split diagnostics

| Field | Value |
| --- | --- |
| cleaner_machine_split.held_out_source_ips[0] | 192.168.10.12 |
| cleaner_machine_split.held_out_source_ips[1] | 192.168.10.15 |
| cleaner_machine_split.held_out_source_ips[2] | 192.168.10.17 |
| cleaner_machine_split.held_out_source_ips[3] | 192.168.10.5 |
| cleaner_machine_split.held_out_source_ips[4] | 192.168.10.9 |
| cleaner_machine_split.counts.train.attack | 722 |
| cleaner_machine_split.counts.train.BENIGN | 95752 |
| cleaner_machine_split.counts.test.attack | 781 |
| cleaner_machine_split.counts.test.BENIGN | 76229 |
| cleaner_machine_split.random_forest.precision | 0.9881 |
| cleaner_machine_split.random_forest.recall | 0.9565 |
| cleaner_machine_split.random_forest.f1 | 0.972 |
| cleaner_machine_split.random_forest.average_precision | 0.991 |
| cleaner_machine_split.random_forest.tn | 76220 |
| cleaner_machine_split.random_forest.fp | 9 |
| cleaner_machine_split.random_forest.fn | 34 |
| cleaner_machine_split.random_forest.tp | 747 |
| cleaner_machine_split.random_forest.fp_per_1000_benign | 0.12 |
| cleaner_without_external_sources.held_out_source_ips[0] | 192.168.10.12 |
| cleaner_without_external_sources.held_out_source_ips[1] | 192.168.10.15 |
| cleaner_without_external_sources.held_out_source_ips[2] | 192.168.10.17 |
| cleaner_without_external_sources.held_out_source_ips[3] | 192.168.10.5 |
| cleaner_without_external_sources.held_out_source_ips[4] | 192.168.10.9 |
| cleaner_without_external_sources.counts.train.attack | 0 |
| cleaner_without_external_sources.counts.train.BENIGN | 95752 |
| cleaner_without_external_sources.counts.test.attack | 781 |
| cleaner_without_external_sources.counts.test.BENIGN | 76229 |
| cleaner_without_external_sources.random_forest.precision | 0 |
| cleaner_without_external_sources.random_forest.recall | 0 |
| cleaner_without_external_sources.random_forest.f1 | 0 |
| cleaner_without_external_sources.random_forest.average_precision | 0.0101 |
| cleaner_without_external_sources.random_forest.tn | 76229 |
| cleaner_without_external_sources.random_forest.fp | 0 |
| cleaner_without_external_sources.random_forest.fn | 781 |
| cleaner_without_external_sources.random_forest.tp | 0 |
| cleaner_without_external_sources.random_forest.fp_per_1000_benign | 0 |

### Caveats

Per-flow results use a chronological split and can reflect dataset label artifacts and exact feature duplicates; see the duplicate check and label-window audit. See [the evaluation protocol](EVALUATION_PROTOCOL.md) and [limitations](LIMITATIONS.md).

## flows_real.json

### Provenance

| Field | Value |
| --- | --- |
| Command line | python -m packetlens reproduce --write |
| UTC time | 2026-11-11T07:52:34Z |
| Version: python | 3.12.10 |
| Version: numpy | 1.26.4 |
| Version: pandas | 3.0.6 |
| Version: scikit-learn | 1.9.1 |
| Seed: isolation_forest | 0 |
| Seed: bootstrap | 42 |
| Seed: granite | model revision controls inference |
| Dataset file | Monday-WorkingHours.pcap_ISCX.csv — available; 268649908 bytes; SHA-256 96f26aea87d513073769b48ce204c2921791149e1c6225f7db65a3fed7973820 |
| Dataset file | Friday-WorkingHours-Morning.pcap_ISCX.csv — available; 75386737 bytes; SHA-256 c061cd98f39d8054aeaed6244a5129a20b3985983d0d022b860ae8aa07fe8d21 |
| Dataset file | Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv — available; 101874777 bytes; SHA-256 7e2ddaa80a5849ba629463296b6128436c161b4a32e8034bb5beae06b0c45e08 |
| Dataset file | Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv — available; 96101069 bytes; SHA-256 1f779b4f0d78f9225554c4de53b5a2c07912b60dcd136ee4c5c1d0d2496b7cc4 |

### Bin counts

| Set | Bins |
| --- | --- |
| train | 292 |
| clean_holdout | 195 |
| attack_set | 484 |
| attack_bins | 152 |

### Overall detector metrics

| Method | Precision | Recall | F1 | False alarms/hour (clean) |
| --- | --- | --- | --- | --- |
| zscore_adaptive | 0.522 [0.19, 0.833] (n=484) | 0.079 [0.02, 0.157] (n=484) | 0.137 [0.037, 0.255] (n=484) | 1.23 [0, 2.77] (n=195) |
| zscore_frozen | 0.623 [0.378, 0.8] (n=484) | 0.217 [0.102, 0.342] (n=484) | 0.322 [0.164, 0.465] (n=484) | 1.54 [0.31, 3.08] (n=195) |
| isolation_forest | 1 [1, 1] (n=484) | 0.171 [0.065, 0.288] (n=484) | 0.292 [0.122, 0.448] (n=484) | 0 [0, 0] (n=195) |
| granite | 0.714 [0.464, 0.9] (n=484) | 0.132 [0.056, 0.221] (n=484) | 0.222 [0.099, 0.345] (n=484) | 1.23 [0, 2.77] (n=195) |

### Metrics by attack family

| Attack family | Method | Precision | Recall | F1 |
| --- | --- | --- | --- | --- |
| Bot | zscore_adaptive | 0 [0, 0] (n=484) | 0 [0, 0] (n=484) | 0 [0, 0] (n=484) |
| Bot | zscore_frozen | 0.057 [0, 0.143] (n=484) | 0.027 [0, 0.063] (n=484) | 0.037 [0, 0.081] (n=484) |
| Bot | isolation_forest | 0 [0, 0] (n=484) | 0 [0, 0] (n=484) | 0 [0, 0] (n=484) |
| Bot | granite | 0.071 [0, 0.211] (n=484) | 0.018 [0, 0.044] (n=484) | 0.029 [0, 0.071] (n=484) |
| DDoS | zscore_adaptive | 0.087 [0, 0.3] (n=484) | 0.095 [0, 0.334] (n=484) | 0.091 [0, 0.259] (n=484) |
| DDoS | zscore_frozen | 0.358 [0.1, 0.567] (n=484) | 0.905 [0.667, 1] (n=484) | 0.514 [0.174, 0.707] (n=484) |
| DDoS | isolation_forest | 0.731 [0.294, 0.964] (n=484) | 0.905 [0.667, 1] (n=484) | 0.809 [0.437, 0.949] (n=484) |
| DDoS | granite | 0.286 [0.024, 0.581] (n=484) | 0.381 [0.028, 0.857] (n=484) | 0.327 [0.038, 0.577] (n=484) |
| PortScan | zscore_adaptive | 0.435 [0.083, 0.75] (n=484) | 0.5 [0.111, 0.867] (n=484) | 0.465 [0.091, 0.717] (n=484) |
| PortScan | zscore_frozen | 0.208 [0.042, 0.406] (n=484) | 0.55 [0.143, 0.909] (n=484) | 0.301 [0.071, 0.518] (n=484) |
| PortScan | isolation_forest | 0.269 [0.036, 0.706] (n=484) | 0.35 [0.056, 0.667] (n=484) | 0.304 [0.051, 0.6] (n=484) |
| PortScan | granite | 0.357 [0.091, 0.63] (n=484) | 0.5 [0.129, 0.84] (n=484) | 0.417 [0.108, 0.65] (n=484) |

### Granite run details

| Field | Value |
| --- | --- |
| revision | 90-30-ft-l1-r2.1 |
| context_length | 90 |
| horizon | 30 |
| feature | flows |
| false_alarm_budget_per_hour | 1 |
| threshold | 4.30819 |
| residual_spread | 383.071 |
| calibration_bins | 292 |
| calibration_residuals | 202 |
| calibration_hours | 3.36667 |
| library_versions | {"granite-tsfm": "0.2.22", "torch": "2.15.0+cpu", "transformers": "4.48.3"} |
| unscored_attack_prefix_bins | 90 |

### Caveats

CIC-IDS2017 flow tables are aggregated into one-minute bins; this is not packet pipeline evaluation. Attack bins require at least five labelled attack flows. See [the evaluation protocol](EVALUATION_PROTOCOL.md) and [limitations](LIMITATIONS.md).
