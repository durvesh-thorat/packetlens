# Limitations

Each item links to the result or implementation evidence that bounds the claim.

| Limitation | Evidence |
|---|---|
| Synthetic traffic and labels are produced together, so synthetic metrics are optimistic and do not estimate field performance. | [`results/evaluation.json`](../results/evaluation.json) |
| Real-data results use CIC-IDS2017 flow tables and their supplied labels; they do not establish performance on other datasets, organizations, or time periods. | [`results/flows_real.json`](../results/flows_real.json), [`results/flowmodel_real.json`](../results/flowmodel_real.json) |
| The current real-data evidence covers one dataset, one Friday, and the ARES malware family for the Bot classifier. | [`results/flows_real.json`](../results/flows_real.json), [`results/flowmodel_audit.json`](../results/flowmodel_audit.json) |
| Per-minute volume aggregation discards flow-level detail, and an attack minute requires at least five labelled attack flows. | [`results/flows_real.json`](../results/flows_real.json), [`packetlens/flows.py`](../packetlens/flows.py) |
| Granite was scored on the single per-minute `flows` series; the other volume methods use six aggregate features. Its first 90 attack bins are unscored, and forecast context may include attack bins. | [`results/flows_real.json`](../results/flows_real.json), [`packetlens/ml.py`](../packetlens/ml.py) |
| PortScan and DDoS per-flow scores can be affected by repeated identical feature vectors. Read the per-class exact-duplicate rates and duplicate-free test precision/recall alongside the headline scores. | [`results/flowmodel_portscan.json`](../results/flowmodel_portscan.json), [`results/flowmodel_ddos.json`](../results/flowmodel_ddos.json) |
| Bot-labelled flows extend beyond the documented attack window. The audit cannot determine whether these labels represent a labeling artifact or real post-window behavior. | [`results/flowmodel_audit.json`](../results/flowmodel_audit.json) |
| The cleaner held-out-machine Bot split retained recall of 0.96. This is consistent with the label-window audit but does not prove that labels are valid or that the model generalizes. | [`results/flowmodel_audit.json`](../results/flowmodel_audit.json) |
| The parser supports Ethernet and Linux cooked link types, but does not follow IPv6 extension headers. Convert pcapng captures to supported pcap first. | [`packetlens/parsers.py`](../packetlens/parsers.py), [`packetlens/pcap.py`](../packetlens/pcap.py) |
| Live capture uses Linux `AF_PACKET` and requires appropriate privileges; it sees only traffic delivered to the selected capture interface. | [`packetlens/capture.py`](../packetlens/capture.py) |
| Default detection thresholds are configuration choices, not universal operating points; networks need validation and tuning against their own benign traffic. | [`packetlens/policies/default.json`](../packetlens/policies/default.json), [`results/flows_real.json`](../results/flows_real.json) |
| The flow-level machine-learning experiments run offline and do not participate in live packet analysis. | [`packetlens/flows.py`](../packetlens/flows.py), [`packetlens/flowmodel.py`](../packetlens/flowmodel.py) |
| Bootstrap intervals summarize variability under the chosen block-resampling scheme; samples under 30 bins are explicitly marked too few to trust. | [`packetlens/stats.py`](../packetlens/stats.py), generated intervals in [`results/flows_real.json`](../results/flows_real.json) and [`results/flowmodel_real.json`](../results/flowmodel_real.json) |
| A benchmark is machine- and load-dependent and is not a capacity guarantee. | [`results/benchmark.json`](../results/benchmark.json) |

These are evidence boundaries, not claims that the limitations can be eliminated by a different threshold or split.
