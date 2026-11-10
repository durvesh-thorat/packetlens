# Learning path: understand, test, then rebuild

Reading this code is not the same as being able to write it. For each module: read the concept,
run the small experiment, then close the file and re-implement it yourself in `scratch/`.
Check your version against the real one with the test named at the end of each step.

## 0. Bytes and byte order (30 min)
Concept: a byte is 8 bits, hexadecimal shows one byte as two characters, big-endian puts the most significant byte first. Network protocols are big-endian.
Experiment:
```python
int.from_bytes(b"\x01\x00", "big")      # predict first: 256
int.from_bytes(b"\x01\x00", "little")   # predict first: 1
import struct; struct.unpack("!HH", b"\x01\xbb\x00\x50")   # (443, 80)
```
Rebuild: a function turning 4 bytes into `192.168.1.1` without `socket.inet_ntoa`.

## 1. The layers (1 hour, no code)
Concept: Ethernet frame contains an IP packet contains a TCP segment or UDP datagram contains an application message (DNS). Each layer is a header followed by the next layer's bytes.
Experiment: open Wireshark, run `ping google.com` and `nslookup example.com`, click each packet, and expand every layer. Write one line per layer: which bytes, which fields.

## 2. pcap files (1 hour) -> `pcap.py`
Concept: 24-byte global header, then for every packet a 16-byte record header and the packet bytes. The magic number tells byte order and timestamp precision.
Experiment: `xxd -l 64 demo.pcap` and find the magic, the link type (1 = Ethernet) and the first record length by hand.
Rebuild: a reader that yields `(timestamp, bytes)`. Check: `tests/test_pcap_and_parsers.py::PcapTests`.

## 3. Ethernet, IPv4, ARP (2 hours) -> `parsers.py`
Concept: Ethernet header 14 bytes (destination, source, ethertype). IPv4 header length is `(first byte & 0x0F) * 4`, never assume 20. Protocol number 6 is TCP, 17 is UDP.
Experiment: decode the first packet by hand on paper, then compare with Wireshark.
Rebuild: `parse_packet` for Ethernet + IPv4 only. Check: `ParserTests.test_tcp_syn`, `test_payload_length_and_ethernet_padding`.
Pitfall to find yourself: what happens if you forget `total_length` and the frame has padding?

## 4. TCP, UDP, DNS (2 hours)
Concept: TCP flags live in the low byte of the 13th header byte. A connection starts SYN, SYN-ACK, ACK. A bare SYN (no ACK) means "I want to connect".
Experiment: `curl http://example.com` while capturing; find the three-way handshake.
Rebuild: TCP and UDP ports and flags, then the DNS question name (length-prefixed labels). Check: `test_dns_query_and_response`, `test_garbage_and_truncation_never_crash`.

## 5. Detection rules (3 hours) -> `detectors.py`
For each detector write down, before reading the code: what does the attack look like in packets, what normal behaviour looks similar, and which single number separates them.
Experiments:
* Run `nmap -sS` against your own lab machine and look at the SYN pattern.
* Change `SynFloodDetector` to key on destination only and watch the fast port scan become a false "flood". That is why the key includes the port.
* Compute `shannon_entropy` for "google", "a8f3k2m9x1q7" and a 30-character random string.
Check: `DetectorTests`.

## 6. Time series and baselines (3 hours) -> `timeseries.py`
Concept: mean, variance, z-score, exponentially weighted averages. Why a variance floor? Why clip a spike before updating the baseline?
Experiment: feed the detector a flat series, then a spike, then a permanent level shift. Plot the baseline.
Rebuild: a plain z-score over a fixed window first, then the EWMA version. Compare false alarms on `generate --no-attacks`.

## 7. Evaluation (2 hours) -> `evaluate.py`
Concept: precision, recall, false positives per hour, detection delay. Why evaluating on traffic you wrote yourself is optimistic.
Experiment: change one threshold and predict, before running, whether recall or precision moves.

## 8. Machine learning (after everything above)
Decide the question first: "does a learned model beat the z-score baseline without per-network tuning?"
Then pick a model and a real dataset and add them behind the `fit` / `predict` interface in `ml.py`.
