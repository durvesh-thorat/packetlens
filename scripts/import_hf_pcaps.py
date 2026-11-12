"""Download and verify classic PCAP captures from curated Hugging Face datasets.

Keeps large captures untracked under `hf_pcaps/` (gitignored) so CI tracked-file
size limits (<= 5 MiB) are preserved while enabling reproducible M5 real-PCAP testing.
"""
import argparse
import hashlib
import json
import struct
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

CURATED_CAPTURES = [
    # maureille/agentic-pcap (CC-BY-4.0) - labeled attack & high-background benign PCAPs
    {
        "dataset": "maureille/agentic-pcap",
        "repo_path": "data/pcaps/low_background/attack/run1235.pcap",
        "local_path": "agentic-pcap/low_background/run1235_arp_spoof.pcap",
        "label": "ARP spoofing",
        "kind": "attack",
    },
    {
        "dataset": "maureille/agentic-pcap",
        "repo_path": "data/pcaps/low_background/attack/run1236.pcap",
        "local_path": "agentic-pcap/low_background/run1236_dns_flood.pcap",
        "label": "DNS flood",
        "kind": "attack",
    },
    {
        "dataset": "maureille/agentic-pcap",
        "repo_path": "data/pcaps/low_background/attack/run1237.pcap",
        "local_path": "agentic-pcap/low_background/run1237_fin_scan.pcap",
        "label": "FIN scan",
        "kind": "attack",
    },
    {
        "dataset": "maureille/agentic-pcap",
        "repo_path": "data/pcaps/low_background/attack/run1239.pcap",
        "local_path": "agentic-pcap/low_background/run1239_null_scan.pcap",
        "label": "NULL scan",
        "kind": "attack",
    },
    {
        "dataset": "maureille/agentic-pcap",
        "repo_path": "data/pcaps/low_background/attack/run1240.pcap",
        "local_path": "agentic-pcap/low_background/run1240_syn_scan.pcap",
        "label": "TCP SYN port scan (nmap -sS)",
        "kind": "attack",
    },
    {
        "dataset": "maureille/agentic-pcap",
        "repo_path": "data/pcaps/low_background/attack/run1241.pcap",
        "local_path": "agentic-pcap/low_background/run1241_slowloris.pcap",
        "label": "Slowloris",
        "kind": "attack",
    },
    {
        "dataset": "maureille/agentic-pcap",
        "repo_path": "data/pcaps/low_background/attack/run1243.pcap",
        "local_path": "agentic-pcap/low_background/run1243_udp_scan.pcap",
        "label": "UDP scan",
        "kind": "attack",
    },
    {
        "dataset": "maureille/agentic-pcap",
        "repo_path": "data/pcaps/low_background/attack/run1244.pcap",
        "local_path": "agentic-pcap/low_background/run1244_xmas_scan.pcap",
        "label": "Xmas scan",
        "kind": "attack",
    },
    {
        "dataset": "maureille/agentic-pcap",
        "repo_path": "data/pcaps/generated_high_background/attack/run1246.pcap",
        "local_path": "agentic-pcap/high_background/run1246_arp_spoof.pcap",
        "label": "ARP spoofing (high background)",
        "kind": "attack",
    },
    {
        "dataset": "maureille/agentic-pcap",
        "repo_path": "data/pcaps/generated_high_background/benign/run1260.pcap",
        "local_path": "agentic-pcap/high_background/run1260_benign.pcap",
        "label": "Benign (high background)",
        "kind": "benign",
    },
    # mtasfi/ton-iot-with-pcap-payload (UNSW ToN_IoT real IoT/network captures)
    {
        "dataset": "mtasfi/ton-iot-with-pcap-payload",
        "repo_path": "normal_DDoS_1.pcap",
        "local_path": "ton-iot/normal_DDoS_1.pcap",
        "label": "ToN_IoT normal + DDoS",
        "kind": "mixed",
    },
    {
        "dataset": "mtasfi/ton-iot-with-pcap-payload",
        "repo_path": "MITM_normal4.pcap",
        "local_path": "ton-iot/MITM_normal4.pcap",
        "label": "ToN_IoT MITM + normal",
        "kind": "mixed",
    },
]


def inspect_classic_pcap_header(path: Path):
    data = path.read_bytes()[:24] if path.stat().st_size < 24 else None
    if data is None:
        with path.open("rb") as f:
            data = f.read(24)
    if len(data) < 24:
        return {"format": "truncated", "supported": False}
    magic = data[:4]
    if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        return {"format": f"non_classic_{magic.hex()}", "supported": False}
    endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
    _, vmaj, vmin, _, _, snaplen, linktype = struct.unpack(endian + "IHHIIII", data)
    return {
        "format": f"classic_pcap_v{vmaj}.{vmin}",
        "linktype": linktype,
        "snaplen": snaplen,
        "supported": (vmaj == 2 and vmin == 4 and linktype in (1, 113)),
    }


def download_entry(entry, out_dir: Path):
    dest = out_dir / entry["local_path"]
    dest.parent.mkdir(parents=True, exist_ok=True)
    url = f"https://huggingface.co/datasets/{entry['dataset']}/resolve/main/{entry['repo_path']}"
    t0 = time.perf_counter()
    digest = hashlib.sha256()
    if not dest.exists() or dest.stat().st_size == 0:
        tmp = dest.with_suffix(".pcap.part")
        req = urllib.request.Request(url, headers={"User-Agent": "packetlens-hf-importer"})
        with urllib.request.urlopen(req, timeout=300) as resp, tmp.open("wb") as out:
            while chunk := resp.read(1024 * 1024):
                out.write(chunk)
                digest.update(chunk)
        tmp.replace(dest)
    else:
        with dest.open("rb") as f:
            while chunk := f.read(1024 * 1024):
                digest.update(chunk)
    elapsed = round(time.perf_counter() - t0, 2)
    header = inspect_classic_pcap_header(dest)
    size = dest.stat().st_size
    return {
        **entry,
        "bytes": size,
        "sha256": digest.hexdigest(),
        "download_s": elapsed,
        "header": header,
    }


def main():
    p = argparse.ArgumentParser(description="Import classic PCAP datasets from Hugging Face")
    p.add_argument("--out-dir", default="hf_pcaps")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--quick", action="store_true", help="only download captures <= 250 MiB")
    args = p.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    items = [e for e in CURATED_CAPTURES if not (args.quick and "run1260" in e["repo_path"])]

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = {pool.submit(download_entry, e, out_dir): e for e in items}
        for fut in as_completed(futs):
            res = fut.result()
            results.append(res)
            print(
                f"{res['local_path']:52s} {res['bytes']/1e6:7.2f} MB "
                f"{res['download_s']:6.2f}s {res['header']['format']} lt={res['header'].get('linktype')} "
                f"supported={res['header']['supported']}",
                flush=True,
            )

    results.sort(key=lambda r: r["local_path"])
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Wrote {manifest_path} ({len(results)} captures)", flush=True)


if __name__ == "__main__":
    main()
