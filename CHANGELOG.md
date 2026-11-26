# Changelog

All notable changes to PacketLens are documented in this file.

## [1.0.0] - 2026-11-26

### Added
- **PCAPNG capture support:** Transparent reading of PCAPNG files (`SHB`, `IDB`, `EPB`, `SPB`), little/big-endian sections, `if_tsresol` timestamp resolution, and Ethernet (`1`) / Linux cooked (`113`) link types alongside classic PCAP v2.4.
- **Extended protocol decoding:** Stacked 802.1Q / 802.1ad QinQ VLAN tag unwrapping (bounded to 4 tags) and bounded IPv6 extension header traversal (`0`, `43`, `44`, `60`).
- **Observability & API enhancements:** Added `stored_packets`, `stored_bytes`, `stored_malformed`, `open_incidents`, and `out_of_order` fields to `/api/health`, server-side sorting (`sort`, `dir`) on `/api/incidents`, and `audit_truncated` on incident detail responses.
- **Release & CI hygiene:** Added MIT `LICENSE`, `.gitattributes` LF normalization, core-only and partial-ML (`pandas` without `scikit-learn`) CI checks, and separated offline CIC-IDS2017 ML experiments into `research/`.

### Changed
- **Dashboard UI overhaul:** Replaced template decorations with a crisp, flat light/dark operational UI, balanced 4-card KPI strip, compact single-row timeline toolbar, in-place `<canvas>` updates preserving hover tooltips, shortened incident IDs with summaries, right-aligned tabular numbers, and responsive `390px` mobile layouts.
- **Research decoupling:** Moved offline ML modules (`flows.py`, `flowmodel.py`, `ml.py`) out of the core `packetlens` package into `research/`, keeping the installed `packetlens` package strictly dependency-free.
- **Documentation decoupling:** `packetlens render-results` updates `README.md` cleanly even when local `docs/` is absent, writing `docs/RESULTS.md` only when `docs/` exists or `--write-docs` is passed.

### Fixed
- **Detectors & host table:** Fixed `SynFloodDetector` mid-second cooldown expiry and out-of-order timestamp handling; filtered `HostTable` destination ports to TCP/UDP only; added dirty-host tracking for incremental SQLite flushes.
- **Store & capture reliability:** Added bounded retry on transient SQLite `locked`/`busy` errors, atomic incident status transition validation, ascending IP sorting for hosts, socket timeout/`stop_event` handling for live capture, HTML report UTC timestamp formatting, and `--allow-remote` `Host` header validation.
- **Dashboard bugs:** Fixed null detector crashes in Detection Quality, rendered per-metric evidence arrays for volumetric incidents, standardized `en-US` number formatting, aligned open-incident nav badge counts, selected confusion matrix models by highest F1, and reduced per-packet lock contention during capture replay.
