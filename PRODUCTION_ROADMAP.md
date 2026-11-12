# PacketLens Production Readiness Roadmap

**Purpose:** Keep the long-term goal, current progress, evidence, and AI-agent rules in one durable place.
**Last reviewed:** 2026-11-11
**Overall status:** Prototype / research project; production readiness not established.
**Current milestone:** M0 — define a specific deployment target.
**Decision owner:** Project maintainer.

> This is a living engineering record, not a promise or certification. Mark work DONE only
> after its exit criteria are met and evidence is recorded. An AI agent saying “done” is
> not evidence by itself.

## 1. Final aim

Develop PacketLens into a dependable, narrowly scoped, **alert-only** network monitoring
system for one authorized deployment environment. It should accurately describe what it
can inspect, make detection and service health understandable to operators, preserve
important incidents reliably, and fail visibly rather than silently appearing healthy.

The first real deployment must not automatically block, change, or disrupt traffic.
“Production-ready” applies only to a named environment, configuration, workload, and set
of acceptance criteria. It does not mean PacketLens is a general replacement for mature
IDS products.

## 2. Scope decisions (complete before a pilot)

- Intended environment: one Windows 11 workstation for on-demand offline analysis and
  replay of PCAP files. This is the first validation target, not live monitoring or a
  production claim.
- Operating system: Windows 11 is the target to validate, not yet a verified support
  claim.
- Network authorization: analyze only captures the maintainer owns or is explicitly
  authorized to handle. Treat capture contents as sensitive.
- Operator and response: the project maintainer reviews alerts; PacketLens is alert-only
  and does not automatically block traffic.
- Capture source: supported PCAP formats and link types only. Do not claim pcapng support;
  convert only as documented and verified. Live Linux `AF_PACKET` is outside this first
  target.
- Traffic capacity: no live traffic-rate target. Maximum file size and processing-capacity
  limits are **TBD** until baseline and load measurements are recorded.
- Detection scope: existing packet/time-volume detectors only. Offline CIC-IDS2017 flow
  experiments remain separate and are not part of live or PCAP packet detection.
- False-alarm and detection acceptance targets: measurable targets are **TBD**; set them
  from representative evidence before a pilot. Do not invent numerical targets.
- Data handling: local-only; captures, addresses, names, and alerts are sensitive. Set a
  retention/deletion period (**TBD**) before using real captures. Until then, use
  synthetic or appropriately authorized data.
- Availability and recovery: on-demand analysis only; no 24/7 availability promise.
  Backup/recovery requirements are **TBD** before deployment.

These decisions define a validation target, not a verified support or production claim.
Resolve each **TBD** before the relevant pilot or deployment activity.

## 3. Current baseline (documented, not freshly audited)

- Python package/CLI. The documented core uses the Python standard library.
- Packet-capture reading/writing and byte-level parsing for supported link and network
protocols. Documented supported link types include Ethernet and Linux cooked frames.
- Packet/time-volume detectors documented for port probing, SYN floods, DNS-tunnel-like
behavior, ARP mapping changes, horizontal scans, and unusual traffic volume.
- JSON policies, SQLite incident/host storage, local dashboard, and standalone HTML
reports.
- Live capture uses Linux `AF_PACKET` and requires suitable privileges. It observes only
traffic delivered to the selected interface.
- Optional CIC-IDS2017 flow experiments run offline and are **not part of live packet
analysis**.
- Documented caveats include unsupported IPv6 extension-header traversal, no built-in
TLS for the HTTP server, and limited dataset/label evidence.
- Synthetic traffic and labels are generated together; synthetic scores do not estimate
field performance. Real-data results and benchmarks are also bounded by their recorded
dataset, split, machine, and measurement setup.

Review the current source, tests, and these documents before relying on this summary:
`README.md`, `docs/EVALUATION_PROTOCOL.md`, `docs/LIMITATIONS.md`, `docs/RESULTS.md`,
`results/*.json`, and `tests/`.

## 4. Target architecture (direction, not a rewrite requirement)

Keep the current architecture simple unless measurements justify a change. Evolve it in
small, tested steps:

1. **Capture adapter:** PCAP or authorized live source; report source errors and observable
packet drops. Keep capture privileges as narrow as practical.
2. **Ingestion:** If capture and analysis are decoupled, use bounded buffering and define
overload behavior. Never silently claim healthy monitoring while falling behind.
3. **Parser/normalized packet:** Validate lengths and protocol boundaries; treat all
packet-derived data as untrusted; count malformed and unsupported input.
4. **Detection/policy:** Keep live packet rules separate from offline ML experiments.
Make rule identifiers, thresholds, policy decisions, and alert evidence inspectable.
5. **Persistence:** Define storage bounds, retention, backup/recovery, shutdown behavior,
and visible handling of database/disk failures.
6. **API/dashboard/reports:** Minimize exposed data/actions; safely render untrusted values;
show stale data and service health. Remote exposure requires a separate security design.
7. **Operations:** Structured logs, useful health/metrics, installation/upgrade/rollback
steps, and a concise operator runbook.

## 5. Milestones and status

Allowed status values: `NOT STARTED`, `IN PROGRESS`, `BLOCKED`, `DONE`.
Update a milestone only with test/evidence links or an exact command and result.

**Milestone-status proxy (as of 2026-11-12):** 2/8 milestones are DONE (25.0%). This is
not overall engineering completion, production readiness, or weighted work progress.

### M0 — Define the target
**Status: IN PROGRESS**
Choose one authorized environment; fill Section 2; define measurable acceptance targets,
operator responsibilities, data handling, and explicit non-goals.
**Exit:** Section 2 is complete and reviewed by the maintainer.

### M1 — Reproduce the baseline
**Status: DONE — baseline captured; known checks skipped/unavailable**
Inspect the worktree first; run existing tests and documented checks; record OS, Python,
commands, outputs, and failures. Do not mix unrelated fixes into baseline work.
**Exit:** The baseline run, failures, and unavailable checks are recorded. This captures
the Dev Container baseline; it does not establish support for other operating systems or
independent reproduction by another developer.

### M2 — Verify correctness boundaries
**Status: DONE — pcap correctness boundaries validated**
Document supported inputs and known gaps. Add focused tests for relevant malformed,
truncated, boundary, empty-capture, and unsupported cases. Ensure failures are visible.
**Exit:** Supported behavior is tested/documented; unsupported input is not reported as
successfully analyzed.

This milestone is satisfied by the focused classic-PCAP boundary checks and CLI coverage
in `tests/test_pcap_and_parsers.py`, plus the documentation in `README.md`. The
validation command with evidence is:
- `python -m unittest discover -s tests -v` — exit 0; 87 tests run, 69 passed,
  18 skipped, 0 failed.

### M3 — Reliability and observability
**Status: NOT STARTED**
Measure representative load, memory, processing delay, and data loss. Test shutdown,
overload, database errors, disk-full handling, and recovery. Define retention and backup.
**Exit:** Operators can detect stale/degraded monitoring and storage failures; recovery is
documented and tested.

### M4 — Security and privacy review
**Status: NOT STARTED**
Threat-model the chosen environment. Review dashboard/API access, sensitive data, tokens,
file permissions, privilege boundaries, retention, and untrusted packet-derived output.
Do not expose the built-in HTTP server directly to an untrusted network.
**Exit:** An experienced reviewer approves the design for the specific deployment.

### M5 — Validate detection quality
**Status: NOT STARTED**
Evaluate representative benign traffic and independently labeled attack examples where
available. Keep final test data out of tuning. Report per-rule precision/recall, false
alarms per hour, misses, uncertainty, and known leakage/label risks. Have a human review
alert usefulness.
**Exit:** Each enabled rule meets M0 targets for relevant evidence, or is disabled/marked
experimental. Synthetic evaluation alone does not pass this milestone.

### M6 — Controlled pilot
**Status: NOT STARTED**
Package deployment for the chosen environment; document install, health checks, triage,
rollback, and shutdown. Run alert-only on an authorized pilot; compare observations with
an independent source; review operator workload and resource use.
**Exit:** The agreed observation period meets M0 criteria with no unresolved critical
security, correctness, or data-loss issue. A pilot does not prove generalization.

### M7 — Deployment decision
**Status: NOT STARTED**
Obtain security/operations review, record remaining risks and owners, and explicitly approve
or reject the exact environment and configuration.
**Exit:** Written decision is scoped to the tested deployment. Reassess after significant
code, policy, data, or infrastructure changes.

## 6. AI-agent workflow and safety rules

The project maintainer remains accountable. Agents may research, implement, and review,
but may not approve their own work or deployment.

- Use one coordinator (the main Copilot Agent) to read this roadmap, pick one task, and
integrate results.
- Researcher and Reviewer roles are read-only. Give them a precise question and expected
output; do not ask them to “fix everything.”
- Use one Implementer for one bounded task. Avoid simultaneous edits to the same files.
Use separate worktrees/branches for independent implementation tasks.
- Each task must state the goal, files in scope, files out of scope, acceptance criteria,
tests, and stop conditions.
- Keep command approval prompts enabled. Run only the commands needed for the task. Do
not auto-approve broad shell commands, installs, credential access, network exposure,
deletion, deployment, pushes, or system-setting changes.
- Work inside an isolated Dev Container/VM with no personal files or secrets exposed.
A worktree separates edits; it is not itself a security sandbox.
- Never place credentials, private captures, or sensitive identifiers in prompts, tests,
logs, or this roadmap. Never commit secrets.
- Do not claim a test, audit, performance result, or deployment passed unless it actually
ran and its evidence is recorded.
- Preserve unrelated user changes. No destructive cleanup or broad refactoring without
explicit maintainer approval.
- If an agent cannot verify a claim, it must label it unverified. If acceptance criteria
are ambiguous or a security-sensitive decision is required, stop and ask the maintainer.

### Required task report from every implementation agent

- Task/milestone and goal
- Files changed
- Behavior changed
- Exact validation command(s) and result
- Evidence/artifact location
- Known limitations and unverified assumptions
- Suggested next task

## 7. Definition of project completion

The project is not “done” because all planned code was written. It is ready only for the
specific pilot/production scope when M0–M7 exit criteria are satisfied, required checks
are reproducible, detection targets are supported by relevant evidence, security/privacy
and operational reviews are complete, and no critical blocker remains. The maintainer
records the final decision and accepted residual risks. Readiness is never a universal
claim for other networks.

## 8. Free-tier and continuity policy

- Prefer local tools and existing dependencies; do not add paid services by default.
- Record progress here so work survives a new chat, model, or account session.
- Free quotas and agent availability can change; verify current provider terms.
- Do not create/switch accounts to bypass usage limits or plan restrictions.
- If AI quota runs out, pause AI work or continue only with tools permitted by the plan.
This file and the repository—not chat history—are the project’s source of truth.

## 9. Progress log

### 2026-11-11 — Roadmap initialized
- Overall status: prototype; production readiness not established.
- Current milestone: M0.
- Evidence: repository documentation and saved evaluation artifacts; no fresh baseline
test run recorded in this log.
- Next task: complete M0 scope decisions, then run M1 baseline checks.

#### 2026-11-11 — M1 Dev Container baseline captured
- Milestone/status: M1 — DONE (baseline captured; known checks skipped/unavailable).
- Goal and files changed: Capture the baseline in the Dev Container; updated
  `PRODUCTION_ROADMAP.md` only.
- Validation command(s) and exact result:
  - `python -c "import platform, os; print(platform.system(), platform.release(), os.getcwd())"`
    — exit 0; `Linux 6.18.33.2-microsoft-standard-WSL2 /workspaces/packetlens`.
  - `python --version` — exit 0; `Python 3.12.16`.
  - `git status --short --branch` — exit 0; worktree not clean, with many pre-existing
    modified and untracked files, including this roadmap, agent profiles, and
    `.devcontainer/`. These changes were preserved.
  - `python -m unittest discover -s tests -v` — exit 0; 70 tests total, 52 passed,
    18 skipped, 0 failed. Skips include unavailable optional `pandas`, `scikit-learn`,
    `torch`, and `tsfm_public`. Output was compacted; individual test and skip details
    were not captured.
  - `node --check packetlens/static/app.js` — exit 127; `node: command not found`.
    Unavailable; not passed. Node was not installed.
- Evidence/artifact: This entry records the Dev Container run. A prior host-side run
  reported the same unittest counts but is separate evidence and is not proof of Windows
  11 support.
- Remaining risks or unverified assumptions: Individual test/skip details and the
  JavaScript syntax check remain unverified. This baseline does not establish Windows 11
  support or production readiness.
- Next task: Review M1 evidence and continue M0 scope decisions.

#### 2026-11-11 — Reject truncated classic pcap records
- Milestone/status: M2 — IN PROGRESS; this is one bounded boundary fix, not completion
  of the milestone.
- Goal and files changed: Make partial pcap record headers and packet payloads explicit
  errors while preserving a valid empty capture. Changed `packetlens/pcap.py`,
  `tests/test_pcap_and_parsers.py`, `README.md`, and this roadmap.
- Behavior changed: `PcapReader` raises `PcapError` for a partial record header or packet
  payload instead of silently ending iteration. A complete global header with no records
  remains valid. Documented that behavior and retained the pcapng limitation.
- Validation command(s) and exact result:
  - `python -m unittest discover -s tests -p 'test_pcap_and_parsers.py' -v` — exit 0;
    15 tests run, all passed.
  - `python -m unittest discover -s tests -v` — exit 0; 72 tests run, 0 failures,
    18 skipped. Skips: 11 tests require pandas and scikit-learn, 4 require pandas,
    and 3 require torch and `tsfm_public`.
  - CLI truncation check using a temporary truncated capture — exit 1 as expected;
    stderr: `error: truncated pcap packet data`.
  - `node --check packetlens/static/app.js` — exit 127; unavailable because `node` is
    not installed. Not passed.
  - `git diff --check` — exit 2 because the repository files use CRLF and Git treated
    added CR characters as trailing whitespace. CRLF-aware check,
    `git -c core.whitespace=cr-at-eol diff --check` — exit 0.
- Evidence/artifact: `PRODUCTION_ROADMAP.md`, `README.md`, and the focused regression
  tests in `tests/test_pcap_and_parsers.py`; runtime was Python 3.12.16 on Linux.
- Remaining risks or unverified assumptions: This change covers physically truncated
  record headers and packet payloads only; semantic bounds such as captured length versus
  snaplen/original length remain unverified. Optional-dependency tests and the JavaScript
  syntax check were unavailable/skipped as noted above. M0 maintainer decisions remain
  as recorded in Section 2; no TBD was resolved here.
- Next task: Continue M2 with one focused validation of malformed record metadata or
  unsupported link types, without treating this task as full pcap format validation.

#### 2026-11-11 — Reject captured lengths greater than original lengths
- Milestone/status: M2 — IN PROGRESS; this is one bounded correctness-boundary fix, not
  completion of the milestone.
- Goal and files changed: Reject classic-pcap records whose captured length exceeds
  their original packet length. Changed `packetlens/pcap.py`,
  `tests/test_pcap_and_parsers.py`, `README.md`, and this roadmap.
- Behavior changed: `PcapReader` raises `PcapError` with both lengths in its message
  before reading or yielding the record payload when captured length exceeds original
  length. Equal lengths remain accepted; a smaller captured length remains valid for a
  snap-truncated capture. Existing physical-truncation errors and complete-empty-capture
  behavior were retained.
- Validation command(s) and exact result:
  - `python -m unittest discover -s tests -p 'test_pcap_and_parsers.py' -v` — exit 0;
    17 tests run, all passed, 0 skipped.
  - `git -c core.whitespace=cr-at-eol diff --check` — exit 0.
  - `python -m unittest discover -s tests -v` — exit 0; 74 tests run, 0 failures,
    18 skipped. Skips: 11 tests require pandas and scikit-learn, 4 require pandas,
    and 3 require torch and `tsfm_public`.
  - One-off CLI integration check using a temporary classic-PCAP record with
    `incl_len=5`, `orig_len=4` — wrapper exit 0; CLI exit 1, empty stdout, stderr:
    `error: pcap captured length 5 exceeds original length 4`. The check was not added
    as a persistent test.
  - JavaScript syntax check — not run; unrelated to this change. No unavailable tools
    were needed for the checks above.
- Evidence/artifact: Regression tests in `tests/test_pcap_and_parsers.py` cover the
  invalid larger captured length and valid smaller captured length; existing tests
  cover equal lengths, physical truncation, and a valid empty capture.
- Remaining risks or unverified assumptions: This check does not validate snaplen,
  timestamp fractions, or other record metadata. CLI failure behavior was checked once;
  partial-analysis semantics remain untested. M0 acceptance targets, traffic capacity,
  retention, and backup/recovery remain TBD and maintainer-owned. Offline PCAP/replay on
  Windows 11 remains the first validation target; Windows 11 is unverified, and Linux
  live capture remains out of scope.
- Next task: Have the coordinator select one further focused M2 boundary check (for
  example, unsupported link-type behavior); do not infer M2 completion from this entry.

#### 2026-11-11 — Enforce classic pcap snaplen bounds
- Milestone/status: M2 — IN PROGRESS; this is one bounded correctness-boundary fix, not
  completion of the milestone.
- Goal and files changed: Reject classic-PCAP record captured lengths larger than the
  global-header snaplen before payload reads, and reject writer data larger than its
  configured snaplen. Changed `packetlens/pcap.py`,
  `tests/test_pcap_and_parsers.py`, `README.md`, and this roadmap.
- Behavior changed: `PcapReader` raises `PcapError` for `incl_len > snaplen`, while
  retaining the existing `incl_len > orig_len` error precedence. Captures with
  `incl_len < orig_len` remain valid when within snaplen. `PcapWriter` rejects packet
  data larger than a nonzero configured snaplen instead of truncating it. Existing
  zero-snaplen behavior is preserved: the reader and writer impose no size bound when
  snaplen is zero.
- Validation command(s) and exact result:
  - `python -m unittest discover -s tests -p 'test_pcap_and_parsers.py' -v` — exit 0;
    21 tests run, all passed.
  - `python -m unittest discover -s tests -v` — exit 0; 78 tests run, 0 failures,
    18 skipped. Skips: 11 tests require pandas and scikit-learn, 4 require pandas,
    and 3 require torch and `tsfm_public`.
  - `git -c core.whitespace=cr-at-eol diff --check` — exit 0 after all changes.
  - Independent PacketLens Reviewer review — no actionable correctness, regression,
    or focused-test gaps found in the supplied diff; reviewer did not run tests.
- Evidence/artifact: Focused regression tests in `tests/test_pcap_and_parsers.py` cover
  captured length equal to snaplen, greater than snaplen before payload read, smaller
  than original but within snaplen, original-length error precedence, writer rejection,
  and existing zero-snaplen behavior. The
  [libpcap savefile documentation](https://www.tcpdump.org/manpages/pcap-savefile.5.html)
  defines snaplen zero as no captured-length limit.
- Remaining risks or unverified assumptions: The savefile documentation defines
  zero-snaplen meaning; PacketLens's `PcapWriter(snaplen=0)` behavior is application
  specific and is now tested to write zero to the header and preserve a nonempty packet
  without truncation. Eighteen optional-dependency tests were skipped as noted above.
  This task does not complete M2 or validate other PCAP metadata/boundaries. Windows 11
  behavior and the remaining M0 decisions are still unverified/TBD.
- Next task: Continue M2 with one separate focused correctness-boundary task; do not
  infer M2 completion from this entry.

#### 2026-11-11 — Test CLI rejection of unsupported PCAP link types
- Milestone/status: M2 — IN PROGRESS; this is a focused CLI regression check, not
  completion of the milestone.
- Goal and files changed: Add subprocess regression tests verifying that `analyze` and
  `serve --pcap` reject a classic-PCAP capture with unsupported link type 999 using
  the existing CLI diagnostic. Changed `tests/test_pcap_and_parsers.py`; no production
  behavior changed.
- Validation command(s) and exact result:
  - `python -m unittest discover -s tests -p 'test_pcap_and_parsers.py' -v` — exit 0;
    23 tests run, all passed, 0 skipped.
  - `python -m unittest discover -s tests -v` — exit 0; 80 tests run, 0 failures,
    18 skipped. Skips: 11 tests require pandas and scikit-learn, 4 require pandas,
    and 3 require torch and `tsfm_public`.
  - `git -c core.whitespace=cr-at-eol show --check HEAD` — exit 0.
- Evidence/artifact: Both CLI regression tests use a valid empty classic-PCAP header
  with link type 999 and assert nonzero exit plus the unsupported-link-type diagnostic.
  Existing CLI checks reject unsupported link types before processing the capture.
- Review findings: PacketLens Reviewer inspected
  `tests/test_pcap_and_parsers.py`, `packetlens/pcap.py`, `packetlens/cli.py`,
  `packetlens/__main__.py`, and link-type definitions in `packetlens/parsers.py`;
  reported no actionable findings and did not run tests. Reviewer could not verify
  the commit object or exact commit diff. The coordinator independently inspected
  commit `a36dd172` and confirmed it contains only the described test change.
- Remaining risks or unverified assumptions: Coverage uses link type 999 and does not
  alter or validate parser behavior. The test commit was already present at HEAD and
  the cached `origin/roadmap/m2-pcap-boundaries` ref; live remote state has not been
  verified because `git ls-remote` could not authenticate. Windows 11 behavior and
  remaining M0 decisions remain unverified/TBD; this does not complete M2.
- Next task: Continue M2 with one further focused correctness-boundary task only after
  the review and publication state of this change is resolved; do not infer M2
  completion from this entry.

#### 2026-11-11 — Reject out-of-range classic pcap timestamp fractions
- Milestone/status: M2 — IN PROGRESS; this is one bounded correctness-boundary fix, not
  completion of the milestone.
- Goal and files changed: Reject classic-PCAP record timestamp fractions outside the
  resolution declared by the file magic. Changed `packetlens/pcap.py`,
  `tests/test_pcap_and_parsers.py`, `README.md`, and this roadmap.
- Behavior changed: `PcapReader` raises `PcapError` for a microsecond fraction greater
  than or equal to 1,000,000 or a nanosecond fraction greater than or equal to
  1,000,000,000, before reading or yielding that record's payload. Fractions through
  resolution minus one remain valid. Existing valid-record, empty-capture, and
  truncated-capture behavior is retained.
- Validation command(s) and exact result:
  - `python -m unittest discover -s tests -p 'test_pcap_and_parsers.py' -v` — exit 0;
    25 tests run, all passed, 0 skipped.
  - `python -m unittest discover -s tests -v` — exit 0; 82 tests run, 0 failures,
    18 skipped. Skips: 11 tests require pandas and scikit-learn, 4 require pandas,
    and 3 require torch and `tsfm_public`.
  - `git -c core.whitespace=cr-at-eol diff --check` — exit 0.
- Evidence/artifact: Focused regression tests exercise the upper valid fraction and the
  exact rejected limit for microsecond and nanosecond files in both byte orders. The
  rejection tests also verify a preceding valid record is yielded and the invalid record
  raises rather than being yielded.
- Review findings: PacketLens Reviewer inspected the supplied patch text and the current
  `packetlens/pcap.py`, `tests/test_pcap_and_parsers.py`, `README.md`, and this roadmap
  entry; reported no actionable findings and did not run tests. Reviewer could not
  independently verify the Git diff; the coordinator inspected the actual diff.
- Remaining risks or unverified assumptions: The timestamp API still returns a Python
  float, whose representation may not preserve nanosecond precision; this task validates
  fraction bounds only. This does not complete M2. Windows 11 behavior and remaining M0
  decisions remain unverified/TBD.
- Next task: Continue with one other bounded M2 correctness-boundary task; do not infer
  M2 completion from this entry.

#### 2026-11-11 — Validate classic-PCAP global-header version
- Milestone/status: M2 — IN PROGRESS; this is one bounded correctness-boundary fix, not
  completion of the milestone.
- Goal and files changed: Accept only classic-PCAP global-header version 2.4 and reject
  unsupported major/minor values before record reads. Changed `packetlens/pcap.py`,
  `tests/test_pcap_and_parsers.py`, `README.md`, and `PRODUCTION_ROADMAP.md`.
- Behavior changed: `PcapReader` raises `PcapError` for any version other than 2.4
  after reading the 24-byte global header and before reading records. Version 2.4
  remains valid. The check applies in either byte order; `PcapWriter` continues to emit
  version 2.4.
- Validation command(s) and exact result:
  - `python -m unittest discover -s tests -p 'test_pcap_and_parsers.py' -v` — exit 0;
    27 tests run, all passed, 0 skipped.
  - `python -m unittest discover -s tests -v` — exit 0; 84 tests run, 0 failures,
    18 skipped. Skips: 11 require pandas and scikit-learn, 4 require pandas, and 3
    require torch and `tsfm_public`.
  - `git -c core.whitespace=cr-at-eol diff --check` — exit 0.
- Evidence/artifact: Focused tests accept 2.4 in both byte orders and reject unsupported
  major and minor versions in both byte orders. A tracking stream verifies rejected
  headers trigger only a 24-byte read, not a record read. README documents the supported
  version and rejection behavior.
- Review findings: PacketLens Reviewer inspected `packetlens/pcap.py`,
  `tests/test_pcap_and_parsers.py`, `README.md`, and the relevant roadmap sections;
  reported no actionable code or test findings and did not run tests. Reviewer could
  not independently compare the Git diff; the coordinator inspected the actual diff.
- Remaining risks or unverified assumptions: This deliberately rejects classic-PCAP
  versions other than 2.4, even if a future supported format requires them. This does
  not complete M2. Windows 11 behavior and the M0 maintainer decisions and TBDs remain
  unverified and unchanged.
- Next task: Continue with one other bounded M2 correctness-boundary task; do not infer
  M2 completion.

#### 2026-11-12 — Clarify classic pcap zero-snaplen behavior
- Milestone/status: M2 — IN PROGRESS; this is a documentation and test clarification,
  not completion of the milestone.
- Goal and files changed: Clarify zero-snaplen reader and PacketLens writer behavior,
  and verify the writer's emitted header field. Changed `README.md`,
  `tests/test_pcap_and_parsers.py`, and this roadmap.
- Behavior changed: README states that reader snaplen zero imposes no captured-length
  bound and distinguishes PacketLens's `PcapWriter(snaplen=0)` behavior: it writes zero
  in the global header and does not truncate nonempty packet data. The test asserts the
  header value and round-trips a nonempty packet.
- Validation command(s) and exact result:
  - `python -m unittest discover -s tests -p 'test_pcap_and_parsers.py' -v` — exit 0;
    27 tests run, all passed, 0 skipped.
  - `python -m unittest discover -s tests -v` — exit 0; 84 tests run, 0 failures,
    18 skipped: 11 require pandas and scikit-learn, 4 require pandas, and 3 require
    torch and `tsfm_public`.
  - `git -c core.whitespace=cr-at-eol diff --check` — exit 0.
- Evidence/artifact: The
  [libpcap savefile documentation](https://www.tcpdump.org/manpages/pcap-savefile.5.html)
  defines snaplen zero as no captured-length limit. The focused regression verifies
  PacketLens's writer emits zero in the header and round-trips a nonempty payload.
- Review status: Pending. PacketLens Reviewer was invoked twice but could not access
  the actual Git diff and made no findings; no independent review result is claimed.
- Remaining risks or unverified assumptions: The writer's zero-snaplen behavior is
  PacketLens-specific; this task does not validate other PCAP formats or boundaries,
  Windows 11 behavior, or any of the M0 maintainer decisions/TBDs.
- Next task: Resolve independent review of this change before selecting another M2 task;
  do not infer M2 completion.

#### 2026-11-12 — Reject unsupported classic-PCAP link types before record reads
- Milestone/status: M2 — IN PROGRESS; this is one bounded correctness-boundary fix, not
  completion of the milestone.
- Goal and files changed: Reject unsupported classic-PCAP link types in the file reader
  before any packet records are read, and make the CLI surface the same message cleanly.
  Changed `packetlens/pcap.py`, `packetlens/cli.py`, `tests/test_pcap_and_parsers.py`,
  `README.md`, and this roadmap.
- Behavior changed: `PcapReader` raises `PcapError` for a global-header link type not in
  the supported set before record iteration begins. The CLI now catches the same error and
  exits with `Unsupported link type <n>. Supported: Ethernet (1) and Linux cooked (113).`
  instead of a traceback.
- Validation command(s) and exact result:
  - `python -m unittest discover -s tests -p 'test_pcap_and_parsers.py' -v` — exit 0;
    28 tests run, all passed.
- Evidence/artifact: The focused regression in `tests/test_pcap_and_parsers.py` covers a
  valid empty capture, the unsupported header case, and the CLI rejection path.
- Remaining risks or unverified assumptions: This task addresses unsupported link-type
  validation in the classic pcap file reader and CLI surface; it does not complete M2 or
  validate other header fields or the Windows 11 target. Remaining M0 decisions and TBDs
  are unchanged.
- Next task: Continue with one more bounded M2 correctness-boundary task only after this
  fix is reviewed; do not infer M2 completion.

#### 2026-11-12 — Reject unsupported classic-PCAP writer link types
- Milestone/status: M2 — IN PROGRESS; this is one bounded correctness-boundary fix, not
  completion of the milestone.
- Goal and files changed: Reject unsupported link types in `PcapWriter` before the output
  file is opened. Changed `packetlens/pcap.py`, `tests/test_pcap_and_parsers.py`,
  `README.md`, and this roadmap.
- Behavior changed: `PcapWriter` raises `PcapError` unless linktype is Ethernet (1) or
  Linux cooked (113); rejected types do not create an output file. Existing reader and
  CLI behavior was not changed by this task.
- Validation command(s) and exact result:
  - `python -m unittest discover -s tests -p 'test_pcap_and_parsers.py' -v` — exit 0;
    30 tests run, 0 skipped, 0 failed.
  - `python -m unittest discover -s tests -v` — exit 0; 87 tests run, 69 passed,
    18 skipped, 0 failed. Of the skips, 11 require pandas and scikit-learn, 4 require
    pandas, and 3 require torch and `tsfm_public`.
- Evidence/artifact: Focused tests verify that linktypes 1 and 113 are emitted, and that
  linktypes 0 and 999 raise `PcapError` without creating the output path. README documents
  the writer's supported link types and rejection behavior.
- Remaining risks or unverified assumptions: Coverage uses representative unsupported
  values 0 and 999; no unrelated pcap metadata validation was added. Windows 11 behavior
  and remaining M0 decisions are unverified/unchanged.
- Next task: Obtain independent review of the patch before selecting another bounded M2
  task; do not infer M2 completion.

#### 2026-11-12 — M2 correctness boundaries closed
- Milestone/status: M2 — DONE.
- Goal and files changed: Close the correctness-boundary milestone by verifying supported
  classic-PCAP inputs and rejecting unsupported or malformed header values before packet
  analysis. Changed `packetlens/pcap.py`, `packetlens/cli.py`,
  `tests/test_pcap_and_parsers.py`, `README.md`, and this roadmap.
- Validation command(s) and exact result:
  - `python -m unittest discover -s tests -v` — exit 0; 87 tests run, 0 failed,
    18 skipped.
  - `git -c core.whitespace=cr-at-eol diff --check` — exit 0.
- Evidence/artifact: The focused boundary tests cover empty captures, supported and
  unsupported link types, version checks, truncation, timestamp fractions, snaplen checks,
  and CLI rejection paths. The full suite passes with only the known optional-dependency
  skips.
- Remaining risks or unverified assumptions: M2 validates classic-PCAP correctness
  boundaries but does not establish Windows 11 support or complete M0 target definition.
  M3 reliability and M4 security review remain outstanding.
- Next task: Resolve M0 deployment-target decisions and continue with M3 reliability work.

### Progress-entry template

#### YYYY-MM-DD — Short task name
- Milestone/status:
- Goal and files changed:
- Validation command(s) and exact result:
- Evidence/artifact:
- Remaining risks or unverified assumptions:
- Next task:

## 10. Maintainer decision log

Record scope, security, privacy, deployment, and risk-acceptance decisions here. AI agents
may prepare evidence or options, but only the project maintainer can approve a decision.

### Decision entry template

#### DEC-YYYY-MM-DD — Short decision title
- Decision and exact scope:
- Decision owner:
- Reviewers consulted:
- Evidence and alternatives considered:
- Risks accepted / rejected:
- Approval status: `PROPOSED` / `APPROVED` / `REJECTED` / `EXPIRED`
- Review date or trigger: