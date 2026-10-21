# Ravensight — Feature Roadmap

> This document captures planned features to be built after the base project is complete.
> Hand this back to Claude at the start of a planning session to resume from here.

---

## Base Project Status

The base project is complete. All modules are working end-to-end:

- `main.py` — entry point and orchestration
- `ravensight/wazuh_client.py` — Wazuh Indexer (OpenSearch) REST API client
- `ravensight/analyser.py` — LLM analysis via Qwen3.6-35B on the local inference server
- `ravensight/reporter.py` — markdown report generation
- `ravensight/baseline.py` — baseline memory persistence (JSON store)
- `ravensight/trending.py` — historical trend analysis and anomaly detection
- `scripts/mitre_sync.py` — MITRE ATT&CK STIX data sync script

---

## Feature Status

| Feature | Status | Notes |
|---------|--------|-------|
| Historical Trending | ✅ Complete | `trending.py` wired into main pipeline |
| MITRE ATT&CK Tagging | ✅ Complete | Tactic reference injected into LLM prompt, tags in report |
| Multi-Model Routing | ~~Superseded~~ | See note below |
| Embedding Model | ✅ Complete | 89 vectors stored, retrieval confirmed working |
| Platform-Aware Alert Context | ✅ Complete | `data/platform_hints.json` with FreeBSD rule 510 hint, `_load_platform_hints()` + `_build_platform_context()` in `ravensight/analyser.py`, `[platform]` section in `config.example.toml` (commit `81f9326`) |
| Progress Bar + LLM Streaming | ✅ Complete | tqdm design (`da2b066`, `b29f77b`) replaced by the rich terminal UI: `ravensight/ui.py` shows a bordered live stderr panel (service status, refreshing progress bars per stage, LLM tokens and tok/s from llama.cpp `timings`) and a finish screen with a cluster table; `--no-progress`, pipes, cron and docker logs keep the plain log format. |
| ASD Framework Mapping | ✅ Complete | `scripts/asd_sync.py` syncs Essential Eight + ISM (commit `42c816b`); ASD context injected in `ravensight/analyser.py` (commit `c23ce1e`); `_render_asd_section()` in `ravensight/reporter.py` (commit `861becf`); ASD path wired in `main.py`, `[asd]` section in `config.example.toml` (commit `eda966f`) |
| Essential Eight Compliance Scoring + ISM Alert Mapping | ✅ Complete | `ravensight/e8_scorer.py` (`score_findings()` / `match_ism_controls()`, commit `b1deb3e`); wired into `main.py` and reporter rendering (commit `2e2b4d9`); per-strategy keyword overrides in `data/e8_keyword_overrides.json` (commit `03c0cb3`); `[e8]` section in `config.example.toml` |
| Essential Eight Evidence-Only Report (section 9) | 🔶 In progress | Phase 1 done (uncommitted at time of update): `ravensight/reporter.py` row prints the scorer's status, labels the `Unmapped` row, and notes a missing or old-format ASD file when `asd_data == {}`; `main.py` passes `None` when `[asd] path` is unset; dead `rule_group` reads removed from `ravensight/e8_scorer.py`; 376 tests pass. Not-applicable state, attestation file and extra evidence sources are not started. |
| Wazuh Query Time Window Fix (section 10) | ✅ Complete | `ravensight/wazuh_client.py` `Client.fetch_alerts` builds `since` from `datetime.now(timezone.utc)` (previously local wall clock labelled `Z`, uncommitted at time of update); `tests/test_wazuh_client.py` checks the window under an Adelaide-offset process timezone and UTC (fails against the old line under Adelaide); 380 tests pass. |
| Report Finding Time Labelling (section 11) | ✅ Complete | `ravensight/reporter.py` `_is_utc()` and the time clause in `_format_finding` add ` UTC` to finding times when every raw timestamp has a zero offset (`Z`, `+0000`, `+00:00`), never when mixed or non-UTC (uncommitted at time of update); `tests/test_reporter_findings.py` updated plus 14 new cases; 394 tests pass. |
| Networked ChromaDB (server mode) | ✅ Complete | Optional `HttpClient` mode in `ravensight/embedder.py` via `chroma_host` / `chroma_port` in `[embeddings]` (`_connect_chroma()` helper, embedded branch byte-for-byte preserved); bundled Chroma service added as optional `chroma` profile in `docker-compose.yml` (image `chromadb/chroma:1.5.9` pinned to match `chromadb==1.5.9` in `requirements.txt`, `IS_PERSISTENT=TRUE` kept as a legacy 0.x no-op — persistence is on by default in the 1.x Rust server, bind mount `./chroma-data:/data` — image's persist_directory default changed from `/chroma/chroma` (0.6.x) to `/data` (1.x), port `8000:8000`); `.env.example` Chroma section + two new `EMBEDDINGS_CHROMA_*` placeholders in `config.template.toml` + two new optional-defaults `export` lines in `docker-entrypoint.sh` (re-verified at the 1.5.9 bump: `chromadb/chroma:1.5.9` exists on Docker Hub, 1.5.9 client `PersistentClient`/`HttpClient`/`chromadb.errors.ChromaError` call signatures unchanged from 0.6.3 — `metadatas=`/`hnsw:space` semantics preserved) |
| Container non-root + seeding fix | ✅ Complete | `Dockerfile` copies `data/defaults/` to `/app/defaults/` (line 19) and adds a build-time `RUN setpriv --version` guard (line 10); `docker-entrypoint.sh` makes `RAVENSIGHT_PUID` / `RAVENSIGHT_PGID` required (0 valid — rootless Docker/Podman, no switch), validates non-negative integers with a `case` pattern rejecting `''` and any non-digit, refuses containers started with `--user` / Compose `user:` (only the entrypoint's `setpriv` switch is honoured), defines a `run_as` helper backed by `setpriv --reuid --regid --clear-groups` (no `--init-groups` — fails for numeric uid with no passwd entry), chowns `/app/config.toml` to PUID:PGID **before** `chmod 600` so the dropped-privilege app can read it, repairs mismatched entries on every start via `find … chown -h … {} +` and logs only when something was repaired (per-entry predicate handles the realistic case of a user-owned dir containing root-owned files), seeds the two `e8_keyword_overrides.json` / `platform_hints.json` defaults via `run_as` from `/app/defaults/` with warn-and-continue on missing source, runs all four sync invocations (two one-time, two in `sync` subcommand) via `run_as`, and finishes with a conditional `exec setpriv`; `.env.example` gains the PUID/PGID block near the top. Follow-up (uncommitted, base `300ec3e`): added PUID=0/PGID≠0 fail-fast check (rootless Docker/Podman requires both 0) and a post-repair `find -print -quit` re-check that warns to stderr when an entry is still not owned by PUID:PGID after chown (read-only mount or NFS root-squash). Deferred (logged in `.session-memos/2026-09-28_10-48.md`): seed files tracked in git and byte-identical to `data/defaults/` (drift risk); SELinux `:z`/`:Z` bind-mount labels; no entrypoint unit tests. |
| Cluster Evidence | ✅ Complete | `ravensight/evidence.py` pure stdlib module — `detect_shape()` classifies one alert into exactly one of seven shapes (vulnerability, syscheck, dpkg, netstat, docker, firewall, generic); `accumulate()` and `project_evidence()` mechanically extract bounded real values from raw alerts (syscheck paths/events/changed_attributes + three-state content verdict; dpkg package/version/status; netstat opened/closed ports keyed by protocol+local-address; docker container/action/signal/compose/image; vulnerability status/version/severity/score_base; firewall action/direction/interface/ipversion/protocol/sources/destinations/dstports parsed from raw OPNsense filterlog lines in `full_log` + `previous_output` because Wazuh's `pf` decoder mis-parses IPv6 lines — never reads `data.srcip`/`data.dstip`/`data.protocol`/`data.srcport`/`data.dstport` for this shape; `sources_total` tracked separately from the capped `sources` display list; generic srcip/dstuser, with `srcip` validated via `ipaddress.ip_address()` to drop decoder artefacts); `render_evidence()` emits `field v1, v2; field v3` with whitespace collapsed and `|` escaped; constants `MAX_EVIDENCE_VALUES=5`, `MAX_EVIDENCE_NETSTAT_VALUES=3`, `MAX_EVIDENCE_VALUE_CHARS=100`, `MAX_EVIDENCE_LINE_CHARS=400`; `ravensight/analyser.py` accumulates in `_new_cluster['evidence_acc']` during the per-alert loop and projects into the output cluster (`'evidence'` key absent when nothing extracted); `_build_prompt` appends ` — evidence: …` (hard-truncated to 400 chars + `…`) and adds one new instruction sentence to the header; `ravensight/reporter.py::_format_finding` renders a `  - Evidence: …` sub-bullet between narrative and CVEs (byte-identical when absent); `cluster_key()`, `baseline._cluster_vector_text()` and `baseline._cluster_summary()` output identical with vs. without evidence (regression-tested); `tests/test_cluster_evidence.py` (37 tests) + 4 additions each to `tests/test_prompt_context.py` and `tests/test_reporter_findings.py` — 201 tests pass (155 pre-existing + 46 new); ruff clean on both new files (pre-existing 51 errors in the repo are unrelated). Build 1c-fix (this row's Notes update) added the firewall shape + generic-srcip IP-validation safety net. |
| Report Clarity (section 12) | ✅ Complete | Phases 1, 1b and 2 shipped: per-finding ISM and E8 pointers in `ravensight/e8_scorer.py` and the "Findings and related controls" table in `ravensight/reporter.py` (commits `cf320c0`, `d4da01b`, `5d4e9d7`), plain wording, glossary and spelled-out firewall labels (`b6238e9`), `than` stop word (`bf43093`); 436 tests pass. |
| Pin Dev Tools (section 13) | ✅ Complete | `requirements-dev.txt` pins `pytest==9.1.1`, `ruff==0.16.9` and `pyright==1.1.414` (uncommitted at time of update); ruff clean and 436 tests pass. Pyright reports 37 errors, not fixed (out of scope) and left for a triage session. |
| Pyright Triage (section 14) | ✅ Complete | Session 1 (tests, commit `0e9d2a0`): `uv run pyright tests/` 29 errors to 0. Session 2 (production code, uncommitted at time of update): 8 errors to 0 in `ravensight/embedder.py`, `baseline.py`, `e8_scorer.py` and `scripts/mitre_sync.py`, all type-only or no-behaviour-change (annotation, local rename, assert, trailing raise), with 9 new tests including the new `tests/test_mitre_sync.py`; ruff clean and 445 tests pass. Pyright is still not a gate and has no config (out of scope). Open: openai/httpx2 exception handling in `analyser.py` left unchecked. |
| Essential Eight Phase 2, manual attestation (section 15) | ✅ Complete | Session 1 (commit `753c37a`): `ravensight/e8_scorer.py` `load_attestation()` reads `data/e8_attestation.json` and returns status, level and reason per strategy (invalid entries skipped with a warning, never blocks a run); tracked example `data/defaults/e8_attestation.example.json`; `[e8] attestation_path` in `config.example.toml`. Session 2 (uncommitted at time of update): `main.py` reads `attestation_path` and passes the result to `Reporter.generate`; `ravensight/reporter.py` E8 table shows "Attested at ML{n}" and "Not applicable" with the reason, keeps "Not assessed" for strategies with no entry, and the how-to-read note says declared statuses come from the operator's attestation (output byte-identical when no attestation exists); 482 tests pass, pyright and ruff clean. Open: the "ML1 to ML4" wording in `ravensight/reporter.py` and its test still says four levels (the data has three). |
| Docker Support for E8 Attestation (section 16) | ✅ Complete | `config.template.toml` `[e8] attestation_path` and `[reports] overwrite`; `docker-entrypoint.sh` exports `RAVENSIGHT_ATTESTATION_PATH` (empty when the file is absent), validates `RAVENSIGHT_REPORTS_OVERWRITE` as exactly `true` or `false`, and adds an `init-attestation` subcommand (copy-if-absent via `run_as`, never seeded on normal starts); `ravensight/e8_scorer.py` `load_attestation()` treats a blank path as unset; README and `.env.example` refreshed (uncommitted at time of update); 509 tests pass. The entrypoint has no tests and was reviewed by reading only, not run in a container. |
| Wazuh Indexer TLS Settings | ✅ Complete | Optional `[wazuh] indexer_verify_tls` (bool, default false) and `indexer_ca_path` (string, default empty, wins over the bool) read in `Client.__init__` in `ravensight/wazuh_client.py`; type rules in `ravensight/config_check.py`; Docker variables `WAZUH_INDEXER_VERIFY_TLS` and `WAZUH_INDEXER_CA_PATH`; README and `.env.example` updated (commit `3e22fcd`). The entrypoint change was reviewed by reading and `sh -n` only, not run in a container. |
| Wazuh Manager Login Removal | ✅ Complete | Unused Wazuh manager API login removed from `ravensight/wazuh_client.py` (`_authenticate`, `_ensure_authenticated`, token fields), `user` and `password` no longer required, and `WAZUH_API_USER`, `WAZUH_API_PASSWORD` and `WAZUH_PORT` dropped from the template and entrypoint (commit `3e22fcd`). `indexer_password` now defaults to an empty string. |
| Alert Cap Warning | ✅ Complete | `Client.fetch_alerts` sets `track_total_hits` and `Client._matched_total` logs one warning when the matched total exceeds the fetched count, so the 10,000-alert cap is no longer silent (commit `3e22fcd`). Warning only, no pagination. |
| Data File Loader Hardening | ✅ Complete | `_load_mitre_tactics`, `_load_platform_hints` and `_load_asd_data` in `ravensight/analyser.py` return an empty result with a warning when a data file is unreadable, not valid UTF-8 or the wrong shape, instead of aborting the run; 12 new tests (commit `b255ebf`). |
| Wazuh Indexer Connection Mode Log Line (section 18) | ✅ Complete | `Client.__init__` in `ravensight/wazuh_client.py` logs one INFO line with host, port and the configured TLS mode (CA file, bundled public CA list, or encrypted but not verified), never a negotiated protocol and never the user or password; four new caplog tests in `tests/test_wazuh_client.py`; 596 tests pass (commit `381237a`). Seen in a live Docker run: `HTTPS, encrypted but certificate not verified (indexer_verify_tls = false)`. |
| Structured JSON Report Output (section 17) | ✅ Complete | Session 1 done (commit `e63c70e`): `Reporter.generate()` in `ravensight/reporter.py` writes a `.json` file beside the markdown report (`schema_version` 1, `generated_at`, `run`, `findings`, `trends_markdown`, `e8_status`, `finding_pointers`, `matched_controls`, `attestation` when present) through `_write_json`, which logs a warning and carries on if the write fails; new optional `run_params` argument; README JSON section; 16 new tests in `tests/test_reporter_json.py`; markdown output proved byte-identical; 612 tests pass. Session 2 (commit `2fc9301`): `[reports] json_output` switch (default true, bool else `ValueError`) read by `Reporter.__init__` in `ravensight/reporter.py` and honoured in `generate()`; `RAVENSIGHT_REPORTS_JSON_OUTPUT` in `config.template.toml`, `docker-entrypoint.sh` (default true, exact true or false check) and `.env.example`; bool check in `ravensight/config_check.py` in both normal and report-only mode; `main.py` passes `run_params` (hours, agent, level) in the full run only, so `run` is null in report-only runs; README updated; 15 new tests, 627 tests pass. Seen in a live Docker run: `run` filled in and the `.json` written with the default. The switch off (`false`) and a bad value were not run in a container, and the entrypoint has no tests. Known limitations are listed in section 17. |
| Unify the Settings Files (section 19) | ✅ Complete | Sessions 2 and 3 built. Session 2 built, Docker run verified, missing-file and sync paths untested (commit `b83cf9a`): `docker-compose.yml` mounts the host `config.toml` read-only at `/app/config.toml`, `docker-entrypoint.sh` checks it exists and is readable by the app user (skipped for `sync` and `init-attestation`) and uses fixed container paths `/app/data` and `/app/reports`, `.env.example` trimmed to Docker-only settings, `config.template.toml` removed; 627 tests pass. Seen in a live Docker run on 21 Oct: config check passed, `Connecting to ChromaDB server at chroma:8000`, report and JSON written. Not run in a container: a missing host file, an unreadable file with a non-zero PUID, `sync` and `init-attestation`. Session 3 (uncommitted at time of update): `ravensight/config_check.py` `_PLACEHOLDER_HINT` and the three Wazuh and LLM error messages in `main.py` now name `config.toml` only, with `tests/test_config_check.py` asserting the full message text; `config.example.toml` has comments only (Docker and host values, `chroma_host = "chroma"`, relative paths); README Docker section rewritten for the single file with an old-variable migration table, config mount in the `docker run` examples, and the stale `config.template.toml` and `EMBEDDINGS_*` text removed; 627 tests pass. The README was reviewed by reading only, and the Docker commands in it were not run. |
| ASD Essentials Evidence Report (section 20) | 🔶 In progress | Session 0 done (research, no code). Prin's dataset verified on 21 Oct against ASD's evidence guide (58/58 actions, 529/529 IGP), assessment workbook and chapter PDF (37/37 technique rows); chapter technique lists and wording added as separate fields. Session 1 (commit `e586407`): tracked `data/defaults/essentials_enterprise_it.json` (Prin's dataset plus `schema_version` 1), new `ravensight/essentials_scorer.py` with `load_essentials()` (empty result and one warning on any read, decode or validation failure, never raises), `[essentials] path` in `config.example.toml`, 57 tests in `tests/test_essentials_scorer.py` including the committed dataset's counts; 684 tests pass, ruff clean. Session 2 (uncommitted at time of update): `extract_alert_clusters` in `ravensight/analyser.py` gives every cluster a sorted, de-duplicated `mitre_ids` list from the alerts' `rule.mitre.id` (new `_mitre_ids` helper; ids stripped, upper-cased and kept only if they match `T` plus four ASCII digits, optionally `.NNN`; bad values skipped, never raises), carried into findings by `_parse_analysis`; the LLM prompt, `_fidelity_flags`, `cluster_key` and the JSON report are unchanged, as 25 new tests in `tests/test_cluster_mitre.py` check; 709 tests pass, ruff clean. Not yet wired into `main.py` or the report (Sessions 3 to 6). |

---

## Planned Features

---

### 1. Multi-Model Routing — Superseded

**Status:** Not building — superseded by Qwen3.6-35B-A3B MoE model.

**Reason:** The original design assumed a single 8B model insufficient for deep
analysis, requiring a two-pass triage approach. Qwen3.6-35B running via CPU-MoE
offload produces significantly better single-pass analysis than the proposed
two-pass pipeline, without the added complexity. The VRAM constraints that made
sequential routing necessary no longer apply with MoE expert offload to RAM.

---

### 2. MITRE ATT&CK Tagging — Complete ✅

**What was built:**
- `mitre_sync.py` — standalone script fetching Enterprise ATT&CK STIX 2.1 bundle
- `data/mitre_attack.json` — local lookup file (15 tactics, 365 techniques, 493 subtechniques)
- `analyser.py` — compact tactic reference injected into LLM prompt
- `reporter.py` — MITRE ATT&CK Tags table in report output
- `config.example.toml` — `[mitre]` section with path and sync_source

---

### 3. Historical Trending — Complete ✅

**What was built:**
- `trending.py` — trend calculation per rule group, anomaly detection
- `baseline.py` — extended with `scan_history` schema
- `main.py` — trending wired into main pipeline
- `reporter.py` — Historical Trends table embedded in report
- `config.example.toml` — `[trending]` section

---

### 4. Embedding Model — Semantic Memory & Alert Retrieval

**What it does:**
Replaces the flat `baseline_state.json` memory with a vector store of embedded
historical alerts. At analysis time, retrieves only the semantically closest past
incidents and feeds them as context to the LLM — finding similar past attacks by
meaning, not keyword matching.

**The problem it solves:**
The current baseline summarises everything into a flat JSON. As history grows,
the prompt context fills with irrelevant past runs. Two incidents can describe the
same attack pattern using completely different words — keyword matching misses them
entirely. Semantic search solves both problems.

**How it works:**
- A dedicated local embedding model encodes each alert cluster into a vector at
  the end of every run
- Vectors are stored in a local vector store alongside metadata (timestamp, rule
  group, severity, raw summary)
- At analysis time, the current alert clusters are embedded and the top-N most
  similar past incidents are retrieved by cosine similarity
- Retrieved incidents are injected into the LLM prompt as structured context:
  "Similar past incidents: ..."
- `baseline.py` is extended to manage both the existing JSON store and the new
  vector store

**Model choice — Qwen3-Embedding-0.6B (recommended):**
- ~0.5GB VRAM — can co-exist with Qwen3.6-35B MoE model simultaneously
- Served via a second llama.cpp instance on port 8081, using the `/v1/embeddings`
  endpoint
- Qwen3-Embedding-4B (~2.5GB) is an alternative if retrieval quality needs
  improving

**Vector store choice — ChromaDB (recommended):**
- Pure Python, no separate server process needed
- Persistent SQLite backend — single file, fits the existing local-first philosophy
- Simple API: `collection.add()`, `collection.query()`
- Handles metadata filtering natively (e.g. filter by date range or rule group)
- Alternative: `sqlite-vec` (even lighter, SQLite extension)

**Key design decisions:**
- Embedding model runs on a second llama.cpp instance (port 8081)
- Migration path needed: existing `baseline_state.json` entries should be embedded
  on first run and loaded into ChromaDB so history is not lost
- Retrieval window is configurable — default top-5 most similar past incidents
- Both stores (JSON baseline and vector store) run in parallel initially — JSON
  baseline is not removed until vector retrieval is proven stable
- Evaluate whether 0.6B embedding quality is sufficient before considering 4B upgrade

---

**Implementation Sessions:**

- **Session 1 — embedder.py** ✅ Complete
  - New module: ChromaDB connection, llama.cpp embeddings endpoint, `add_embedding()` and `query_similar()` methods
  - Out of scope: all other files

- **Session 2 — baseline.py + config** ✅ Complete
  - Extend `Manager.__init__()` to accept optional `embedder` parameter and store as `self._embedder`
  - Extend `Manager.update()` to call `self._embedder.add_embedding()` when embedder is present
  - Add `[embeddings]` section to `config.example.toml`
  - Add `chromadb` to `requirements.txt`
  - Out of scope: `retrieve_similar()`, `analyser.py`, `main.py`, `embedder.py` (read only)

- **Session 3 — analyser.py** ✅ Complete
  - Update `_build_prompt()` to accept and inject retrieved similar incidents context
  - Add `retrieve_similar()` call before prompt construction
  - Out of scope: `baseline.py`, `main.py`, `embedder.py`

- **Session 4 — main.py wiring** ✅ Complete
  - Instantiate `Embedder` from config
  - Pass embedder instance to `Baseline.Manager` constructor
  - Wire retrieval into the main analysis pipeline
  - Out of scope: any changes to `baseline.py`, `analyser.py`, or `embedder.py`

- **Session 5 — config + requirements final pass** ✅ Complete
  - Verified `config.example.toml` `[embeddings]` section has correct keys
  - Verified `chromadb` present in `requirements.txt`
  - Updated `README.md` — added chromadb to requirements table, port 8081 server entry, `[embeddings]` config keys section
  - ⚠️ **Manual step required:** `config.example.toml` is the template — any new `[embeddings]` section must be manually copied into the live `config.toml` by the user. The agent never touches `config.toml` as it contains credentials.
  - Out of scope: any logic changes

---

**Validation Status:** ✅ Complete

- Run 1 completed — alerts embedded into ChromaDB, no retrieval output (expected — empty store on first run)
- Run 2 confirmed — 89 vectors stored in `alerts` collection, embedding server
  receiving requests (HTTP 200 on port 8081), ChromaDB sqlite file growing
- Pipeline confirmed end-to-end: Wazuh alerts → Qwen3-Embedding-0.6B → ChromaDB

**Operational Notes:**

- Embedding server (`start-embed`) must be started before running Ravensight
- Use `--ctx-size 512 --n-gpu-layers 0` on the embedding server — keeps VRAM footprint to ~564 MiB
- Do not use `--ub` flag — invalid on current llama.cpp build
- VRAM budget with both servers running: ~8.6GB / 12GB (3.6GB headroom)
- `[embeddings]` section must be present in live `config.toml` — agent only updates `config.example.toml`

---
- `ravensight/embedder.py` — new module: connects to llama.cpp embeddings endpoint, encodes
  alert clusters, manages ChromaDB collection
- `ravensight/baseline.py` — extend to write embeddings on update, add `retrieve_similar()`
- `ravensight/analyser.py` — update `_build_prompt()` to inject retrieved context
- `config.toml` — add `[embeddings]` section with model ID, endpoint port,
  ChromaDB path, top-N retrieval count
- `requirements.txt` — add `chromadb`
- `data/chromadb/` — vector store directory (gitignored)

---

### 5. Platform-Aware Alert Context

**What it does:**
Injects platform metadata into the LLM prompt before analysis so that findings
are interpreted relative to the OS and filesystem the agent is running on.
Prevents the LLM from escalating structural false positives that are a direct
consequence of platform behaviour rather than a security event.

**Background:**
Rootcheck rule 510 on a FreeBSD/OPNsense agent produces level 7 alerts for
`/boot/efi` link count mismatches. This is a structural false positive: FAT32
does not implement Unix hard link counts, so the mismatch is architectural
rather than suspicious. Without platform context, the LLM escalated this to a
"confirmed rootkit — rebuild immediately" recommendation. The fix is context,
not suppression — the LLM still makes the final call, but with accurate
information about what the platform does normally.

**How it works:**
- `data/platform_hints.json` holds a lookup table keyed by OS platform
  (e.g. `freebsd`, `linux`, `windows`); each entry lists known rule/path
  combinations that are structural false positives on that platform, with a
  plain-English hint explaining why
- `analyser.py` extracts `agent.os.platform` from the alert batch, looks up
  any matching hints for the rule IDs present, and prepends a Platform Context
  block to the prompt before the alert summary
- `wazuh_client.py` already returns `agent.os` fields as part of the full
  `_source` payload — no query changes required; verified at session start

**Platform hints JSON structure:**

```json
{
  "freebsd": {
    "description": "FreeBSD and derivatives (OPNsense, pfSense)",
    "filesystem_notes": "FAT32 (EFI partition) does not implement Unix hard link counts.",
    "rules": {
      "510": {
        "paths": ["/boot/efi"],
        "hint": "Link count mismatches on /boot/efi are a structural FAT32 artefact on FreeBSD/OPNsense — not an indicator of rootkit activity. Do not escalate."
      }
    }
  }
}
```

**Prompt injection format:**

```
Platform context:
- Agent: firewall-01 (freebsd — FreeBSD and derivatives)
- Filesystem notes: FAT32 (EFI partition) does not implement Unix hard link counts.
- Known false positives for this platform:
  - Rule 510 on /boot/efi: Link count mismatches are a structural FAT32 artefact — not a rootkit indicator. Do not escalate.
```

**Key design decisions:**
- Hints are injected as context, not hard suppression rules — the LLM retains
  full authority over the final finding; the hint is advisory
- `platform_hints.json` is editable without code changes — new false positives
  are added to the JSON file as they are discovered; no code session required
- Graceful skip if `platform_hints.json` is absent or a platform has no entry —
  analysis continues without the platform block; run is never blocked
- If multiple agents with different OS platforms are present in the same batch,
  all relevant platform blocks are injected (one per distinct platform found)
- No new Python dependencies required

**New files/changes:**
- `data/platform_hints.json` — platform/rule false positive hint table
  (gitignored alongside MITRE and ASD data; regenerate from source or maintain
  manually; starts with the FreeBSD/rule 510 entry)
- `ravensight/analyser.py` — add `_load_platform_hints()` and
  `_build_platform_context()` helpers; update `_build_prompt()` to call them
  and prepend the platform block when hints are present
- `config.example.toml` — add `[platform]` section with `hints_path` key
- `wazuh_client.py` — read-only verification at session start; no code change
  expected

---

**Implementation Sessions:**

- **Session 1 — data/platform_hints.json**
  - Read `wazuh_client.py` to confirm `agent.os.platform` and `agent.os.name`
    are returned in the existing `_source` payload; confirm field paths; document
    any discrepancy — no code change to `wazuh_client.py` expected
  - Create `data/platform_hints.json` with the initial FreeBSD entry (rule 510,
    path `/boot/efi`, hint text as above) and the top-level JSON schema
    (`platform key → description, filesystem_notes, rules → rule_id → paths, hint`)
  - Add `data/platform_hints.json` to `.gitignore` alongside `data/mitre_attack.json`
    and `data/asd_framework.json`
  - Out of scope: `analyser.py`, `config.example.toml`, any logic changes

- **Session 2 — ravensight/analyser.py + config.example.toml**
  - Read `analyser.py` in full before touching anything; identify the exact
    insertion point in `_build_prompt()`
  - Add `_load_platform_hints(hints_path: str) -> dict` — reads
    `data/platform_hints.json`; returns empty dict on file-not-found with a
    `logger.warning`; called once per `analyse()` invocation
  - Add `_build_platform_context(alerts: list[dict], hints: dict) -> str` —
    extracts distinct `agent.os.platform` values from alert `_source` fields;
    looks up each platform in `hints`; for each platform found, checks rule IDs
    present in the alert batch against `hints[platform]["rules"]`; builds and
    returns the formatted platform block string (empty string if no matches)
  - Update `_build_prompt()`: accept `platform_context: str` parameter; if
    non-empty, prepend it before the alert summary block
  - Update `analyse()`: call `_load_platform_hints()` with path from `llm_config`
    (or a hardcoded default `"data/platform_hints.json"` if config key absent);
    call `_build_platform_context()`; pass result to `_build_prompt()`
  - `config.example.toml`: add `[platform]` section with
    `hints_path = "data/platform_hints.json"`
  - Out of scope: `_parse_analysis()`, `wazuh_client.py`, `reporter.py`,
    `baseline.py`, streaming logic

---

**Operational Notes:**

- Add new false positives directly to `data/platform_hints.json` — no code
  session required; format follows the existing FreeBSD entry
- Rule IDs in the JSON must match the Wazuh rule ID as a string (e.g. `"510"`,
  not `510`) — check `rule.id` field in a raw alert to confirm
- If `agent.os.platform` is absent in an alert (can happen with agentless
  sources), `_build_platform_context()` skips that alert silently
- Run smoke test after Session 2:
  `python -c "from ravensight import analyser; print('imports OK')"`

---

### 6. Progress Bar + LLM Streaming

**What it does:**
Two complementary improvements to terminal feedback during a Ravensight run.
Part A adds tqdm progress bars to phases with known counts — alert fetch,
baseline migration, and embedding calls. Part B replaces the blocking
`chat.completions.create()` call with a streaming response that displays a
live token counter and generation speed as the model writes, giving real proof
of liveness rather than a spinner over a silent connection.

**The problem it solves:**
All three phases block for seconds to minutes with no output. The embedding
migration loop and the LLM call are the main pain points. A determinate bar
over the migration loop shows actual progress; the streaming token counter
shows the model is generating rather than hanging, and surfaces generation
speed (tokens/s) as a useful operational signal when tuning the inference
server.

**Part A — tqdm progress bars (known counts):**
- `wazuh_client.py` — spinner during the OpenSearch HTTP request (single call,
  total unknown during flight); closes and reports fetched count via
  `tqdm.write()` on return
- `embedder.py` — determinate bar over the baseline migration loop
  (`tqdm(items, desc="Embedding migration", unit=" entry")`; total = number of
  entries, known upfront); separate spinner over `query_similar()` call
- `main.py` — `--no-progress` flag; `show_progress` bool derived once
  (`not args.no_progress and sys.stdout.isatty()`) and threaded into
  `Client`, `Embedder`, and `analyse()`; step labels via `tqdm.write()` to
  avoid interleaving with active bars

**Part B — LLM streaming token counter:**
- `analyser.py` — `client.chat.completions.create(stream=True)` replaces the
  blocking call; response is consumed chunk by chunk; each chunk's
  `delta.content` is accumulated into `full_text` and counted as one token;
  a `tqdm(total=None, unit=" tok", desc="Analysing")` bar is updated on
  each non-empty chunk — tqdm's built-in rate calculation yields tokens/s
  automatically; the bar closes when the stream ends; `full_text` is passed
  to `_parse_analysis()` unchanged — no downstream changes required
- When `show_progress` is False, streaming still runs (it is strictly better
  than a blocking call for liveness) but the tqdm bar is disabled; chunk
  accumulation is unchanged

**Library choice — tqdm:**
- Pure Python, zero native dependencies, minimal overhead
- Works correctly in standard terminals and over SSH — no curses requirement
- `tqdm(total=None)` for indeterminate phases; determinate for known counts
- Rate display (`tok/s`) emerges from tqdm's own elapsed time tracking —
  no manual rate calculation needed

**Key design decisions:**
- Streaming is unconditional — `stream=True` regardless of `--no-progress`;
  only the tqdm bar display is gated on `show_progress`; this keeps Part B
  permanently beneficial (avoids a long blocking HTTP hold on the connection)
- `show_progress` is derived once in `main.py` and passed down — no module
  reads `sys.stdout.isatty()` directly; single point of control
- Bars are automatically suppressed when stdout is not a TTY (cron, pipes,
  log redirection) via the `disable` parameter — no special cron config needed
- Part B is the higher-priority change; if session scope must be trimmed,
  Part A (wazuh_client.py spinner, embedder.py bar) is deferred before
  Part B (analyser.py streaming) is touched

**New files/changes:**
- `requirements.txt` — add `tqdm>=4.66`
- `main.py` — `--no-progress` flag; `show_progress` bool; pass to sub-modules;
  step labels via `tqdm.write()`
- `ravensight/wazuh_client.py` — spinner + count display in `fetch_alerts()`
- `ravensight/embedder.py` — determinate bar over migration loop; spinner over
  `query_similar()`
- `ravensight/analyser.py` — `stream=True`; chunk accumulation loop; tqdm token
  counter; `full_text` passed to `_parse_analysis()` unchanged

---

**Implementation Sessions:**

- **Session 1 — Part A: tqdm bars (wazuh_client.py, embedder.py, main.py)**
  - Add `tqdm>=4.66` to `requirements.txt`
  - `main.py`: add `--no-progress` CLI flag; derive
    `show_progress = not args.no_progress and sys.stdout.isatty()`; pass
    `show_progress` to `wazuh_client.Client.__init__()` and
    `embedder.Embedder.__init__()`; use `tqdm.write()` for step labels
  - `ravensight/wazuh_client.py`: add `show_progress: bool = False` to
    `__init__()`; in `fetch_alerts()`, wrap the `requests.post()` call with
    `tqdm(total=None, desc="Fetching alerts", disable=not self.show_progress)`
    as a context manager; on return, call
    `tqdm.write(f"Fetched {len(alerts)} alerts")` to report the count
  - `ravensight/embedder.py`: add `show_progress: bool = False` to
    `__init__()`; wrap the baseline migration loop with
    `tqdm(items, desc="Embedding migration", unit=" entry", disable=not self.show_progress)`;
    wrap the `query_similar()` HTTP call with a `tqdm(total=None)` spinner
  - Out of scope: `analyser.py`, `reporter.py`, `baseline.py`, `trending.py`,
    `embedder.py` ChromaDB and vector logic, any analysis logic

- **Session 2 — Part B: LLM streaming (analyser.py only)**
  - `ravensight/analyser.py`: add `show_progress: bool = False` parameter to
    `analyse()`; replace `client.chat.completions.create(...)` with
    `client.chat.completions.create(..., stream=True)`; consume the stream
    in a loop: `for chunk in stream: content = chunk.choices[0].delta.content or ""; full_text += content; if content: bar.update(1)`;
    wrap loop with `tqdm(total=None, desc="Analysing", unit=" tok", disable=not show_progress)`;
    after loop, pass `full_text` to `_parse_analysis()` unchanged
  - `main.py`: pass `show_progress` to `analyser.analyse()` (one-line change
    to the existing call site added in Session 1)
  - Out of scope: `_parse_analysis()` logic, `_build_prompt()`, `wazuh_client.py`,
    `embedder.py`, `reporter.py`, `baseline.py`

---

**Operational Notes:**

- Streaming (`stream=True`) is always active regardless of `--no-progress` —
  only the tqdm display is gated; the streaming loop runs in both modes
- Progress bars are automatically suppressed when stdout is not a TTY
- `tqdm.write()` is used for all step labels while bars are active to prevent
  line-clobber artefacts; existing `logging` calls are unaffected if the log
  handler writes to stderr (default `logging.basicConfig` behaviour)
- Expected streaming display: `Analysing... 1247 tok [00:29<?, 43.0 tok/s]`
- Run smoke test after each session:
  `python -c "from ravensight import wazuh_client, embedder, analyser; print('imports OK')"`

---

### 7. ASD Framework Mapping

**What it does:**
Maps alert findings and recommendations to Australian cyber security controls —
the Essential Eight (ASD) and a curated subset of the ISM (Australian Government
Information Security Manual) — so that recommendations in Ravensight reports align
with Australian regulatory language. Example output: "Isolate affected host —
Essential Eight: Restrict Administrative Privileges (ML2), ISM-1175."

**The problem it solves:**
MITRE ATT&CK tagging names the threat tactic; ASD mapping closes the loop by
naming the defensive control. For Australian operators (government, critical
infrastructure, regulated entities), ISM and Essential Eight are the reference
frameworks. Aligning recommendations to these controls makes reports actionable
within Australian compliance contexts without manual cross-referencing.

**How it works:**
- `scripts/asd_sync.py` builds a local `data/asd_framework.json` lookup file
  combining Essential Eight strategies and a curated ISM control subset
- Essential Eight data is maintained as a structured static dataset in the sync
  script (8 strategies × 4 maturity levels = 32 control entries); the ASD does
  not publish a machine-readable version, and the framework is stable enough
  that manual updates on major revision are acceptable
- ISM data is fetched from the ACSC-published ISM Excel workbook
  (cyber.gov.au/resources-business-and-government/essential-cyber-security/ism)
  and filtered to controls relevant to the alert types Ravensight handles:
  access control, system monitoring, patch management, incident response,
  network security (approximately 80–120 controls from ~750 total)
- At analysis time, `analyser.py` reads the local file and injects a compact
  ASD control reference into the LLM prompt alongside the MITRE tactic reference
- The LLM maps findings and recommendations to Essential Eight strategies
  (with maturity level) and ISM control IDs
- `reporter.py` outputs an ASD Framework Alignment table in the report

**Key design decisions:**
- No live fetching during report runs — always reads from local JSON file, same
  pattern as MITRE ATT&CK tagging
- `asd_sync.py` run manually or on ISM update cadence (quarterly) — not
  triggered automatically by Ravensight
- Essential Eight is hardcoded in the sync script, not fetched — avoids HTML
  scraping fragility; the ASD publishes no machine-readable Essential Eight
  source; the framework is revised infrequently (major revisions announced publicly)
- ISM fetch parses the official ACSC Excel workbook; the sync script filters
  by control category rather than manual curation so the filter logic can be
  adjusted without editing the dataset itself
- Curated ISM subset rather than full 750-control set — injecting all controls
  would exceed useful prompt context; relevance filtering keeps the injected
  reference compact (same approach as MITRE tactic-only injection)
- ASD mapping and MITRE mapping are independent — both can appear in the same
  report section; reporter handles each as a separate table

**New files/changes:**
- `scripts/asd_sync.py` — new standalone sync script; builds Essential Eight
  static dataset + fetches and filters ISM Excel workbook; writes
  `data/asd_framework.json`
- `data/asd_framework.json` — local ASD lookup file (gitignored if large)
- `ravensight/analyser.py` — update `_build_prompt()` to load and inject compact
  ASD control reference alongside existing MITRE context
- `ravensight/reporter.py` — add ASD Framework Alignment table to report output,
  parallel to existing MITRE ATT&CK Tags table
- `config.example.toml` — add `[asd]` section with local data path, ISM source
  URL, and ISM category filter list

---

**Implementation Sessions:**

- **Session 1 — scripts/asd_sync.py + data/asd_framework.json**
  - New script `scripts/asd_sync.py`:
    - Essential Eight static dataset: 8 strategies, each with 4 maturity level
      entries (ML1–ML4), including strategy name, maturity level, and a one-line
      description of the control requirement at that level
    - ISM fetch: download the ACSC ISM Excel workbook from the configured source
      URL; parse with `openpyxl`; filter rows where the Control Category column
      matches the configured category list (e.g. `["Access Control", "System
      Monitoring", "Patch Management", "Incident Response", "Network Management"]`)
    - Write combined output to `data/asd_framework.json` with two top-level keys:
      `essential_eight` (list of 32 entries) and `ism` (list of filtered controls,
      each with `id`, `category`, `description`)
    - Add `openpyxl` to `requirements.txt`
  - Out of scope: `analyser.py`, `reporter.py`, `config.example.toml`, all
    `ravensight/` modules

- **Session 2 — ravensight/analyser.py**
  - Update `_build_prompt()` to accept `asd_context: str` parameter (compact
    formatted string, built from `data/asd_framework.json` before the call)
  - Add `_build_asd_context()` helper function: reads `data/asd_framework.json`,
    formats Essential Eight strategies as a compact reference block (strategy name
    + ML range), appends ISM control IDs and one-line descriptions grouped by
    category; returns a string short enough to fit within prompt budget
  - Update `analyse()` to call `_build_asd_context()` when the ASD data file
    exists (graceful skip with a warning log if file is absent — run is not
    blocked by missing ASD data)
  - Out of scope: `reporter.py`, `main.py`, `config.example.toml`, MITRE prompt
    logic (read only for reference)

- **Session 3 — ravensight/reporter.py**
  - Add `_build_asd_table()` helper: formats the ASD mappings returned in the
    analysis dict as a markdown table with columns: Finding, Essential Eight
    Strategy, Maturity Level, ISM Controls
  - Update `_build_report()` to call `_build_asd_table()` and insert the table
    after the existing MITRE ATT&CK Tags section; skip gracefully if no ASD
    mappings are present in the analysis dict
  - Out of scope: `analyser.py`, `main.py`, `config.example.toml`, MITRE
    reporter logic (read only for reference)

- **Session 4 — config.example.toml + README.md**
  - Add `[asd]` section to `config.example.toml`:
    ```toml
    [asd]
    data_path = "data/asd_framework.json"
    ism_source_url = "https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism"
    ism_categories = ["Access Control", "System Monitoring", "Patch Management", "Incident Response", "Network Management"]
    ```
  - Update `README.md`: add `asd_sync.py` to scripts table; add `[asd]` config
    keys to config reference section; add note that `asd_sync.py` must be run
    before first use and re-run after ISM quarterly update
  - ⚠️ **Manual step required:** `[asd]` section must be manually copied from
    `config.example.toml` into live `config.toml`. Agent never touches `config.toml`.
  - Out of scope: any logic changes to `analyser.py`, `reporter.py`, or
    `asd_sync.py`

---

**Operational Notes:**

- Run `python scripts/asd_sync.py` before first Ravensight run with ASD mapping enabled
- Re-run `asd_sync.py` after each ISM quarterly update (ACSC typically publishes
  in January, April, July, October)
- Essential Eight does not require re-sync unless ASD publishes a major revision —
  check cyber.gov.au/essential-eight when revisions are announced
- If `data/asd_framework.json` is absent, Ravensight logs a warning and continues
  without ASD mapping — the run is not blocked
- `openpyxl` is added to `requirements.txt` as a new dependency (ISM Excel parse);
  no other new dependencies introduced
- Run smoke test after implementation: `python -c "from ravensight import analyser, reporter; print('imports OK')"`
- ASD data file is gitignored alongside MITRE data — regenerate locally after clone

---

### 8. Essential Eight Compliance Scoring + ISM Alert Mapping

**What it does:**
After each analysis run, maps findings against both the Essential Eight
strategies and ISM controls to produce scan-relevant output. The E8 table
becomes a compliance posture indicator (✓ / -) and the ISM controls table
shrinks to only the controls relevant to what was actually found — instead
of always showing the same 78 controls regardless of scan content.

**Sessions: 3**

---

#### Session 1 — ravensight/e8_scorer.py (new module)

New module with two public functions:

```python
def score_findings(
    findings: list[dict],
    asd_data: dict,
) -> dict[str, dict[int, bool]]:
    """
    Map findings against Essential Eight strategies and maturity levels.

    Returns: { strategy_name: { 1: True, 2: False, 3: False, 4: False } }
    True  = no evidence of failure at this level
    False = finding suggests control failure at this level
    """

def match_ism_controls(
    findings: list[dict],
    asd_data: dict,
    max_controls: int = 15,
) -> list[dict]:
    """
    Return ISM controls relevant to the current scan findings.

    Matches finding descriptions against ISM control descriptions using
    keyword overlap. Returns up to max_controls most relevant controls,
    sorted by match score descending. Falls back to full list if no
    matches found.
    """
```

Matching approach (no second LLM call — keyword only):
- For E8: match finding description keywords against strategy names and
  maturity level descriptions
- For ISM: score each control by counting keyword overlaps between the
  finding description and the control description + category
- A finding mapped to an E8 strategy marks ML1 as False (ML1 failure
  implies all higher levels also fail)
- ISM controls ranked by cumulative match score across all findings

---

#### Session 2 — Wire into main.py + reporter.py

- `main.py`:
  - Call `e8_scorer.score_findings()` after analysis
  - Call `e8_scorer.match_ism_controls()` after analysis
  - Pass both results to `reporter.generate()`

- `reporter.py`: update `_render_asd_section()` to accept:
  - `e8_scores` dict → dynamic ✓ / - table instead of static all-✓
  - `matched_controls` list → replace full 78-control table with
    scan-relevant subset only
  - If no matches found → show message:
    `> No ISM controls matched findings from this scan.`

---

#### Session 3 — Validation + tuning

- Run against a live batch with known alert types
- Verify E8 scoring produces sensible strategy mappings
- Verify ISM controls returned are relevant to the alerts found
- Tune keyword matching in `e8_scorer.py` based on results
- Document override keywords in `data/e8_keyword_overrides.json`
  (same extensible pattern as `platform_hints.json`)
- If keyword accuracy proves insufficient, Session 3 can optionally
  introduce embedding similarity matching using the existing `Embedder`
  as a drop-in upgrade — same interface, no downstream changes needed

---

**Key constraints:**
- No second LLM call — all matching must be fast and fully offline
- Keyword matching only in Sessions 1 and 2
- Embedder upgrade is optional and only if keyword accuracy is poor
- `e8_scorer.py` has no dependencies on any other Ravensight module
  except the `asd_data` dict it receives as a parameter

---

### 9. Essential Eight Evidence-Only Report

**What it does:**
Brings the Essential Eight (E8) section in line with Build 2b. Ravensight
reads alerts, not system configuration, so it cannot measure maturity. Every
strategy is reported as "Not assessed", with related findings and ISM controls
shown as pointers for review. The pass/fail (✓ / -) wording in section 8 is
superseded by this section.

**Design rule:** evidence-only. No invented verdicts. Any new state must come
from named evidence (an attestation entry, platform data or an extra evidence
source), never from keyword matching alone.

**Sessions: 1 so far (Phase 1). Later phases are added here before they start.**

---

#### Phase 1 — Remove quiet defects (no new features)

In scope:
- `ravensight/reporter.py`: the E8 table row prints the status returned by
  `score_findings()` instead of a hard-coded string (falls back to
  "Not assessed" when there is no score)
- `ravensight/reporter.py`: the "Unmapped" pseudo-strategy stays visible but is
  clearly labelled as not one of the Essential Eight, with status
  "Not assessed"
- `ravensight/reporter.py`: when the ASD data file is missing or from an older
  format, `Reporter._build_report` shows a short note saying so and pointing at
  `scripts/asd_sync.py`
- `main.py`: one line, pass `None` (not `{}`) as `asd_data` when `[asd] path`
  is not set, so the note appears only for a missing or old-format file
- `ravensight/e8_scorer.py`: stop reading the unused `rule_group` field in
  keyword matching and update the docstrings
- `tests/test_e8_scorer.py` and `tests/test_reporter_findings.py`: tests for
  each change above

Out of scope:
- A "Not applicable" state
- An attestation file declaring what the operator has implemented
- Optional extra evidence sources (for example Wazuh SCA results)
- Any change to how findings are matched to controls
- `analyser._build_asd_context` (the LLM prompt also sees "Unmapped"; logged as
  deferred)
- `scripts/asd_sync.py` and `data/asd_framework.json`
- `config.toml` and `config.example.toml`

---

### 10. Wazuh Query Time Window Fix

**What it does:**
`WazuhClient.fetch_alerts` builds its `since` value from the local clock of the
machine running Ravensight but labels it UTC (`Z`), so the lookback window is
shifted by the machine's UTC offset. This section makes the window true UTC on
any machine timezone.

**Sessions: 1**

---

#### Session 1 — UTC lookback window

In scope:
- `ravensight/wazuh_client.py`: build `since` from `datetime.now(timezone.utc)`
  with the same output format
- `tests/test_wazuh_client.py` (new): asserts the `since` sent to the indexer is
  UTC under a non-UTC process timezone and under UTC, including `hours` smaller
  than the offset

Out of scope:
- Baseline, trending, reporter and similar-incident timestamps (naive local
  time by design)
- Any `time_zone` query parameter or Wazuh server settings
- `config.toml` and `config.example.toml`

---

### 11. Report Finding Time Labelling

**What it does:**
Finding times in the report (`first_seen` / `last_seen`) come straight from the
Wazuh `@timestamp`, which is UTC, while the "Generated" line uses the local
clock of the machine running Ravensight. The report shows both with no zone
label, which is confusing. This section labels the finding times as UTC.

**Sessions: 1**

---

#### Session 1 — UTC label on finding times

In scope:
- `ravensight/reporter.py`: the time clause in `_format_finding` (and
  `_trim_timestamp`) marks the times as UTC when the raw timestamp carries a
  zero offset (`Z`, `+0000` or `+00:00`), for example
  `(2026-10-12 00:24 → 2026-10-12 00:55 UTC)`. A timestamp with a non-zero offset
  or no offset is shown as before, never mislabelled
- `tests/test_reporter_findings.py`: update the time clause assertions and add
  tests for each case above

Out of scope:
- Converting finding times to local time
- Timestamps in the LLM prompt, baseline, trending, "Generated" line and
  similar-incident output
- Any change to `ravensight/analyser.py` or how `first_seen` / `last_seen` are
  stored
- `config.toml` and `config.example.toml`

---

### 12. Report Clarity — ASD Alignment and Plain Wording

**What it does:**
Makes the report easier to read and to explain to other people. The ASD
Framework section becomes finding-centred: one table showing which finding
relates to which Essential Eight strategy and ISM control, and why. Terms and
abbreviations are explained in the report itself.

**Design rule:** evidence-only, as in section 9. Pointers come from word
matching on a finding's description and recommendation, never from the LLM.
No pass or fail wording.

**Sessions: 2. Later phases are added here before they start.**

#### Phase 1 — Per-finding pointers and ASD layout
In scope:
- `ravensight/e8_scorer.py`: a per-finding result for ISM and E8 matches,
  including the shared words. `match_ism_controls` keeps returning its flat
  list for the existing callers
- `main.py`: pass the per-finding result to `Reporter.generate`
- `ravensight/reporter.py`: `_render_asd_section` shows a "Findings and related
  controls" table (Finding, Essential Eight, ISM controls, Matched on), ordered
  by finding ID, at most 15 rows, highest severity first, with a line for the
  number not shown and a line naming findings with no match
- The E8 strategy table collapses to one line when no strategy matched
- One short "How to read this" note replaces the repeated notes
- Tests for each change
Out of scope: E8 Phase 2 (attestation, "Not applicable"), the LLM prompt,
`evidence.py`, `data/asd_framework.json`, `config.toml`

#### Phase 1b — Matching accuracy
In scope:
- `ravensight/e8_scorer.py`: light stemming in `_extract_keywords` (drop common
  endings such as ed, ing, es, s) so patched/patches and updated/updates match
- `ravensight/e8_scorer.py`: add boilerplate words to `E8_GENERIC_WORDS`
  (action, confirm, multiple, expected)
- `ravensight/reporter.py`: the "no ISM controls matched" branch uses
  `is not None` so an empty match list shows the no-match line instead of
  every ISM control
- Tests for each change
Out of scope: Phase 2 wording, E8 Phase 2, the LLM prompt, stored baseline data

#### Phase 2 — Plain wording and report tidy-up
In scope:
- `ravensight/reporter.py`: one line under the report title explaining that
  C1, C2… are clusters (alerts with the same rule), numbered per run
- Spelled-out names at first use: ASD, ISM, Essential Eight, ML, UTC
- A short glossary at the end listing only terms used in that report
- `ravensight/evidence.py`: firewall evidence labels spelled out (source,
  destination, destination port, interface, direction, protocol)
- Past-incident dates shown as plain dates
- `ravensight/reporter.py`: remove the flat "Relevant ISM Controls" list now
  that the per-finding table covers it (the "no ISM controls matched" line
  moves into the per-finding section)
- `ravensight/reporter.py`: the per-finding table shows each ISM category once
  after the control IDs
- The how-to-read note says pointers can vary a little between runs because
  they use the finding's recommendation text
- Tests for each change
Out of scope: matching logic, E8 Phase 2, the LLM prompt, baseline data
(the stale "pfSense" label lives in `baseline_state.json` and Chroma)

---

### 13. Pin Dev Tools

**What it does:**
`requirements-dev.txt` only sets lower bounds (`pytest>=9.0`, `ruff>=0.6`) and does
not list pyright, so lint and type results can change between machines and over
time. This section pins the dev tools to the versions installed in the project
environment, so a clean run today stays clean.

**Sessions: 1**

---

#### Session 1 — Pin pytest, ruff and pyright

In scope:
- `requirements-dev.txt`: pin `pytest`, `ruff` and `pyright` to exact versions
  (`==`), using the versions the project environment resolves to now; add
  `pyright` if it is missing
- Run `uv run ruff check .` and `uv run pytest` with the pinned versions and
  report the results (expected: ruff clean, 436 tests pass)
- Fix only ruff errors that the pinned version reports on files the build
  already touched; list any others under Not Finished

Out of scope:
- Any change to `ravensight/`, `main.py`, `scripts/` or test logic
- `requirements.txt` and the Dockerfile
- Pyright configuration, or fixing pyright findings (report the count only)
- The stale "pfSense" label, the Chroma client/server version warning, and the
  stale graft summaries (none are code changes)
- `config.toml` and `config.example.toml`

---

### 14. Pyright Triage

**What it does:**
Pyright 1.1.414 (pinned in section 13) reports 37 errors on a clean `main` (436
tests pass, ruff clean). This section brings the count down in two steps: test
files first, where there is no behaviour risk, then production code, where some
errors may be real bugs.

**Sessions: 2**

---

#### Session 1 — Test files only (about 27 errors)

In scope:
- Test stub embedders passed where `Embedder | None` is expected (about 10):
  fix with a `Protocol` or a cast
- Possibly-None attribute access (about 10): fix with type narrowing
- `chromadb.errors` not recognised as a module attribute (5)
- `httpx` versus `httpx2` mismatches (3)
- Edits to test files only

Out of scope:
- Any change to `ravensight/`, `main.py` or `scripts/`
- Pyright configuration, or making pyright a gate (see the section-wide note below)
- `config.toml` and `config.example.toml`

#### Session 2 — Production code (about 10 errors)

In scope:
- `ravensight/embedder.py`, `ravensight/baseline.py`, `ravensight/e8_scorer.py`
  and `scripts/mitre_sync.py`
- Some errors may be real bugs, for example a `str` assigned to a list value at
  `baseline.py:104` and a missing return in `scripts/mitre_sync.py:27`. Each fix
  needs its own check and its own test
- The plan for the session decides whether to fix the code or the types, per error

Out of scope:
- Pyright configuration, or making pyright a gate (see the section-wide note below)
- `config.toml` and `config.example.toml`

Out of scope for the whole section:
- Adding a pyright config or making pyright a gate. That waits until the error
  count is near zero

---

### 15. Essential Eight Phase 2 — Manual Attestation

**What it does:**
Ravensight reads alerts, not system configuration, so it cannot measure Essential
Eight (E8) maturity (section 9). This phase lets the operator declare, in a data
file, what they have implemented. Each strategy can be marked "Not applicable"
or "Attested" at a stated maturity level, with a reason. The report shows the
declaration instead of "Not assessed".

**Design rule:** evidence-only, as in section 9. The only new evidence is the
operator's own attestation, and the report says so.

**Sessions: 2**

Decisions:
- Where it lives: `data/e8_attestation.json`, editable without code changes, in
  the style of `data/platform_hints.json`
- Shape: per strategy only, not per maturity level. Each entry is either
  "Not applicable" or "Attested" at a stated maturity level, with a free-text
  reason. No date field
- Report behaviour: "Not applicable" strategies are shown with their reason, not
  hidden. They stay distinct from "Not assessed"
- Evidence: attestation only. No extra evidence sources in this phase
- Docker: the real `data/e8_attestation.json` is not seeded into the data
  directory by the entrypoint in this phase. A tracked example,
  `data/defaults/e8_attestation.example.json`, is shipped and copied by hand. The
  drift risk for seeded defaults is already logged as deferred (see the
  "Container non-root + seeding fix" row)

#### Session 1 — Load and validate the attestation file

In scope:
- `ravensight/e8_scorer.py`: load `data/e8_attestation.json` and return a
  per-strategy status of "Not applicable", "Attested" (with maturity level) or
  "Not assessed" (no entry), each with the reason
- Graceful skip if the file is absent, as for `platform_hints.json`: log a
  warning and carry on, never block a run
- `data/defaults/e8_attestation.example.json`: a tracked example in the agreed
  shape. The real `data/e8_attestation.json` is gitignored and created by hand,
  so the example must not contain real claims
- `config.example.toml`: an `[e8] attestation_path = "data/e8_attestation.json"`
  key, next to `overrides_path`
- Validation: valid maturity levels are ML1 to ML3; entries are keyed by the
  exact strategy names in `data/asd_framework.json`; an invalid level, an unknown
  strategy name or a malformed file is skipped with a warning and never stops a
  run
- Tests for each change

Out of scope:
- `ravensight/reporter.py` and `main.py`
- A date field on entries
- Per-maturity-level entries
- Any change to how findings are matched to controls
- Any change to `.gitignore`. Its existing rules already ignore
  `data/e8_attestation.json` and allow `data/defaults/*.json`
- `config.toml`

#### Session 2 — Show attestation in the report

In scope:
- `main.py`: pass the attestation result to `Reporter.generate`
- `main.py` reads `[e8] attestation_path` and calls the loader from Session 1
- A strategy's related findings stay listed under its Attested or Not applicable
  status
- `ravensight/reporter.py`: the E8 table shows "Not applicable" strategies with
  their reason, "Attested" strategies with their maturity level and reason, and
  keeps "Not assessed" for strategies with no entry
- The how-to-read note says the status comes from the operator's attestation,
  not from Wazuh
- Tests for each change

Out of scope:
- Any change to `ravensight/e8_scorer.py` loading logic (Session 1)
- The LLM prompt (`analyser._build_asd_context`)
- `scripts/asd_sync.py` and `data/asd_framework.json`
- `config.toml`

Out of scope for the whole section:
- Extra evidence sources, including Wazuh SCA results
- Seeding the real `data/e8_attestation.json` automatically (any change to
  `docker-entrypoint.sh` or the `Dockerfile`)
- A date field on attestation entries
- Per-maturity-level attestation

---

### 16. Docker Support for E8 Attestation

**What it does:**
Section 15 added the operator's Essential Eight attestation file, but Docker users
cannot use it: `config.template.toml` has no `attestation_path`, so the container
never reads the file. This section makes the attestation usable in the Docker
setup, which is the main way people run Ravensight.

**Sessions: 1**

Decisions (agreed with Prin):
- This section is the one allowed exception to the section 15 whole-section
  out-of-scope line on `docker-entrypoint.sh` and seeding. Everything else in
  section 15 stays as written
- The real file is never seeded automatically. A user's attestation is their own
  claim, and a seeded copy would carry the placeholder reasons that the loader
  skips
- Users create the file with an explicit `init-attestation` entrypoint subcommand,
  in the style of `sync`. It copies `/app/defaults/e8_attestation.example.json`
  into the mounted data directory only if `e8_attestation.json` is absent, and
  never overwrites
- Quiet when absent: every Docker user without a file must not get a "file not
  found" warning on each run. The entrypoint passes the path to the config only
  when the file exists, and the loader treats an empty path like "not set"
- The data directory is already a bind mount (`./data:/app/data`), so no
  `docker-compose.yml` volume change is needed

#### Session 1 — Wire attestation into the Docker setup

In scope:
- `config.template.toml`: an `[e8] attestation_path` key built from
  `RAVENSIGHT_DATA_DIR`, empty when the file does not exist
- `docker-entrypoint.sh`: the existence check for the path, and the
  `init-attestation` subcommand (copy-if-absent, run as the dropped user via
  `run_as`, file owned by PUID:PGID)
- `ravensight/e8_scorer.py`: `load_attestation()` treats an empty or unset path as
  "not set" without a warning
- `.env.example` and `README.md`: how to create the file in the mounted data
  directory with `init-attestation`, edit it, and where it is read from
- Docker `overwrite` setting (added at Prin's request): `config.template.toml`
  `[reports] overwrite = ${RAVENSIGHT_REPORTS_OVERWRITE}`, a default of `false` in
  `docker-entrypoint.sh`, and a row in `.env.example` and `README.md`. The value
  must stay a TOML bare `true` or `false`
- README and docs refresh (added at Prin's request): `README.md` and any file under
  `docs/` other than the roadmap that still describes the old report file name
  (`reports/<date>_security_report.md`), the `reports/trending_<date>.md` file, or
  "ML1 to ML4", corrected to match the code
- Tests for the Python change. Entrypoint behaviour is checked by running the
  script's logic in review, as no entrypoint unit tests exist (logged as deferred
  in the "Container non-root + seeding fix" row)

Out of scope:
- Seeding the real `data/e8_attestation.json` automatically, on any start
- The `Dockerfile` (the example already ships in `/app/defaults/`) and
  `docker-compose.yml`
- Any change to how the attestation is validated or shown in the report
- A new environment variable beyond what the template needs and
  `RAVENSIGHT_REPORTS_OVERWRITE`
- `config.toml`

### 17. Structured JSON Report Output

**What it does:**
Alongside the markdown report, Ravensight writes a machine-readable JSON file
holding the same findings, evidence, controls and trends. It is the first step
towards a future read-only web UI, which Prin wants to think about later and is
not urgent. The JSON file gives any later viewer a stable data source, so a UI
never has to parse markdown.

**Sessions: 2 so far. Later sessions are added here before they start.**

Decisions (agreed with Prin):
- The markdown report stays the primary output and is unchanged. The JSON file is
  an extra, written next to it with the same base name and a `.json` extension
- The JSON is built from the same data the reporter already receives
  (`analysis`, trends, ASD data, E8 scores, matched controls, finding pointers
  and attestation), never by parsing the rendered markdown
- The file carries a `schema_version` field so a future viewer can detect changes
- No new network service and no new dependency (standard library `json` only)
- Session 1 carries trends as the rendered markdown string (key `trends_markdown`,
  `null` when absent), because the reporter receives trends as text. Structured
  trends are a later session

#### Session 1 — Define and write the JSON

In scope:
- `ravensight/reporter.py`: a new method on `Reporter` that builds a plain dict
  and writes it as UTF-8 JSON beside the markdown report; `generate()` calls it
  after the markdown file is written and still returns the markdown path
- The dict holds: `schema_version`, generation time (UTC), the run window and
  filters (hours, agent, level), the findings (id, severity, recommendation, narrative, hosts,
  times, evidence, CVEs, notes), trends, E8 status per strategy, per-finding
  control pointers, and attestation when present
- A short description of the schema in `README.md`
- Tests: valid JSON, expected keys, `schema_version`, and a markdown report that is
  byte-identical with and without the JSON feature

Out of scope:
- `ravensight/analyser.py`, `ravensight/evidence.py` and prompt changes
- Any change to the markdown wording or layout
- `config.toml`

#### Session 2 — Config switch and wiring

In scope:
- `config.example.toml` and `config.template.toml`: a `[reports] json_output`
  boolean (default `true`), plus the matching Docker entrypoint export if the
  template needs one
- `docker-entrypoint.sh`: the variable `RAVENSIGHT_REPORTS_JSON_OUTPUT` with a default
  of `true`, and a check that it is exactly `true` or `false`, the same way
  `RAVENSIGHT_REPORTS_OVERWRITE` is handled
- `main.py`: pass the setting to `Reporter` (it already receives the whole
  `[reports]` section, so this needs no change if that stays true), and pass the run
  parameters (hours, agent, level) to `generate()` in the full run only
- `ravensight/reporter.py`: `Reporter.__init__` reads `[reports] json_output`
  (default `true`, a bool, otherwise `ValueError`, as for `overwrite`), and
  `generate()` skips the JSON write when it is `false`. The markdown output is
  unchanged
- `ravensight/config_check.py`: a light type check for the new key, run in both
  normal and report-only mode
- `README.md` and `.env.example`: document the `json_output` switch
  (`RAVENSIGHT_REPORTS_JSON_OUTPUT`) and the `run` key now being filled
- Tests for each change

Decisions (agreed with Prin):
- Report-only runs have no run window, so their JSON keeps `run` as `null`
- With `json_output = false` in overwrite mode, an older same-day `.json` stays
  beside the new markdown and no warning is logged. This is accepted and documented
  in the README. Deleting files is not part of this session

Out of scope:
- The web UI itself, in any form (server, pages, routes, static files)
- Authentication or access control
- Charts and any graphical output
- Writing to a database or an external service
- Reading old reports back, or converting existing markdown reports to JSON
- `config.toml`

Out of scope for the whole section:
- The web UI itself, authentication and charts
- Any change to the markdown report content
- Any change to the LLM prompt or analysis logic

Known limitations after Session 1 (to improve in a later session, not yet planned):
- Trends are carried as the rendered markdown string (`trends_markdown`), not as
  structured data. Structured trends need `ravensight/trending.py` and `main.py`
- `run` (hours, agent, level) is `null` in real runs until Session 2 wires `main.py`
- In overwrite mode, if the JSON write fails on a same-day rerun, the previous
  run's `.json` stays beside the new markdown, and the only sign is a warning.
  A later viewer could read stale data
- Blank unattached findings are dropped from the JSON, as they are in the markdown,
  which loses a little data from a machine-readable file
- If the temporary `.json.tmp` file cannot be deleted during failure cleanup, the
  `OSError` escapes `generate()` after the markdown is already written
- A non-iterable `hosts`, `flags`, `notes` or `cves` value (malformed data) makes
  the whole JSON be skipped with a warning, and a string value is split into
  characters
- `json.dumps` keeps its default `allow_nan=True`, so a NaN or infinity value
  would be written as `NaN` or `Infinity`, which is not strictly valid JSON
- The `reporter.py` module and `Reporter` class docstrings still describe
  markdown only
- The Docker image, entrypoint and compose files were not checked for the new
  `.json` files, and the feature has not been run in a container

### 18. Wazuh Indexer Connection Mode Log Line

**What it does:**
Ravensight tells the operator, at startup, how it is configured to connect to
the Wazuh Indexer, so people can see which TLS mode they are using. It reports
the configured mode only, never a negotiated protocol or handshake result.

**Sessions: 1**

#### Session 1 — One INFO line in Client.__init__

In scope:
- `ravensight/wazuh_client.py`: `Client.__init__`, after `indexer_verify` is
  resolved, logs one INFO line with host, port and the configured mode: CA file
  path, bundled public CA list, or encrypted but not verified
  (`indexer_verify_tls = false`)
- `tests/test_wazuh_client.py`: caplog tests for each mode, and one test that a
  distinctive test user and password never appear in the logs

Out of scope:
- Any change to verify behaviour, `fetch_alerts` or the hard-coded `https://` URL
- Any new config key, `ravensight/config_check.py`, `main.py`, `README.md` and
  `.env.example`
- Reporting a negotiated TLS version or cipher
- `config.toml` and `config.example.toml`

### 19. Unify the Settings Files

**What it does:**
Ravensight keeps its settings in two parallel sets of files, one for host runs and one
for Docker. Prin wants the project as simple as it can be, with one place to change a
setting, because two places are confusing and error-prone. This section first decides
how to unify them, then builds it. No design is chosen yet.

**Sessions: 3. Session 1 (the decision) is done. Sessions 2 and 3 build it.**

How settings work today (checked in the repository):
- Host runs read `config.toml` through `main.py` (`--config`, default `config.toml`
  and `tomllib`). Prin copies `config.example.toml` to `config.toml` by hand. Its
  values are literal placeholders such as `YOUR_WAZUH_HOST`, with long comments
- Docker runs read `.env` through `env_file` in `docker-compose.yml`. At start,
  `docker-entrypoint.sh` fills `config.template.toml` (values such as
  `${LLM_MAX_TOKENS}`) with `string.Template.substitute`, and writes the result as
  the container's `config.toml`. A host `config.toml` is never mounted or used in
  Docker
- The entrypoint also holds the defaults for optional variables, the list of
  required variables and the exact `true` or `false` checks. `.env.example` lists the
  variables
- A new setting therefore has to be added in up to five places: `config.example.toml`,
  `config.template.toml`, `docker-entrypoint.sh`, `.env.example`, and the README. Edits
  made in the wrong file have no effect (for example, `max_tokens` set in `config.toml`
  does nothing for a Docker run)
- The two TOML files have already drifted in their comments. No test checks that they
  list the same keys (a search of `tests/` finds no reference to either file)
- `main.py` and `ravensight/config_check.py` messages say "config.toml (or .env with
  Docker)", so users are told about both

Options to decide in Session 1 (none chosen):
- A. One TOML file for both. Docker mounts the operator's `config.toml` and the
  template, the variable substitution and most of the `.env` variables are removed.
  Needs relative data and report paths to work inside the container (to be verified
  against the Dockerfile working directory), and a rule for the Chroma host name
- B. Environment variables as the single source for both host and Docker. The code reads
  environment overrides over built-in defaults. Larger code change
- C. Keep two files but remove the chance of drift: generate one from the other, or
  add a test that both list the same keys. Smallest change, but two places remain
- Sequencing: section 17 Session 2 was built first (commit `2fc9301`), then this
  section

Decision (agreed with Prin): Option A. One `config.toml` holds every Ravensight
setting for host and Docker runs. Docker mounts it read-only and `.env` keeps only
variables that configure Docker itself (`RAVENSIGHT_PUID`, `RAVENSIGHT_PGID`, `TZ`,
the host mount paths and the Chroma port). A missing `config.toml` stops the
container with a clear message that points at `config.example.toml`.

Decision (agreed with Prin): ChromaDB comes from the Ravensight bundle to keep things
simple at this stage. `chroma_host` is `chroma` (port 8000) for the bundled Chroma
service in Docker. Support for a separate or external ChromaDB server is a later item
and is not part of this section.

#### Session 1 — Decide how to unify (no code)

In scope:
- A read-only study of `config.example.toml`, `config.template.toml`, `.env.example`,
  `docker-entrypoint.sh`, `docker-compose.yml`, `Dockerfile`, the settings parts of
  `README.md`, the config loading in `main.py`, and `ravensight/config_check.py`
- A written proposal to Prin: each option with its trade-offs, every file and setting
  it affects, how Prin's existing `.env` and `config.toml` would migrate, and the
  follow-on sessions needed, which are then added to this section for Prin to review
  before any build starts

Out of scope:
- Any edit to code, tests, config examples, `.env.example`, the entrypoint, the
  Dockerfile, compose or the README
- Opening, printing or quoting `config.toml` or `.env` (they hold live credentials)

#### Session 2 — Docker runs from the shared config.toml

In scope:
- `docker-compose.yml`: mount the host `config.toml` read-only at `/app/config.toml`,
  with the host path taken from a variable that defaults to `./config.toml`, like the
  data and reports mounts
- `Dockerfile`: stop copying `config.template.toml`
- `docker-entrypoint.sh`: remove the template substitution, the defaults, required
  checks and true/false checks for Ravensight settings, the export of the attestation
  path, and the `chown` and `chmod` of `config.toml`. Add a check that
  `/app/config.toml` exists, with a clear message pointing at `config.example.toml`.
  Keep the PUID and PGID checks, the ownership repair, the seeding, the syncs and
  `init-attestation`, using the container paths `/app/data` and `/app/reports`
- Delete `config.template.toml`
- `.env.example`: keep only the variables that configure Docker itself, with a note
  that every other setting now lives in `config.toml`
- Tests for any Python change (the entrypoint has no tests)

Out of scope:
- `README.md`, `ravensight/config_check.py` message text and `config.example.toml`
  (Session 3)
- Renaming a setting, or any change to how `main.py` reads `config.toml`
- Opening, editing or printing `config.toml` or `.env`

#### Session 3 — Documents, messages and checks

In scope:
- `README.md`: rewrite the configuration and Docker sections for the single file,
  including how to copy `config.example.toml` and the migration from `.env`, that the
  host folders can be changed in `.env` (`RAVENSIGHT_HOST_DATA_PATH`,
  `RAVENSIGHT_HOST_REPORTS_PATH`, `RAVENSIGHT_HOST_CONFIG_PATH`) while the paths inside
  the container are fixed (`/app/data`, `/app/reports`, `/app/config.toml`), that a
  missing host `config.toml` makes Docker create a directory of that name, and that the
  host file must be readable by the uid set in `RAVENSIGHT_PUID`
- `config.example.toml`: comments that say which values to use for Docker and for a
  host run, including `chroma_host` (decided before Session 2) and the relative data
  and report paths
- `ravensight/config_check.py` and `main.py`: change the messages that say
  "config.toml (or .env with Docker)" so they say `config.toml`
- Tests for the changed messages

Out of scope:
- Any change to settings, defaults, validation rules or code paths other than the
  message text
- Opening, editing or printing `config.toml` or `.env`

Out of scope for the whole section:
- Opening, editing or printing `config.toml` or `.env`
- Renaming a setting or changing its meaning or default, unless Prin agrees it in
  Session 1
- Putting credentials in git or in the Docker image
- A new dependency, unless Prin agrees it in Session 1

### 20. ASD Essentials Evidence Report

**What it does:**
On 15 October 2026 ASD launched the ASD Essentials, an evolution of the Essential
Eight. ASD plans to deprecate the Essential Eight in about 12 months and retire it in
about 24, and keeps both live on cyber.gov.au during the transition. This section adds
the Essentials for enterprise IT to the Ravensight report, next to the Essential Eight.
It shows which Essentials principles and actions each finding points at, and shows the
operator's own declared ratings. It does not rate anything itself.

**How the Essentials work (from cyber.gov.au, checked 21 October 2026):**
- Principles are outcomes (ISM-aligned identifiers such as `GOV-01`, `PRO-13`,
  `DET-01`). Actions are what must be done. Domains are where the work applies
- Enterprise IT has two capability domains (governance and culture, visibility and
  response) and six technical domains: boundary services, identity services, critical
  processes and services, privileged environments, business systems and user devices
- The technical matrix maps each action to MITRE ATT&CK technique names
- Each action is rated per applicable domain on four levels: not assessed, not
  effective, partially effective, fully effective. The principle rating is the lowest
  action rating. ASD's phases are an implementation order, not a maturity rating
- Confirmed in Session 0 against ASD's Assessment process guide (pp. 10, 20-24): the
  four ratings, the weakest-link rule (a principle is partially or fully effective only
  once all its applicable actions are assessed), and a domain with nothing assessed
  shown as N/A. The ATT&CK mapping is "a guide rather than a scoring mechanism"; ASD
  suggests comparing observed techniques with mapped actions to set priorities, without
  changing any rating

**Design rule:** evidence-only, as in sections 9, 12 and 15. Ravensight reads alerts,
not configuration, so it cannot derive an effectiveness rating. Findings point at
principles and actions, with the reason. A rating appears only when the operator
declares it in an attestation file, and the report says so. No pass or fail wording,
and no domain percentage.

**Sessions: 7 (Session 0 done). Later phases are added here before they start.
Section 19 Session 3 is built first.**

Decisions (agreed with Prin):
- Enterprise IT chapter only. The OT and cloud chapters are later items
- The Essential Eight section and its data stay as they are until ASD retires it
- A hand-built dataset is acceptable if ASD publishes no machine-readable file. Session
  0 checks first. If a dataset is hand-built, it records the source page and the date
  it was checked
- Attestation is per principle, with an optional list of domains, not per action per
  domain (about 30 entries, not hundreds)
- The report shows ASD's priority phase order for the principles, taken from ASD's
  published guidance, and says plainly that a phase is not a rating
- The report shows the four-level scale only for attested principles. Everything else
  stays "Not assessed"
- Essentials is added alongside the Essential Eight, not as a replacement. Removing the
  Essential Eight is a separate decision for later
- The dataset is Prin's hand-built `essentials_enterprise_it.json` (from ASD's evidence
  guide PDF and assessment workbook), verified on 21 Oct 2026 against the evidence guide,
  the workbook and the chapter PDF. It is tracked in `data/defaults/` because it is
  reference data no script can regenerate, and has a top-level `schema_version`. It is
  an unofficial community dataset, derived from ASD's publications under CC BY 4.0,
  "© Commonwealth of Australia 2026"; its `source` block keeps the copyright line, the
  licence name and link, the change note and the unofficial/not-endorsed notice
- Each technical action keeps two technique lists: `mitre_technique_names` from the
  evidence guide and `mitre_technique_names_chapter` from the chapter. Matching uses both.
  Where ASD's documents word an action differently, `action_text_chapter` records the
  chapter's wording
- The ASD source documents are not kept in this repo, in any commit or in any post. The
  PDFs carry the Coat of Arms and ASD logos, which CC BY 4.0 does not cover, and the
  workbook carries no licence notice. Re-verify against the official publications at
  cyber.gov.au
- ASD's ATT&CK mapping is a guide for setting priorities, not a rating. Ravensight never
  rates or assesses compliance itself

#### Session 0 — Research and confirm (no code), done 21 Oct 2026

In scope:
- A read-only study of ASD's Essentials for enterprise IT, the Assessment process
  guide and the Implementation planning guide on cyber.gov.au
- Whether ASD publishes the principles and actions in a machine-readable form
  (OSCAL, JSON or a workbook), and whether the ISM catalogue now carries the
  Essentials principle identifiers
- Whether the Wazuh alerts Ravensight reads carry MITRE fields (for example
  `rule.mitre.id`), by reading `ravensight/wazuh_client.py` and the evidence code
- The exact rating names, rating rules and priority phase names
- A written proposal to Prin that confirms or changes Sessions 1 to 5 below

Out of scope:
- Any edit to code, tests, config examples, the entrypoint, the Dockerfile or the README
- Opening, printing or quoting `config.toml` or `.env`

Result: ASD publishes no machine-readable Essentials file (the ISM OSCAL catalogue
predates the launch). Wazuh alerts carry `rule.mitre.id` (seen in Prin's dashboard), but
nothing in Ravensight reads it yet. Prin built the dataset instead; see the decisions
above.

#### Session 1 — Dataset and loader

In scope:
- `data/defaults/essentials_enterprise_it.json` (new, tracked): Prin's verified dataset
  (58 actions, 28 principles, 8 domains, 212 domain/action pairs, 529 IGP statements),
  with a top-level `schema_version` of 1 added and no other content change
- `ravensight/essentials_scorer.py` (new): a loader that returns the data, or an empty
  result with a warning when the file is missing, unreadable, not UTF-8, not JSON or
  fails validation, never stopping a run (the conventions of `analyser._load_asd_data`).
  Validation: required keys and types, `schema_version`, action id pattern and
  uniqueness, every action domain present in `domains`, ISM ids in `ISM-NNNN` form
- `config.example.toml`: an `[essentials]` section with
  `path = "data/defaults/essentials_enterprise_it.json"`
- Tests: each loader failure path, each validation rule, and a test that the committed
  file loads with the expected counts

Out of scope:
- `main.py`, `ravensight/reporter.py`, `ravensight/analyser.py` and the LLM prompt
- Docker and the README (Session 6)
- Any dataset content change other than adding `schema_version`
- `data/asd_framework.json` and the Essential Eight data
- `config.toml`

#### Session 2 — Carry MITRE technique ids onto clusters

In scope:
- `ravensight/analyser.py` (and `ravensight/evidence.py` if the plan shows it is the
  better place): collect the `rule.mitre.id` values of a cluster's raw alerts into a new
  cluster field (for example `mitre_ids`, sorted and without duplicates). Alerts without
  the field add nothing
- The field reaches findings through `_parse_analysis`, as other cluster fields do
- Tests, including that the LLM prompt text is unchanged and that `_fidelity_flags`
  behaves as before

Out of scope:
- Any LLM prompt change
- `ravensight/reporter.py`, the markdown report and the JSON report
- `cluster_key()`, baseline and embedding text
- `config.toml`

#### Session 3 — Finding pointers

In scope:
- `ravensight/essentials_scorer.py`: a per-finding result listing the actions a finding
  points at (with principle, domains and priority phase), each with its reason:
  - MITRE: the finding's `mitre_ids` resolved to ATT&CK names through
    `data/mitre_attack.json`, a sub-technique also counting as its parent, matched
    case-insensitively against both technique lists
  - ISM: the finding's ISM pointers (from `e8_scorer.map_findings_to_controls`)
    matched against each action's `ism_excl_e8` and `e8_ism`
  - Keyword matching as a last-resort fallback, as in `ravensight/e8_scorer.py`
- No second LLM call; the module receives its data as arguments
- Tests for each route

Out of scope:
- Any change to `ravensight/e8_scorer.py`
- Any rating
- `main.py`, `ravensight/reporter.py` and the LLM prompt
- `config.toml`

#### Session 4 — Attestation

In scope:
- `ravensight/essentials_scorer.py`: a loader for `data/essentials_attestation.json`.
  Each entry is keyed by principle identifier and is either "Not applicable" or one
  of the four ratings, with a free-text reason and an optional list of domains
- Invalid entries, unknown identifiers and a malformed file are skipped with a
  warning and never stop a run; example placeholder reasons are skipped, as in section 15
- `data/defaults/essentials_attestation.example.json`: a tracked example with no real
  claims. The real file is gitignored and created by hand
- `config.example.toml`: an `attestation_path` key in `[essentials]`
- Tests for each change

Out of scope:
- A date field, per-action or per-domain ratings, and any derived rating
- Seeding the real file automatically
- `ravensight/reporter.py` and `main.py`
- `config.toml`

#### Session 5 — Report and JSON

In scope:
- `main.py`: read the `[essentials]` section, load the dataset, build the finding
  pointers and attestation, and pass the results to `Reporter.generate`
- The how-to-read note also says that the ATT&CK mapping is a guide for setting
  priorities, not a rating, and that an attested rating is the operator's own
  declaration per principle (a simplification of ASD's per-action, per-domain rating),
  not an ASD assessment
- The report and the JSON carry the attribution "© Commonwealth of Australia 2026,
  CC BY 4.0" wherever Essentials data is shown
- `ravensight/reporter.py`: an "ASD Essentials" section with a "Findings and related
  principles" table, ASD's phase order, and attested ratings with their reasons.
  "Not assessed" stays the default. The how-to-read note says ratings come from the
  operator's attestation, not from Wazuh
- The JSON report gains an Essentials key and a bumped `schema_version`
- The glossary gains the new terms
- Tests for each change, including a markdown report that is byte-identical when
  Essentials data is absent

Out of scope:
- The Essential Eight section, apart from keeping it in place
- The LLM prompt
- `config.toml`

#### Session 6 — Docker and documents

In scope:
- `docker-entrypoint.sh`: an `init-essentials-attestation` subcommand (copy if absent,
  never overwrite, run as the dropped user), and how the dataset is found when
  `RAVENSIGHT_HOST_DATA_PATH` is not the repository's `data/` folder (for example
  seeding it from `/app/defaults/`, as for `platform_hints.json`)
- `README.md` and `.env.example` if a Docker-only setting changes: the dataset and its
  attribution, how to create and edit the attestation file, and a note on the Essential
  Eight transition timeline
- The entrypoint has no tests, so its behaviour is checked in review (logged as deferred)

Out of scope:
- Seeding the real attestation file automatically
- Any change to how findings are matched or shown
- `config.toml`

Out of scope for the whole section:
- Retiring or changing the Essential Eight section or data
- The OT and cloud chapters
- Computing domain percentages or any rating Ravensight derives itself
- Any LLM prompt change
- Changing the dataset content, except a fix verified against the ASD source files
- A web UI
- Opening, editing or printing `config.toml` or `.env`

## Suggested Build Order

1. ~~Historical Trending~~ — Complete ✅
2. ~~MITRE ATT&CK Tagging~~ — Complete ✅
3. ~~Multi-Model Routing~~ — Superseded ✅
4. ~~Embedding Model~~ — Complete ✅
5. **Platform-Aware Alert Context** — Queued (2 sessions; low risk; addresses known false positive before adding more features)
6. **Progress Bar + LLM Streaming** — Planned (2 sessions; cosmetic layer; good to have before ASD adds more prompt complexity)
7. **ASD Framework Mapping** — Planned (4 sessions; same pattern as MITRE tagging)

---

## Infrastructure Reference

| Item | Detail |
|------|--------|
| Inference server | yubaba (llama.cpp b9037, OpenAI-compatible API) |
| GPU | RTX 3060 12GB VRAM |
| CPU | Intel i7-1260P, 16GB RAM |
| OS | Ubuntu Server 24.04 LTS, NVIDIA driver 580.159.03, CUDA 13.0 |
| API endpoint (main) | `http://<yubaba-ip>:8080/v1` |
| API endpoint (embeddings) | `http://<yubaba-ip>:8081/v1` |
| Model — analysis | `Qwen3.6-35B-A3B` (~2.8GB VRAM, ~7-8GB RAM experts, ~17 t/s) |
| Model — triage (unused) | `Qwen2.5-Coder` (~5.9GB VRAM) |
| Model — embeddings | `Qwen3-Embedding-0.6B` (~0.5GB VRAM) |
| Model — coding (local, unused by Claude Code) | `Qwen3.5-9B` (~5.5GB VRAM, ~42 t/s) |
| Router mode | Enabled in llama.cpp via `model.ini` |
| MoE offload | `cpu-moe = true` for Qwen3.6-35B and Gemma4-26B |
| Vector store | ChromaDB (local SQLite backend) |

---

*Created: 2026-05-01 — last updated: 2026-05-11*