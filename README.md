<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/ravensight-logo-dark.jpg">
    <source media="(prefers-color-scheme: light)" srcset="docs/ravensight-logo-light-half.jpg">
    <img src="docs/ravensight-logo-dark.jpg" alt="Ravensight logo" width="600">
  </picture>
</p>

# Ravensight — Wazuh Security Log Analyser

A local-first security log analyser that pulls alerts from the Wazuh Indexer (OpenSearch) REST API,
analyses them using a local LLM via llama.cpp, and generates structured
markdown security reports (plus a JSON copy) with baseline memory tracking and historical trending.

> Named for Huginn and Muninn, Odin's ravens — sent out each day to watch the
> world and report back what they see. Ravensight does the same for your logs.

---

## What It Does

- Connects to the **Wazuh Indexer (OpenSearch)** to pull security alerts by time range,
  agent, or severity level
- Analyses alert patterns using a **local LLM via llama.cpp** — no data leaves
  your network
- Generates **markdown security reports** (plus a JSON copy) summarising threats, anomalies, and
  recommended actions
- Maintains a **baseline memory** of normal behaviour so repeated noise is
  distinguished from genuine alerts
- Tracks **historical alert trends** per rule group — surfaces slow-burn threats
  that single-run baseline comparison misses
- Tags findings against **MITRE ATT&CK** and the **ASD Essential Eight / ISM**
  for Australian-aligned reporting; Essential Eight strategies are Not assessed
  unless you supply an attestation file, in which case they can be Attested or
  Not applicable, shown with related ISM controls
- Retrieves **similar past incidents** via a local ChromaDB vector store for
  semantic context
- Runs on a local homelab — designed for self-hosted Wazuh deployments

---

## Architecture

```
main.py               # Entry point — CLI and orchestration
ravensight/
├── wazuh_client.py    # Wazuh Indexer (OpenSearch) REST API client
├── analyser.py        # LLM analysis via llama.cpp OpenAI-compatible API
├── reporter.py        # Markdown report generation plus a JSON copy
├── baseline.py        # Baseline memory persistence (JSON store)
├── trending.py        # Historical trend analysis and anomaly detection
├── embedder.py        # ChromaDB vector store and embedding client
└── e8_scorer.py       # Essential Eight related-control scoring + ISM control matching
scripts/
├── mitre_sync.py      # MITRE ATT&CK dataset sync
└── asd_sync.py        # ASD Essential Eight / ISM dataset sync
```

---

## Prerequisites

Read this first — first-time users tend to hit missing-dependency gaps here,
not in the setup steps below.

### Hard requirements (the tool cannot run without these)

- **A reachable Wazuh deployment (4.x or later):**
  - Wazuh Indexer (OpenSearch) REST API on TCP/9200 — the actual alert store
  - If the Indexer binds to localhost only, set `network.host: 0.0.0.0` in
    `/etc/wazuh-indexer/opensearch.yml` and restart the indexer service
- **A reachable OpenAI-compatible LLM inference endpoint** — llama.cpp (or
  any `/v1/chat/completions`-compatible server) is fine; the `api_key` field
  is not validated.

### Depending on how you run Ravensight

**Docker (recommended):**

- **Docker + Docker Compose V2** — the image bundles its own Python and
  dependencies, so nothing else needs installing on the host. Compose V2
  (profile support) is needed if you want the bundled ChromaDB server,
  which lives behind the `chroma` profile (see [Docker](#docker)). Plain
  `docker compose up`/`down` will not start it.

**Local / development:**

- **Python 3.11, 3.12, or 3.13** — `chromadb==1.5.9` (pinned in
  `requirements.txt`) does not yet support Python 3.14+. If your system
  Python is newer, `uv` can install a supported version for the virtual
  environment (see [Local / development setup](#local--development-setup)).
- **[uv](https://docs.astral.sh/uv/)** (recommended) — manages the virtual
  environment and runs Ravensight inside it without any activation step,
  so the same commands work in every shell. Plain `pip` + `venv` also works.

### Optional (the tool runs correctly without these)

- **Embedding model server** plus a populated `[embeddings]` section in
  `config.toml` enables semantic "Similar Past Incidents" retrieval via
  ChromaDB. Without it, Ravensight only constructs an embedder when the
  `[embeddings]` section is present in the config — the rest of the
  pipeline runs unchanged.
- Embeddings are optional in Docker too, and are configured by the
  `[embeddings]` section of `config.toml`.

### Python packages

Installed automatically by `uv pip install -r requirements.txt` (or
`pip install -r requirements.txt`): `requests`, `openai`,
`chromadb==1.5.9`, `rich`, `httpx`. See `requirements.txt` for exact pins.

---

## Setup

### 1. Clone the repo

```bash
git clone git@github.com:sli3/Ravensight.git
cd Ravensight
```

### 2. Choose how to run Ravensight

- **[Docker](#docker) (recommended)** — single container by default, or with
  Docker Compose and the optional bundled ChromaDB server
- **Local / development** — run Ravensight directly on the host, e.g. if
  you are developing or testing changes; continue with the steps below.
  The [Docker](#docker) section also covers a hybrid setup (host app plus
  Docker-hosted ChromaDB)

---

### Local / development setup

#### 1. Create a virtual environment

```bash
uv venv --python 3.11
uv pip install -r requirements.txt
```

No activation step is needed — `uv` finds the project's `.venv`
automatically, so these commands work the same in bash, zsh, fish or any
other shell.

Or with standard venv:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

#### 2. Configure

Copy the example config and fill in your values:

```bash
cp config.example.toml config.toml
```

The Wazuh manager API login is no longer used, so old `wazuh.port`, `wazuh.user` and `wazuh.password` entries (and `WAZUH_API_USER`, `WAZUH_API_PASSWORD` and `WAZUH_PORT` in Docker) can be deleted but are harmless.

| Key | Description |
|-----|-------------|
| `wazuh.host` | Your Wazuh hostname or IP, used as the default Indexer host |
| `wazuh.indexer_host` | Wazuh Indexer (OpenSearch) IP — defaults to `wazuh.host` when unset |
| `wazuh.indexer_port` | Indexer port (default: 9200) |
| `wazuh.indexer_user` | Indexer username (default: admin) |
| `wazuh.indexer_password` | Indexer password |
| `wazuh.indexer_verify_tls` | Optional. `true` verifies the Indexer TLS certificate; default `false` (no verification) |
| `wazuh.indexer_ca_path` | Optional path to a CA certificate (or folder) used to verify the Indexer; default empty. A set path wins over `indexer_verify_tls = false`. Verification also checks the hostname, so a self-signed certificate must include the `indexer_host` name or IP in its SAN or the request fails with an SSL error (logged as "Failed to connect to Wazuh Indexer") |
| `llm.base_url` | llama.cpp server URL (e.g. `http://yubaba:8080/v1`) |
| `llm.model` | Model ID served by llama.cpp — whatever your server exposes (e.g. `Ornith-1.5-9B`) |
| `llm.api_key` | Any string — llama.cpp does not validate |
| `reports.output_dir` | Where to write markdown reports |
| `reports.overwrite` | `false` (default) writes `reports/<date>/security_report_<time>.md` so reruns never overwrite; `true` writes `reports/<date>_security_report.md` and overwrites the same-day file |
| `reports.json_output` | `true` (default) writes a JSON copy of each report beside the markdown; `false` writes markdown only. Must be exactly `true` or `false` |
| `e8.overrides_path` | Essential Eight keyword blocklist. Default: `data/e8_keyword_overrides.json` |
| `e8.attestation_path` | Optional manual Essential Eight attestations. Copy `data/defaults/e8_attestation.example.json` to `data/e8_attestation.json` |
| `essentials.path` | ASD Essentials dataset (reference data, do not edit). Value in `config.example.toml`: `data/defaults/essentials_enterprise_it.json` (not built into the code). Docker needs a different value, see [Docker](#2-configure-1) |
| `essentials.attestation_path` | Optional manual Essentials attestations. Value in `config.example.toml`: `data/essentials_attestation.json` (not built into the code). Copy `data/defaults/essentials_attestation.example.json` to start |
| `baseline.path` | Path to the baseline JSON file |
| `platform.agents_path` | Optional map from Wazuh agent name to vendor/platform so reports name the right product. Default: `data/platform_agents.json` |

#### Embedding Model Configuration

Ravensight uses a separate embedding model server for semantic retrieval:

| Key | Description | Example |
|-----|-------------|---------|
| `embeddings.endpoint` | URL of the embedding model server | `http://yubaba:8081/v1` |
| `embeddings.model` | Model ID served by the embedding server | `Qwen3-Embedding-0.6B` |
| `embeddings.chroma_db_path` | Path to ChromaDB vector store (embedded mode only — ignored if `chroma_host` is set) | `data/chroma/embedded` |
| `embeddings.chroma_host` | ChromaDB server hostname — set this to switch from embedded mode to a networked Chroma server. See [Bundled ChromaDB server](#bundled-chromadb-server-docker-compose---profile-chroma) | `localhost` |
| `embeddings.chroma_port` | ChromaDB server port (only used if `chroma_host` is set; default `8000`) | `8000` |
| `embeddings.top_k` | Number of similar incidents to retrieve | `5` |

> **Note:** The Wazuh Indexer must be accessible on port 9200 from the machine
> running Ravensight. If your indexer is bound to localhost only, update
> `network.host` in `/etc/wazuh-indexer/opensearch.yml` to `0.0.0.0` and
> restart the indexer service.

#### 3. Run

```bash
uv run python3 main.py --hours 24
```

If you used standard venv instead of `uv`, call the virtual environment's
Python directly:

```bash
.venv/bin/python3 main.py --hours 24
```

---

## Docker

Docker is the recommended way to run Ravensight. The image bundles its own
Python and dependencies, so there is no virtual environment to manage. This
is an alternative to the local setup above — you don't need both.

### 1. Build the image

```bash
docker build -t ravensight .
```

### 2. Configure

Docker uses the same `config.toml` as a host run, mounted read-only into the
container at `/app/config.toml`.

1. Copy the example and fill it in. The keys are the same as in the
   [Local / development setup](#2-configure) table:

   ```bash
   cp config.example.toml config.toml
   ```

   Wazuh and LLM hosts must be reachable from inside the container, so use real
   hostnames or IPs, not `localhost`. Leave the relative paths (`data/...`,
   `reports`) as written: the container runs from `/app`.

   The one exception is `essentials.path`. Docker users must set
   `path = "defaults/essentials_enterprise_it.json"` in the `[essentials]`
   section, because the image holds the dataset at `/app/defaults/`. The host
   default `data/defaults/essentials_enterprise_it.json` would resolve to
   `/app/data/defaults/...`, which does not exist, and the Essentials section
   would be missing from the report (the log would show an "Essentials
   dataset not found" warning). `attestation_path = "data/essentials_attestation.json"`
   works unchanged, because `/app/data` is the mounted data folder.

2. Copy `.env.example` to `.env` for the Docker-only settings:

   ```bash
   cp .env.example .env
   ```

   `.env` holds `RAVENSIGHT_PUID`, `RAVENSIGHT_PGID`, `TZ`, the host path
   variables (`RAVENSIGHT_HOST_DATA_PATH`, `RAVENSIGHT_HOST_REPORTS_PATH`,
   `RAVENSIGHT_HOST_CONFIG_PATH`, `RAVENSIGHT_HOST_CHROMA_PATH`) and
   `RAVENSIGHT_CHROMA_PORT`. Defaults are documented in `.env.example`.

The host folders can be changed with `RAVENSIGHT_HOST_DATA_PATH`,
`RAVENSIGHT_HOST_REPORTS_PATH` and `RAVENSIGHT_HOST_CONFIG_PATH`, but the paths
inside the container are fixed: `/app/data`, `/app/reports` and
`/app/config.toml`.

If the host `config.toml` is missing, Docker creates a directory of that name
and the container then stops with a clear message. Delete the directory and
create the real file. The host file must be readable by the uid in
`RAVENSIGHT_PUID`.

**Migrating from the old `.env` settings.** The old Docker variables are no
longer read. Set the matching key in `config.toml` instead:

| Old variable | `config.toml` key |
|--------------|-------------------|
| `WAZUH_HOST` | `wazuh.host` |
| `WAZUH_INDEXER_HOST` | `wazuh.indexer_host` |
| `WAZUH_INDEXER_PORT` | `wazuh.indexer_port` |
| `WAZUH_INDEXER_USER` | `wazuh.indexer_user` |
| `WAZUH_INDEXER_PASSWORD` | `wazuh.indexer_password` |
| `WAZUH_INDEXER_VERIFY_TLS` | `wazuh.indexer_verify_tls` |
| `WAZUH_INDEXER_CA_PATH` | `wazuh.indexer_ca_path` |
| `LLM_BASE_URL` | `llm.base_url` |
| `LLM_MODEL` | `llm.model` |
| `LLM_API_KEY` | `llm.api_key` |
| `LLM_TEMPERATURE` | `llm.temperature` |
| `LLM_MAX_TOKENS` | `llm.max_tokens` |
| `EMBEDDINGS_ENDPOINT` | `embeddings.endpoint` |
| `EMBEDDINGS_MODEL` | `embeddings.model` |
| `EMBEDDINGS_TOP_K` | `embeddings.top_k` |
| `EMBEDDINGS_CHROMA_HOST` | `embeddings.chroma_host` |
| `EMBEDDINGS_CHROMA_PORT` | `embeddings.chroma_port` |
| `TRENDING_WINDOW_DAYS` | `trending.window_days` |
| `TRENDING_MAX_ROWS` | `trending.max_rows` |
| `RAVENSIGHT_REPORTS_OVERWRITE` | `reports.overwrite` |
| `RAVENSIGHT_REPORTS_JSON_OUTPUT` | `reports.json_output` |

`RAVENSIGHT_DATA_DIR` and `RAVENSIGHT_REPORTS_DIR` no longer exist: the
container paths are fixed. A variable left in `.env` is ignored and harmless.

**Time zone (optional).** The container runs in UTC unless you set `TZ` in
`.env` to your IANA time zone name (e.g. `TZ=Australia/Adelaide`). Set it to
match any host-side runs so Docker and host-side runs agree on the local day
used by Trends, report folders and file names, and the "Generated" time.
Recreate the container after setting it (`docker compose run` creates a new one
each time). Set it once and leave it: changing it later makes old history
entries read as the new local time, and an empty `TZ=` stays UTC. On days that
had both host and container runs before `TZ` was set, Trends may show a stale
"Latest" for that day only, which corrects itself on the next run.

### 3. Run

```bash
docker run \
  --env-file .env \
  -v ./config.toml:/app/config.toml:ro \
  -v ./data:/app/data \
  -v ./reports:/app/reports \
  ravensight
```

On first start, if `data/mitre_attack.json` or `data/asd_framework.json` are
missing, the container automatically runs the corresponding sync script before
the main analysis — the same one-time sync described in the ASD/MITRE sections
below. Subsequent starts skip the sync unless those files are deleted.

A default `e8_keyword_overrides.json` and `platform_hints.json` are seeded into
the mounted `data/` volume on first start if you haven't provided your own —
edit them directly in your mounted `data/` folder afterwards; the container
never overwrites an existing file there.

To map Wazuh agent names to their actual vendor and platform (so reports name
the right product even when a rule description says something different), create
`data/platform_agents.json` in your mounted data folder by copying
`data/defaults/platform_agents.example.json`. This file is optional, never
seeded by the container, and not required for Ravensight to run.

To record manual Essential Eight attestations, create `data/e8_attestation.json`
from the bundled example:

```bash
docker run --env-file .env -v ./data:/app/data ravensight init-attestation
# or, with Compose
docker compose run --rm ravensight init-attestation
```

This never overwrites an existing file and does not run a sync. Edit
`data/e8_attestation.json` and remove the `EXAMPLE:` prefixes; it is picked up on
the next start. Until you edit it, one warning per placeholder entry appears on
each run.

To record manual ASD Essentials declarations, create
`data/essentials_attestation.json` from the bundled example (see
[ASD Essentials](#asd-essentials-in-the-report)):

```bash
docker run --env-file .env -v ./data:/app/data ravensight init-essentials-attestation
# or, with Compose
docker compose run --rm ravensight init-essentials-attestation
```

This never overwrites an existing file and does not run a sync. Edit
`data/essentials_attestation.json` and remove the `EXAMPLE:` prefixes; it is
picked up on the next start. Until you edit it, one warning per placeholder
entry appears on each run.

### Forcing a re-sync

MITRE ATT&CK and the ASD ISM are both revised periodically. To force a re-sync
of both reference datasets on demand — without deleting the existing files
first — pass `sync` as the container command:

```bash
docker run --env-file .env -v ./data:/app/data ravensight sync
```

This refreshes both `mitre_attack.json` and `asd_framework.json` regardless of
whether they already exist, then exits.

### Passing extra flags to the analysis run

Anything else after the image name overrides the default command, but still
runs through the same start-up checks:

```bash
docker run --env-file .env -v ./config.toml:/app/config.toml:ro -v ./data:/app/data -v ./reports:/app/reports ravensight \
  python3 main.py --config /app/config.toml --hours 1 --level 12
```

### Bundled ChromaDB server (`docker compose --profile chroma`)

The `chroma` service in `docker-compose.yml` is opt-in via a Compose
profile — it is **not** started by a plain `docker compose up`. Every
command that needs to manage the bundled Chroma container must include
`--profile chroma` explicitly, or the container is silently never created
(no warning):

```bash
# Start Ravensight and the bundled Chroma server together
docker compose --profile chroma up -d

# Inspect / follow logs for just the chroma container
docker compose --profile chroma ps
docker compose --profile chroma logs -f chroma

# Stop and remove everything in the profile
docker compose --profile chroma down
```

To point Ravensight at the bundled server, set in `config.toml`'s
`[embeddings]` section:

```toml
chroma_host = "chroma"
chroma_port = 8000
```

Leave `chroma_host` unset (the default) to keep the single-container
embedded mode — the bundled server is a network-mode switch, not a default.

### Hybrid: host app plus Docker-hosted Chroma

You can run Ravensight on the host (`uv run python3 main.py`, following the
[Local / development setup](#local--development-setup)) while ChromaDB lives
in the bundled Compose container — useful when you want to keep your host's
Python environment but isolate ChromaDB behind a managed server.

```bash
# Start only the chroma container (publishes port 8000 on host loopback)
docker compose --profile chroma up -d chroma
```

Then, in `config.toml`'s `[embeddings]` section, add:

```toml
chroma_host = "localhost"
chroma_port = 8000
```

`chroma_host = "localhost"` is the explicit switch to networked/server mode
— `chroma_db_path` is then ignored. The `chroma` hostname that Compose's
internal DNS provides only resolves from inside the `ravensight` Compose
network; for a host process reaching into the published port, use
`localhost`.

---

## Usage

```
usage: main.py [-h] [--config CONFIG] [--hours N] [--agent AGENT]
                [--level LEVEL] [--log-level LEVEL] [--report-only]
                [--no-progress]

options:
  --config PATH    Path to config file (default: config.toml)
  --hours N        Analyse alerts from the last N hours (default: 24)
  --agent AGENT    Filter to a specific agent name or ID
  --level LEVEL    Minimum alert level to include (default: 7)
  --log-level      Logging verbosity: DEBUG, INFO, WARNING, ERROR, CRITICAL (default: INFO)
  --report-only    Generate report from last baseline without re-querying Wazuh
  --no-progress    Plain output: no live panel or colours (e.g. for cron or log redirection)
```

In a terminal, Ravensight shows a live status panel and a finish summary on
stderr; with `--no-progress`, in pipes, under cron or in docker logs, you get
plain log lines instead.

### Example output

```
2026-09-22 06:39:00 - INFO - Fetched 9984 alerts from Wazuh Indexer
2026-09-22 06:39:00 - INFO - Updated baseline with 2 findings
2026-09-22 06:39:01 - INFO - Report written to reports/2026-09-22/security_report_06-39-01.md
```

---

## Reports

Reports are saved to the `reports/` directory as markdown files, each with a
JSON copy beside it (see [JSON report](#json-report)). By default each
run writes `reports/<YYYY-MM-DD>/security_report_<HH-MM-SS>.md`, so reruns never
overwrite. With `[reports] overwrite = true` the file is
`reports/<YYYY-MM-DD>_security_report.md` and is overwritten on the same day.
Each report contains, in order:

- **Summary** — overall threat posture for the period
- **Findings** — LLM-identified threats and patterns grouped by rule group
- **Similar Past Incidents** — related historical findings retrieved via the
  ChromaDB vector store
- **MITRE ATT&CK Tags** — tactics and techniques mapped to the period's findings
- **Historical Trends** — slow-burn anomalies flagged across recent runs
- **Recommendations** — LLM-generated response suggestions

### JSON report

Each run also writes a machine-readable JSON file with the same name as the
markdown report and a `.json` suffix, for example
`reports/<YYYY-MM-DD>/security_report_<HH-MM-SS>.json`, or
`reports/<YYYY-MM-DD>_security_report.json` with `overwrite = true`. It is UTF-8
and carries `"schema_version": 2`. Top-level keys:

- `schema_version` — integer, currently `2`
- `generated_at` — generation time in UTC (ISO 8601)
- `run` — run window and filters: `hours`, `agent` and `level` in a full run, and
  `null` in a `--report-only` run
- `findings` — a list; each item has a `type`. Clusters and vulnerabilities carry
  `id`, `severity`, `description`, `count`, `hosts`, `first_seen`, `last_seen`,
  `narrative`, `flags`, `evidence`, `notes`, `cves` and `recommendation`. LLM notes
  not linked to alert data have `type` `"unattached"` with `description` and
  `recommendation`. Plain-text findings from older baselines are
  `{"type": "legacy", "text": ...}`
- `trends_markdown` — the Historical Trends section as a markdown string (not
  structured data), or `null`
- `e8_status` — Essential Eight strategies with their status and related findings and
  controls, or `null`
- `finding_pointers` — per-finding Essential Eight and ISM control pointers, or `null`
- `matched_controls` — matched ISM controls, or `null`
- `attestation` — your Essential Eight attestation; the key is omitted when there is none
- `essentials` — always present; `null` when there is no Essentials data. When
  present its keys are `attribution`, `licence`, `notice`,
  `dataset_schema_version` (the dataset file's own version, currently `1`, not the
  report's `schema_version`), `finding_actions` (a list) and `attestation` (an
  object keyed by principle id, each entry with `status`, `reason` and
  `domains`). `essentials.attestation` is separate from the top-level Essential
  Eight `attestation` key

`severity` and `recommendation` hold what the markdown shows. The summary, MITRE
ATT&CK tags and similar past incidents are not in the JSON. The markdown is the
primary output: if the JSON cannot be written, Ravensight logs a warning and the
markdown report is still produced.

To turn the JSON copy off, set `[reports] json_output = false` (default `true`; it
must be exactly `true` or `false`). This applies to Docker too, through the mounted
`config.toml`. With `json_output = false` and `overwrite = true`, an older same-day
`.json` file stays beside the new markdown report and no warning is logged.

---

## Baseline Memory

Ravensight tracks a baseline of findings and recommendations from previous runs.
On each run, the current analysis updates the baseline. The `--report-only` flag
generates a report from the last saved baseline without querying Wazuh or the LLM.

The baseline is stored as a JSON file at the path configured in `config.toml`.

---

## Historical Trending

`trending.py` tracks per-rule-group alert volumes across runs and detects
slow-burn threats that single-run baseline comparison misses.

- Each run appends a timestamped snapshot of rule group counts to the scan history
- `trending.py` reads the history over a configurable rolling window (default 30 days)
- Rule groups with consistently increasing counts across 3+ consecutive runs are
  flagged as anomalies with a ⚠️ marker
- Output is a markdown table embedded in the main report

---

## MITRE ATT&CK & ASD Essential Eight / ISM

Findings are tagged against the **MITRE ATT&CK** framework and Australia's
**ASD Essential Eight** and **ISM** controls.

- `scripts/mitre_sync.py` pulls the MITRE ATT&CK enterprise dataset (STIX JSON)
  to `data/mitre_attack.json`
- `scripts/asd_sync.py` pulls the ASD ISM catalog (OSCAL JSON) from ASD's ISM
  OSCAL catalogue (GitHub first, cyber.gov.au fallback) to `data/asd_framework.json`
- Both datasets are synced once and used fully offline afterwards — re-run the
  sync scripts manually (or `docker run ravensight sync` in Docker) to pick up
  a new release
- `data/defaults/e8_strategy_map.json` holds the control-to-strategy map used by
  `asd_sync.py`; an `asd_framework.json` from before this change must be regenerated
- `data/e8_keyword_overrides.json` reduces Essential Eight scoring false
  positives via a keyword blocklist
- `data/e8_attestation.json` is a hand-edited, git-ignored, optional file of manual
  Essential Eight attestations. Entries still prefixed `EXAMPLE:` are treated as
  placeholders and warned about
- `data/essentials_attestation.json` is a hand-edited, git-ignored, optional file of
  manual ASD Essentials declarations (see
  [ASD Essentials in the report](#asd-essentials-in-the-report))
- `data/platform_hints.json` is a hand-edited false-positive hint table
- `data/platform_agents.json` is a hand-edited, git-ignored, optional map of Wazuh agent name → vendor/platform

Ravensight is an independent open-source project. It is not produced, endorsed or supported by ASD. Essential Eight statuses come only from the attestations you provide; otherwise they show as Not assessed.

ASD plans to deprecate the Essential Eight in about 12 months and retire it in about 24 from the 15 October 2026 launch of the ASD Essentials. Ravensight runs the Essentials alongside the Essential Eight and keeps the Essential Eight section and data as they are. Retiring them is a separate later decision.

---

## ASD Essentials in the report

Full runs add an Essentials section to the report, but only when `config.toml`
has an `[essentials]` section (copy it from `config.example.toml`). Without it,
no Essentials section appears and no warning is logged. The section points findings at the
Essentials principles and actions they relate to. It never rates anything: ASD's
phases are an implementation order, not a rating, and ASD's ATT&CK mapping is a
guide for setting priorities, not a rating. Report-only runs (`--report-only`)
have no Essentials section.

Findings are matched to principles by three routes: MITRE ATT&CK, ISM controls and
keywords. The MITRE route needs `data/mitre_attack.json`, which Docker syncs
automatically on first start. Without it, only the ISM and keyword routes can match.

Statuses come only from your own declarations in `data/essentials_attestation.json`,
keyed by principle id (for example `DET-01`). The status words are Not applicable,
Not assessed, Not effective, Partially effective and Fully effective. Every
principle defaults to Not assessed. Ravensight does not assess anything itself.

On a host run, copy `data/defaults/essentials_attestation.example.json` to
`data/essentials_attestation.json`, edit it with your real declarations and remove
the `EXAMPLE:` prefixes. In Docker, run `init-essentials-attestation` (see
[Docker](#3-run-1)). A missing file gives a warning on every run, and a file with
`EXAMPLE:` entries gives one warning per placeholder entry on every run.

---

## ASD Essentials for enterprise IT dataset

`data/defaults/essentials_enterprise_it.json` is a structured JSON version of the enterprise IT chapter of ASD's Essentials for enterprise IT. It has 8 domains, 28 principles, 58 actions, 212 domain/action pairs and 529 implementation statements, plus the mapped ISM controls and MITRE ATT&CK technique names. The report's Essentials section uses it as reference data.

**This is an unofficial community dataset.** It is not produced, endorsed or supported by the Australian Signals Directorate (ASD). It contains no ratings or assessments, and nothing here implies any ASD partnership, approval or certification. Please check against ASD's official documents at [cyber.gov.au](https://www.cyber.gov.au/publication/essentials-for-enterprise-it) before relying on it.

**Source and licence.** All content is derived from ASD's official publications, which are licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), © Commonwealth of Australia 2026. See [ASD's copyright page](https://www.cyber.gov.au/about-us/copyright). The dataset's own notice reads: "UNOFFICIAL community dataset. Not produced, endorsed or supported by ASD. Check against ASD's official documents at cyber.gov.au before relying on it." The documents used are:

- ASD Essentials for enterprise IT (the chapter)
- Assessment evidence guide for enterprise IT
- Essentials for enterprise IT - Assessment Workbook

**What was changed.** I restructured the content from ASD's PDFs and workbook into JSON and checked it against those three documents. Where they differ, both versions are kept rather than merged (for example `mitre_technique_names` from the evidence guide and `mitre_technique_names_chapter` from the chapter). Technique names are ASD's names, not ATT&CK technique IDs. The `source` block inside the JSON records the same information.

**What is not included.** ASD's publications, logos and the Commonwealth Coat of Arms are not in this repository. They are not covered by the CC BY 4.0 licence.

---

## Roadmap

Feature status and full design notes are tracked in one place:
[`docs/RAVENSIGHT_ROADMAP.md`](docs/RAVENSIGHT_ROADMAP.md).

---

## Inference Server

Ravensight is designed to run against a dedicated local llama.cpp inference node.
All LLM calls are made over the local LAN via the OpenAI-compatible REST API.
No data is sent to any cloud service.

See [`docs/yubaba-server-reference.md`](docs/yubaba-server-reference.md) for
the full server specification (gitignored — contains local network details).

---

## Development Workflow

This project uses the [Huginn](https://github.com/sli3/Huginn) workflow template,
adapted for Claude Code — structured sessions, safety gates, and session memos.

```
Ravensight/
├── main.py
├── ravensight/
│   ├── wazuh_client.py
│   ├── analyser.py
│   ├── reporter.py
│   ├── baseline.py
│   ├── trending.py
│   ├── embedder.py
│   └── e8_scorer.py
├── scripts/
│   ├── mitre_sync.py
│   └── asd_sync.py
├── tests/
├── data/
│   ├── defaults/             # Seed files baked into the Docker image
│   │   ├── e8_attestation.example.json
│   │   ├── e8_keyword_overrides.json
│   │   ├── e8_strategy_map.json
│   │   ├── platform_agents.example.json
│   │   └── platform_hints.json
│   ├── mitre_attack.json     # Gitignored — regenerable via mitre_sync.py
│   ├── asd_framework.json    # Gitignored — regenerable via asd_sync.py
│   ├── baseline_state.json   # Gitignored
│   └── chroma/embedded/      # Gitignored — vector store
├── reports/                  # Gitignored — generated output
├── config.example.toml
├── docker-entrypoint.sh
├── Dockerfile
├── requirements.txt
├── docs/
│   └── RAVENSIGHT_ROADMAP.md
├── AGENTS.md
├── CLAUDE.md
├── .mcp.json
├── LICENSE
├── .gitignore
├── .session-memos/           # Gitignored working notes
└── .claude/
    ├── agents/
    ├── hooks/
    └── skills/
```

Prompt calibration harness (needs a running local LLM):
`uv run python scripts/eval_prompt.py --runs 5 --json ~/Downloads/eval.json`

---

## Licence

Ravensight's code is MIT — see [LICENSE](LICENSE). The ASD Essentials for enterprise IT dataset (`data/defaults/essentials_enterprise_it.json`) is derived from ASD's publications and remains under CC BY 4.0, © Commonwealth of Australia 2026 — see [the section above](#asd-essentials-for-enterprise-it-dataset).