# Ravensight — Feature Roadmap

> What is planned and in progress. Finished sections are archived word for word in
> `docs/roadmap-archive.md`. Commits, test counts and run notes live in git and the session
> memos, not here. When a session is built, its scope text collapses to one line here.

---

## Feature Status

| Feature | Status | Where |
|---------|--------|-------|
| Multi-Model Routing | ~~Superseded~~ | Archive §1 |
| MITRE ATT&CK Tagging | ✅ Complete | Archive §2 |
| Historical Trending | ✅ Complete | Archive §3 |
| Embedding Model | ✅ Complete | Archive §4 |
| Platform-Aware Alert Context | ✅ Complete | Archive §5 |
| Progress Bar + LLM Streaming (now the rich terminal UI) | ✅ Complete | Archive §6 |
| ASD Framework Mapping | ✅ Complete | Archive §7 |
| Essential Eight Scoring + ISM Mapping | ✅ Complete | Archive §8 |
| Essential Eight Evidence-Only Report | 🔶 In progress | §9 below, see Open Items |
| Wazuh Query Time Window Fix | ✅ Complete | Archive §10 |
| Report Finding Time Labelling | ✅ Complete | Archive §11 |
| Report Clarity | ✅ Complete | Archive §12 |
| Pin Dev Tools | ✅ Complete | Archive §13 |
| Pyright Triage | ✅ Complete | Archive §14 |
| Essential Eight Manual Attestation | ✅ Complete | Archive §15 |
| Docker Support for E8 Attestation | ✅ Complete | Archive §16 |
| Structured JSON Report Output | ✅ Complete | Archive §17 |
| Wazuh Indexer Connection Mode Log Line | ✅ Complete | Archive §18 |
| Unify the Settings Files | ✅ Complete | Archive §19 |
| ASD Essentials Evidence Report | ✅ Complete | Archive §20 |
| Report Table Tidy-up | ✅ Complete | Archive §21 |
| Analysis Coverage and Prompt Evidence Cut | ✅ Complete | Archive §22 |
| Networked ChromaDB, Container non-root, Cluster Evidence, Wazuh Indexer TLS, Manager Login Removal, Alert Cap Warning, Data File Loader Hardening | ✅ Complete | Archive Feature Status table |
| Web UI Report Viewer | 🔶 In progress | §23 below: Sessions 1 and 2 built, Session 3 open |
| Trends Chart in the Viewer | 🔶 In progress | §24 below: Sessions 1 to 3 built, Session 4 open |

## Open Items

One line each. Fix them in a session of their own, or close them here with Prin's say-so.

- §9: its "Not applicable" state and attestation file were delivered by §15, so only extra
  evidence sources (such as Wazuh SCA results) remain. Prin to decide whether to close §9
- Pyright does not check the openai/httpx2 exception handling in `ravensight/analyser.py`
- The LLM stream's `finish_reason` is not logged, the report shows nothing for a cluster
  with no commentary, and reply length needs watching against `max_tokens` (8192)
- `docker-entrypoint.sh` has no unit tests, seeded default files can drift from
  `data/defaults/`, and SELinux `:z` mount labels are not handled
- Never run in a container: `json_output = false` or a bad value, a missing or unreadable
  host `config.toml`, `sync`, and the README's Docker commands
- The 10,000-alert cap only warns (no pagination), and keyword matching ignores negation
  (by design)
- The JSON report's known limitations are listed in archive §17
- Viewer: Safari may misread six-digit fractional seconds in `generated_at`, tick labels have
  no year, a reversed time range is swapped silently, 500 findings make a very tall page, and
  an empty notices box shows when all five notice fields are blank
- Viewer not checked yet: a narrow window, 30 or more findings, the empty-findings state, the
  opened "N more findings" group, long CIS labels, and printing (closed sections do not
  print)

---

## Active Sections

Finished sections keep their numbers in `docs/roadmap-archive.md` (see the table above).

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

### 23. Web UI Report Viewer

**What it does:** a read-only viewer for the JSON report, `web/index.html`, so a run can be
read as a page. Built on the `web-ui-report` branch.

**Design rule:** the viewer reads the JSON report only, never the markdown, and shows only
what the JSON holds. It never works out a rating, a score or a percentage, and it keeps
every ASD notice the report shows (AGENTS.md "ASD Material and Claims"). Many of the rules
below are enforced by `tests/test_web_viewer.py`.

Rules (agreed with Prin):
- Layout and style follow artboard E, `docs/web-ui/Viewer.dc.html` (placeholder data, never
  reused as code). Field names come from the real JSON, never from the design. Any other
  departure from artboard E needs a rule here first
- One self-contained HTML file with inline CSS and plain JavaScript, opened from disk, one
  report loaded through a file picker. No framework, library, build step, network request,
  server or Python dependency. All JSON text is inserted as text, never as HTML
- Derived in the viewer, not in the JSON: the alert total, the severity totals and the time
  window (`generated_at` minus `run.hours`). The "Check" line is built from `flags`, only
  when `flags` is not empty
- An unknown `schema_version` shows a clear message. The status line keeps "Report loaded."
  and every error message as they are
- Wherever Essentials data appears: the JSON's own attribution, licence link, "modified"
  note and unofficial notice, never paraphrased. Phases are an implementation order, and
  ratings are the operator's own declaration
- Timeline: one range bar per finding from `first_seen` to `last_seen`, with a dot at each
  end (one dot when they are equal or very close). A dot is never called an alert time
- The pointer map has the 8 ASD domain names as fixed rows, kept in one constant
- Departures from artboard E (Prin, 23 and 24 Oct 2026):
  - the page column may be up to 1800px wide, with at least 24px each side
  - the run details are header chips
  - the file picker is a compact violet button with a folder icon, with the read-only
    sentence beside it; there is no Read-only chip, no footer and no idle status text
  - each evidence field is one row, with a fixed label column and the values as chips (the
    label column is narrower when the panel is 480px or less); every value is shown as
    written
  - no text has a length limit, so notes and finding text fill their box
  - the finding's narrative and recommendation sit in two columns on a wide window and
    stack on a narrow one

Built: Session 1, JSON schema version 3 (commit `2af63af`). Session 2, the viewer (commits
`acce411` and `5a1d60a`), with later style commits and the departures above.

#### Session 3 — Check against real reports and tidy

In scope:
- Run the viewer against real reports from live runs (a full run, a run with no Essentials
  data, a run with empty commentary and a run with `flags`), and fix only defects in
  `web/` and its tests
- Changes Prin records under Rules first
- Update `README.md` and this section's Feature Status row

Out of scope:
- New screens or data

Out of scope for the whole section:
- Any server, route, API, port, Docker serving, authentication, sharing or uploading a report
- Writing to any file, or any form that changes data
- Any rating, score, percentage, pass or fail wording, or colour that implies one
- Per-alert timeline dots and an "Alert time" legend, and any figure the JSON does not hold
- Similar past incidents, the summary line, MITRE tags, the glossary, and comparing or
  listing several reports
- Charts and structured trends, except as section 24 adds them
- ASD or ACSC logos, the Commonwealth Coat of Arms, ASD PDFs or screenshots of ASD documents
- Any change to the JSON shape (except as section 24 adds), the markdown report, the LLM
  prompt, or how findings are matched or analysed
- Retiring or changing the Essential Eight section
- Opening, editing or printing `config.toml` or `.env`

### 24. Trends Chart in the Viewer

**What it does:** the per-day trend counts reach the JSON report as data (a `trends` key,
schema version 4), and the viewer draws them as a line chart with a trends table. Built on
the `web-ui-report` branch.

**Design rule:** the chart shows only what the JSON holds. The viewer never works out a
rating, a score, a percentage or a forecast. Direction and anomaly are `trending.py`'s own
values, shown as text, and no colour implies a rating or a severity (no red, amber or
green).

Rules (agreed with Prin):
- `trends` is `null` when `[trending]` is missing, there is no scan history or no qualifying
  daily run, in full and `--report-only` runs alike. Otherwise it holds `window_days`,
  `days` (`YYYY-MM-DD`), `hidden` and `rows` (`label`, `counts` with zero for an absent
  day, `latest`, `avg`, `days_seen`, `direction`, `anomaly`), in the text table's rows and
  order, with no cluster key. The markdown and `trends_markdown` are unchanged
- The viewer accepts schema versions 3 and 4. A schema 3 report shows the trends text only
- The chart is plain inline SVG: one line per finding, a dot on each day with data, day and
  count axes, days with no daily run left off the axis, and a neutral palette
- Lines shown at first: rows that are `new` or flagged as an anomaly, then the largest
  `latest`, up to 5. Every row can be switched on or off, so no finding is hidden
- The table is built from `trends.rows`, never by parsing `trends_markdown`. Its columns are
  Finding, Avg/day, Latest, Direction (with "anomaly" when flagged) and Daily counts, a
  small line on its own 0-to-max scale. Rows are one line high, the swatch is the toggle,
  shown rows are bold, the default rows come first and the rest sit in a closed "N more
  findings" section. The `trends_markdown` text sits in a closed "Text version" section
- Text only, and attributes set through one helper, never HTML

Built: Session 1, report side (commit `395bfaa`). Session 2, the chart (commit `9c7b372`).
Session 3, the trends table (commit `f70df42`).

#### Session 4 — Check against real reports and tidy

In scope:
- Run the report and the viewer against real runs (a run with a long history, a run with a
  short history of one or two days, a run with no history and a report-only run) and fix
  only defects in `ravensight/trending.py`, `ravensight/reporter.py`, `web/` and their tests
- Update `README.md` and this section's Feature Status row

Out of scope:
- New screens or data, and any item not covered by the Rules

Out of scope for the whole section:
- Any change to how trends, direction or anomalies are worked out (window length,
  thresholds, same-day rerun collapsing, vendor aliases), to the baseline file format or to
  how scan history is stored
- Forecasts, trend lines, thresholds, sigma values or any figure the JSON lacks, and any
  rating, score, percentage, pass or fail wording, or colour that implies one (including
  colour for direction)
- Sorting or filtering the table, and "Show all" or "Clear" controls
- Per-alert detail, comparing or listing several reports, and exporting an image
- A chart library, any framework and any network request
- Any other change to the JSON shape, the markdown report, the LLM prompt or analysis logic
- A web server, authentication, or uploading a report anywhere
- Opening, editing or printing `config.toml` or `.env`

## Suggested Build Order

1. Section 23 Session 3 and section 24 Session 4 together (one real-report check of the
   viewer), then merge the `web-ui-report` branch
2. Section 9: close it or plan its next phase (see Open Items)

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

*Created: 2026-05-01 — last updated: 2026-10-24*