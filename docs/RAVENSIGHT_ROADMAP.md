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
| Essential Eight Evidence-Only Report | ✅ Closed | Archive §9 |
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
| Report Reading Flow | 🔶 In progress | §25 below: Sessions 1 to 3 built (commits `011c01e`, `362cb0a`), Session 4 open |
| SCA Check Grouping | 🔶 In progress | §26 below: Session 1 built (commit `18a5724`), Session 2 open |

## Open Items

One line each. Fix them in a session of their own, or close them here with Prin's say-so.

- Pyright does not check the openai/httpx2 exception handling in `ravensight/analyser.py`
- The report shows nothing for a cluster with no commentary. The run log now shows the
  stream's `finish_reason` and warns when a reply stops at `max_tokens`
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
  - the order of the sections, the intro box, the terms box and the highlighted
    recommendation: see section 25

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

### 25. Report Reading Flow

**What it does:** puts the markdown report and the web viewer in one reading order that a
first-time reader can follow: what this is, what happened, what to do about it, how it
compares, then reference material. It changes order and a few joining sentences only, never
the data.

**Design rule:** order and wording only. Nothing is rated, scored, hidden or added, and every
ASD notice stays wherever it is now, word for word. A section moves as a whole.

Rules (agreed with Prin, 26 Oct 2026; pm proposed them when Prin asked pm to decide):
- One reading order in both outputs: (1) a short how-to-read note, (2) the summary,
  (3) the findings, each as what happened, then the recommended action, then the evidence,
  (4) how it compares: similar past incidents (markdown only) and the trends, (5) reference
  material: MITRE ATT&CK tags (markdown only), then ASD Essentials, then the ASD Framework
  (Essential Eight and ISM), (6) terms, notices and attribution
- Markdown: each finding's recommendation is printed under its narrative and Check line,
  before its evidence. An unattached note keeps its prefix and prints its recommendation the
  same way. The separate Recommendations section stays only for an old-format report that
  has no dictionary findings
- Markdown: a finding with no commentary, or no recommendation, shows a plain sentence
  saying so, using the viewer's existing wording
- ASD Essentials comes before the ASD Framework section in the markdown, as in the viewer.
  The Essential Eight section keeps its content and is not retired
- The trends keep their rows, notes and wording (section 24's Rules stand). Only their place
  changes: straight after the similar past incidents in the markdown, and before the
  framework sections in the viewer
- Markdown: the Glossary stays last. The how-to-read note under the title gains one
  sentence that gives the reading order and says terms are explained in the Glossary at the
  end when it has entries
- Markdown: the Glossary leaves out the "Cluster (C1, C2…)" and "UTC" entries, because the
  how-to-read note under the title already explains both. The entries stay in the glossary
  data (the viewer's Terms box still uses them), and no other glossary entry changes
- The finding's recommendation is highlighted in both outputs, because it answers "what do I
  do?". Viewer: the recommendation sits in a callout box (a left accent border and a light
  background from the existing design tokens, in both themes), kept in its current place
  beside the narrative (stacked on a narrow window), labelled "Recommendation". Markdown:
  the recommendation line becomes a blockquote starting "**Recommendation:**". One neutral
  accent is used for every recommendation, including "No action" ones, and no colour implies
  a rating, a severity or urgency (no red, amber or green). The "No recommendation was
  generated." sentence stays plain and muted, with no box. The recommendation text itself is
  never reworded
- Viewer: the order is run summary and timeline, Findings, Trends, ASD Essentials, Essential
  Eight, Terms. The navigation follows the page order. Where artboard E orders these
  differently, this section's order wins
- Viewer: a short plain-language "How to read this report" box shows after a report loads,
  and a closed "Terms used on this page" box sits at the end. Both are fixed page text, not
  report data. The terms cover cluster, UTC, ASD, ISM, Essential Eight, ASD Essentials,
  principle and action, priority phase, CVE, MITRE ATT&CK, anomaly and Check, reusing the
  Glossary's wording wherever it has an entry
- No existing how-to-read note, notice, attribution, licence line or glossary entry is
  reworded. Only the sentences and boxes named above are new

#### Session 1 — Markdown report order

In scope:
- `ravensight/reporter.py`: the section order in `_build_report`, the recommendation line in
  `_format_finding`, the no-commentary and no-recommendation sentences, the Recommendations
  section for old-format reports only, and the extra intro sentence
- `tests/test_reporter_findings.py`, `tests/test_reporter_essentials.py` and any other
  reporter test that pins a section's place or the Recommendations section
- `README.md`: the "Each report contains" list

Out of scope:
- `web/`, `ravensight/trending.py` (the trends text moves, it is not changed) and the JSON
  report

#### Session 2 — Viewer order, intro and terms

In scope:
- `web/index.html`: the section order, the navigation order, the "How to read this report"
  box and the "Terms used on this page" box
- `tests/test_web_viewer.py`
- `README.md`: the "Report viewer" paragraph

Out of scope:
- `ravensight/` and the JSON report

#### Session 3 — Glossary duplicates

In scope:
- `ravensight/reporter.py`: `_render_glossary` skips the "Cluster (C1, C2…)" and "UTC"
  entries when the how-to-read note under the title is in the report
- `tests/test_reporter_findings.py`, and any other reporter test that expects those two
  entries in the Glossary

Out of scope:
- `web/` and the viewer's Terms box, the other glossary entries and their wording, the
  how-to-read note, and the JSON report

#### Session 4 — Highlighted recommendation

In scope:
- `ravensight/reporter.py`: the recommendation line in `_format_finding` becomes a blockquote
  starting "**Recommendation:**", for cluster, vulnerability and unattached findings that have
  one
- `web/index.html`: the CSS for a recommendation callout and the recommendation block in
  `renderClusterDetail` (and the unattached or other-finding detail if it shows one)
- `tests/test_reporter_findings.py`, `tests/test_web_viewer.py` and any other test that
  expects the old recommendation line
- `README.md`: only if a sentence there describes the old recommendation line

Out of scope:
- The wording of any recommendation, the "No recommendation was generated." sentence's
  wording, the order of sections, the JSON report, and `ravensight/` other than `reporter.py`

Out of scope for the whole section:
- Any change to the JSON report (keys, values or `schema_version`), to how trends, direction
  or anomalies are worked out, to how findings are matched or analysed, or to the LLM prompt
- Rewording, shortening or paraphrasing an existing how-to-read note, ASD notice,
  attribution, licence line or glossary entry
- Hiding, sorting, filtering or capping findings or trend rows, and any "Show all" or "Clear"
  control
- Any rating, score, percentage, pass or fail wording, or colour that implies one
- Retiring or changing the content of the Essential Eight section
- New screens or data, per-alert detail, and comparing or listing several reports
- A web server, a network request, a framework, a build step, or writing to any file
- Opening, editing or printing `config.toml` or `.env`

### 26. SCA Check Grouping

**What it does:** Wazuh's Security Configuration Assessment (SCA) raises one alert per check
result after an agent restart, an upgrade or a policy change. Ravensight groups rule alerts
by rule description, and every check has its own description, so one scan becomes one
finding per check (127 findings on 29 Oct 2026, after an `apt full-upgrade` on the Wazuh
server). Most of them then get no commentary, because only the first 40 clusters reach the
model. This section groups the check-result alerts of one SCA policy into one finding, with
the checks as evidence.

**Design rule:** the finding shows only what Wazuh reported. Ravensight never works out a
score, a percentage, a count of passed or failed checks as a rating, or a compliance verdict
from SCA alerts, and SCA results never set an Essential Eight or Essentials status (those come
only from Prin's attestation files).

Rules (agreed with Prin, 29 Oct 2026; pm proposed them when Prin chose this option):
- An SCA check-result alert is one whose `rule.groups` includes `sca` and whose
  `data.sca.type` is `check`. Session 1 confirms these field names against a real alert
  before relying on them
- Check-result alerts group by SCA policy name, one finding per policy, with hosts merged as
  for other rule alerts
- The finding's description is the same from run to run, so trends, the baseline and similar
  past incidents follow it: "SCA checks: " followed by the policy name. It never includes a
  count; the alert count is the finding's count, as for any cluster
- The cluster type stays `rule`, so the JSON report (keys, values and `schema_version`) and
  the viewer need no change. Severity comes from the highest rule level, as for any cluster
- Evidence lists the check titles, each with the result Wazuh recorded for it, word for word,
  capped like other evidence lists with "+N more". This is Wazuh's data shown as evidence,
  not a Ravensight rating
- The SCA summary alert ("SCA summary: …") is not a check-result alert and stays its own
  finding, unchanged. An alert without the SCA fields groups as it does today
- How findings are matched to MITRE, ISM, the Essential Eight and the Essentials is
  unchanged; a grouped SCA finding is matched like any other finding

Built: Session 1, Grouping and evidence (commit `18a5724`).

#### Session 2 — Check against a real SCA scan

In scope:
- Run against a window that holds SCA check alerts (for example the 29 Oct 2026 upgrade, or
  after restarting an agent) and fix only defects in the files listed for Session 1
- This section's Feature Status row

Out of scope:
- New evidence fields or wording beyond the Rules above

Out of scope for the whole section:
- Any score, percentage, pass or fail summary or compliance rating worked out by Ravensight,
  and feeding SCA results into any Essential Eight or Essentials status
- How any other alert groups, the 40-cluster prompt cap and the alert level threshold
- Any change to the JSON report, the viewer or the markdown report's layout
- Reading SCA results from the Wazuh API: only the alerts Ravensight already fetches
- The LLM prompt, `ravensight/reporter.py`, `web/` and the JSON report shape
- Opening, editing or printing `config.toml` or `.env`

## Suggested Build Order

1. Section 23 Session 3 and section 24 Session 4 together (one real-report check of the
   final layout)
2. Section 25 Session 4, the highlighted recommendation (Prin asked for it to come after the
   item above)
3. Section 26 Sessions 1 and 2, SCA check grouping

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

*Created: 2026-05-01 — last updated: 2026-10-26*