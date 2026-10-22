"""Static checks for web/index.html, the single-file report viewer.

LIMITS: these tests only read the HTML file as text. They cannot execute the
JavaScript, so they cannot prove that a path is read correctly, only that every
declared read exists in the schema 3 sample (or in a small inline payload for
shapes the sample lacks) and that every literal read is declared. A render bug,
a ReferenceError or a layout defect is not caught here. Prin's browser check and
roadmap section 23 Session 3 cover that.

Further limits:
- The model's output (for example the display text built from a map-valued field)
  cannot be checked without running JavaScript. Only the READS paths are resolved,
  against the sample and EXTRA_PAYLOAD, which follows the real shapes in
  ravensight/evidence.py.
- An rd( literal is matched to READS by its trailing segments (leaf names), so a
  literal can be covered by a different READS entry that ends the same way.
- Keys that come from data are read through the array form of rd( (for example
  rd(shape, [key])); those reads are not individual literals. The RD_ARGS rule
  rejects an rd( call whose path is a bare identifier, apart from the names in
  RD_BARE_PATH_ALLOWED (currently none).
- The `.href =` and `.className =` check finds the enclosing function by the nearest
  preceding top-level `function name(` line, so it assumes helpers sit at column 0.
- The section, navigation and fixed-wording checks only look for text and ids in the
  file. They do not show that a section draws the right content from a real report.
"""

import json
import re
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
VIEWER = ROOT / "web" / "index.html"
FIXTURE = ROOT / "tests" / "fixtures" / "report-schema3-sample.json"
DATASET = ROOT / "data" / "defaults" / "essentials_enterprise_it.json"

MIN_READS = 40

# Paths the viewer reads that the sample fixture does not hold. Each one must be absent
# from the fixture and present in EXTRA_PAYLOAD below, so none goes unchecked.
OPTIONAL_PATHS: dict[str, str] = {
    "findings[].text": "legacy findings only; the sample has a rule finding",
    "findings[].evidence.*.more.*": "overflow counts; the sample syscheck has no 'more'",
    "findings[].evidence.*.*.*": (
        "map-valued fields (vulnerability, firewall) are absent from the sample"
    ),
    "findings[].evidence.per_host.*.*.*.*": "per-host evidence is absent from the sample",
    "findings[].evidence.per_host.*": "per-host evidence is absent from the sample",
    "findings[].evidence.per_host.*.*": "per-host evidence is absent from the sample",
    "findings[].evidence.per_host.*.*.*": "per-host evidence is absent from the sample",
    "findings[].evidence.per_host.*.*.more.*": "per-host evidence is absent from the sample",
    "essentials.finding_actions[].actions[].reasons[].ism_id": "sample reason is a MITRE one",
    "essentials.finding_actions[].actions[].reasons[].field": "sample reason is a MITRE one",
    "essentials.finding_actions[].actions[].reasons[].shared": "sample reason is a MITRE one",
}

# Shapes the sample lacks: a legacy finding, evidence shapes, per-host evidence, the
# overflow counts, and the ISM and keyword reasons. The evidence shapes follow the real
# projections in ravensight/evidence.py: vulnerability.statuses is a map of status to
# count; firewall has sources_total, sources_by_version (map of version to count) and
# direction_scopes (map of direction to a list of [source scope, destination scope]).
EXTRA_PAYLOAD: dict[str, Any] = {
    "findings": [
        {"type": "legacy", "text": "Plain text finding."},
        {
            "type": "rule",
            "evidence": {
                "firewall": {
                    "actions": ["block"],
                    "protocols": ["tcp"],
                    "sources": ["192.0.2.1", "192.0.2.2"],
                    "sources_total": 3,
                    "sources_by_version": {"ipv4": 2, "ipv6": 1},
                    "src_scopes": ["external"],
                    "dst_scopes": ["internal"],
                    "direction_scopes": {"in": [["external", "internal"]]},
                    "more": {"sources": 1},
                },
                "dpkg": {"packages": ["example 1.0: installed"]},
                "netstat": {"added": ["tcp 0.0.0.0:22 (sshd)"], "removed": []},
                "docker": {"containers": ["web"], "actions": ["start"]},
                "vulnerability": {"statuses": {"Active": 2}, "severities": ["High"]},
                "generic": {"srcips": ["192.0.2.1"]},
                "syscheck": {"content": "changed", "events": ["modified"], "paths": ["/x"]},
                "per_host": {
                    "host-b": {
                        "syscheck": {"events": ["modified"], "paths": ["/y"], "more": {"paths": 2}},
                        "vulnerability": {"statuses": {"Active": 1}},
                    }
                },
            },
        },
    ],
    "essentials": {
        "finding_actions": [
            {
                "actions": [
                    {"reasons": [{"route": "ism", "ism_id": "ISM-0000", "field": "e8_ism"}]},
                    {"reasons": [{"route": "keyword", "shared": ["patch"]}]},
                ]
            }
        ]
    },
}

BANNED_SINKS: list[tuple[str, str]] = [
    ("innerHTML", r"innerHTML"),
    ("outerHTML", r"outerHTML"),
    ("insertAdjacentHTML", r"insertAdjacentHTML"),
    ("document.write", r"document\s*\.\s*write"),
    ("eval(", r"\beval\s*\("),
    ("new Function", r"new\s+Function\b"),
    ("DOMParser", r"DOMParser"),
    ("createContextualFragment", r"createContextualFragment"),
    ("setAttribute on...", r"setAttribute\s*\(\s*[\"']\s*on"),
    ("srcdoc", r"srcdoc"),
    ("javascript: URL", r"javascript\s*:"),
    ("handler assignment", r"\.on[a-z]+\s*=(?!=)"),
]

BANNED_NETWORK: list[tuple[str, str]] = [
    ("fetch(", r"\bfetch\s*\("),
    ("XMLHttpRequest", r"XMLHttpRequest"),
    ("WebSocket", r"WebSocket"),
    ("sendBeacon", r"sendBeacon"),
    ("import(", r"\bimport\s*\("),
    ("importScripts", r"importScripts"),
    ("EventSource", r"EventSource"),
]

BANNED_TERMS = [
    "kamaji",
    "yubaba",
    "opnsense",
    "192.168",
    "ornith",
    "logo",
    "coat of arms",
    "coat-of-arms",
    "acsc",
]

BANNED_WORDS = re.compile(
    r"\b(pass|passed|fail|failed|compliant|compliance|score|grade|graded|percentage|rated)\b",
    re.IGNORECASE,
)

# The https address may appear only on this exact line (the constant's definition).
URL_DEFINITION_LINE = 'const SAFE_LINK_PREFIX = "https://";'

# Assignments that must stay inside named helpers: pattern -> allowed function names.
GUARDED_ASSIGNMENTS: dict[str, tuple[str, ...]] = {
    r"\.href\s*=(?!=)": ("safeLink",),
    r"\.className\s*=(?!=)": ("el", "showMessage"),
}

# A bare identifier may be the path argument of rd( only for these internal uses.
RD_BARE_PATH_ALLOWED: frozenset[str] = frozenset()

RD_CALL = re.compile(r"(?<!function )(?<![\w$.])rd\(")
RD_ARGS = re.compile(
    r"(?<!function )(?<![\w$.])rd\(\s*[A-Za-z_$][\w$]*\s*,\s*"
    r"(\"(?:[^\"\\]|\\.)*\"|\[|[A-Za-z_$][\w$]*)"
)


def _text() -> str:
    """Return the viewer source as UTF-8 text."""
    return VIEWER.read_text(encoding="utf-8")


def _html_only(text: str) -> str:
    """Return the page with the contents of its script block removed."""
    return re.sub(r"<script>.*?</script>", "<script></script>", text, flags=re.DOTALL)


def _extract_array(name: str, text: str) -> list[Any]:
    """Read a top-level `const NAME = [...]` JSON array from the script by regex."""
    match = re.search(rf"const {name} = (\[.*?\n\]);", text, flags=re.DOTALL)
    assert match, f"{name} array not found in web/index.html"
    return json.loads(match.group(1))


def _resolve(node: Any, tokens: list[str]) -> bool:
    """Return True when the path tokens exist in node ([] is any list item, * any key)."""
    if not tokens:
        return True
    head, rest = tokens[0], tokens[1:]
    is_list = head.endswith("[]")
    key = head[:-2] if is_list else head
    if key == "*":
        children = list(node.values()) if isinstance(node, dict) else []
    elif isinstance(node, dict) and key in node:
        children = [node[key]]
    else:
        children = []
    if is_list:
        children = [item for child in children if isinstance(child, list) for item in child]
    return any(_resolve(child, rest) for child in children)


def _exists(node: Any, path: str) -> bool:
    """Return True when a dotted READS path exists in node."""
    return _resolve(node, path.split("."))


def _covers(literal: str, entry: str) -> bool:
    """Return True when an rd() literal names the trailing segments of a READS entry."""
    wanted, full = literal.split("."), entry.split(".")
    return len(wanted) <= len(full) and full[-len(wanted):] == wanted


def _rd_calls(text: str) -> tuple[int, list[str]]:
    """Return (number of rd( calls, the string literals passed to them)."""
    total = len(RD_CALL.findall(text))
    literals = []
    for match in RD_ARGS.finditer(text):
        if match.group(1).startswith('"'):
            literals.append(json.loads(match.group(1)))
    return total, literals


def _bare_path_args(text: str) -> list[str]:
    """Return the bare identifiers used as the path argument of rd( calls."""
    found = []
    for match in RD_ARGS.finditer(text):
        arg = match.group(1)
        if not arg.startswith(('"', "[")):
            found.append(arg)
    return found


def _assignment_sites(text: str, pattern: str) -> list[tuple[int, str]]:
    """Return (line number, enclosing top-level function) for each match of pattern."""
    sites = []
    current = ""
    for number, line in enumerate(text.splitlines(), start=1):
        header = re.match(r"function\s+([\w$]+)\s*\(", line)
        if header:
            current = header.group(1)
        if re.search(pattern, line):
            sites.append((number, current))
    return sites


def _hits(text: str, patterns: list[tuple[str, str]]) -> list[str]:
    """Return the names of the banned patterns found in text."""
    return [name for name, pattern in patterns if re.search(pattern, text)]


def _load_json(path: Path) -> Any:
    """Load a JSON file."""
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# (a) READS against the sample, and the rd() convention
# ---------------------------------------------------------------------------


def test_reads_is_present_and_not_tiny() -> None:
    """READS must be a real list: not empty, not tiny, no duplicates, all strings."""
    reads = _extract_array("READS", _text())
    assert len(reads) >= MIN_READS
    assert len(reads) == len(set(reads))
    assert all(isinstance(entry, str) and entry for entry in reads)


def test_resolver_self_test() -> None:
    """The resolver finds real paths and rejects invented ones, so the check is not trivial."""
    sample = {"a": [{"b": {"c": 1}}], "m": {"x": {"y": 2}}, "empty": []}
    assert _exists(sample, "a[].b.c")
    assert _exists(sample, "m.*.y")
    assert not _exists(sample, "a[].b.nope")
    assert not _exists(sample, "empty[].b")
    assert not _exists(sample, "m.*.nope")
    assert not _exists(sample, "a.b")


def test_every_read_exists_in_the_sample_or_extra_payload() -> None:
    """Every READS entry resolves in the sample fixture, or is listed and found in the extras."""
    reads = _extract_array("READS", _text())
    fixture = _load_json(FIXTURE)
    missing = []
    for entry in reads:
        if _exists(fixture, entry):
            continue
        if entry in OPTIONAL_PATHS and _exists(EXTRA_PAYLOAD, entry):
            continue
        missing.append(entry)
    assert missing == []


def test_optional_paths_are_honest() -> None:
    """Each OPTIONAL_PATHS entry is in READS, absent from the sample and in the extras."""
    reads = _extract_array("READS", _text())
    fixture = _load_json(FIXTURE)
    for path in OPTIONAL_PATHS:
        assert path in reads, f"{path} is not in READS"
        assert not _exists(fixture, path), f"{path} is in the sample, so it is not optional"
        assert _exists(EXTRA_PAYLOAD, path), f"{path} is not in EXTRA_PAYLOAD"


def test_rd_calls_use_a_simple_first_argument() -> None:
    """Every rd( call has a plain identifier first and a double-quoted, array or name path."""
    total, literals = _rd_calls(_text())
    matched = len(RD_ARGS.findall(_text()))
    assert total > 20
    assert literals
    assert matched == total, "an rd( call has an unusual first or second argument"


def test_every_rd_literal_is_declared_in_reads() -> None:
    """Every string literal passed to rd( names the end of a READS entry."""
    text = _text()
    reads = _extract_array("READS", text)
    _, literals = _rd_calls(text)
    undeclared = sorted({lit for lit in literals if not any(_covers(lit, e) for e in reads)})
    assert undeclared == []


def test_every_reads_entry_is_used_by_an_rd_literal() -> None:
    """Every READS entry is covered by at least one literal rd( call."""
    text = _text()
    reads = _extract_array("READS", text)
    _, literals = _rd_calls(text)
    unused = [entry for entry in reads if not any(_covers(lit, entry) for lit in literals)]
    assert unused == []


def test_rd_path_is_never_a_bare_identifier() -> None:
    """A bare-identifier path in rd( is allowed only for the named internal uses."""
    used = set(_bare_path_args(_text()))
    assert used <= RD_BARE_PATH_ALLOWED, f"rd( called with a bare path: {sorted(used)}"


def test_bare_path_self_test() -> None:
    """The bare-path scan catches a planted identifier path and ignores literals and arrays."""
    assert _bare_path_args("const a = rd(obj, path, 1);") == ["path"]
    assert _bare_path_args('rd(obj, "a.b"); rd(obj, [key]);') == []


def test_covers_self_test() -> None:
    """Literal matching follows whole trailing segments only."""
    assert _covers("status", "e8_status.*.status")
    assert _covers("more.*", "findings[].evidence.*.more.*")
    assert _covers("run.hours", "run.hours")
    assert not _covers("tatus", "e8_status.*.status")
    assert not _covers("hours", "run.hours.extra")
    assert not _covers("a.b.c", "b.c")


# ---------------------------------------------------------------------------
# (b) The fixed ASD domain names
# ---------------------------------------------------------------------------


def test_asd_domains_match_the_dataset_in_order() -> None:
    """The ASD_DOMAINS constant equals the dataset's domains[].name list, in order."""
    domains = _extract_array("ASD_DOMAINS", _text())
    expected = [entry["name"] for entry in _load_json(DATASET)["domains"]]
    assert len(expected) == 8
    assert [entry["name"] for entry in domains] == expected
    assert [entry["kind"] for entry in domains] == ["capability"] * 2 + ["technical"] * 6


def test_sample_domain_names_are_asd_domains() -> None:
    """Every domain name in the sample is an ASD_DOMAINS name, so the map shows a dot."""
    known = {entry["name"] for entry in _extract_array("ASD_DOMAINS", _text())}
    ess = _load_json(FIXTURE)["essentials"]
    names = [
        domain["name"]
        for finding in ess["finding_actions"]
        for action in finding["actions"]
        for domain in action["domains"]
    ]
    for entry in ess["attestation"].values():
        names.extend(entry["domains"])
    assert names, "the sample holds no domain names"
    assert set(names) <= known


# ---------------------------------------------------------------------------
# (c) No network, no external references
# ---------------------------------------------------------------------------


def test_no_external_references_in_markup_or_css() -> None:
    """No script src, link, img, import, font face, url(), iframe or form action."""
    text = _text()
    html = _html_only(text)
    assert not re.search(r"<script[^>]*\bsrc\s*=", text, re.IGNORECASE)
    assert not re.search(r"<link\b", text, re.IGNORECASE)
    assert not re.search(r"<iframe\b", text, re.IGNORECASE)
    assert not re.search(r"<form\b", text, re.IGNORECASE)
    assert not re.search(r"\baction\s*=", html, re.IGNORECASE)
    assert not re.search(r"@import", text, re.IGNORECASE)
    assert not re.search(r"@font-face", text, re.IGNORECASE)
    assert not re.search(r"(?<![A-Za-z])url\s*\(", text, re.IGNORECASE)


def test_href_and_src_values_are_fragments_or_data() -> None:
    """Only href="#..." and data: values appear in markup attributes."""
    html = _html_only(_text())
    for value in re.findall(r"\bhref\s*=\s*[\"']([^\"']*)[\"']", html, re.IGNORECASE):
        assert value.startswith("#"), f"href {value!r} is not an in-page fragment"
    for value in re.findall(r"\bsrc\s*=\s*[\"']([^\"']*)[\"']", html, re.IGNORECASE):
        assert value.startswith("data:"), f"src {value!r} is not a data: value"
    assert not re.search(r"\b(src|href|action)\s*=\s*[\"']\s*//", html, re.IGNORECASE)


def test_no_http_url_outside_whitelisted_constants() -> None:
    """No http:// address at all, and https:// only on the exact constant definition line."""
    text = _text()
    assert "http://" not in text.lower()
    assert text.count(URL_DEFINITION_LINE) == 1
    for number, line in enumerate(text.splitlines(), start=1):
        if "https://" in line.lower():
            assert line.strip() == URL_DEFINITION_LINE, (
                f"line {number} holds an https address outside the constant definition"
            )


def test_guarded_assignments_stay_in_their_helpers() -> None:
    """`.href =` only in safeLink, and `.className =` only in el and showMessage."""
    text = _text()
    for pattern, allowed in GUARDED_ASSIGNMENTS.items():
        sites = _assignment_sites(text, pattern)
        assert sites, f"no assignment found for {pattern}, so the check is not testing anything"
        outside = [(line, func) for line, func in sites if func not in allowed]
        assert outside == [], f"{pattern} used outside {allowed}: {outside}"


def test_guarded_assignment_self_test() -> None:
    """The assignment scan catches a planted violation and attributes sites to functions."""
    planted = (
        "function safeLink(h) {\n  a.href = h;\n}\n"
        "function render(x) {\n  a.href = x;\n  n.className = 'c';\n}\n"
    )
    assert _assignment_sites(planted, r"\.href\s*=(?!=)") == [(2, "safeLink"), (5, "render")]
    assert _assignment_sites(planted, r"\.className\s*=(?!=)") == [(6, "render")]
    assert _assignment_sites("if (a.href == b) {}", r"\.href\s*=(?!=)") == []


def test_no_network_apis() -> None:
    """None of the network APIs appears anywhere, comments included."""
    assert _hits(_text(), BANNED_NETWORK) == []


def test_network_scan_self_test() -> None:
    """The network scan reports known bad strings, so an empty result means something."""
    assert _hits("x = fetch (u)", BANNED_NETWORK) == ["fetch("]
    assert _hits("new XMLHttpRequest()", BANNED_NETWORK) == ["XMLHttpRequest"]
    assert _hits("const s = new EventSource(u)", BANNED_NETWORK) == ["EventSource"]
    assert _hits("prefetching text", BANNED_NETWORK) == []


# ---------------------------------------------------------------------------
# (d) No HTML sinks
# ---------------------------------------------------------------------------


def test_no_html_sinks() -> None:
    """None of the banned DOM sinks appears anywhere, comments included."""
    assert _hits(_text(), BANNED_SINKS) == []


def test_no_inline_event_attributes() -> None:
    """No inline on...= attribute in the markup."""
    html = _html_only(_text())
    assert not re.search(r"<[^>]*\son[a-z]+\s*=", html, re.IGNORECASE)


def test_sink_scan_self_test() -> None:
    """The sink scan reports known bad strings, so an empty result means something."""
    assert _hits("el.innerHTML = x", BANNED_SINKS) == ["innerHTML"]
    assert "handler assignment" in _hits("btn.onclick = go", BANNED_SINKS)
    assert "eval(" in _hits("eval (code)", BANNED_SINKS)
    assert "new Function" in _hits("new Function('x')", BANNED_SINKS)
    assert "setAttribute on..." in _hits("a.setAttribute('onclick', x)", BANNED_SINKS)
    assert _hits("retrieval and addEventListener", BANNED_SINKS) == []
    assert re.search(r"<[^>]*\son[a-z]+\s*=", '<a onclick="x">', re.IGNORECASE)


# ---------------------------------------------------------------------------
# (e) Banned names and words
# ---------------------------------------------------------------------------


def test_no_banned_terms() -> None:
    """None of the banned names, hosts or logo terms appears, in any case."""
    lowered = _text().lower()
    found = [term for term in BANNED_TERMS if term in lowered]
    assert found == []


def test_no_images() -> None:
    """The page has no img tag and no url( reference."""
    text = _text()
    assert not re.search(r"<img\b", text, re.IGNORECASE)
    assert "url(" not in text.lower()


def test_no_banned_whole_words() -> None:
    """Rating words (pass, fail, compliance, score, grade, percentage, rated) never appear."""
    assert BANNED_WORDS.findall(_text()) == []


def test_banned_word_scan_self_test() -> None:
    """The whole-word scan catches known bad words and leaves allowed ones alone."""
    assert BANNED_WORDS.findall("A Pass, a FAILED run, compliance and score") == [
        "Pass",
        "FAILED",
        "compliance",
        "score",
    ]
    assert BANNED_WORDS.findall("rating, ratings, declared ratings, score_base, bypass") == []
    assert BANNED_WORDS.findall("A grade, graded, Percentage and rated") == [
        "grade",
        "graded",
        "Percentage",
        "rated",
    ]
    assert BANNED_WORDS.findall("clampPercent, MIN_BAR_PERCENT, generated_at, upgrades") == []
    lowered = "the Kamaji host and ACSC".lower()
    assert [term for term in BANNED_TERMS if term in lowered] == ["kamaji", "acsc"]


# ---------------------------------------------------------------------------
# (f) Required pieces
# ---------------------------------------------------------------------------


def test_required_pieces_are_present() -> None:
    """The file declares the schema constant, the version message, a try/catch and the CSP."""
    text = _text()
    assert "SUPPORTED_SCHEMA" in text
    assert "schema version" in text
    assert re.search(r"\btry\s*\{", text)
    assert re.search(r"\bcatch\s*\(", text)
    assert text.lstrip().lower().startswith("<!doctype html>")
    assert '<html lang="en">' in text
    assert '<meta charset="utf-8">' in text
    assert 'name="viewport"' in text


def test_csp_meta_tag_is_exact() -> None:
    """The Content-Security-Policy meta tag carries the agreed policy."""
    policy = (
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "img-src data:; base-uri 'none'; form-action 'none'"
    )
    assert f'<meta http-equiv="Content-Security-Policy" content="{policy}">' in _text()


@pytest.mark.parametrize("name", ["READS", "ASD_DOMAINS"])
def test_constant_arrays_are_valid_json(name: str) -> None:
    """READS and ASD_DOMAINS parse as JSON, so the tests can read them."""
    assert isinstance(_extract_array(name, _text()), list)


# ---------------------------------------------------------------------------
# (g) Sections, navigation, fixed wording and the README
# ---------------------------------------------------------------------------

SECTION_IDS = ["overview", "timeline", "findings", "essentials", "e8", "trends"]
NAV_TARGETS = ["overview", "findings", "essentials", "e8", "trends"]

# Wording the page must carry as written (statements, empty states and labels).
REQUIRED_PHRASES = [
    "Not assessed",
    "Operator: ",
    "No commentary",
    "Check",
    "implementation order",
    "Read-only view of the JSON report.",
    "This report has no ASD Essentials data. Report-only runs do not include it.",
    "ASD Essentials for enterprise IT",
    "Attribution and licence",
    "Declared ratings",
    "No ratings declared.",
    "No principles were pointed at for this cluster.",
    "Table view",
    "No trend data",
    "time not available",
    "All phases",
    "No recommendation was generated.",
    "The model wrote no commentary for this cluster.",
    "Ravensight reads alerts, not system settings, so it never rates or assesses.",
    "Kept alongside the Essentials while ASD transitions",
    "No finding has a pointer in these domains.",
]


def test_section_ids_exist_once_each() -> None:
    """Each of the six section elements is present exactly once, with its body element."""
    html = _html_only(_text())
    for name in SECTION_IDS:
        assert len(re.findall(rf'<section id="{name}"', html)) == 1, name
        assert html.count(f'id="{name}-body"') == 1, name


def test_nav_anchors_line_up_with_element_ids() -> None:
    """Every nav href="#x" points at an element with id x, and all five links are there."""
    html = _html_only(_text())
    nav = re.search(r"<nav\b.*?</nav>", html, flags=re.DOTALL)
    assert nav, "no nav element"
    targets = re.findall(r'href="#([^"]+)"', nav.group(0))
    assert targets == NAV_TARGETS
    for target in targets:
        assert html.count(f'id="{target}"') == 1, f"nav target {target} has no single element"


def test_required_phrases_are_present() -> None:
    """The fixed statements, labels and empty-state lines appear in the file."""
    text = _text()
    missing = [phrase for phrase in REQUIRED_PHRASES if phrase not in text]
    assert missing == []


def test_every_literal_id_lookup_has_one_element() -> None:
    """Each literal getElementById("x") or querySelector("#x") matches exactly one id="x"."""
    text = _text()
    html = _html_only(text)
    wanted = set(re.findall(r"getElementById\(\s*\"([^\"]+)\"\s*\)", text))
    wanted |= set(re.findall(r"querySelector(?:All)?\(\s*\"#([\w-]+)\"\s*\)", text))
    assert "report-file" in wanted and "message" in wanted and "nav" in wanted
    for name in sorted(wanted):
        assert html.count(f'id="{name}"') == 1, f"id {name!r} is not in the markup exactly once"


def test_cluster_types_include_rule_vulnerability_and_cluster() -> None:
    """CLUSTER_TYPES lists rule, vulnerability and the cluster fallback."""
    match = re.search(r"const CLUSTER_TYPES = (\[[^\]]*\]);", _text())
    assert match, "CLUSTER_TYPES not found"
    assert set(json.loads(match.group(1))) == {"rule", "vulnerability", "cluster"}


def test_e8_status_needs_attested_before_a_level() -> None:
    """e8StatusText tests the declared status "Attested" before it shows a level."""
    text = _text()
    start = text.index("function e8StatusText(")
    body = text[start : text.index("\n}\n", start)]
    assert 'declaredStatus === "Attested"' in body
    assert body.index('declaredStatus === "Attested"') < body.index("Attested at ML")


def test_page_has_no_img_and_no_external_url() -> None:
    """No img tag, no http address, and no protocol-relative address in the whole file."""
    text = _text()
    assert not re.search(r"<img\b", text, re.IGNORECASE)
    assert "http://" not in text.lower()
    assert not re.search(r"(?<![:\w])//[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)
    others = [
        line
        for line in text.splitlines()
        if "https://" in line.lower() and line.strip() != URL_DEFINITION_LINE
    ]
    assert others == []


def test_every_section_is_filled_by_a_render_function() -> None:
    """Each section body is looked up by a render function, which calls showSection."""
    text = _text()
    for name in SECTION_IDS:
        assert f'getElementById("{name}-body")' in text, f"no render for {name}"
        assert f'showSection("{name}")' in text, f"{name} is never shown"


def test_readme_describes_the_viewer() -> None:
    """The README names the viewer file, the schema version it reads and that it is read-only."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Report viewer" in readme
    assert "web/index.html" in readme
    assert "schema version 3" in readme
    assert "read-only" in readme
