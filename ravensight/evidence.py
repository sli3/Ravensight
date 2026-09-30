"""
evidence.py — mechanical per-cluster evidence extraction from raw alerts.

Each alert cluster carries a few real values ('evidence') pulled straight from
its alerts' fields — file paths, package statuses, opened and closed ports,
container actions, vulnerability states. Evidence is data-built, never
LLM-written, and bounded in size; it is shown to the LLM in the prompt cluster
lines and to the reader in the report. Pure standard-library module.
"""

import ipaddress
import re
from typing import Any

MAX_EVIDENCE_VALUES = 5
MAX_EVIDENCE_NETSTAT_VALUES = 3
MAX_EVIDENCE_VALUE_CHARS = 100
MAX_EVIDENCE_LINE_CHARS = 400

_ELLIPSIS = "…"
_CONTENT_ATTRIBUTES = frozenset({"md5", "sha1", "sha256", "size"})
_EXCLUDED_SEVERITIES = frozenset({"", "-"})
_EXCLUDED_SCORE_BASES = frozenset({"", "-", "-1"})
_FILTERLOG_RE = re.compile(r"filterlog(?:\[\d+\])?:\s*(.*)$")


def _clean(value: Any) -> str:
    """Coerce a raw field to a collapsed, truncated string ('' when empty)."""
    if value is None:
        return ""
    text = " ".join(str(value).split())
    if not text:
        return ""
    if len(text) > MAX_EVIDENCE_VALUE_CHARS:
        return text[: MAX_EVIDENCE_VALUE_CHARS - 1] + _ELLIPSIS
    return text


def _sanitise(value: Any) -> str:
    """Collapse whitespace and escape pipes in one rendered value."""
    return " ".join(str(value).split()).replace("|", "\\|")


def _add_unique(
    values: list[str], value: Any, cap: int = MAX_EVIDENCE_VALUES
) -> None:
    """Append a cleaned distinct value, first-seen order, bounded by cap."""
    text = _clean(value)
    if not text or text in values or len(values) >= cap:
        return
    values.append(text)


def detect_shape(alert: dict[str, Any]) -> str:
    """Classify one alert into exactly one of the seven evidence shapes.

    First match wins: vulnerability, syscheck, dpkg, netstat, docker,
    firewall, then 'generic' as the catch-all — a shape string is always
    returned.
    """
    source = alert.get("_source") or {}
    rule = source.get("rule") or {}
    data = source.get("data")
    if not isinstance(data, dict):
        data = {}
    groups = rule.get("groups") or []
    vuln = data.get("vulnerability")
    if (isinstance(vuln, dict) and bool(vuln)) or (
        "vulnerability-detector" in groups
    ):
        return "vulnerability"
    if "syscheck" in groups:
        return "syscheck"
    if "dpkg" in groups:
        return "dpkg"
    if str(rule.get("id")) == "533":
        return "netstat"
    if "docker" in groups:
        return "docker"
    predecoder = source.get("predecoder")
    if not isinstance(predecoder, dict):
        predecoder = {}
    full_log = source.get("full_log")
    if not isinstance(full_log, str):
        full_log = ""
    if (
        predecoder.get("program_name") == "filterlog"
        or "filterlog[" in full_log
        or "filterlog:" in full_log
    ):
        return "firewall"
    return "generic"


def _empty_shape_acc(shape: str) -> dict[str, Any]:
    """Create the empty per-shape accumulator dict."""
    if shape == "syscheck":
        return {"paths": [], "events": [], "changed": []}
    if shape == "dpkg":
        return {"entries": {}}
    if shape == "netstat":
        return {"added": [], "removed": []}
    if shape == "docker":
        return {
            "containers": [],
            "actions": [],
            "signals": [],
            "compose": [],
            "images": [],
        }
    if shape == "vulnerability":
        return {"statuses": {}, "versions": [], "severities": [], "score_bases": []}
    if shape == "firewall":
        return {
            "actions": [],
            "directions": [],
            "interfaces": [],
            "ipversions": [],
            "protocols": [],
            "sources": [],
            "destinations": [],
            "dstports": [],
            "sources_total": 0,
            "sources_distinct": set(),
        }
    return {"srcips": [], "dstusers": []}


def _accumulate_syscheck(acc: dict[str, Any], alert: dict[str, Any]) -> None:
    """Merge one alert's syscheck path/event/changed attributes into acc."""
    source = alert.get("_source") or {}
    syscheck = source.get("syscheck")
    if not isinstance(syscheck, dict):
        return
    _add_unique(acc["paths"], syscheck.get("path"))
    _add_unique(acc["events"], syscheck.get("event"))
    changed = syscheck.get("changed_attributes")
    if isinstance(changed, list):
        for attribute in changed:
            _add_unique(acc["changed"], attribute)


def _accumulate_dpkg(acc: dict[str, Any], alert: dict[str, Any]) -> None:
    """Merge one alert's dpkg package/version/status into acc."""
    source = alert.get("_source") or {}
    data = source.get("data")
    if not isinstance(data, dict):
        return
    package = _clean(data.get("package"))
    version = _clean(data.get("version"))
    if not package or not version:
        return
    status = _clean(data.get("dpkg_status")).removeprefix("status ")
    entries: dict[str, list[str]] = acc["entries"]
    key = f"{package} {version}"
    if key not in entries and len(entries) >= MAX_EVIDENCE_VALUES:
        return
    statuses = entries.setdefault(key, [])
    _add_unique(statuses, status)


def _parse_netstat_log(log: Any) -> dict[str, dict[str, Any]]:
    """Parse a netstat log into entries keyed by protocol + local address.

    The 'ossec: output:' header line is dropped. The process label is the
    text after the first '/' in the last field, or None when absent.
    """
    entries: dict[str, dict[str, Any]] = {}
    if not isinstance(log, str):
        return entries
    for line in log.splitlines():
        line = line.strip()
        if not line or line.startswith("ossec: output:"):
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        key = f"{fields[0]} {fields[1]}"
        process: str | None = None
        last = fields[-1]
        if "/" in last:
            process = last.split("/", 1)[1] or None
        entries[key] = {
            "label": _clean(key),
            "process": _clean(process) if process else None,
        }
    return entries


def _add_netstat_entry(
    entries: list[dict[str, Any]], entry: dict[str, Any]
) -> None:
    """Append a distinct netstat diff entry, bounded by the netstat cap."""
    if any(existing["label"] == entry["label"] for existing in entries):
        return
    if len(entries) >= MAX_EVIDENCE_NETSTAT_VALUES:
        return
    entries.append(entry)


def _accumulate_netstat(acc: dict[str, Any], alert: dict[str, Any]) -> None:
    """Merge one alert's opened/closed netstat ports into acc.

    No previous_log means no diff baseline and therefore no evidence.
    Same key with a different PID or process is not a change.
    """
    source = alert.get("_source") or {}
    previous = source.get("previous_log")
    if not previous or not isinstance(previous, str):
        return
    current_entries = _parse_netstat_log(source.get("full_log"))
    previous_entries = _parse_netstat_log(previous)
    if not current_entries or not previous_entries:
        return
    for key, entry in current_entries.items():
        if key not in previous_entries:
            _add_netstat_entry(acc["added"], entry)
    for key, entry in previous_entries.items():
        if key not in current_entries:
            _add_netstat_entry(acc["removed"], entry)


def _compose_fields(attrs: dict[str, Any]) -> tuple[str, str]:
    """Return the (project, service) compose labels, flat or nested keys."""
    project = attrs.get("com.docker.compose.project")
    service = attrs.get("com.docker.compose.service")
    nested = attrs.get("com")
    if isinstance(nested, dict):
        docker_ns = nested.get("docker")
        if isinstance(docker_ns, dict):
            compose = docker_ns.get("compose")
            if isinstance(compose, dict):
                project = project or compose.get("project")
                service = service or compose.get("service")
    return _clean(project), _clean(service)


def _accumulate_docker(acc: dict[str, Any], alert: dict[str, Any]) -> None:
    """Merge one alert's docker container/action/signal/compose/image into acc."""
    source = alert.get("_source") or {}
    data = source.get("data")
    if not isinstance(data, dict):
        return
    docker = data.get("docker")
    if not isinstance(docker, dict):
        return
    actor = docker.get("Actor")
    actor = actor if isinstance(actor, dict) else {}
    attrs = actor.get("Attributes")
    attrs = attrs if isinstance(attrs, dict) else {}
    _add_unique(acc["actions"], docker.get("Action"))
    _add_unique(acc["containers"], attrs.get("name"))
    _add_unique(acc["signals"], attrs.get("signal"))
    _add_unique(acc["images"], attrs.get("image"))
    project, service = _compose_fields(attrs)
    if project and service:
        _add_unique(acc["compose"], f"{project}/{service}")
    elif project or service:
        _add_unique(acc["compose"], project or service)


def _accumulate_vulnerability(acc: dict[str, Any], alert: dict[str, Any]) -> None:
    """Merge one alert's vulnerability status/version/severity/score into acc."""
    source = alert.get("_source") or {}
    data = source.get("data")
    if not isinstance(data, dict):
        return
    vuln = data.get("vulnerability")
    if not isinstance(vuln, dict):
        return
    status = _clean(vuln.get("status"))
    if status:
        statuses: dict[str, int] = acc["statuses"]
        statuses[status] = statuses.get(status, 0) + 1
    package = vuln.get("package")
    if isinstance(package, dict):
        _add_unique(acc["versions"], package.get("version"))
    severity = _clean(vuln.get("severity"))
    if severity not in _EXCLUDED_SEVERITIES:
        _add_unique(acc["severities"], severity)
    score = vuln.get("score")
    if isinstance(score, dict):
        base = _clean(score.get("base"))
        if base not in _EXCLUDED_SCORE_BASES:
            _add_unique(acc["score_bases"], base)


def _accumulate_firewall(acc: dict[str, Any], alert: dict[str, Any]) -> None:
    """Merge one alert's OPNsense filterlog lines into the firewall accumulator."""
    source = alert.get("_source") or {}
    full_log = source.get("full_log")
    previous_output = source.get("previous_output")

    lines: list[str] = []
    if isinstance(full_log, str):
        lines.extend(full_log.splitlines())
    if isinstance(previous_output, str):
        lines.extend(previous_output.splitlines())

    for line in lines:
        match = _FILTERLOG_RE.search(line)
        if not match:
            continue
        fields = match.group(1).split(",")
        if len(fields) < 9:
            continue

        interface = _clean(fields[4])
        action = _clean(fields[6])
        direction = _clean(fields[7])
        ipversion_raw = _clean(fields[8])
        if ipversion_raw == "4":
            ipversion = "ipv4"
            version_slice_len = 11
        elif ipversion_raw == "6":
            ipversion = "ipv6"
            version_slice_len = 8
        else:
            continue

        if len(fields) < 9 + version_slice_len:
            continue

        version_fields = fields[9 : 9 + version_slice_len]
        if ipversion == "ipv4":
            protoname = _clean(version_fields[7])
            src = _clean(version_fields[9])
            dst = _clean(version_fields[10])
        else:
            protoname = _clean(version_fields[3])
            src = _clean(version_fields[6])
            dst = _clean(version_fields[7])

        _add_unique(acc["actions"], action)
        _add_unique(acc["directions"], direction)
        _add_unique(acc["interfaces"], interface)
        _add_unique(acc["ipversions"], ipversion)
        _add_unique(acc["protocols"], protoname)
        _add_unique(acc["destinations"], dst)

        if src:
            _add_unique(acc["sources"], src)
            acc["sources_distinct"].add(src)
            acc["sources_total"] = len(acc["sources_distinct"])

        if protoname in ("tcp", "udp"):
            port_start = 9 + version_slice_len
            if len(fields) >= port_start + 3:
                dstport = _clean(fields[port_start + 1])
                _add_unique(acc["dstports"], dstport)


def _accumulate_generic(acc: dict[str, Any], alert: dict[str, Any]) -> None:
    """Merge one alert's generic srcip/dstuser values into acc."""
    source = alert.get("_source") or {}
    data = source.get("data")
    if not isinstance(data, dict):
        return
    srcip = data.get("srcip")
    if srcip is not None:
        try:
            ipaddress.ip_address(str(srcip))
        except ValueError:
            pass
        else:
            _add_unique(acc["srcips"], srcip)
    _add_unique(acc["dstusers"], data.get("dstuser"))


_SHAPE_ACCUMULATORS = {
    "syscheck": _accumulate_syscheck,
    "dpkg": _accumulate_dpkg,
    "netstat": _accumulate_netstat,
    "docker": _accumulate_docker,
    "vulnerability": _accumulate_vulnerability,
    "firewall": _accumulate_firewall,
    "generic": _accumulate_generic,
}


def accumulate(acc: dict[str, Any], alert: dict[str, Any]) -> None:
    """Extract one alert's evidence and merge it into the cluster accumulator.

    Never raises: missing or malformed fields are treated as no evidence.
    """
    if not isinstance(alert, dict):
        return
    shape = detect_shape(alert)
    shape_acc = acc.setdefault(shape, _empty_shape_acc(shape))
    _SHAPE_ACCUMULATORS[shape](shape_acc, alert)


def _project_syscheck(acc: dict[str, Any]) -> dict[str, Any]:
    """Project the syscheck accumulator, deriving the three-state content verdict."""
    out: dict[str, Any] = {}
    if acc["paths"]:
        out["paths"] = sorted(acc["paths"])
    if acc["events"]:
        out["events"] = sorted(acc["events"])
    if acc["changed"]:
        changed = sorted(acc["changed"])
        out["changed"] = changed
        if _CONTENT_ATTRIBUTES.intersection(changed):
            out["content"] = "changed"
        else:
            out["content"] = "unchanged"
    return out


def _project_dpkg(acc: dict[str, Any]) -> dict[str, Any]:
    """Project the dpkg accumulator into rendered package entries."""
    entries: dict[str, list[str]] = acc["entries"]
    if not entries:
        return {}
    rendered = []
    for key, statuses in entries.items():
        if statuses:
            rendered.append(f"{key}: {', '.join(sorted(statuses))}")
        else:
            rendered.append(key)
    return {"packages": sorted(rendered)}


def _render_port(entry: dict[str, Any]) -> str:
    """Render one netstat diff entry, dropping the process suffix when absent."""
    process = entry.get("process")
    if process:
        return f"{entry['label']} ({process})"
    return entry["label"]


def _project_netstat(acc: dict[str, Any]) -> dict[str, Any]:
    """Project the netstat accumulator into added/removed port lists."""
    out: dict[str, Any] = {}
    if acc["added"]:
        out["added"] = sorted(_render_port(entry) for entry in acc["added"])
    if acc["removed"]:
        out["removed"] = sorted(_render_port(entry) for entry in acc["removed"])
    return out


def _project_docker(acc: dict[str, Any]) -> dict[str, Any]:
    """Project the docker accumulator, omitting empty lists."""
    out: dict[str, Any] = {}
    for field in ("containers", "actions", "signals", "compose", "images"):
        if acc[field]:
            out[field] = sorted(acc[field])
    return out


def _project_vulnerability(acc: dict[str, Any]) -> dict[str, Any]:
    """Project the vulnerability accumulator, omitting empty fields."""
    out: dict[str, Any] = {}
    if acc["statuses"]:
        out["statuses"] = dict(sorted(acc["statuses"].items()))
    for field in ("versions", "severities", "score_bases"):
        if acc[field]:
            out[field] = sorted(acc[field])
    return out


def _project_firewall(acc: dict[str, Any]) -> dict[str, Any]:
    """Project the firewall accumulator, omitting empty fields."""
    out: dict[str, Any] = {}
    for field in (
        "actions",
        "directions",
        "interfaces",
        "ipversions",
        "protocols",
        "destinations",
        "dstports",
    ):
        if acc[field]:
            out[field] = sorted(acc[field])
    if acc["sources"]:
        out["sources"] = sorted(acc["sources"])
    if acc["sources_total"]:
        out["sources_total"] = acc["sources_total"]
    return out


def _project_generic(acc: dict[str, Any]) -> dict[str, Any]:
    """Project the generic accumulator, omitting empty lists."""
    out: dict[str, Any] = {}
    if acc["srcips"]:
        out["srcips"] = sorted(acc["srcips"])
    if acc["dstusers"]:
        out["dstusers"] = sorted(acc["dstusers"])
    return out


_SHAPE_PROJECTORS = {
    "syscheck": _project_syscheck,
    "dpkg": _project_dpkg,
    "netstat": _project_netstat,
    "docker": _project_docker,
    "vulnerability": _project_vulnerability,
    "firewall": _project_firewall,
    "generic": _project_generic,
}


def project_evidence(acc: dict[str, Any]) -> dict[str, Any] | None:
    """Project an accumulator into the output evidence dict.

    Lists are sorted. Returns None when nothing was extracted, so the
    'evidence' key stays absent from the output cluster.
    """
    if not isinstance(acc, dict) or not acc:
        return None
    evidence: dict[str, Any] = {}
    for shape, shape_acc in acc.items():
        projector = _SHAPE_PROJECTORS.get(shape)
        if projector is None:
            continue
        projected = projector(shape_acc)
        if projected:
            evidence[shape] = projected
    return evidence or None


def _render_syscheck(data: dict[str, Any]) -> list[str]:
    """Render syscheck evidence fields."""
    parts = []
    if data.get("paths"):
        parts.append("paths " + ", ".join(_sanitise(p) for p in data["paths"]))
    if data.get("events"):
        parts.append("event " + ", ".join(_sanitise(e) for e in data["events"]))
    if data.get("changed"):
        parts.append(
            "changed " + ", ".join(_sanitise(a) for a in data["changed"])
        )
    if data.get("content"):
        parts.append("content " + _sanitise(data["content"]))
    return parts


def _render_dpkg(data: dict[str, Any]) -> list[str]:
    """Render dpkg evidence entries."""
    return [_sanitise(entry) for entry in data.get("packages", [])]


def _render_netstat(data: dict[str, Any]) -> list[str]:
    """Render netstat evidence fields."""
    parts = []
    if data.get("added"):
        parts.append("opened " + ", ".join(_sanitise(e) for e in data["added"]))
    if data.get("removed"):
        parts.append("closed " + ", ".join(_sanitise(e) for e in data["removed"]))
    return parts


_DOCKER_LABELS = (
    ("containers", "container"),
    ("actions", "action"),
    ("signals", "signal"),
    ("compose", "compose"),
    ("images", "image"),
)


def _render_docker(data: dict[str, Any]) -> list[str]:
    """Render docker evidence fields."""
    parts = []
    for field, label in _DOCKER_LABELS:
        if data.get(field):
            parts.append(
                label + " " + ", ".join(_sanitise(v) for v in data[field])
            )
    return parts


def _render_vulnerability(data: dict[str, Any]) -> list[str]:
    """Render vulnerability evidence fields."""
    parts = []
    statuses = data.get("statuses")
    if statuses:
        parts.append(
            "status "
            + ", ".join(
                f"{_sanitise(status)}×{count}"
                for status, count in statuses.items()
            )
        )
    for field, label in (
        ("versions", "version"),
        ("severities", "severity"),
        ("score_bases", "score"),
    ):
        if data.get(field):
            parts.append(
                label + " " + ", ".join(_sanitise(v) for v in data[field])
            )
    return parts


def _render_firewall(data: dict[str, Any]) -> list[str]:
    """Render firewall evidence fields in documented order."""
    parts = []
    if data.get("actions"):
        parts.append(
            "action " + ", ".join(_sanitise(v) for v in data["actions"])
        )
    if data.get("directions"):
        parts.append("dir " + ", ".join(_sanitise(v) for v in data["directions"]))
    if data.get("interfaces"):
        parts.append(
            "iface " + ", ".join(_sanitise(v) for v in data["interfaces"])
        )
    if data.get("ipversions"):
        parts.append(", ".join(sorted(data["ipversions"])))
    if data.get("protocols"):
        parts.append("proto " + ", ".join(_sanitise(v) for v in data["protocols"]))
    sources = data.get("sources")
    if sources:
        src_part = "src " + ", ".join(_sanitise(v) for v in sources)
        total = data.get("sources_total")
        if isinstance(total, int) and total > 1:
            src_part += f" ({total} distinct)"
        parts.append(src_part)
    if data.get("destinations"):
        parts.append("dst " + ", ".join(_sanitise(v) for v in data["destinations"]))
    if data.get("dstports"):
        parts.append(
            "dport " + ", ".join(_sanitise(v) for v in data["dstports"])
        )
    return parts


def _render_generic(data: dict[str, Any]) -> list[str]:
    """Render generic evidence fields."""
    parts = []
    if data.get("srcips"):
        parts.append("srcip " + ", ".join(_sanitise(v) for v in data["srcips"]))
    if data.get("dstusers"):
        parts.append(
            "dstuser " + ", ".join(_sanitise(v) for v in data["dstusers"])
        )
    return parts


_SHAPE_RENDERERS = {
    "vulnerability": _render_vulnerability,
    "syscheck": _render_syscheck,
    "dpkg": _render_dpkg,
    "netstat": _render_netstat,
    "docker": _render_docker,
    "firewall": _render_firewall,
    "generic": _render_generic,
}


def render_evidence(evidence: dict[str, Any] | None) -> str:
    """Render a cluster's evidence dict as one bounded single-line string.

    Fields join with '; ', values within a field with ', '. Whitespace in each
    value collapses to single spaces and '|' escapes as '\\|'. Returns '' when
    evidence is absent or empty.
    """
    if not isinstance(evidence, dict) or not evidence:
        return ""
    parts: list[str] = []
    for shape, renderer in _SHAPE_RENDERERS.items():
        data = evidence.get(shape)
        if isinstance(data, dict) and data:
            parts.extend(renderer(data))
    return "; ".join(part for part in parts if part)