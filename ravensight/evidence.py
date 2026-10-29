"""
evidence.py — mechanical per-cluster evidence extraction from raw alerts.

Each alert cluster carries a few real values ('evidence') pulled straight from
its alerts' fields — syscheck (Wazuh file-integrity monitoring) file paths and
content verdicts, dpkg package/version/status pairs, netstat opened and closed
ports with their processes, docker container action/signal/compose/image
tuples, vulnerability status/severity/score, firewall action/direction/
interface/ipversion/protocol/sources/destinations/destination-port tuples
parsed from OPNsense filterlog lines (the firewall's log format), SCA check
titles with Wazuh's result, and generic srcip/dstuser fallbacks. These eight
shapes provide evidence that is data-built, never LLM-written, and
bounded in size.
"""

import ipaddress
import re
from typing import Any

MAX_EVIDENCE_VALUES = 5
MAX_EVIDENCE_NETSTAT_VALUES = 3
MAX_EVIDENCE_VALUE_CHARS = 100
MAX_EVIDENCE_LINE_CHARS = 400
MAX_EVIDENCE_HOST_CHARS = 120

_ELLIPSIS = "…"
_CONTENT_ATTRIBUTES = frozenset({"md5", "sha1", "sha256", "size"})
_EXCLUDED_SEVERITIES = frozenset({"", "-"})
_EXCLUDED_SCORE_BASES = frozenset({"", "-", "-1"})
_FILTERLOG_RE = re.compile(r"filterlog(?:\[\d+\])?:\s*(.*)$")

_INTERNAL_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
]


def _classify_ip_scope(ip_str: str) -> str | None:
    """Classify one IP string as 'internal' or 'external' against an explicit
    internal-network list; return None for unparseable values. Documentation
    ranges (RFC 5737, 2001:db8::/32) deliberately count as external so redacted
    fixtures behave like real traffic.
    """
    if not isinstance(ip_str, str):
        return None
    try:
        addr = ipaddress.ip_address(ip_str)
    except (TypeError, ValueError):
        return None
    return "internal" if any(addr in net for net in _INTERNAL_NETS) else "external"


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


def sanitise_cell(value: Any) -> str:
    """Collapse whitespace and escape pipes in one rendered value."""
    return " ".join(str(value).split()).replace("|", "\\|")


_sanitise = sanitise_cell


def truncate_words(text: str, limit: int) -> str:
    """Truncate text to at most limit characters, breaking at a word boundary."""
    if len(text) <= limit:
        return text
    cut = text.rfind(" ", 0, limit - 1)
    if cut == -1:
        return text[: limit - 1] + _ELLIPSIS
    return text[:cut] + _ELLIPSIS


def _add_unique(
    values: list[str],
    value: Any,
    cap: int = MAX_EVIDENCE_VALUES,
    dropped: dict[str, set[str]] | None = None,
    field: str = "",
) -> None:
    """Append a cleaned distinct value, first-seen order, bounded by cap.

    A distinct value refused only because of the cap is recorded in dropped[field].
    """
    text = _clean(value)
    if not text or text in values:
        return
    if len(values) >= cap:
        if dropped is not None:
            dropped.setdefault(field, set()).add(text)
        return
    values.append(text)


def _with_more(values: str, data: dict[str, Any], field: str) -> str:
    """Append ' (+N more)' to rendered values when the field overflowed its cap."""
    more = data.get("more")
    if isinstance(more, dict) and more.get(field):
        return f"{values} (+{more[field]} more)"
    return values


def _more_out(out: dict[str, Any], acc: dict[str, Any]) -> dict[str, Any]:
    """Add the 'more' overflow counts to a projection, only when a cap was hit."""
    dropped = acc.get("dropped") or {}
    more = {field: len(vals) for field, vals in sorted(dropped.items()) if vals}
    if out and more:
        out["more"] = more
    return out


def sca_check_policy(alert: dict[str, Any]) -> str | None:
    """Return the cleaned policy name for a valid SCA check alert, else None."""
    if not isinstance(alert, dict):
        return None
    source = alert.get("_source")
    if not isinstance(source, dict):
        return None
    rule = source.get("rule")
    if not isinstance(rule, dict):
        return None
    groups = rule.get("groups")
    if not isinstance(groups, (list, tuple, set)) or "sca" not in groups:
        return None
    data = source.get("data")
    if not isinstance(data, dict):
        return None
    sca = data.get("sca")
    if not isinstance(sca, dict) or sca.get("type") != "check":
        return None
    policy = sca.get("policy")
    if not isinstance(policy, str):
        return None
    return _clean(policy) or None


def detect_shape(alert: dict[str, Any]) -> str:
    """Classify one alert into exactly one of the eight evidence shapes.

    First match wins: vulnerability, syscheck, dpkg, netstat, docker,
    sca, firewall, then 'generic' as the catch-all — a shape string is always
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
    if sca_check_policy(alert) is not None:
        return "sca"
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
    if shape == "sca":
        return {"checks": [], "dropped": {}}
    if shape == "syscheck":
        return {"paths": [], "events": [], "changed": [], "dropped": {}}
    if shape == "dpkg":
        return {"entries": {}, "dropped": {}}
    if shape == "netstat":
        return {"added": [], "removed": [], "dropped": {}}
    if shape == "docker":
        return {
            "containers": [],
            "actions": [],
            "signals": [],
            "compose": [],
            "images": [],
            "dropped": {},
        }
    if shape == "vulnerability":
        return {
            "statuses": {},
            "versions": [],
            "severities": [],
            "score_bases": [],
            "dropped": {},
        }
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
            "src_scopes": set(),
            "dst_scopes": set(),
            "direction_scopes": {},
            "sources_total": 0,
            "sources_distinct": set(),
            "sources_by_version": {"ipv4": set(), "ipv6": set()},
            "dropped": {},
        }
    return {"srcips": [], "dstusers": [], "dropped": {}}


def _accumulate_syscheck(acc: dict[str, Any], alert: dict[str, Any]) -> None:
    """Merge one alert's syscheck path/event/changed attributes into acc."""
    source = alert.get("_source") or {}
    syscheck = source.get("syscheck")
    if not isinstance(syscheck, dict):
        return
    _add_unique(
        acc["paths"],
        syscheck.get("path"),
        dropped=acc["dropped"], field="paths",
    )
    _add_unique(
        acc["events"],
        syscheck.get("event"),
        dropped=acc["dropped"], field="events",
    )
    changed = syscheck.get("changed_attributes")
    if isinstance(changed, list):
        for attribute in changed:
            _add_unique(
                acc["changed"], attribute, dropped=acc["dropped"], field="changed"
            )


def _dpkg_fields(alert: dict[str, Any]) -> tuple[str, str, str] | None:
    """Return (package, version, status) from one dpkg alert's data, or None.

    Package and version are required; status may be empty.
    """
    source = alert.get("_source") or {}
    data = source.get("data")
    if not isinstance(data, dict):
        return None
    package = _clean(data.get("package"))
    version = _clean(data.get("version"))
    if not package or not version:
        return None
    status = _clean(data.get("dpkg_status")).removeprefix("status ")
    return package, version, status


def dpkg_event(alert: dict[str, Any]) -> tuple[str, str] | None:
    """Return ('<package> <version>', status) for one dpkg alert.

    Parsing is identical to _accumulate_dpkg: data.package, data.version, and
    data.dpkg_status with the 'status ' prefix removed. Returns None when
    package, version or status is missing.
    """
    fields = _dpkg_fields(alert)
    if fields is None:
        return None
    package, version, status = fields
    if not status:
        return None
    return f"{package} {version}", status


def _accumulate_dpkg(acc: dict[str, Any], alert: dict[str, Any]) -> None:
    """Merge one alert's dpkg package/version/status into acc."""
    fields = _dpkg_fields(alert)
    if fields is None:
        return
    package, version, status = fields
    key = f"{package} {version}"
    entries: dict[str, list[str]] = acc["entries"]
    if key not in entries and len(entries) >= MAX_EVIDENCE_VALUES:
        acc["dropped"].setdefault("packages", set()).add(key)
        return
    statuses = entries.setdefault(key, [])
    if status:
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
    entries: list[dict[str, Any]],
    entry: dict[str, Any],
    dropped: dict[str, set[str]] | None = None,
    field: str = "",
) -> None:
    """Append a distinct netstat diff entry, bounded by the netstat cap."""
    if any(existing["label"] == entry["label"] for existing in entries):
        return
    if len(entries) >= MAX_EVIDENCE_NETSTAT_VALUES:
        if dropped is not None:
            dropped.setdefault(field, set()).add(entry["label"])
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
            _add_netstat_entry(acc["added"], entry, acc["dropped"], "added")
    for key, entry in previous_entries.items():
        if key not in current_entries:
            _add_netstat_entry(acc["removed"], entry, acc["dropped"], "removed")


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
    _add_unique(
        acc["actions"], docker.get("Action"), dropped=acc["dropped"], field="actions"
    )
    _add_unique(
        acc["containers"], attrs.get("name"), dropped=acc["dropped"], field="containers"
    )
    _add_unique(
        acc["signals"], attrs.get("signal"), dropped=acc["dropped"], field="signals"
    )
    _add_unique(
        acc["images"], attrs.get("image"), dropped=acc["dropped"], field="images"
    )
    project, service = _compose_fields(attrs)
    if project and service:
        _add_unique(
            acc["compose"],
            f"{project}/{service}",
            dropped=acc["dropped"],
            field="compose",
        )
    elif project or service:
        _add_unique(
            acc["compose"],
            project or service,
            dropped=acc["dropped"],
            field="compose",
        )


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
        _add_unique(
            acc["versions"],
            package.get("version"),
            dropped=acc["dropped"],
            field="versions",
        )
    severity = _clean(vuln.get("severity"))
    if severity not in _EXCLUDED_SEVERITIES:
        _add_unique(
            acc["severities"], severity, dropped=acc["dropped"], field="severities"
        )
    score = vuln.get("score")
    if isinstance(score, dict):
        base = _clean(score.get("base"))
        if base not in _EXCLUDED_SCORE_BASES:
            _add_unique(
                acc["score_bases"],
                base,
                dropped=acc["dropped"],
                field="score_bases",
            )


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

        _add_unique(acc["actions"], action, dropped=acc["dropped"], field="actions")
        _add_unique(
            acc["directions"], direction, dropped=acc["dropped"], field="directions"
        )
        _add_unique(
            acc["interfaces"], interface, dropped=acc["dropped"], field="interfaces"
        )
        _add_unique(
            acc["ipversions"], ipversion, dropped=acc["dropped"], field="ipversions"
        )
        _add_unique(
            acc["protocols"], protoname, dropped=acc["dropped"], field="protocols"
        )
        src_scope = _classify_ip_scope(src)
        if src_scope:
            acc["src_scopes"].add(src_scope)
        dst_scope = _classify_ip_scope(dst)
        if dst_scope:
            acc["dst_scopes"].add(dst_scope)
        if src_scope and dst_scope and direction:
            acc["direction_scopes"].setdefault(direction, set()).add(
                (src_scope, dst_scope)
            )
        _add_unique(
            acc["destinations"], dst, dropped=acc["dropped"], field="destinations"
        )

        if src:
            _add_unique(acc["sources"], src)
            acc["sources_distinct"].add(src)
            acc["sources_total"] = len(acc["sources_distinct"])
            acc["sources_by_version"][ipversion].add(src)

        if protoname in ("tcp", "udp"):
            port_start = 9 + version_slice_len
            if len(fields) >= port_start + 3:
                dstport = _clean(fields[port_start + 1])
                _add_unique(
                    acc["dstports"],
                    dstport,
                    dropped=acc["dropped"],
                    field="dstports",
                )


def _accumulate_sca(acc: dict[str, Any], alert: dict[str, Any]) -> None:
    """Merge one SCA check title and Wazuh result into acc."""
    check = alert["_source"]["data"]["sca"].get("check")
    if not isinstance(check, dict):
        return
    title = check.get("title")
    if not isinstance(title, str) or not title.strip():
        return
    title = " ".join(title.split())
    result = check.get("result")
    result = " ".join(str(result).split()) if result is not None else ""
    title_limit = MAX_EVIDENCE_VALUE_CHARS - len(result) - 2
    if result and title_limit > 0:
        value = f"{truncate_words(title, title_limit)}: {result}"
    else:
        value = truncate_words(title, MAX_EVIDENCE_VALUE_CHARS)
    _add_unique(acc["checks"], value, dropped=acc["dropped"], field="checks")


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
            _add_unique(
                acc["srcips"], srcip, dropped=acc["dropped"], field="srcips"
            )
    _add_unique(
        acc["dstusers"],
        data.get("dstuser"),
        dropped=acc["dropped"],
        field="dstusers",
    )


_SHAPE_ACCUMULATORS = {
    "syscheck": _accumulate_syscheck,
    "dpkg": _accumulate_dpkg,
    "netstat": _accumulate_netstat,
    "docker": _accumulate_docker,
    "vulnerability": _accumulate_vulnerability,
    "firewall": _accumulate_firewall,
    "sca": _accumulate_sca,
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
    paths = sorted(acc["paths"]) if acc["paths"] else []
    events = sorted(acc["events"]) if acc["events"] else []
    changed = sorted(acc["changed"]) if acc["changed"] else []
    if changed:
        out["content"] = (
            "changed" if _CONTENT_ATTRIBUTES.intersection(changed) else "unchanged"
        )
    if events:
        out["events"] = events
    if changed:
        out["changed"] = changed
    if paths:
        out["paths"] = paths
    return _more_out(out, acc)


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
    return _more_out({"packages": sorted(rendered)}, acc)


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
    return _more_out(out, acc)


def _project_docker(acc: dict[str, Any]) -> dict[str, Any]:
    """Project the docker accumulator, omitting empty lists."""
    out: dict[str, Any] = {}
    for field in ("containers", "actions", "signals", "compose", "images"):
        if acc[field]:
            out[field] = sorted(acc[field])
    return _more_out(out, acc)


def _project_vulnerability(acc: dict[str, Any]) -> dict[str, Any]:
    """Project the vulnerability accumulator, omitting empty fields."""
    out: dict[str, Any] = {}
    if acc["statuses"]:
        out["statuses"] = dict(sorted(acc["statuses"].items()))
    for field in ("versions", "severities", "score_bases"):
        if acc[field]:
            out[field] = sorted(acc[field])
    return _more_out(out, acc)


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
        if acc["sources_total"] > 1:
            out["sources_by_version"] = {
                version: len(acc["sources_by_version"][version])
                for version in ("ipv4", "ipv6")
                if acc["sources_by_version"][version]
            }
    if acc["src_scopes"]:
        out["src_scopes"] = sorted(acc["src_scopes"])
    if acc["dst_scopes"]:
        out["dst_scopes"] = sorted(acc["dst_scopes"])
    if acc["direction_scopes"]:
        out["direction_scopes"] = {
            direction: sorted([list(pair) for pair in pairs])[:2]
            for direction, pairs in sorted(acc["direction_scopes"].items())
        }
    return _more_out(out, acc)


def _project_sca(acc: dict[str, Any]) -> dict[str, Any]:
    """Project the SCA accumulator into sorted check values."""
    if not acc["checks"]:
        return {}
    return _more_out({"checks": sorted(acc["checks"])}, acc)


def _project_generic(acc: dict[str, Any]) -> dict[str, Any]:
    """Project the generic accumulator, omitting empty lists."""
    out: dict[str, Any] = {}
    if acc["srcips"]:
        out["srcips"] = sorted(acc["srcips"])
    if acc["dstusers"]:
        out["dstusers"] = sorted(acc["dstusers"])
    return _more_out(out, acc)


_SHAPE_PROJECTORS = {
    "syscheck": _project_syscheck,
    "dpkg": _project_dpkg,
    "netstat": _project_netstat,
    "docker": _project_docker,
    "vulnerability": _project_vulnerability,
    "firewall": _project_firewall,
    "sca": _project_sca,
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
    if data.get("content"):
        parts.append("content " + _sanitise(data["content"]))
    if data.get("events"):
        parts.append(
            "event "
            + _with_more(
                ", ".join(_sanitise(e) for e in data["events"]), data, "events"
            )
        )
    if data.get("changed"):
        parts.append(
            "changed "
            + _with_more(
                ", ".join(_sanitise(a) for a in data["changed"]), data, "changed"
            )
        )
    if data.get("paths"):
        parts.append(
            "paths "
            + _with_more(
                ", ".join(_sanitise(p) for p in data["paths"]), data, "paths"
            )
        )
    return parts


def _render_dpkg(data: dict[str, Any]) -> list[str]:
    """Render dpkg evidence entries."""
    parts = [_sanitise(entry) for entry in data.get("packages", [])]
    more = data.get("more")
    if parts and isinstance(more, dict) and more.get("packages"):
        noun = "package" if more["packages"] == 1 else "packages"
        parts[-1] += f" (+{more['packages']} more {noun})"
    return parts


def _render_netstat(data: dict[str, Any]) -> list[str]:
    """Render netstat evidence fields."""
    parts = []
    if data.get("added"):
        parts.append(
            "opened "
            + _with_more(
                ", ".join(_sanitise(e) for e in data["added"]), data, "added"
            )
        )
    if data.get("removed"):
        parts.append(
            "closed "
            + _with_more(
                ", ".join(_sanitise(e) for e in data["removed"]), data, "removed"
            )
        )
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
                label
                + " "
                + _with_more(
                    ", ".join(_sanitise(v) for v in data[field]), data, field
                )
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
                label
                + " "
                + _with_more(
                    ", ".join(_sanitise(v) for v in data[field]), data, field
                )
            )
    return parts


_PLAIN_FIREWALL_LABELS = {
    "dir": "direction",
    "iface": "interface",
    "ip versions": "IP versions",
    "proto": "protocol",
    "src": "source",
    "dst": "destination",
    "dport": "destination port",
}


def _render_firewall(data: dict[str, Any], plain_labels: bool = False) -> list[str]:
    """Render firewall evidence fields in documented order.

    With plain_labels the abbreviated field names are spelled out; the default
    keeps the short labels used in the LLM prompt.
    """

    def label(short: str) -> str:
        """Return the field label, spelled out when plain_labels is set."""
        return _PLAIN_FIREWALL_LABELS.get(short, short) if plain_labels else short

    parts = []
    if data.get("actions"):
        parts.append(
            "action "
            + _with_more(
                ", ".join(_sanitise(v) for v in data["actions"]), data, "actions"
            )
        )
    if data.get("directions"):
        parts.append(
            f"{label('dir')} "
            + _with_more(
                ", ".join(_sanitise(v) for v in data["directions"]),
                data,
                "directions",
            )
        )
    if data.get("interfaces"):
        parts.append(
            f"{label('iface')} "
            + _with_more(
                ", ".join(_sanitise(v) for v in data["interfaces"]),
                data,
                "interfaces",
            )
        )
    src_scopes = data.get("src_scopes") or []
    dst_scopes = data.get("dst_scopes") or []
    direction_scopes = data.get("direction_scopes") or {}
    if direction_scopes and len(direction_scopes) >= 2:
        per_direction_groups = []
        for dir_ in sorted(direction_scopes):
            pairs = sorted(direction_scopes[dir_])[:2]
            group = ", ".join(f"{src_} → {dst_}" for src_, dst_ in pairs)
            per_direction_groups.append(f"{_sanitise(dir_)} {group}")
        parts.append("scope " + " / ".join(per_direction_groups))
    elif src_scopes and dst_scopes:
        src_side = ", ".join(src_scopes)
        dst_side = ", ".join(dst_scopes)
        parts.append(f"scope {src_side} → {dst_side}")
    if data.get("ipversions"):
        parts.append(
            f"{label('ip versions')} "
            + _with_more(
                ", ".join(sorted(data["ipversions"])), data, "ipversions"
            )
        )
    if data.get("protocols"):
        parts.append(
            f"{label('proto')} "
            + _with_more(
                ", ".join(_sanitise(v) for v in data["protocols"]), data, "protocols"
            )
        )
    sources = data.get("sources")
    if sources:
        src_part = f"{label('src')} " + ", ".join(_sanitise(v) for v in sources)
        total = data.get("sources_total")
        versions = data.get("sources_by_version") or {}
        if isinstance(total, int) and total > 1:
            suffix = ", ".join(
                f"{count} {version}"
                for version, count in versions.items()
                if count
            )
            src_part += f" ({total} distinct: " + suffix + ")"
        parts.append(src_part)
    if data.get("destinations"):
        parts.append(
            f"{label('dst')} "
            + _with_more(
                ", ".join(_sanitise(v) for v in data["destinations"]),
                data,
                "destinations",
            )
        )
    if data.get("dstports"):
        parts.append(
            f"{label('dport')} "
            + _with_more(
                ", ".join(_sanitise(v) for v in data["dstports"]), data, "dstports"
            )
        )
    return parts


def _render_sca(data: dict[str, Any]) -> list[str]:
    """Render SCA check titles and their Wazuh results."""
    if not data.get("checks"):
        return []
    return [
        "checks "
        + _with_more(
            ", ".join(_sanitise(value) for value in data["checks"]), data, "checks"
        )
    ]


def _render_generic(data: dict[str, Any]) -> list[str]:
    """Render generic evidence fields."""
    parts = []
    if data.get("srcips"):
        parts.append(
            "srcip "
            + _with_more(
                ", ".join(_sanitise(v) for v in data["srcips"]), data, "srcips"
            )
        )
    if data.get("dstusers"):
        parts.append(
            "dstuser "
            + _with_more(
                ", ".join(_sanitise(v) for v in data["dstusers"]), data, "dstusers"
            )
        )
    return parts


def _render_per_host(data: dict[str, Any], plain_labels: bool = False) -> list[str]:
    """Render per-host evidence as one bracketed segment per host.

    Each host's inner text is that host's projected evidence rendered with
    the shape renderers (per_host excluded), fields joined by '; '. Inner
    text longer than MAX_EVIDENCE_HOST_CHARS is cut with an ellipsis before
    the closing bracket.
    """
    segments: list[str] = []
    for host in sorted(data):
        inner_parts: list[str] = []
        for shape, renderer in _SHAPE_RENDERERS.items():
            if shape == "per_host":
                continue
            inner = data[host].get(shape)
            if isinstance(inner, dict) and inner:
                if shape == "firewall":
                    inner_parts.extend(_render_firewall(inner, plain_labels))
                else:
                    inner_parts.extend(renderer(inner))
        inner = "; ".join(inner_parts)
        if len(inner) > MAX_EVIDENCE_HOST_CHARS:
            cut = truncate_words(inner, MAX_EVIDENCE_HOST_CHARS)
            inner = cut[: -len(_ELLIPSIS)].rstrip(",; ") + _ELLIPSIS
        segments.append(f"[{_sanitise(host)}: {inner}]")
    if not segments:
        return []
    return ["per host " + " ".join(segments)]


_SHAPE_RENDERERS = {
    "vulnerability": _render_vulnerability,
    "syscheck": _render_syscheck,
    "dpkg": _render_dpkg,
    "netstat": _render_netstat,
    "docker": _render_docker,
    "firewall": _render_firewall,
    "sca": _render_sca,
    "generic": _render_generic,
    "per_host": _render_per_host,
}


def _mark_content_differs(data: dict[str, Any], per_host: Any) -> dict[str, Any]:
    """Replace the combined syscheck content verdict with 'differs by host'
    when the per-host verdicts disagree; used for the report only.
    """
    if not isinstance(per_host, dict) or not data.get("content"):
        return data
    values = set()
    for host_data in per_host.values():
        syscheck = host_data.get("syscheck") if isinstance(host_data, dict) else None
        if isinstance(syscheck, dict) and syscheck.get("content"):
            values.add(syscheck["content"])
    if len(values) >= 2:
        return {**data, "content": "differs by host"}
    return data


def render_evidence(
    evidence: dict[str, Any] | None, plain_labels: bool = False
) -> str:
    """Render a cluster's evidence dict as one single-line string.

    Size is bounded by the value caps applied when evidence is extracted and
    by the per-host cap; the prompt's overall line cap
    (MAX_EVIDENCE_LINE_CHARS) is applied by the caller, not here.

    Fields join with '; ', values within a field with ', '. Whitespace in each
    value collapses to single spaces and '|' escapes as '\\|'. Returns '' when
    evidence is absent or empty. plain_labels (for the report) spells out
    firewall field names and shows 'content differs by host' when hosts
    disagree on the syscheck verdict; the default keeps the prompt's short
    labels.
    """
    if not isinstance(evidence, dict) or not evidence:
        return ""
    parts: list[str] = []
    for shape, renderer in _SHAPE_RENDERERS.items():
        data = evidence.get(shape)
        if isinstance(data, dict) and data:
            if shape == "syscheck" and plain_labels:
                data = _mark_content_differs(data, evidence.get("per_host"))
            if shape in ("firewall", "per_host"):
                parts.extend(renderer(data, plain_labels))
            else:
                parts.extend(renderer(data))
    return "; ".join(part for part in parts if part)
