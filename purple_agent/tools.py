"""Local FunctionTools.

These cover everything the SecOps MCP server cannot do for us: the Sigma corpus,
log synthesis, run marking, and the oracle that checks generated events against
the detections they were aimed at. Verification against the tenant (udm_search,
rules, alerts, cases) goes through purple_agent.secops_rest -- the Chronicle REST
API directly, because the hosted MCP endpoint needs a separate permission this
tenant's identity does not hold.

Following the convention in the sibling projects, every function returns a
JSON-serialisable dict and never raises -- a tool that raises leaves the model
holding a call that got no response, and models fill that gap by inventing one.
"""

from __future__ import annotations

import asyncio
import json
import re
import threading
import time
from typing import Any

from . import config, marking, platform_core, secops_rest, usage
from .corpus import match as sigma_match
from .corpus import retrieve
from .synth import mapping, planner, winevt

_SUMMARY_DESCRIPTION_CHARS = 300

# Verification timeline, measured from the moment import_logs returns. The three
# stages settle at different speeds, and querying one before it is due returns
# an empty result that reads exactly like a negative finding.
#
#   parse       ~2 min  events normalised into UDM (observed ~2 min, stable)
#   detection   ~5 min  rule evaluation and SOAR case creation lag ingestion
#   verdict     10 min  nothing may be called a failure before this
_PARSE_CHECK_SECONDS = 120
_DETECTION_CHECK_SECONDS = 300
_VERDICT_FLOOR_SECONDS = 600

# Padding either side of the ingest moment for every verification search.
#
# UDM filters on the EVENT's own timestamp, not on when it was ingested, and
# generated events are deliberately backdated a few minutes (synth.scenario.
# new_scenario). A window derived from "now", or from a rounded run start,
# therefore excludes the run's own events. Observed live: a model-chosen
# startTime of 17:50:00Z missed its own 17:49:05Z event by 55 seconds and
# reported a tenant that had already detected the attack and opened a case as a
# parser failure. Detections inherit the event timestamp too, so a single bad
# window blinds the parse check and the detection check alike.
#
# So the window is computed here and handed to the model rather than left to it.
#
# The two sides are NOT symmetric, and treating them as symmetric caused a
# confidently wrong verdict. An hour of padding BEFORE ingest reaches back over
# any earlier run in the same session, and `list_rule_detections` returns those
# earlier detections indistinguishably from this run's. Observed live: a run that
# ingested at 19:33 claimed a detection stamped 19:03:30 -- fired on the PREVIOUS
# run's events -- together with the case it raised, and reported PASS for a
# technique nothing had actually detected. The tell was a reported latency of 24
# seconds against a platform that had just measured ~5 minutes.
#
# Backdating is bounded (synth.scenario.new_scenario stamps events `minutes_ago`,
# default 3), so the lower bound only has to clear that, not an hour. The upper
# bound stays wide: detections and cases lag ingest, and a detection AFTER our
# ingest cannot belong to an earlier run.
_SEARCH_PAD_BEFORE_SECONDS = 600     # 10 min -- 3x the backdating, with margin
_SEARCH_PAD_AFTER_SECONDS = 3600     # detections and cases lag; wide is harmless

# Built chains, keyed by run_id, so ingest and verification can refer back to a
# run without the full XML making another round trip through the model.
_RUNS: dict[str, dict[str, Any]] = {}

# The run each conversation is currently working on -- set by every run-scoped
# tool, read by save_run_report at the end of that conversation's turn.
#
# Needed because "which run is this turn about" and "which run was ingested most
# recently" are different questions, and answering the second lost a report:
# after a WerFault run was ingested and reported, a later Stage-A-only turn
# about a different rule was written into the WerFault run's folder, overwriting
# its report.md with text about the other run. The Stage-A run was never
# ingested, so the "latest ingested" answer never moved off the first one.
#
# Keyed by session, because a hosted deployment serves several conversations in
# one process. As a single global it was a race with the same consequence as the
# bug above: two testers a minute apart, and whoever called a run-scoped tool
# last owned the variable, so the first one's report was written into the second
# one's folder. Only the on-disk report is affected -- ingest_run takes an
# explicit run_id, so no run ever ingests another run's events -- but that report
# is the deliverable.
_focused_runs: dict[str, str] = {}
_focus_lock = threading.Lock()


def _focus(run_id: str, tool_context=None) -> None:
    """Record that this conversation is now working on this run."""
    if not run_id:
        return
    with _focus_lock:
        _focused_runs[platform_core._session_key(tool_context)] = run_id


def _summarise(rule) -> dict[str, Any]:
    return {
        "sigma_id": rule.sigma_id,
        "title": rule.title,
        "description": rule.description[:_SUMMARY_DESCRIPTION_CHARS],
        "level": rule.level,
        "status": rule.status,
        "logsource": rule.logsource,
        "techniques": rule.techniques,
        "condition": rule.condition,
    }


# --------------------------------------------------------------------------
# Corpus
# --------------------------------------------------------------------------
_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)


def search_detections(
    query: str = "",
    product: str = "",
    category: str = "",
    technique_id: str = "",
    level: str = "",
    limit: int = 8,
) -> dict:
    """Search the Sigma detection corpus for rules describing a threat.

    Hybrid search: exact keyword matching (best for tool names like "mimikatz"
    or "sekurlsa"), semantic similarity (best for phrases like "dumping
    credentials from memory"), and structured filters.

    To emulate a MITRE technique, pass its id as `technique_id` (or just as
    `query` -- a bare id like "T1197" is routed to the structured filter
    automatically). Do NOT free-text the technique's *name* from memory: model
    recall of ATT&CK names is unreliable, and the retrieved rules -- not your
    memory -- define what the technique actually is. (T1197 is BITS Jobs, not
    "bi-directional communication".)

    Prefer rules whose logsource category can be generated. Generatable
    categories: process_access, process_creation, image_load, file_event,
    file_change, file_delete, process_tampering, registry_set, registry_add,
    registry_delete, registry_rename, registry_event, network_connection,
    dns_query, create_remote_thread, ps_script, ps_module.

    Args:
        query: Free text describing the threat, tool, or behaviour. A bare
            technique id here is treated as a technique_id filter.
        product: Logsource product filter, e.g. "windows".
        category: Logsource category filter, e.g. "process_access".
        technique_id: MITRE technique filter, e.g. "T1003.001".
        level: Severity filter: "critical", "high", "medium", "low".
        limit: Maximum rules to return (default 8).

    Returns:
        dict with `count`, `rules`, and `generatable_count`. When a technique's
        rules exist but none are generatable, `guidance` explains why.
    """
    # A bare technique id typed into `query` is a filter, not free text --
    # otherwise "T1197" matches unrelated rules by fuzzy keyword/semantic score
    # (e.g. a T1110 password-spray rule), which is how the wrong scenario gets
    # emulated.
    if query and not technique_id and _TECHNIQUE_ID.match(query.strip()):
        technique_id = query.strip().upper()
        query = ""

    try:
        rules = retrieve.search(
            query=query, product=product, category=category,
            technique_id=technique_id, level=level, limit=max(1, min(limit, 25)),
        )
    except Exception as exc:  # noqa: BLE001
        return {
            "error": f"{type(exc).__name__}: {exc}",
            "hint": "Is the index built? Run: python scripts/build_index.py",
        }

    out = []
    for rule in rules:
        summary = _summarise(rule)
        summary["generatable"] = bool(
            mapping.resolve_event_ids(rule.logsource_category, rule.logsource_service)
        )
        out.append(summary)

    generatable = sum(1 for r in out if r["generatable"])
    result = {"count": len(out), "generatable_count": generatable, "rules": out}

    if out and generatable == 0:
        # The technique is covered by Sigma but only in log sources this agent
        # cannot synthesise (e.g. T1197's bits-client / proxy rules). Say so
        # plainly rather than letting the agent generate the wrong event type.
        sources = sorted({
            r["logsource"].get("category") or r["logsource"].get("service") or "?"
            for r in out
        })
        result["guidance"] = (
            "Rules exist but none map to a generatable Windows event. Their log "
            f"sources are: {', '.join(sources)}. Try a broader search (drop the "
            "product/category filter) to find a process_creation or image_load "
            "rule for the same behaviour -- e.g. the tool's command line -- or "
            "tell the user this technique cannot be emulated with the current "
            "event templates."
        )
    return result


def get_detection_rule(sigma_id: str) -> dict:
    """Fetch one Sigma rule in full, including its detection logic.

    Use this to read the exact field selectors a rule matches on -- those are
    what the generated events must satisfy.

    Args:
        sigma_id: The rule's Sigma id from search_detections.

    Returns:
        dict with the rule's metadata, `detection` (raw selection blocks), and
        `condition`.
    """
    rule = retrieve.get_rule(sigma_id)
    if rule is None:
        return {"error": f"no rule with sigma_id {sigma_id!r} in the index"}
    return {
        **_summarise(rule),
        "description": rule.description,
        "detection": rule.detection,
        "falsepositives": rule.falsepositives,
        "references": rule.references,
    }


def list_supported_events() -> dict:
    """List the Windows event types this agent can generate.

    Returns:
        dict with each supported Event ID, its channel, its Chronicle log type,
        and its EventData field names.
    """
    return {
        "events": mapping.supported_events(),
        "generatable_categories": sorted(mapping.CATEGORY_EVENTS),
        "note": (
            "Sysmon ingests as WINDOWS_SYSMON and Security-channel events as "
            "WINEVTLOG_XML. They need separate import_logs calls."
        ),
    }


# --------------------------------------------------------------------------
# Generation
# --------------------------------------------------------------------------
def start_run(tool_context=None) -> dict:
    """Begin a purple-team run: mint a run id and its marker hostname.

    Call this FIRST. Every generated event carries the returned hostname, which
    is what keeps synthetic data distinguishable from real activity in the SIEM
    and what finds the run again after ingest.

    Returns:
        dict with `run_id`, `hostname`, `fqdn`, `started_at`, `udm_query` (the
        search to try FIRST after ingest) and `udm_queries` -- the ordered
        fallbacks to work through if it comes back empty. Events carry the FQDN,
        so an exact match on the short hostname is the LAST thing to try, not
        the first.
    """
    run = marking.new_run()
    _RUNS[run.run_id] = {"run": run, "events": []}
    _focus(run.run_id, tool_context)
    return run.to_dict()


def plan_events(sigma_ids: list[str]) -> dict:
    """Work out which events and field values would satisfy the given rules.

    Maps each rule's logsource to a Windows Event ID and inverts its selectors
    into concrete field values. Review the plan, fill in anything listed in
    `unresolved`, then pass the steps to build_events.

    Args:
        sigma_ids: Sigma rule ids to target, from search_detections.

    Returns:
        dict with `steps` (each carrying event_id and fields), `unmappable`
        rules, and `unresolved_total`.
    """
    if not sigma_ids:
        return {"error": "no sigma_ids supplied"}
    try:
        return planner.plan_from_rules(sigma_ids)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}


def build_events(
    run_id: str,
    hostname: str,
    steps_json: str,
    sigma_ids: list[str],
    username: str = "",
    domain: str = "",
    tool_context=None,
) -> dict:
    """Generate the Windows Event XML, then check it before anything is sent.

    Runs three things in one call so none can be skipped: synthesis, the Sigma
    oracle, and the marking check. Read `oracle.assessment` and
    `marking.safe_to_ingest` before proposing an import.

    Args:
        run_id: From start_run.
        hostname: The marker hostname from start_run.
        steps_json: JSON array of steps from plan_events, with any edits. Each
            step needs `event_id` and `fields`; `offset_seconds` is optional.
        sigma_ids: The rule ids these events are meant to satisfy.
        username: Optional actor username (default svc_backup).
        domain: Optional Windows NetBIOS domain. Defaults to
            PURPLE_NETBIOS_DOMAIN, or CORP when that is unset.

    Returns:
        dict with a compact per-event `summary`, `oracle`, `marking`,
        `log_types`, and the `saved` folder. The raw XML is deliberately NOT
        returned -- it is held server-side and written to disk. Ingest it with
        `ingest_run(run_id)`, which needs no payload from you.
    """
    if not marking.is_valid_run_id(run_id):
        return {
            "error": f"invalid run_id {run_id!r} -- must be the 8-character id "
            "start_run returned, not a value composed by hand. This run_id "
            "would otherwise be joined onto the output directory unescaped.",
        }
    expected_hostname = f"{config.HOST_PREFIX}{run_id}"
    if hostname != expected_hostname:
        return {
            "error": f"hostname {hostname!r} does not match this run's marker "
            f"{expected_hostname!r} -- pass the hostname start_run returned for "
            "this run_id, unedited. Marking works by checking generated events "
            "for the hostname they were built with, so a self-consistent but "
            "wrong hostname would pass its own check and still ingest unmarked.",
        }
    _focus(run_id, tool_context)
    try:
        steps = json.loads(steps_json)
    except json.JSONDecodeError as exc:
        return {"error": f"steps_json is not valid JSON: {exc}"}
    if not isinstance(steps, list) or not steps:
        return {"error": "steps_json must be a non-empty JSON array of steps"}

    try:
        built = planner.build_chain(
            steps, hostname=hostname, username=username, domain=domain
        )
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}

    events: list[winevt.GeneratedEvent] = built["events"]
    if not events:
        return {"error": "no events were generated", "errors": built["errors"]}

    oracle = planner.verify_chain(sigma_ids, events) if sigma_ids else {}
    if oracle:
        oracle["assessment"] = _oracle_assessment(
            oracle["matched"], oracle["unsupported"], oracle["rules_checked"]
        )

    plausibility = []
    for ev in events:
        for finding in _implausible_fields(ev.fields):
            plausibility.append({"event_id": ev.fields.get("EventID"), **finding})

    mark = marking.check_events([e.fields for e in events], hostname)
    mark["guidance"] = (
        "Safe to import."
        if mark["safe_to_ingest"]
        else (
            f"{len(mark['unmarked_indexes'])} event(s) do not reference {hostname}. "
            "Do NOT import."
        )
    )

    groups = winevt.group_by_log_type(events)
    _RUNS.setdefault(run_id, {})["events"] = events
    _RUNS[run_id]["groups"] = groups
    # ingest_run's actual gate. mark["safe_to_ingest"] alone is advisory text in
    # the return value -- a model can misread it or be talked out of it. Storing
    # it here is what makes "unmarked synthetic data must never be ingested" an
    # enforced invariant instead of a prompt the model is trusted to follow.
    _RUNS[run_id]["safe_to_ingest"] = mark["safe_to_ingest"]
    # The rules this run set out to exercise, kept so find_run_detections can
    # match them against the tenant's own rule names later. Without this the
    # model picks candidates by eye from one page of a 500+ rule inventory, and
    # a rule it never saw reads as "nothing fired".
    _RUNS[run_id]["targets"] = [
        {"sigma_id": r.get("rule_id"), "title": r.get("rule_title")}
        for r in (oracle.get("results") or [])
        if r.get("rule_title")
    ]

    run_ctx = marking.RunContext(
        run_id=run_id,
        hostname=hostname,
        started_at=built["context"]["started"],
        # From the built events, not config: the manifest's UDM queries must
        # match the FQDN that was actually written into <Computer>.
        dns_domain=built["context"].get("dns_domain", ""),
    )
    # Replace the run minted by start_run: this one knows the domain the events
    # were actually built with, so ingest and verification quote the right FQDN.
    _RUNS[run_id]["run"] = run_ctx
    try:
        saved = marking.save_run(
            run_ctx,
            {"events": [e.to_dict() for e in events], "groups": groups},
            groups=groups,
        )
    except OSError as exc:
        saved = {"error": f"could not write run folder: {exc}"}

    return {
        "run_id": run_id,
        "hostname": hostname,
        "context": built["context"],
        "event_count": len(events),
        # No `groups` here on purpose: the raw XML is ~4 KB and re-emitting it
        # through the model is what blew the output-token cap. It lives in _RUNS
        # and on disk; ingest_run() reads it directly.
        "summary": [_event_row(e) for e in events],
        "oracle": oracle,
        "marking": mark,
        "implausible_values": plausibility,
        "plausibility_guidance": (
            "" if not plausibility else
            f"{len(plausibility)} generated value(s) are not telemetry a real "
            "Windows host would produce -- fragments were joined into nonsense. "
            "The oracle still says MATCH because every fragment is present, but a "
            "deployed rule will not fire on these, and the run would report a "
            "coverage gap that is really a GENERATION problem. Rewrite the listed "
            "fields in your steps as realistic values that still contain every "
            "fragment in the rule's constraints, then call build_events again."
        ),
        "build_errors": built["errors"],
        "saved": saved,
        "log_types": sorted(groups),
    }


# Fields worth showing per event, by channel. A compact row instead of the full
# ordered EventData map keeps build_events' output small.
_KEY_FIELDS = (
    "Image", "NewProcessName", "SourceImage", "TargetImage", "CommandLine",
    "GrantedAccess", "TargetFilename", "TargetObject", "DestinationIp",
    "QueryName", "ServiceName", "TargetUserName",
)


def _event_row(event) -> dict:
    """One compact summary row for an event -- never the whole field map."""
    fields = {k: event.fields[k] for k in _KEY_FIELDS if k in event.fields and event.fields[k] not in ("-", "0", "")}
    # Cap any single value so an over-long path can't reinflate the payload.
    fields = {k: (v[:120] + "…" if len(str(v)) > 120 else v) for k, v in list(fields.items())[:4]}
    return {
        "event_id": event.event_id,
        "channel": event.channel,
        "log_type": event.log_type,
        "key_fields": fields,
    }


def _oracle_assessment(matched: int, unsupported: int, total: int) -> str:
    if total == 0:
        return "No rules checked."
    if matched:
        return (
            f"{matched}/{total} target rules are satisfied by these events. "
            "Detection content with this logic SHOULD fire. If SecOps reports "
            "nothing after ingest, that is a genuine coverage gap."
        )
    if unsupported == total:
        return (
            "Every target rule uses logic this oracle cannot evaluate against a "
            "single event. Inconclusive -- do not report it as either success "
            "or a coverage gap."
        )
    return (
        "No target rule is satisfied by these events. This is a GENERATION "
        "problem, not a coverage gap. Adjust the step fields using the exact "
        "values from get_detection_rule and rebuild before importing anything."
    )


async def ingest_run(run_id: str, tool_context=None) -> dict:
    """Import a built run's events into SecOps and start the verification clock.

    This is the Stage B ingest. It reads the generated XML from the run store and
    calls `secops_rest.import_logs` once per log type -- from here, not from your
    output. You pass only the run_id; no XML, no forwarder id, no per-log-type
    loop. This is deliberate: re-emitting kilobytes of event XML is what
    exhausts the response token budget, and a truncated import is malformed XML
    that the parser silently drops.

    Only call this after the user has confirmed the import. It writes to a live
    SIEM.

    Args:
        run_id: The run id from start_run, already passed to build_events.

    Returns:
        dict with per-log-type `results` ({log_type, event_count, status}), the
        marker `hostname` and `fqdn`, and `verification` -- when each check
        becomes due, plus `udm_queries`, the ordered searches to try once the
        parse stage is due. An `import_logs` success is an empty body --
        accepted, not verified; only udm_search confirms parsing.
    """
    _focus(run_id, tool_context)
    entry = _RUNS.get(run_id) or {}
    groups = entry.get("groups") or {}
    if not groups:
        return {
            "error": f"run {run_id!r} has no built events",
            "next_step": (
                "Call build_events for this run. If it WAS built earlier in this "
                "conversation, the run store was lost -- it lives in the server "
                "process, and a hosted instance that scales to zero while idle "
                "discards it. Nothing was ingested. Re-run start_run and "
                "build_events; the generated events are deterministic, so the "
                "same scenario reproduces."
            ),
        }

    if not entry.get("safe_to_ingest"):
        return {
            "error": f"run {run_id!r} is not safe to ingest -- build_events "
            "reported event(s) missing the marker hostname (marking."
            "safe_to_ingest was false). Unmarked synthetic data in this "
            "tenant is indistinguishable from a real intrusion.",
            "next_step": (
                "Read the `marking` field from that build_events response, fix "
                "whatever produced unmarked events, and call build_events again "
                "before retrying ingest_run."
            ),
        }

    if not config.FORWARDER_ID:
        return {
            "error": "SECOPS_FORWARDER_ID is not set in purple_agent/.env",
            "hint": "Discover one with: python scripts/find_forwarder.py",
        }

    results = []
    any_ok = False
    for log_type, logs in groups.items():
        response = await secops_rest.import_logs(log_type, logs, config.FORWARDER_ID)
        if "error" in response:
            results.append({
                "log_type": log_type,
                "event_count": len(logs),
                "status": "error",
                "detail": f"{response['error']}: {str(response.get('detail',''))[:160]}",
            })
        else:
            any_ok = True
            results.append({
                "log_type": log_type,
                "event_count": len(logs),
                "status": "accepted",  # empty body = accepted, not verified
            })

    run_obj = entry.get("run")
    hostname = run_obj.hostname if run_obj else ""

    if not any_ok:
        return {
            "run_id": run_id,
            "hostname": hostname,
            "results": results,
            "error": "every import_logs call failed; nothing was ingested",
        }

    # Start the verification clock now that data is in flight.
    clock = record_ingest(run_id)

    return {
        "run_id": run_id,
        "hostname": hostname,
        "fqdn": run_obj.fqdn if run_obj else "",
        "results": results,
        "verification": {
            "ingested_at": clock["ingested_at"],
            "parse_check_due_in_seconds": clock["parse_check_due_in_seconds"],
            "detection_check_due_in_seconds": clock["detection_check_due_in_seconds"],
            "verdict_allowed_in_seconds": clock["verdict_allowed_in_seconds"],
            # Repeated here, at the point of use: the events carry the FQDN, so
            # the exact short-hostname search is the last rung to try, not the
            # first. Run these in order and stop at the first hit.
            "udm_queries": run_obj.udm_queries if run_obj else [],
            # The time range those queries must use. Supplied rather than left
            # to the caller: every rung of the ladder returns nothing if the
            # window excludes the event, which reads as a parse failure.
            "search_window": clock["search_window"],
        },
        "note": clock["note"],
    }


# --------------------------------------------------------------------------
# Context and support
# --------------------------------------------------------------------------
def sigma_coverage_reference(technique_id: str) -> dict:
    """Count the Sigma rules that exist for a MITRE technique.

    Context for the report: "Sigma publishes N rules for this technique, SecOps
    matched M" is more actionable than SecOps' answer alone.

    Args:
        technique_id: MITRE technique, e.g. "T1003.001".

    Returns:
        dict with the rule count, severity breakdown, and a sample.
    """
    rules = retrieve.rules_for_technique(technique_id, limit=200)
    if not rules:
        return {"technique_id": technique_id, "sigma_rule_count": 0}
    by_level: dict[str, int] = {}
    for rule in rules:
        by_level[rule.level or "unrated"] = by_level.get(rule.level or "unrated", 0) + 1
    return {
        "technique_id": technique_id,
        "sigma_rule_count": len(rules),
        "by_level": by_level,
        "sample": [{"sigma_id": r.sigma_id, "title": r.title} for r in rules[:10]],
    }


def record_ingest(run_id: str) -> dict:
    """Start the verification clock. Call IMMEDIATELY after the last import_logs.

    Everything downstream is timed from this moment. Without it,
    verification_status cannot tell you what is due and you will be guessing.

    Args:
        run_id: The run id from start_run.

    Returns:
        dict with the recorded time and when each verification stage becomes due.
    """
    entry = _RUNS.setdefault(run_id, {})
    entry["ingested_at"] = time.time()
    return {
        "run_id": run_id,
        "ingested_at": _iso(entry["ingested_at"]),
        "parse_check_due_in_seconds": _PARSE_CHECK_SECONDS,
        "detection_check_due_in_seconds": _DETECTION_CHECK_SECONDS,
        "verdict_allowed_in_seconds": _VERDICT_FLOOR_SECONDS,
        "search_window": _search_window(entry["ingested_at"]),
        "note": (
            "Check parsing first. Do not query detections, alerts or cases "
            f"until {_DETECTION_CHECK_SECONDS // 60} minutes have elapsed -- rule "
            "evaluation and SOAR case creation lag ingestion, and an early query "
            "returns an empty result that looks like a negative finding."
        ),
    }


def _iso(epoch: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _search_window(ingested_at: float) -> dict:
    """The startTime/endTime every verification query for this run must use.

    Returned from ingest_run, verification_status and await_stage so the model
    always has it to hand and never has cause to derive one. See
    _SEARCH_PAD_BEFORE_SECONDS for why deriving one is a trap, and why the two
    sides are not the same size.
    """
    return {
        "startTime": _iso(ingested_at - _SEARCH_PAD_BEFORE_SECONDS),
        "endTime": _iso(ingested_at + _SEARCH_PAD_AFTER_SECONDS),
        "note": (
            "Pass these verbatim as startTime/endTime to every udm_search and "
            "list_rule_detections call for this run. Do NOT compute your own: "
            "UDM filters on the event's own timestamp, which is backdated "
            "several minutes from the ingest time, so a window derived from the "
            "run start or from 'now' silently excludes this run's own events "
            "and reads as a parse failure."
        ),
    }


def _stage_readiness(elapsed: int) -> dict:
    """Per-stage readiness for a given elapsed time. Shared by the status and
    the blocking-wait tools so their verdicts can never drift apart."""
    parse_due = elapsed >= _PARSE_CHECK_SECONDS
    detection_due = elapsed >= _DETECTION_CHECK_SECONDS
    verdict_ok = elapsed >= _VERDICT_FLOOR_SECONDS

    if not parse_due:
        next_step = (
            f"Wait {_PARSE_CHECK_SECONDS - elapsed}s, then udm_search for the "
            "marker host -- FQDN first, then the regex and exact-hostname "
            "fallbacks from start_run's udm_queries."
        )
    elif not detection_due:
        next_step = (
            "Parse check is due now (udm_search: FQDN first, then the regex and "
            "exact-hostname fallbacks before calling it a parse failure). "
            "Do NOT query detections, "
            f"alerts or cases yet -- {_DETECTION_CHECK_SECONDS - elapsed}s "
            "remaining before those are meaningful."
        )
    elif not verdict_ok:
        next_step = (
            "Detections and cases are due now: list_rule_detections, then "
            f"list_cases. Do not state a verdict for another "
            f"{_VERDICT_FLOOR_SECONDS - elapsed}s."
        )
    else:
        next_step = "All checks are due. A verdict may now be stated."

    return {
        "elapsed_seconds": elapsed,
        "elapsed_readable": f"{elapsed // 60}m{elapsed % 60:02d}s",
        "parse_check_due": parse_due,
        "detection_and_case_check_due": detection_due,
        "verdict_allowed": verdict_ok,
        "next_step": next_step,
    }


# Stage name -> the elapsed threshold at which it becomes meaningful to check.
_STAGE_THRESHOLDS = {
    "parse": _PARSE_CHECK_SECONDS,
    "detections": _DETECTION_CHECK_SECONDS,
    "detection": _DETECTION_CHECK_SECONDS,   # alias
    "cases": _DETECTION_CHECK_SECONDS,       # alias
    "verdict": _VERDICT_FLOOR_SECONDS,
}
# Largest in-order transition (detections -> verdict) is 300s, so one call
# covers any single stage step. A bounded, chunked sleep keeps the whole Stage B
# poll loop to one model turn per stage instead of a status/wait loop per turn.
_AWAIT_CAP_SECONDS = 300
_AWAIT_CHUNK_SECONDS = 10


def verification_status(run_id: str, tool_context=None) -> dict:
    """How long since ingest, and which verification steps are due yet.

    A cheap, non-blocking “where am I?” check. In the normal Stage B flow you do
    not need to call this repeatedly -- prefer `await_stage`, which waits until a
    stage is due and returns this same readiness in one call.

    Args:
        run_id: The run id from start_run.

    Returns:
        dict with elapsed time, per-stage readiness, and what to do next.
    """
    _focus(run_id, tool_context)
    entry = _RUNS.get(run_id) or {}
    ingested_at = entry.get("ingested_at")
    if ingested_at is None:
        return {
            "run_id": run_id,
            "error": "no ingest recorded for this run",
            "hint": "Call record_ingest(run_id) right after import_logs.",
        }
    elapsed = int(time.time() - ingested_at)
    return {
        "run_id": run_id,
        **_stage_readiness(elapsed),
        "search_window": _search_window(ingested_at),
    }


async def await_stage(run_id: str, stage: str, tool_context=None) -> dict:
    """Wait until a verification stage is due, then return its readiness.

    This is how Stage B passes time. Instead of polling verification_status
    turn by turn -- each a full model turn that re-reads the whole context --
    call await_stage ONCE per stage. It blocks server-side until the
    stage settles, then returns, so the whole poll costs one turn per stage.

    Call the stages in order as you need them:
      "parse"       ~2 min  -> then udm_search for the marker host, working
                               start_run's udm_queries in order (FQDN, regex,
                               exact) until one hits
      "detections"  ~5 min  -> then list_rule_detections, list_cases (aliases:
                               "detection", "cases")
      "verdict"     10 min  -> earliest a firm verdict may be stated

    A single call blocks at most ~5 minutes. If you skip ahead (e.g. ask for
    "verdict" straight after ingest) it returns `due: false` after the cap --
    call it again, or await the earlier stages first.

    Args:
        run_id: The run id from start_run.
        stage: "parse", "detections", or "verdict".

    Returns:
        dict with `stage`, `due`, `waited_seconds`, and the same readiness fields
        as verification_status.
    """
    _focus(run_id, tool_context)
    threshold = _STAGE_THRESHOLDS.get((stage or "").strip().lower())
    if threshold is None:
        return {
            "run_id": run_id,
            "error": f"unknown stage {stage!r}",
            "valid_stages": ["parse", "detections", "verdict"],
        }

    entry = _RUNS.get(run_id) or {}
    ingested_at = entry.get("ingested_at")
    if ingested_at is None:
        return {
            "run_id": run_id,
            "error": "no ingest recorded for this run",
            "hint": "Call record_ingest(run_id) right after import_logs.",
        }

    started = time.time()
    deadline = started + _AWAIT_CAP_SECONDS
    while True:
        elapsed = int(time.time() - ingested_at)
        if elapsed >= threshold:
            due = True
            break
        if time.time() >= deadline:
            due = False
            break
        # Sleep only as long as needed, in small chunks so the wait stays
        # interruptible and re-reads the real clock each time.
        remaining_to_due = threshold - elapsed
        remaining_to_cap = deadline - time.time()
        await asyncio.sleep(
            max(1, min(_AWAIT_CHUNK_SECONDS, remaining_to_due, remaining_to_cap))
        )

    waited = int(time.time() - started)
    readiness = _stage_readiness(int(time.time() - ingested_at))
    result = {"run_id": run_id, "stage": stage, "due": due,
              "waited_seconds": waited, **readiness,
              "search_window": _search_window(ingested_at)}
    if not due:
        result["next_step"] = (
            f"Still {threshold - readiness['elapsed_seconds']}s before {stage} is "
            "due (you may have skipped ahead). Call await_stage again, or await "
            "the earlier stages first."
        )
    return result


def _run_to_persist(session_id: str) -> str | None:
    """The run THIS conversation's artefacts belong to, or None to write nothing.

    The run this session's turn actually worked on, and only if it has been
    ingested -- "ingested" meaning ingest_run recorded a timestamp on it. A
    Stage-A-only dry run leaves just its generated events, not a report.

    Deliberately NOT "the most recently ingested run", and deliberately scoped to
    the calling session rather than the process: both of those are different
    questions, and answering either of them wrote one run's report into another
    run's folder. There is no fallback here on purpose. If this session's focused
    run was never ingested, the right outcome is to write nothing, not to write
    somewhere else.
    """
    with _focus_lock:
        run_id = _focused_runs.get(session_id)
    if run_id is None:
        return None
    entry = _RUNS.get(run_id) or {}
    return run_id if entry.get("ingested_at") else None


def save_run_report(callback_context) -> None:
    """After-agent callback: write the report and token usage to the run folder.

    Runs at the end of each turn. If the run this turn worked on has been
    ingested, its folder (out/<run_id>/) gets:
      - report.md   the turn's report -- captured from the model callback, never
                    re-emitted by the model
      - usage.json  the session's token totals. Because this fires AFTER the
                    final model response's usage was recorded, this figure is
                    complete -- unlike the in-chat token_usage tool, which
                    cannot count the response that contains it.

    A later turn about the SAME run overwrites both, so the last turn leaves the
    finished report. A turn about a different run writes to that run's folder,
    or nowhere if it was never ingested -- see _run_to_persist.

    The buffered text is cleared either way, so a turn's report can never leak
    into the next one's folder. Never raises -- a callback that throws would
    abort the agent's response.
    """
    session_id = platform_core._session_key(callback_context)
    try:
        run_id = _run_to_persist(session_id)
        if run_id is None:
            return

        directory = config.OUT_DIR / run_id
        directory.mkdir(parents=True, exist_ok=True)

        report = usage.get_report(session_id)
        if report.strip():
            (directory / "report.md").write_text(report, encoding="utf-8")

        snap = usage.snapshot(session_id)
        (directory / "usage.json").write_text(
            json.dumps(snap.to_dict(), indent=2), encoding="utf-8"
        )
    except Exception as exc:  # noqa: BLE001 - a callback must never abort the turn
        # Best-effort persistence; log via print since this is off the tool path.
        print(f"[save_run_report] could not persist run artefacts: {exc}")
    finally:
        usage.clear_report(session_id)
    return None


def token_usage(tool_context) -> dict:
    """Return this session's LLM token usage so far, for the report.

    Call this LAST, once the report body is written, and append the numbers as
    the final section. The count covers the whole session -- Stage A and Stage B
    together, since it is one conversation.

    One honest limitation: the total excludes the very response that contains it.
    A model cannot count the tokens of the message it has not finished writing,
    so the figure is "everything up to this final turn". State it as such.

    Returns:
        dict with `llm_calls`, `prompt_tokens`, `completion_tokens`,
        `cached_tokens`, `total_tokens`, an `estimated_cost_usd` (null when the
        model has no pricing entry), and a one-line `summary`.
    """
    session = getattr(tool_context, "session", None)
    session_id = getattr(session, "id", "default")
    snap = usage.snapshot(session_id)
    result = snap.to_dict()
    result["note"] = (
        "Whole-session total up to but not including this final response. "
        "Cost is an estimate from the configured per-token rate."
    )
    return result




# --------------------------------------------------------------------------
# SecOps verification -- direct Chronicle REST
#
# These replace the MCP toolset one for one, keeping the tool names AND argument
# names the INSTRUCTION already teaches (udm_search, list_rules, get_rule,
# list_rule_detections, list_cases, get_case, list_case_alerts). The prompt is
# 340 lines of operational knowledge earned against this tenant; changing the
# transport underneath it must not cost that.
#
# Results are projected here rather than in trim_tool_result, which skips local
# FunctionTool results by design. Same projections, applied at source.
# --------------------------------------------------------------------------
async def udm_search(query: str, startTime: str, endTime: str,
                     maxEvents: int = 50) -> dict:
    """Search normalised UDM events. Use for the parse check after ingest.

    Args:
        query: A UDM query, e.g. `principal.hostname = "PT-LAB-A1B2C3D4.corp.local"`.
            Work start_run's `udm_queries` in order; an empty result on one rung
            means try the next, not that the events are missing.
        startTime: RFC3339, from the run's `search_window`. Do not compute it.
        endTime: RFC3339, from the run's `search_window`.
        maxEvents: Cap on returned events (default 50).

    Returns:
        dict with `event_count` and `events` projected to the fields verification
        reads, or `error` when the call failed.
    """
    r = await secops_rest.udm_search(query, startTime, endTime, maxEvents)
    if "error" in r:
        return r
    events = r.get("events") or []
    return {
        "event_count": len(events),
        "events": [platform_core._project_udm_event(e) for e in events],
        "note": "Projected to key fields; full UDM omitted to bound context.",
    }


async def list_rules(pageSize: int = 100) -> dict:
    """List detection rules, projected to identity only -- never the YARA-L text.

    Scan the display names for candidates matching the behaviour you generated.
    Do NOT enumerate with get_rule; check at most 3-5 named candidates.

    Args:
        pageSize: Rules per page (default 100).

    Returns:
        dict with `rule_count` and `rules` (ruleId, displayName, severity, type,
        alertingEnabled), or `error`.
    """
    r = await secops_rest.list_rules(pageSize)
    if "error" in r:
        return r
    rules = r.get("rules") or []
    return {"rule_count": len(rules),
            "rules": [platform_core._project_rule(x) for x in rules]}


async def get_rule(ruleId: str) -> dict:
    """Fetch one rule's metadata.

    Args:
        ruleId: Last path segment, e.g. `ru_00000000-0000-0000-0000-000000000000`.

    Returns:
        The projected rule, or `error`.
    """
    r = await secops_rest.get_rule(ruleId)
    return r if "error" in r else platform_core._project_rule(r)


def _project_detection(d: dict) -> dict:
    return {
        "id": d.get("id"),
        "ruleName": (d.get("detection") or [{}])[0].get("ruleName")
        if isinstance(d.get("detection"), list) else None,
        "detectionTime": d.get("detectionTime"),
        "createdTime": d.get("createdTime"),
    }


def _attribute_detections(found: list, entry: dict, marker: str) -> tuple[list, list]:
    """Split raw detections into ones this run may claim and ones it may not.

    A detection is only this run's evidence if it fired on this run's events.
    Two independent signals say so, and a detection needs to fail neither:

      - its `detectionTime` is not older than the earliest event this run could
        have produced (ingest minus the backdating allowance)
      - the run's marker hostname appears somewhere in the raw detection

    The marker is the strong signal and it is present in the detection record --
    it is simply not in the SOAR *alert*, which is why the instruction correctly
    tells the model not to demand it there. Reading it here closes the gap that
    let one run claim an earlier run's detection and its case.
    """
    ingested_at = entry.get("ingested_at")
    if ingested_at is None:
        return [_project_detection(d) for d in found], []

    floor = ingested_at - _SEARCH_PAD_BEFORE_SECONDS
    mine, theirs = [], []
    for d in found:
        stamp = d.get("detectionTime") or ""
        reason = ""
        try:
            from datetime import datetime, timezone
            when = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc).timestamp()
            if when < floor:
                reason = (f"detectionTime {stamp} predates this run's ingest window "
                          f"(floor {_iso(floor)}) -- it fired on earlier events")
        except (ValueError, TypeError):
            pass  # unparseable stamp: fall through to the marker check

        if not reason and marker and marker not in json.dumps(d, default=str):
            reason = (f"the raw detection does not reference this run's marker "
                      f"host {marker} -- it fired on someone else's events")

        if reason:
            projected = _project_detection(d)
            projected["excluded_because"] = reason
            theirs.append(projected)
        else:
            mine.append(_project_detection(d))
    return mine, theirs


async def list_rule_detections(ruleId: str, startTime: str, endTime: str,
                               pageSize: int = 50, tool_context=None) -> dict:
    """Detections a rule produced in a window -- did the rule actually fire.

    Only detections that fired on THIS run's events are returned. Detections from
    an earlier run of the same rule are moved to `not_this_run` and must never be
    reported as evidence: a run that claims one of those reports a PASS for a
    technique nothing detected.

    startTime and endTime are REQUIRED. Use the run's `search_window`: a
    detection carries the timestamp of the EVENT it fired on, which is backdated,
    so a narrower window hides real detections and reads as a coverage gap.

    Args:
        ruleId: e.g. `ru_00000000-0000-0000-0000-000000000000`.
        startTime: RFC3339, from `search_window`.
        endTime: RFC3339, from `search_window`.
        pageSize: Cap on detections returned.

    Returns:
        dict with `detection_count` and `detections` (id, rule, times), plus
        `not_this_run` when any were excluded -- or `error`.
    """
    r = await secops_rest.list_rule_detections(ruleId, startTime, endTime, pageSize)
    if "error" in r:
        return r
    found = r.get("detections") or []

    with _focus_lock:
        run_id = _focused_runs.get(platform_core._session_key(tool_context))
    entry = _RUNS.get(run_id) or {}
    run_ctx = entry.get("run")
    marker = getattr(run_ctx, "hostname", "") or ""

    mine, theirs = _attribute_detections(found, entry, marker)
    result: dict[str, Any] = {"detection_count": len(mine), "detections": mine}
    if theirs:
        result["not_this_run"] = theirs
        result["instruction_to_model"] = (
            f"{len(theirs)} detection(s) for this rule fell inside the search "
            "window but did NOT fire on this run's events -- they are listed "
            "under `not_this_run` with the reason. Do NOT cite them, and do NOT "
            "claim a case whose alert carries one of their ids. If "
            "`detection_count` is 0, this rule did not fire for this run."
        )
    return result


def _run_ingested_at(tool_context=None) -> float | None:
    """When this conversation's focused run was ingested, or None."""
    with _focus_lock:
        run_id = _focused_runs.get(platform_core._session_key(tool_context))
    return (_RUNS.get(run_id) or {}).get("ingested_at")


def _predates_run(create_time: Any, ingested_at: float | None) -> bool:
    """True when a case was already open before this run could have caused it.

    A case that exists before your events arrive is not your evidence, however
    well its name matches what you generated. Observed live twice: a run claimed
    a case opened 22 minutes before its own ingest because the rule name looked
    right, and reported it as a detection of the technique under test.
    """
    if ingested_at is None or not create_time:
        return False
    try:
        stamp = float(create_time) / 1000.0     # epoch millis
    except (TypeError, ValueError):
        from datetime import datetime, timezone
        try:
            stamp = datetime.strptime(str(create_time), "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc).timestamp()
        except (TypeError, ValueError):
            return False
    return stamp < (ingested_at - _SEARCH_PAD_BEFORE_SECONDS)


# --------------------------------------------------------------------------
# Plausibility of the generated field values
#
# `unresolved` being empty means every constraint was invertible. It does NOT
# mean the values are telemetry a Windows host would emit. When several
# `contains` fragments land on one field they are joined, and the join is
# frequently nonsense:
#
#   Details       C:\Perflogs :\Users\ \Favorites
#   TargetObject  C:\Users\...\Temp\Common Startup SOFTWARE\Microsoft\Windows\...
#   CommandLine   Microsoft\Windows\CurrentVersion\Run C:\users\Public\ del /s /f
#
# Every fragment is present, so the oracle returns MATCH and nothing flags it.
# But a deployed rule will not fire on a value like that, and "nothing fired"
# then reads as a coverage gap when it is a generation problem -- the first row
# of the failure table this project exists to keep apart.
#
# Checked at build time rather than plan time because the model authors
# `steps_json`: a value can be implausible whether the inverter composed it or
# the model wrote it.
# --------------------------------------------------------------------------
_PATHISH_FIELDS = re.compile(
    r"image|command|filename|targetobject|details|parentcommand|path|module",
    re.I,
)


def _implausible_fields(fields: dict) -> list[dict]:
    """Generated values that no real host would produce. Empty is the good case."""
    findings = []
    for name, value in (fields or {}).items():
        text = str(value)
        if not text or not _PATHISH_FIELDS.search(name):
            continue
        why = ""
        if len(re.findall(r"[A-Za-z]:\\", text)) > 1:
            why = "contains more than one drive root -- fragments were joined"
        elif re.search(r"(?<![A-Za-z]):\\", text):
            why = "contains a drive separator with no drive letter"
        elif "  " in text:
            why = "contains a doubled space -- fragments were joined"
        elif re.search(r"targetobject", name, re.I) and re.search(r"[A-Za-z]:\\", text):
            why = "a registry key path containing a filesystem path"
        if why:
            findings.append({"field": name, "value": text[:160], "problem": why})
    return findings


# --------------------------------------------------------------------------
# Matching the tenant's rules to the rules a run targeted
#
# The model used to choose candidate rules by reading display names off one page
# of `list_rules`. On any tenant whose rule count exceeds RULE_PAGE_CAP, that is
# a fraction of the inventory, and a rule outside the page is indistinguishable
# from a rule that did not fire. Observed live: a run targeting Sigma's
# "DotNet CLR DLL Loaded By Scripting Applications" reported a coverage gap
# while a tenant rule with a different vendor prefix and a shortened title had
# fired and opened a HIGH case. Five tokens in common, never compared, because
# the model never saw it.
#
# Matching by token overlap over the WHOLE inventory is cheap and would have
# caught that in one pass. Vendor prefixes and connectives are dropped so a
# company-prefixed tenant rule name and its matching Sigma title land on the
# same tokens.
# --------------------------------------------------------------------------
_RULE_NAME_NOISE = {
    "the", "a", "an", "of", "by", "via", "for", "to", "in", "on", "with", "and",
    "or", "is", "from", "using", "rule", "detection", "detections", "detect",
    "detects", "detected", "potential", "possible", "generic", "demo", "test",
    "lab", "purpleteam", "community", "common", "hacktool", "windows",
}
_MIN_TOKEN_OVERLAP = 2


def _name_tokens(name: str) -> set[str]:
    """Comparable tokens from a rule name, whatever its naming convention."""
    return {
        t for t in re.split(r"[^A-Za-z0-9]+", str(name or "").lower())
        if len(t) > 1 and t not in _RULE_NAME_NOISE
    }


def _rank_candidate_rules(targets: list[dict], rules: list[dict],
                          limit: int = 20) -> list[dict]:
    """Tenant rules most likely to cover what this run targeted, best first.

    Overlap coefficient rather than Jaccard: tenant names carry prefixes and
    suffixes the Sigma title does not, and penalising a rule for being verbosely
    named is exactly the mistake that produced the false gap.
    """
    scored: list[tuple[float, int, dict]] = []
    for rule in rules:
        display = rule.get("displayName") or ""
        rule_tokens = _name_tokens(display)
        if not rule_tokens:
            continue
        best_score, best_overlap, best_target = 0.0, 0, ""
        for target in targets:
            target_tokens = _name_tokens(target.get("title"))
            if not target_tokens:
                continue
            shared = rule_tokens & target_tokens
            if len(shared) < _MIN_TOKEN_OVERLAP:
                continue
            score = len(shared) / min(len(rule_tokens), len(target_tokens))
            if score > best_score:
                best_score, best_overlap = score, len(shared)
                best_target = target.get("title", "")
        if best_overlap:
            scored.append((best_score, best_overlap, {
                "ruleId": str(rule.get("name", "")).rsplit("/", 1)[-1],
                "displayName": display,
                "matches_target": best_target,
                "shared_tokens": best_overlap,
                "score": round(best_score, 2),
            }))
    scored.sort(key=lambda s: (-s[0], -s[1]))
    return [item for _, _, item in scored[:limit]]


async def find_run_detections(tool_context=None) -> dict:
    """Which of the tenant's rules fired on THIS run's events. Use this instead
    of choosing candidate rules yourself.

    Scans the whole rule inventory, ranks it against the rules this run targeted,
    queries detections for the best candidates, and keeps only detections that
    reference this run's marker host. Picking candidates by reading display names
    is how a run misses the rule that actually fired and reports a coverage gap
    that is not there.

    Returns:
        dict with `fired` (rules that produced a detection for this run),
        `rules_total`, `rules_checked` and `scope` -- quote `scope` in the verdict,
        because a "nothing fired" claim is only as wide as what was examined.
        `fired: []` with a full scope line is a real negative.
    """
    with _focus_lock:
        run_id = _focused_runs.get(platform_core._session_key(tool_context))
    entry = _RUNS.get(run_id) or {}
    ingested_at = entry.get("ingested_at")
    if ingested_at is None:
        return {"error": "no ingested run in this session; call ingest_run first"}

    targets = entry.get("targets") or []
    if not targets:
        return {"error": f"run {run_id} recorded no target rules; rebuild it"}

    marker = getattr(entry.get("run"), "hostname", "") or ""
    window = _search_window(ingested_at)

    listing = await secops_rest.list_rules(page_size=1000)
    if "error" in listing:
        return listing
    all_rules = listing.get("rules") or []
    candidates = _rank_candidate_rules(targets, all_rules)

    fired, checked = [], []
    for cand in candidates:
        raw = await secops_rest.list_rule_detections(
            cand["ruleId"], window["startTime"], window["endTime"], 50)
        checked.append(cand["displayName"])
        if "error" in raw:
            continue
        mine, _ = _attribute_detections(raw.get("detections") or [], entry, marker)
        if mine:
            fired.append({**cand, "detections": [d["id"] for d in mine],
                          "detection_count": len(mine)})

    return {
        "fired": fired,
        "rules_total": len(all_rules),
        "rules_checked": len(checked),
        "targets_exercised": [t["title"] for t in targets],
        "scope": (
            f"{len(checked)} of {len(all_rules)} tenant rules examined -- those "
            f"whose names overlap the {len(targets)} rule(s) this run targeted."
        ),
        "checked_rules": checked,
    }


async def list_cases(pageSize: int = 25, orderBy: str = "CreateTime desc",
                     tool_context=None) -> dict:
    """List SOAR cases, newest first. Call with NO filter -- sort and scan.

    Every case is tagged `predates_this_run`. A case tagged true was already open
    before your events reached the platform and CANNOT be yours, no matter how
    closely its name matches the behaviour you generated -- name similarity is
    not evidence, and this tenant raises cases from other sources continuously.

    Args:
        pageSize: Cases per page (default 25).
        orderBy: Sort order; leave as the default.

    Returns:
        dict with `case_count` and `cases` projected to id, name, priority,
        stage, status, createTime, alertCount, predates_this_run -- or `error`.
    """
    r = await secops_rest.list_cases(pageSize, orderBy)
    if "error" in r:
        return r
    cases = r.get("cases") or []
    ingested_at = _run_ingested_at(tool_context)

    projected = []
    stale = 0
    for c in cases:
        p = platform_core._project_case(c)
        p["predates_this_run"] = _predates_run(c.get("createTime"), ingested_at)
        stale += bool(p["predates_this_run"])
        projected.append(p)

    out: dict[str, Any] = {"case_count": len(projected), "cases": projected}
    if stale:
        out["instruction_to_model"] = (
            f"{stale} of these cases were already open before this run's events "
            "arrived (`predates_this_run: true`). They cannot be yours. Do not "
            "cite them, and do not treat a matching rule name as confirmation -- "
            "name similarity is not evidence of causation."
        )
    return out


async def get_case(caseId: str) -> dict:
    """Fetch one case.

    Args:
        caseId: Numeric case id, e.g. "100000".

    Returns:
        The projected case, or `error`.
    """
    r = await secops_rest.get_case(caseId)
    return r if "error" in r else platform_core._project_case(r)


async def list_case_alerts(caseId: str, pageSize: int = 50,
                           tool_context=None) -> dict:
    """Alerts attached to a case -- use this to confirm a case is YOURS.

    Match on a detection id from list_rule_detections appearing as the alert's
    ticketId or inside its identifier. Do NOT require the marker hostname: these
    alerts carry rule identity and a risk score, never the underlying event's
    hostname, so demanding it makes every real case look unrelated.

    A matching rule NAME is not confirmation. If the result carries
    `predates_this_run`, the case was open before your events arrived and the
    answer is already no.

    Args:
        caseId: Numeric case id.
        pageSize: Cap on alerts returned.

    Returns:
        dict with `alert_count` and `alerts` (identifier, ruleGenerator,
        ticketId, priority, status, createTime), or `error`.
    """
    ingested_at = _run_ingested_at(tool_context)
    if ingested_at is not None:
        case = await secops_rest.get_case(caseId)
        if "error" not in case and _predates_run(case.get("createTime"), ingested_at):
            return {
                "caseId": caseId,
                "predates_this_run": True,
                "case_created": case.get("createTime"),
                "instruction_to_model": (
                    f"Case {caseId} was already open before this run's events "
                    "reached the platform, so it cannot have been caused by them. "
                    "Do NOT claim it. If no other case qualifies, the correct "
                    "report is 'no case was opened for this run'."
                ),
            }

    r = await secops_rest.list_case_alerts(caseId, pageSize)
    if "error" in r:
        return r
    alerts = r.get("caseAlerts") or []
    return {
        "alert_count": len(alerts),
        "alerts": [
            {
                "identifier": a.get("identifier"),
                "ruleGenerator": a.get("ruleGenerator"),
                "ticketId": a.get("ticketId"),
                "priority": a.get("priority"),
                "status": a.get("status"),
                "createTime": a.get("createTime"),
            }
            for a in alerts
        ],
    }
