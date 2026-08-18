"""Shared plumbing: Google ADC auth, model construction, and the guards that stop
the agent reporting detections it never actually observed.

The Chronicle transport lives in purple_agent.secops_rest, along with the
(method, path) allowlist that keeps this production tenant read-only apart from
the confirmed log import.

Adapted from an earlier, read-only-only SecOps agent this project's auth and
anti-fabrication machinery was built against; the tool allowlist here is new,
because this agent writes (generates and ingests logs) where that one only read.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
from typing import Any

import google.auth
import google.auth.transport.requests
import httpx
from google.genai import types

from . import config, usage

logger = logging.getLogger(__name__)

_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
_credentials = None
_credentials_lock = threading.Lock()


def _fresh_token() -> str:
    """Return a valid ADC access token, refreshing it if it has expired.

    ADC is resolved here, on first call, not at import time. Stage A (corpus
    search, generation, the oracle) never calls this -- it is all local -- and
    importing purple_agent to use only Stage A must not require Google
    credentials that Stage A itself has no use for.
    """
    global _credentials
    if _credentials is None:
        with _credentials_lock:
            if _credentials is None:
                _credentials, _ = google.auth.default(scopes=_SCOPES)
    if not _credentials.valid:
        _credentials.refresh(google.auth.transport.requests.Request())
    return _credentials.token



# Stage A support. Generation itself is local (purple_agent.synth), because the
# server's Gemini-backed generation tools --
# generate_threat_detection_opportunity, generate_synthetic_events, and
# evaluate_rule_coverage -- return "permission denied" for this identity. They
# are a separately entitled feature of SecOps; if that entitlement is granted
# later they can be added back here and used ahead of local generation.

# Stage B -- live ingest. import_logs is the only tool that puts data into the
# SIEM, and the agent must confirm before using it.
#
# It is deliberately NOT model-facing. A run's event XML is several KB, and
# having the model re-emit it into an import_logs tool-call exhausts the response
# token budget (MAX_TOKENS) and, worse, a truncated call is malformed XML the
# parser drops silently. Instead tools.ingest_run() reads the XML from the run

# Stage B verification -- did it parse, did a rule fire.
#
# list_security_alerts and get_security_alert are deliberately ABSENT. The
# server returns HTTP 500 for list_security_alerts on every argument shape
# tried (with and without a time range, 2h and 24h windows):
#
#   {"error":{"code":500,"message":"Invalid JSON payload received. Parsing
#    terminated before end of input.\n{\"alerts\":{\"alerts\":\n^"}}
#
# It emits a progress frame and then a truncated body -- a server-side defect,
# not a usage error, and not something a retry fixes. Leaving it exposed just
# burns model turns on an error it cannot resolve. Detections are read through
# list_rule_detections instead, and case-level outcome through CASE_TOOLS.

# Stage B verification -- did SOAR actually open a case.

# The allowlist for the whole package. Deliberately absent: generate_rules,
# validate_rule, create_rule. They exist on the server and would let the agent
# close a coverage gap by authoring a YARA-L rule, but writing detection content
# into a live tenant is a far larger blast radius than writing logs and should
# be a separate, explicit decision.


# --------------------------------------------------------------------------
# Hard denylist -- production tenant configuration
#
# The configured SecOps tenant is a PRODUCTION environment. This tool must
# never alter its
# configuration: not parsers, not detection rules, not feeds, not reference
# lists or data tables, and not the state of cases and alerts that human
# analysts are working.
#
# This is enforced structurally rather than by instruction. An allowlist alone
# is not enough -- it protects against tools being added carelessly, but not
# against someone adding one deliberately without realising the environment is
# production. Anything here fails at toolset construction, loudly.
#
# Note the asymmetry that makes this workable: writing *data* (import_logs) is
# the entire point of the tool and is gated behind user confirmation. Writing
# *configuration* is never in scope, at any confirmation level.
#
# read-only parser inspection (list_parsers / get_parser / run_parser) is fine
# and deliberately not listed: run_parser evaluates parser code against a sample
# in a sandbox and deploys nothing. It is how scripts/validate_templates.py
# checks templates without touching the tenant.
# --------------------------------------------------------------------------



def make_model():
    """Build the model for the agent.

    Gemini model ids are passed through as plain strings so ADK uses its native
    Google path (and, with GOOGLE_GENAI_USE_VERTEXAI=TRUE, the same ADC as
    SecOps). Anything else -- GLM, Claude, any OpenRouter id -- is routed through
    LiteLLM.

    LiteLLM is imported lazily because it is the heaviest dependency in the tree
    (~115 MB with its own transitive openai) and a Gemini deployment never
    touches it. Importing it at module scope made every container pay for it.
    """
    if config.MODEL.startswith("openrouter/") or "/" in config.MODEL:
        from google.adk.models.lite_llm import LiteLlm

        return LiteLlm(
            model=config.MODEL,
            max_tokens=config.MAX_TOKENS,
            temperature=config.TEMPERATURE,
        )
    return config.MODEL


# --------------------------------------------------------------------------
# Liveness gate
#
# The instruction-level "do not fabricate" rule is not enough on its own. When
# SecOps cannot be reached at all -- an expired ADC token is the
# usual cause -- the toolset resolves to zero tools, so the agent never issues a
# call, no tool error is ever raised, and `tool_error_response` never fires.
# What the model sees is a task and no way to do it, and observed behaviour at
# that point is model-dependent: one model refused, another invented six feeds
# with plausible timestamps and reported "all healthy".
#
# So the gate is structural. If the server is unreachable the agent does not run.
# --------------------------------------------------------------------------
_HEALTH_TTL_SECONDS = 60.0
_health_cache: tuple[float, str | None] = (0.0, None)
_health_lock = threading.Lock()


def _cached_health() -> tuple[bool, str | None]:
    """(fresh, reason) from the health cache, without probing the server."""
    with _health_lock:
        checked_at, cached = _health_cache
        return (time.monotonic() - checked_at < _HEALTH_TTL_SECONDS, cached)


def _record_health(result: dict[str, Any]) -> str | None:
    """Reduce a tools/list result to a reason string and cache it."""
    global _health_cache
    reason = None
    if "error" in result:
        reason = str(result["error"])[:300]
    elif not result.get("tools"):
        reason = "the server returned no tools"

    with _health_lock:
        _health_cache = (time.monotonic(), reason)
    return reason


async def _unreachable_reason() -> str | None:
    """Return why SecOps is unreachable, or None when it is fine."""
    fresh, cached = _cached_health()
    if fresh:
        return cached
    from . import secops_rest        # imported here: secops_rest imports us

    reason = await secops_rest.health()
    with _health_lock:
        global _health_cache
        _health_cache = (time.monotonic(), reason)
    return reason


async def require_live_tools(callback_context):
    """Short-circuit the agent when SecOps is unreachable.

    Returning Content from a before-agent callback makes ADK skip the agent and
    emit that content as its output, so the model is never given the chance to
    answer a question it has no data for.

    Async because ADK awaits an awaitable callback result and runs a sync one
    inline: a blocking probe here delays the first response of every session in
    the process, not just this one.

    Offline mode skips the gate so Stage A can be run conversationally with no
    tenant at all. That is not a hole: secops_rest.call refuses every Chronicle
    request in offline mode, so the thing this gate exists to prevent -- the
    model reporting a detection result it never obtained -- is enforced at the
    transport instead, where it cannot be reasoned around.
    """
    if config.OFFLINE:
        return None

    reason = await _unreachable_reason()
    if reason is None:
        return None

    agent = getattr(callback_context, "agent_name", "this agent")
    logger.error("[gate] %s blocked -- SecOps unreachable: %s", agent, reason)
    hint = ""
    if "eauthentication" in reason or "credential" in reason.lower():
        hint = "\n\nRun `gcloud auth application-default login` and try again."
    return types.Content(
        role="model",
        parts=[
            types.Part(
                text=(
                    "**Cannot run — Google SecOps is unreachable.** No data was "
                    "retrieved, so there is nothing to report and I will not guess."
                    f"\n\nError: `{reason}`{hint}"
                )
            )
        ],
    )


def tool_error_response(tool, args, tool_context, error):
    """Turn a failed tool call into an explicit error result for the model.

    Without this, ADK re-raises: the node dies, and the model is left holding a
    tool call that never got a response. Observed consequence -- it fills the gap
    from imagination. Returning a dict means the failure arrives as a tool result
    the model has to read and repeat.

    ADK invokes this by keyword, so the parameter names matter.
    """
    detail = f"{type(error).__name__}: {error}"
    logger.warning("[tool-error] %s -- %s", tool.name, detail)
    return {
        "error": detail,
        "tool": tool.name,
        "instruction_to_model": (
            f"The tool '{tool.name}' FAILED and returned no data. You have no "
            "results for this call. Report this error verbatim to the user. Do "
            "NOT invent, estimate, or infer what the result would have been, and "
            "do not issue a verdict that depends on it."
        ),
    }


def track_usage(callback_context, llm_response):
    """Accumulate token usage and buffer the model's text; touch nothing else.

    Two jobs, both read back after the turn ends:
      - token totals -> the token_usage tool and the saved usage.json
      - the latest non-empty text -> the report written to the run folder,
        captured here so the model never has to re-emit it.

    ADK invokes after-model callbacks by keyword, so the parameter names matter.
    Returning None means "no override" -- the response passes through unchanged.
    """
    session = getattr(callback_context, "session", None)
    session_id = getattr(session, "id", "default")

    meta = getattr(llm_response, "usage_metadata", None)
    if meta is not None:
        totals = usage.record(session_id, meta, config.MODEL)
        logger.info("[usage] %s  %s", session_id[:8], totals.format())

    content = getattr(llm_response, "content", None)
    if content is not None:
        text = "".join(
            p.text or "" for p in (content.parts or []) if getattr(p, "text", None)
        )
        usage.buffer_report(session_id, text)
    return None


# --------------------------------------------------------------------------
# Tool-result trimming
#
# Verification tool results are model INPUT, and they accumulate in the
# conversation history across a Stage B loop. Left raw they blow the context
# window, not the per-response cap: one udm_search at maxEvents=100 is ~180 KB
# (~45k tokens) of full UDM objects, and a few retries in history exceed the
# 202,752-token window with a 400, not a MAX_TOKENS.
#
# The model does not need whole UDM events to verify a run -- it needs event
# types, timestamps and hostnames. So heavy results are projected to those
# fields before they enter history, and anything else is capped by raw size.
# --------------------------------------------------------------------------
UDM_MAX_EVENTS = 25       # clamp; projected events are tiny, but bound the fetch
LIST_PAGE_CAP = 25        # cases / detections page size
RULE_PAGE_CAP = 100       # rules are projected to ~5 fields, so a full page fits
RESULT_CEILING_CHARS = 8_000   # generic backstop for any un-projected result


def _project_udm_event(event: dict) -> dict:
    """Keep only the fields verification reads; drop the rest of the UDM object."""
    udm = event.get("udm", {}) or {}
    meta = udm.get("metadata", {}) or {}
    principal = udm.get("principal", {}) or {}
    target = udm.get("target", {}) or {}
    return {
        "eventType": meta.get("eventType"),
        "productEventType": meta.get("productEventType"),
        "eventTimestamp": meta.get("eventTimestamp"),
        "logType": meta.get("logType"),
        "principalHostname": principal.get("hostname"),
        "targetHostname": target.get("hostname"),
    }


def _project_case(case: dict) -> dict:
    """The case fields the report and the ownership check need -- no blobs."""
    return {
        "caseId": str(case.get("name", "")).rsplit("/", 1)[-1],
        "displayName": case.get("displayName"),
        "priority": case.get("priority"),
        "stage": case.get("stage"),
        "status": case.get("status"),
        "createTime": case.get("createTime"),
        "alertCount": case.get("alertCount"),
    }


def _project_rule(rule: dict) -> dict:
    """Rule identity only -- never the YARA-L text.

    Without this, `list_rules` fell through to the generic character ceiling,
    which truncates raw JSON mid-object. Observed live: a 41,049-char listing
    cut to 8,000 left the model seeing 19 of 100 rules, with the id at the cut
    point sliced mid-string. It then called get_rule on ids missing their final
    character (`...2c037f164b9` for `...2c037f164b9c`), got "invalid rule_id",
    and -- having no way to make progress -- re-enumerated the same ids
    indefinitely.

    Projecting per-rule means every id stays whole, whatever the page size.
    """
    return {
        "ruleId": str(rule.get("name", "")).rsplit("/", 1)[-1],
        "displayName": rule.get("displayName"),
        "severity": (rule.get("severity") or {}).get("displayName"),
        "type": rule.get("type"),
        "alertingEnabled": rule.get("alertingEnabled"),
    }


# --------------------------------------------------------------------------
# Loop guard
#
# A model with no legal next move does not stop -- it repeats. Observed live:
# `list_rule_detections` requires a ruleId and there is no bulk form, so when the
# agent could not name a candidate rule it fell back to calling `get_rule` on
# every id it could see, cycling the same 18 ids every ~88 seconds with no
# termination condition. Nothing in the stack noticed.
#
# Identical (tool, args) repeats are the precise signal; the per-tool ceiling is
# a backstop for a cycle that varies its arguments. Both are per session, because
# the loop spans turns.
# --------------------------------------------------------------------------
REPEAT_CALL_LIMIT = 3      # identical tool+args calls before refusing
PER_TOOL_CALL_LIMIT = 60   # calls to one tool in a session before refusing

_repeat_counts: dict[str, dict[str, int]] = {}
_tool_counts: dict[str, dict[str, int]] = {}


def _session_key(tool_context) -> str:
    session = getattr(tool_context, "session", None) if tool_context else None
    return str(getattr(session, "id", "default"))


def _loop_guard(name: str, args: dict, tool_context) -> dict | None:
    """Refuse a call that is going round in circles. None means proceed."""
    key = _session_key(tool_context)
    try:
        signature = f"{name}:{json.dumps(args, sort_keys=True, default=str)}"
    except Exception:  # noqa: BLE001 - a guard must never break the call path
        signature = f"{name}:{args!r}"

    repeats = _repeat_counts.setdefault(key, {})
    tools = _tool_counts.setdefault(key, {})
    repeats[signature] = repeats.get(signature, 0) + 1
    tools[name] = tools.get(name, 0) + 1

    if repeats[signature] >= REPEAT_CALL_LIMIT:
        reason = (
            f"'{name}' has already been called {repeats[signature]} times with "
            "these exact arguments, and returned the same thing each time."
        )
    elif tools[name] >= PER_TOOL_CALL_LIMIT:
        reason = (
            f"'{name}' has been called {tools[name]} times in this session, "
            "which is far past the point of diminishing returns."
        )
    else:
        return None

    logger.warning("[loop-guard] blocked %s -- %s", name, reason)
    return {
        "error": "repeated call blocked",
        "tool": name,
        "reason": reason,
        "instruction_to_model": (
            "STOP calling this tool. Repeating it will not produce a new answer. "
            "Report what you have established so far and state plainly what you "
            "could not determine and why. An honest 'I could not determine X' is "
            "a correct result; an endless search is not."
        ),
    }


def clamp_tool_args(tool, args, tool_context):
    """before_tool_callback: cap page sizes, then refuse calls that are looping.

    Mutates args in place. Returns None to let the (now-bounded) call proceed, or
    a dict to short-circuit it -- ADK hands that dict back as the tool result.
    """
    name = getattr(tool, "name", "")
    if name == "udm_search":
        requested = args.get("maxEvents")
        args["maxEvents"] = min(int(requested), UDM_MAX_EVENTS) if requested else UDM_MAX_EVENTS
    elif name in ("list_cases", "list_rule_detections"):
        requested = args.get("pageSize")
        args["pageSize"] = min(int(requested), LIST_PAGE_CAP) if requested else LIST_PAGE_CAP
    elif name == "list_rules":
        # Projected per-rule below, so the cap bounds context rather than
        # protecting ids -- but a smaller page still keeps the listing readable.
        requested = args.get("pageSize")
        args["pageSize"] = min(int(requested), RULE_PAGE_CAP) if requested else RULE_PAGE_CAP
        # The OData filter is documented but does not work: every filtered call
        # observed returned {}, which the model reads as "no such rule" rather
        # than "the filter is broken". Drop it and let it scan the projection.
        args.pop("filter", None)

    return _loop_guard(name, args, tool_context)


def trim_tool_result(tool, args, tool_context, tool_response):
    """after_tool_callback: bound a tool result before it enters history.

    Field projection now happens inside the verification tools themselves --
    they call Chronicle directly and return already-compact dicts, and this
    callback never saw those anyway (it only ever unwrapped MCP-shaped
    responses). What remains is the backstop the projections do not cover: a
    raw-size ceiling, so an unexpectedly large result cannot silently consume
    the context window.

    Returns a replacement result, or None to leave it untouched. Never raises --
    a throwing callback aborts the turn.
    """
    try:
        if not isinstance(tool_response, dict):
            return None
        blob = json.dumps(tool_response, default=str)
        if len(blob) <= RESULT_CEILING_CHARS:
            return None
        return {
            "truncated": True,
            "original_size_chars": len(blob),
            "preview": blob[:RESULT_CEILING_CHARS],
            "instruction_to_model": (
                f"The result from '{getattr(tool, 'name', '?')}' exceeded the "
                "size ceiling and was truncated. Narrow the query (a smaller "
                "page size or a tighter time window) rather than reasoning from "
                "a partial object."
            ),
        }
    except Exception:  # noqa: BLE001 - a callback must never break the turn
        return None


NO_FABRICATION = """
## Ground rule

Every fact you report must come from a tool result you actually received in this
turn. If a tool returns an `error`, returns nothing, or you never called it, then
you have no data -- say so.

Never invent or guess a rule id, detection, alert, case id, hostname, timestamp,
or event count, and never issue a verdict that rests on data you did not get.
"The tool failed, so I cannot answer" is a correct and useful reply. A confident
report built on nothing is not, and someone will act on it.

"No rule fired" is a valid and genuinely useful result. It is the coverage gap
this exercise exists to find. Never dress it up as success, and never invent a
detection to make the run look productive.
""".strip()
