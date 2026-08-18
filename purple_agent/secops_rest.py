"""Direct Chronicle REST transport, replacing the hosted MCP endpoint.

Why this exists rather than `mcp_call`: the MCP endpoint is a separate door with
its own permission, `mcp.googleapis.com/tools.call`. The lab's service account
holds Chronicle data permissions -- udmSearch, logs.import, rules.list -- but not
that one, so every MCP call returned HTTP 403 while the underlying operations
were perfectly available. This talks to Chronicle directly and needs only the
Chronicle permissions the identity already has.

Every path here was read out of the `secops` SDK and then verified live against
the tenant before a line of this module was written. Two would have been wrong if
guessed: detections are `legacy:legacySearchDetections`, not a subresource of the
rule, and cases resolve under both v1alpha and v1beta.

The operations mirror the MCP tool names they replace one for one, so the
INSTRUCTION's vocabulary does not change.
"""

from __future__ import annotations

import asyncio
import base64
import re
from typing import Any

import httpx

from . import config, platform_core

# --------------------------------------------------------------------------
# Path allowlist -- this project's production guard
#
# The MCP toolset could be constrained by tool NAME, because the server defined
# the tools. A REST client composes its own requests, so the guard has to sit
# where the request is issued or it does not exist at all.
#
# Read-only by construction: every entry is a GET except the single log import,
# which is the whole point of the agent and is gated behind user confirmation
# upstream. Nothing here can create, update or delete tenant configuration --
# not parsers, rules, feeds, reference lists, data tables, nor the state of cases
# and alerts analysts are working. That is the same asymmetry the MCP allowlist
# encodes: writing DATA is in scope, writing CONFIGURATION never is.
# --------------------------------------------------------------------------
_ALLOWED: tuple[tuple[str, str], ...] = (
    ("GET", r":udmSearch"),
    ("GET", r"rules"),
    ("GET", r"rules/[\w.-]+"),
    ("GET", r"legacy:legacySearchDetections"),
    ("GET", r"cases"),
    ("GET", r"cases/\d+"),
    ("GET", r"cases/\d+/caseAlerts"),
    ("GET", r"forwarders"),
    ("POST", r"logTypes/[A-Z0-9_]+/logs:import"),
)

_ALLOWED_RE = tuple((m, re.compile(p)) for m, p in _ALLOWED)


class ForbiddenRequest(RuntimeError):
    """Raised before any socket opens. A bug here must be loud, not silent."""


def _check(method: str, path: str) -> None:
    # fullmatch, not match with a `^...$` pattern: `$` matches just before a
    # single trailing newline, not strictly end-of-string, so `match` would let
    # "rules/abc\n" through an allowlist meant only for "rules/abc".
    if not any(m == method and rx.fullmatch(path) for m, rx in _ALLOWED_RE):
        raise ForbiddenRequest(
            f"refusing {method} {path}: not in the Chronicle REST allowlist. "
            "This tenant is production; add the path to _ALLOWED only if it is a "
            "read, or the confirmed log import."
        )


def _instance() -> str:
    return (
        f"projects/{config.PROJECT_ID}/locations/{config.REGION}"
        f"/instances/{config.CUSTOMER_ID}"
    )


def _host() -> str:
    return f"https://{config.REGION}-chronicle.googleapis.com"


async def call(
    method: str,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
    version: str = "v1alpha",
    timeout: float = 120.0,
) -> dict[str, Any]:
    """One authenticated Chronicle request. Never raises except ForbiddenRequest.

    Async for the same reason mcp_call was: ADK runs a sync tool inline on the
    event loop, so a blocking HTTP call here stalls every other session in the
    process.
    """
    _check(method, path)

    # Offline mode refuses here rather than at agent start-up, because this is
    # the one function every Chronicle operation goes through -- reads, the log
    # import, everything. Refusing at the chokepoint makes Stage B impossible
    # rather than merely unavailable, and hands the model an explicit error it
    # must report instead of a silence it might fill in.
    if config.OFFLINE:
        return {
            "error": "offline mode (PURPLE_OFFLINE=1): no SecOps request was made",
            "detail": (
                f"{method} {path} was refused before any network call. Stage A "
                "-- search, plan, build, oracle -- works offline; ingest and every "
                "verification step need a configured tenant. Unset PURPLE_OFFLINE "
                "and supply credentials to run Stage B."
            ),
        }

    url = f"{_host()}/{version}/{_instance()}/{path}"
    try:
        token = await asyncio.to_thread(platform_core._fresh_token)
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.request(
                method,
                url,
                params=params,
                json=body,
                headers={
                    "Authorization": f"Bearer {token}",
                    "x-goog-user-project": config.PROJECT_ID,
                    "content-type": "application/json",
                },
            )
    except Exception as exc:  # noqa: BLE001 - surfaced to the model verbatim
        return {"error": f"{type(exc).__name__}: {exc}"}

    if response.status_code != 200:
        detail = response.text[:400]
        try:
            detail = response.json().get("error", {}).get("message", detail)[:400]
        except Exception:  # noqa: BLE001
            pass
        return {"error": f"HTTP {response.status_code}", "detail": detail}
    try:
        return response.json()
    except Exception:  # noqa: BLE001
        return {"error": "response was not JSON", "body": response.text[:400]}


# --------------------------------------------------------------------------
# Operations -- one per MCP tool they replace
# --------------------------------------------------------------------------
async def udm_search(query: str, start_time: str, end_time: str,
                     limit: int = 50) -> dict[str, Any]:
    return await call("GET", ":udmSearch", params={
        "query": query, "timeRange.startTime": start_time,
        "timeRange.endTime": end_time, "limit": limit,
    })


async def list_rules(page_size: int = 100) -> dict[str, Any]:
    return await call("GET", "rules", params={"pageSize": page_size})


async def get_rule(rule_id: str) -> dict[str, Any]:
    return await call("GET", f"rules/{rule_id}")


async def list_rule_detections(rule_id: str, start_time: str, end_time: str,
                               page_size: int = 50) -> dict[str, Any]:
    # Not rules/{id}/detections -- that 404s. The server exposes detection search
    # as a legacy collection-level method taking ruleId as a parameter.
    return await call("GET", "legacy:legacySearchDetections", params={
        "ruleId": rule_id, "startTime": start_time,
        "endTime": end_time, "pageSize": page_size,
    })


async def list_cases(page_size: int = 25,
                     order_by: str = "CreateTime desc") -> dict[str, Any]:
    return await call("GET", "cases",
                      params={"pageSize": page_size, "orderBy": order_by})


async def get_case(case_id: str) -> dict[str, Any]:
    return await call("GET", f"cases/{case_id}")


async def list_case_alerts(case_id: str, page_size: int = 50) -> dict[str, Any]:
    return await call("GET", f"cases/{case_id}/caseAlerts",
                      params={"pageSize": page_size})


async def import_logs(log_type: str, logs: list[str],
                      forwarder_id: str) -> dict[str, Any]:
    """The only write. Payload shape mirrors the SDK: base64 per log entry,
    under inline_source, with the forwarder as a full resource name."""
    return await call(
        "POST",
        f"logTypes/{log_type}/logs:import",
        body={
            "inline_source": {
                "logs": [
                    {"data": base64.b64encode(entry.encode("utf-8")).decode("utf-8")}
                    for entry in logs
                ],
                "forwarder": f"{_instance()}/forwarders/{forwarder_id}",
            }
        },
    )


async def health() -> str | None:
    """Why Chronicle is unreachable, or None when it is fine.

    Reads one rule: cheap, touches no tenant state, and exercises the same auth
    and quota-project path every other call uses. Unlike the MCP `tools/list`
    probe it replaced, this fails when the identity cannot actually USE the API
    -- that probe passed for an identity that then 403'd on every real call.
    """
    result = await list_rules(page_size=1)
    if "error" in result:
        return f"{result['error']}: {str(result.get('detail', ''))[:200]}"
    return None
