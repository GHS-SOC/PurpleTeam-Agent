"""Run every event template through Chronicle's real parsers. Ingests nothing.

This exists because a whole class of defect is invisible offline and invisible
at ingest time: `import_logs` returns success for an event the parser will later
reject, and the only symptom is that nothing ever appears in UDM. Which reads,
downstream, as a coverage gap.

`run_parser` gives the actual rejection reason in seconds:

    field "SourcePort": strconv.Atoi: parsing "-": invalid syntax
    field backstory.File.sha256 "..." too long for type HASH (66 bytes, max 64)
    FILE_CREATION missing target.file field

Run after touching anything in purple_agent/synth/:

    python scripts/validate_templates.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from purple_agent import config  # noqa: E402
from purple_agent import platform_core  # noqa: E402
from purple_agent.synth import mapping, winevt  # noqa: E402
from purple_agent.synth.scenario import new_scenario  # noqa: E402

TENANT = {
    "projectId": config.PROJECT_ID,
    "customerId": config.CUSTOMER_ID,
    "region": config.REGION,
}


async def _mcp_call(method: str, params: dict) -> dict:
    """One JSON-RPC call against the hosted MCP endpoint."""
    import httpx

    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    async with httpx.AsyncClient(timeout=120.0) as client:
        r = await client.post(
            config.MCP_URL, json=payload,
            headers={"Authorization": f"Bearer {platform_core._fresh_token()}",
                     "content-type": "application/json",
                     "accept": "application/json, text/event-stream",
                     "x-goog-user-project": config.PROJECT_ID},
        )
    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}", "body": r.text[:400]}
    try:
        return r.json().get("result", {})
    except Exception:  # noqa: BLE001 - SSE frame
        for line in r.text.splitlines():
            if line.startswith("data:"):
                import json as _j
                return _j.loads(line[5:].strip()).get("result", {})
        return {"error": "unparsable response"}


def call(name: str, args: dict) -> tuple[str | None, str | None]:
    # run_parser has no Chronicle REST equivalent, so this script still speaks
    # MCP -- the one thing that does. It is kept here rather than in
    # platform_core so the agent has exactly one transport: two of them is what
    # let a stubbed test suite ingest into a production tenant.
    #
    # Needs an identity holding mcp.tools.call AND chronicle.parsers.*. The lab's
    # service account holds neither; run this as a developer.
    result = asyncio.run(
        _mcp_call("tools/call", {"name": name, "arguments": {**TENANT, **args}})
    )
    if "error" in result:
        return None, f"transport: {str(result['error'])[:200]}"
    text = "\n".join(
        b.get("text", "") for b in result.get("content", []) if b.get("type") == "text"
    )
    return text, None


def best_parser(log_type: str) -> tuple[str, str]:
    """Pick the richest parser for a log type.

    Deliberately not "the ACTIVE one": this tenant carries a 1.2 KB custom
    WINEVTLOG_XML override that flattens every Security event to GENERIC_EVENT
    and drops the hostname, alongside the full ~1.5 MB Chronicle parser. Picking
    by size validates against the parser that actually extracts fields.
    """
    listing, err = call("list_parsers", {"logType": log_type, "pageSize": 20})
    if err or not listing:
        return "", err or "no parser listing"
    best_code, best_id = "", ""
    for parser in json.loads(listing).get("parsers", []):
        detail, _ = call(
            "get_parser",
            {"logType": log_type, "parserId": parser.get("parserId", "")},
        )
        if not detail:
            continue
        code = json.loads(detail).get("code", "")
        if len(code) > len(best_code):
            best_code, best_id = code, parser.get("parserId", "")
    return best_code, best_id


def main() -> int:
    parsers: dict[str, str] = {}
    for log_type in sorted({t.log_type for t in mapping.TEMPLATES.values()}):
        code, parser_id = best_parser(log_type)
        if not code:
            print(f"error: no parser code for {log_type} ({parser_id})", file=sys.stderr)
            return 1
        parsers[log_type] = code
        print(f"{log_type:16} parser {parser_id} ({len(code):,} bytes)")

    context = new_scenario(f"{config.HOST_PREFIX}VALIDATE", seed=5)
    passed, failed, degraded = [], [], []
    print()

    for event_id in sorted(mapping.TEMPLATES):
        event = winevt.build_event(event_id, context)
        out, err = call(
            "run_parser",
            {
                "logType": event.log_type,
                "parserCode": parsers[event.log_type],
                "sampleLogs": [event.xml],
            },
        )
        if err:
            failed.append((event_id, err))
            print(f"  {event_id:>5} {event.log_type:16} ERROR {err[:110]}")
            continue

        result = json.loads(out)["runParserResults"][0]
        if "error" in result:
            message = result["error"].get("message", "")
            failed.append((event_id, message))
            print(f"  {event_id:>5} {event.log_type:16} FAIL  {message[:130]}")
            continue

        events = result.get("parsedEvents", {}).get("events", [])
        parsed = events[0]["event"] if events else {}
        event_type = parsed.get("metadata", {}).get("eventType", "?")
        hostname = parsed.get("principal", {}).get("hostname", "")

        # Parsing without extracting the marker hostname is not a pass: the
        # whole verification path keys on that field.
        if event_type == "GENERIC_EVENT" or not hostname:
            degraded.append((event_id, event_type, hostname or "unknown"))
            print(f"  {event_id:>5} {event.log_type:16} WEAK  {event_type:22} host={hostname or 'unknown'}")
        else:
            passed.append(event_id)
            print(f"  {event_id:>5} {event.log_type:16} OK    {event_type:22} host={hostname}")

    total = len(mapping.TEMPLATES)
    print(f"\n  parsed cleanly : {len(passed)}/{total}")
    if degraded:
        print(f"  weakly parsed  : {len(degraded)} -> {[d[0] for d in degraded]}")
        print("    Parsed, but as GENERIC_EVENT or without a hostname. These will "
              "ingest and then be unfindable by marker host, and are unlikely to "
              "trigger field-based detections.")
    if failed:
        print(f"  rejected       : {len(failed)}")
        for event_id, message in failed:
            print(f"    {event_id}: {message[:200]}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
