"""Synthetic-data marking.

`import_logs` accepts no labels and no custom event time, so there is no
out-of-band way to tag what this agent writes into the SIEM. Marking is
therefore in-band, by hostname: every run pins a host named
`<prefix><run_id>`, e.g. `PT-LAB-A3F91C2D`.

That single convention carries three jobs:

- an analyst can exclude everything synthetic with `principal.hostname = /^PT-LAB-/`
- one run is isolated with an exact hostname match
- it doubles as the `udm_search` key that proves ingestion actually landed

If the marker is missing from generated events, the run must not be ingested --
unmarked synthetic data in a live SIEM is indistinguishable from a real
intrusion, and someone will work it as one.

**Searching for the marker after ingest is not a single query.** Generated
events carry the FQDN in `<Computer>` (`PT-LAB-A3F91C2D.corp.local`, see
`synth.scenario.ScenarioContext.fqdn`), and Chronicle normalises that whole
string into `principal.hostname`. An exact match on the short marker hostname
therefore returns nothing on a run that ingested perfectly -- observed in the
field, and read as a parse failure when it was a query-shape mistake. So the
marker resolves to an ordered ladder (`udm_queries`): FQDN first, unanchored
regex second, short hostname last. Only an empty result from ALL THREE is
evidence that the events did not parse.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from . import config

# The exact shape new_run() mints: 8 hex chars, upper or lower.
_RUN_ID_RE = re.compile(r"[0-9A-Fa-f]{8}")


def is_valid_run_id(run_id: str) -> bool:
    """True if run_id has the shape new_run() generates.

    save_run() joins run_id onto OUT_DIR unescaped (`config.OUT_DIR /
    run.run_id`). A run_id is a tool argument that comes back from the model,
    not a value we mint and keep control of end to end -- nothing stops it
    being handed something else, and a value like "../../tmp/pwn" walks the
    write straight out of OUT_DIR. Callers that accept a fresh run_id from a
    tool argument must check this before it reaches a filesystem path.

    fullmatch, not match with a `^...$` pattern: `$` matches just before a
    single trailing newline, not strictly end-of-string, so `match` would
    accept "ABCDEF12\\n" -- the same class of bug secops_rest._check exists
    to avoid, missed here on first pass.
    """
    return bool(_RUN_ID_RE.fullmatch(run_id or ""))


def udm_query_ladder(hostname: str, dns_domain: str | None = None) -> list[dict[str, str]]:
    """The ordered hostname searches that find a run's events, best first.

    Chronicle stores whatever the log carried, and these events carry the FQDN,
    so the exact short-hostname match that reads as the obvious query is the one
    least likely to hit. Try them in this order and stop at the first hit:

    1. FQDN      -- what `<Computer>` actually contains, so it matches directly.
    2. regex     -- unanchored, so it matches the marker inside an FQDN whatever
                    suffix the tenant appended (or none at all). This is the
                    rung that rescues a run when the domain is not what we
                    assumed.
    3. short host -- only correct if something stripped the domain on the way in.

    Args:
        hostname: The run's marker hostname, e.g. `PT-LAB-A3F91C2D`.
        dns_domain: DNS suffix used in generated events. `None` reads the
            configured `PURPLE_DNS_DOMAIN`; `""` drops rung 1, which is right
            when there is no suffix -- it would be identical to rung 3.
    """
    suffix = config.DNS_DOMAIN if dns_domain is None else dns_domain

    def both_fields(expression: str) -> str:
        return (
            f"principal.hostname = {expression} OR "
            f"target.hostname = {expression}"
        )

    ladder: list[dict[str, str]] = []
    if suffix:
        ladder.append(
            {
                "step": "fqdn",
                "query": both_fields(f'"{hostname}.{suffix}"'),
                "why": "generated events carry the FQDN in <Computer>; try this first",
            }
        )
    ladder.append(
        {
            "step": "regex",
            "query": both_fields(f"/{hostname}/"),
            "why": "matches the marker inside any FQDN suffix, expected or not",
        }
    )
    ladder.append(
        {
            "step": "exact",
            "query": both_fields(f'"{hostname}"'),
            "why": "only matches if the domain was stripped during normalisation",
        }
    )
    return ladder


@dataclass
class RunContext:
    """Identity for one generate/ingest/verify cycle."""

    run_id: str
    hostname: str
    started_at: str
    dns_domain: str = ""

    def __post_init__(self) -> None:
        # Read at construction, not as a class default, so a test or a caller
        # that overrides config.DNS_DOMAIN is honoured.
        if not self.dns_domain:
            self.dns_domain = config.DNS_DOMAIN

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "hostname": self.hostname,
            "fqdn": self.fqdn,
            "started_at": self.started_at,
            "udm_query": self.udm_query,
            "udm_queries": self.udm_queries,
        }

    @property
    def fqdn(self) -> str:
        """The name generated events actually carry in `<Computer>`."""
        return f"{self.hostname}.{self.dns_domain}" if self.dns_domain else self.hostname

    @property
    def udm_queries(self) -> list[dict[str, str]]:
        """Ordered hostname searches for this run -- try each until one hits."""
        return udm_query_ladder(self.hostname, self.dns_domain)

    @property
    def udm_query(self) -> str:
        """The query to run FIRST. Fall through `udm_queries` if it is empty.

        Not "the query that finds this run": one query cannot be that, because
        whether the domain survives normalisation is a tenant property we do not
        control. Treating this string as definitive is what turns a successful
        ingest into a reported parse failure.
        """
        return self.udm_queries[0]["query"]


def new_run() -> RunContext:
    """Mint a new run id and its marker hostname."""
    run_id = uuid.uuid4().hex[:8].upper()
    return RunContext(
        run_id=run_id,
        hostname=f"{config.HOST_PREFIX}{run_id}",
        started_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def _serialise(node: Any, depth: int = 0) -> str:
    """Flatten arbitrary event structure to searchable text."""
    if depth > 8:
        return ""
    if isinstance(node, dict):
        return " ".join(_serialise(v, depth + 1) for v in node.values())
    if isinstance(node, list):
        return " ".join(_serialise(v, depth + 1) for v in node)
    return "" if node is None else str(node)


def check_events(events: list[Any], hostname: str) -> dict[str, Any]:
    """Report which events carry the marker hostname.

    Substring matching over the whole serialised event on purpose: the marker
    may land in any of several fields depending on log type (Computer,
    principal.hostname, target.hostname), and requiring a specific one would
    reject correctly-marked events.
    """
    needle = hostname.lower()
    marked, unmarked = [], []
    for position, event in enumerate(events):
        (marked if needle in _serialise(event).lower() else unmarked).append(position)

    return {
        "hostname": hostname,
        "total": len(events),
        "marked": len(marked),
        "unmarked_indexes": unmarked,
        "safe_to_ingest": bool(events) and not unmarked,
    }


def parse_events(events_json: str) -> tuple[list[Any], str]:
    """Decode an events payload. Returns (events, error_message).

    Accepts a JSON array, a single JSON object, or newline-delimited JSON --
    `generate_synthetic_events` returns raw logs and UDM in different shapes,
    and the model should not have to normalise them by hand.
    """
    text = (events_json or "").strip()
    if not text:
        return [], "no events supplied"

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        events = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                # Not JSON at all -- raw XML/CEF lines are still markable.
                events.append(line)
        if not events:
            return [], "events_json is not valid JSON or newline-delimited JSON"
        return events, ""

    if isinstance(parsed, list):
        return parsed, ""
    if isinstance(parsed, dict):
        # Tolerate a wrapper object around the list.
        for key in ("events", "udmEvents", "udm_events", "logs", "rawLogs"):
            value = parsed.get(key)
            if isinstance(value, list):
                return value, ""
        return [parsed], ""
    return [parsed], ""


def save_run(
    run: RunContext,
    payload: dict[str, Any],
    groups: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Write a run's artefacts to <PURPLE_OUT_DIR>/<run_id>/.

    Three kinds of file, because they serve different jobs:

    - `<LOG_TYPE>.xml` -- one raw event per line, exactly the strings passed to
      `import_logs`. This is the replayable artefact: it can be re-ingested,
      diffed between runs, or handed to someone without this tool.
    - `events.json`   -- structured events plus the flat field view the oracle saw.
    - `manifest.json` -- run identity, counts, and the UDM query that finds the
      run after ingest, so a folder is self-describing weeks later.

    Returns a dict of what was written.
    """
    directory = config.OUT_DIR / run.run_id
    directory.mkdir(parents=True, exist_ok=True)

    written: dict[str, str] = {}

    events_path = directory / "events.json"
    events_path.write_text(
        json.dumps({"run": run.to_dict(), **payload}, indent=2), encoding="utf-8"
    )
    written["events"] = str(events_path)

    counts: dict[str, int] = {}
    for log_type, logs in (groups or {}).items():
        # Newline-delimited: each line is one complete event, so the file can be
        # replayed with a one-line read loop.
        xml_path = directory / f"{log_type}.xml"
        xml_path.write_text("\n".join(logs) + "\n", encoding="utf-8")
        written[log_type] = str(xml_path)
        counts[log_type] = len(logs)

    manifest_path = directory / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "run": run.to_dict(),
                "log_types": counts,
                "total_events": sum(counts.values()),
                "files": written,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    written["manifest"] = str(manifest_path)

    return {"directory": str(directory), "files": written, "log_type_counts": counts}
