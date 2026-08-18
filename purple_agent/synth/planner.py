"""Plan and build an event chain from Sigma rules.

The bridge between `corpus/` (what to detect) and `winevt.py` (how to write it).
Given rule ids, this works out which Windows events carry that telemetry, what
field values satisfy the selectors, and emits the events -- then hands the
result to the oracle so a miss is caught before anything is ingested.
"""

from __future__ import annotations

from typing import Any

from ..corpus import match as sigma_match
from ..corpus import retrieve
from . import mapping, satisfy, winevt
from .scenario import ScenarioContext, new_scenario


def _explicit_event_id(value: Any) -> int:
    """Read an Event ID a rule pinned in its selection. 0 when there is none."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def plan_from_rules(sigma_ids: list[str]) -> dict[str, Any]:
    """Work out the events and field values needed to satisfy each rule.

    Returns a draft plan. `unresolved` entries are constraints that could not be
    inverted automatically (regexes, exclusion collisions); the caller supplies
    literals for those before building.
    """
    steps: list[dict[str, Any]] = []
    problems: list[dict[str, str]] = []

    for sigma_id in sigma_ids:
        rule = retrieve.get_rule(sigma_id)
        if rule is None:
            problems.append({"sigma_id": sigma_id, "reason": "not in the index"})
            continue

        plan = satisfy.plan_selection(rule.detection, rule.condition)

        # A rule that selects on `EventID: 4624` is naming the event it wants;
        # that beats the logsource-category guess. Pull it out of the field plan
        # -- EventID belongs in the <System> header, not in EventData.
        explicit = _explicit_event_id(plan.fields.pop("EventID", ""))
        plan.constraints.pop("EventID", None)

        event_ids = mapping.resolve_event_ids(
            rule.logsource_category, rule.logsource_service, explicit=explicit
        )
        if not event_ids:
            problems.append({
                "sigma_id": sigma_id,
                "rule_title": rule.title,
                "reason": (
                    f"logsource category {rule.logsource_category!r} / service "
                    f"{rule.logsource_service!r} has no Windows event mapping. "
                    "Pick a rule whose category is one of: "
                    + ", ".join(sorted(mapping.CATEGORY_EVENTS))
                ),
            })
            continue

        # Sigma's generic `registry_event` category cannot say which of Sysmon
        # 12, 13 and 14 a rule means, but a pinned EventType can: only 12 emits
        # CreateKey/DeleteKey, only 14 renames. Without this a DeleteKey rule
        # gets a SetValue event that can never trip it.
        pinned_type = plan.fields.get("EventType", "")
        if isinstance(pinned_type, str):
            owner = mapping.registry_event_for_type(pinned_type)
            if owner and owner in event_ids:
                event_ids = (owner,) + tuple(e for e in event_ids if e != owner)

        steps.append({
            "sigma_id": rule.sigma_id,
            "rule_title": rule.title,
            "level": rule.level,
            "logsource": rule.logsource,
            "event_id": event_ids[0],
            "alternate_event_ids": list(event_ids[1:]),
            "fields": plan.fields,
            "constraints": plan.constraints,
            "unresolved": plan.unresolved,
            "avoided_filters": plan.avoided_filters,
        })

    return {
        "steps": steps,
        "unmappable": problems,
        "unresolved_total": sum(len(s["unresolved"]) for s in steps),
    }


def build_chain(
    steps: list[dict[str, Any]],
    hostname: str,
    username: str = "",
    domain: str = "",
    seed: int | None = None,
) -> dict[str, Any]:
    """Build the event chain from a (possibly model-edited) plan.

    Every event shares one ScenarioContext, so the chain reads as a single
    session on one host rather than unrelated fragments.
    """
    context: ScenarioContext = new_scenario(
        hostname=hostname, username=username, domain=domain, seed=seed
    )

    events: list[winevt.GeneratedEvent] = []
    errors: list[dict[str, str]] = []

    for position, step in enumerate(steps):
        event_id = int(step.get("event_id") or 0)
        try:
            event = winevt.build_event(
                event_id=event_id,
                context=context,
                overrides=step.get("fields") or {},
                # Space events a few seconds apart so the chain has a plausible
                # order rather than all landing on one timestamp.
                offset_seconds=int(step.get("offset_seconds", position * 7)),
            )
        except ValueError as exc:
            errors.append({"sigma_id": step.get("sigma_id", ""), "error": str(exc)})
            continue
        events.append(event)

    return {
        "context": context.to_dict(),
        "events": events,
        "errors": errors,
    }


def verify_chain(
    sigma_ids: list[str], events: list[winevt.GeneratedEvent]
) -> dict[str, Any]:
    """Run the oracle over the built chain.

    This is the check that separates "the generator produced logs that were
    never going to match" from "SecOps has a real coverage gap". It runs on the
    flat field view, not the XML, so it tests the same values that were written.
    """
    field_views = [e.fields for e in events]
    results = []
    for sigma_id in sigma_ids:
        rule = retrieve.get_rule(sigma_id)
        if rule is None:
            results.append({"sigma_id": sigma_id, "verdict": "UNKNOWN_RULE"})
            continue
        results.append(sigma_match.match_any(rule, field_views).to_dict())

    matched = sum(1 for r in results if r.get("verdict") == sigma_match.MATCH)
    unsupported = sum(1 for r in results if r.get("verdict") == sigma_match.UNSUPPORTED)
    return {
        "rules_checked": len(results),
        "matched": matched,
        "unsupported": unsupported,
        "results": results,
    }
