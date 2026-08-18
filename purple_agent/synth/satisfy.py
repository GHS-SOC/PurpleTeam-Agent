"""Turn Sigma selectors into concrete field values that satisfy them.

A Sigma selector is a *constraint*, not a value. `CommandLine|contains:
'sekurlsa::logonpasswords'` says what must appear somewhere in the command line;
it does not give you a command line. This module inverts each constraint into a
value that provably satisfies it.

Two things make this harder than string formatting, and both are where naive
generation quietly fails:

- **Several constraints can target one field.** A rule may require CallTrace to
  start with one string, contain another, and end with a third. They must be
  composed into a single value, not applied one at a time.
- **`condition: selection and not filter` means the filter must be actively
  avoided.** Generate a value that happens to match `filter`, and the rule looks
  satisfied but excludes the event. The result is a "coverage gap" that is
  really a generation bug.

Anything that cannot be inverted (a regex, a `fieldref`) is reported in
`unresolved` for the model to supply a literal for. It is never guessed at.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from ..corpus import match as sigma_match

# Modifiers whose constraint we can invert into a value.
_INVERTIBLE = {"contains", "startswith", "endswith", "all", "windash", "cidr"}
# Modifiers we recognise but cannot invert without guessing.
_UNINVERTIBLE = {"re", "fieldref", "base64", "base64offset", "utf16", "utf16le",
                 "utf16be", "wide", "expand"}


@dataclass
class FieldPlan:
    """The value chosen for one field, and how it was derived."""

    field: str
    value: str
    constraints: list[str] = field(default_factory=list)


@dataclass
class SelectionPlan:
    """Concrete field values satisfying one rule's positive selections."""

    fields: dict[str, str] = field(default_factory=dict)
    constraints: dict[str, list[str]] = field(default_factory=dict)
    unresolved: list[dict[str, str]] = field(default_factory=list)
    avoided_filters: list[str] = field(default_factory=list)
    # Fields whose tail was pinned by an `endswith` constraint. Only these may
    # have a later `contains` fragment spliced in BEFORE the closing character;
    # for anything else the trailing bracket or quote is part of the fragment
    # itself, and splicing into it destroys both fragments. See _compose.
    suffix_pinned: set[str] = field(default_factory=set, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fields": self.fields,
            "constraints": self.constraints,
            "unresolved": self.unresolved,
            "avoided_filters": self.avoided_filters,
        }


def _split_key(key: str) -> tuple[str, list[str]]:
    parts = key.split("|")
    return parts[0], [p.lower() for p in parts[1:]]


def _first_value(value: Any, modifiers: list[str]) -> Any:
    """Pick a representative value from a selector.

    For a plain list (OR) the first entry is enough. `|all` needs every entry,
    handled by the caller.
    """
    if isinstance(value, list):
        return value[0] if value else ""
    return value


def _invert_cidr(expected: str) -> str:
    """A concrete address inside the CIDR network a rule pinned.

    `DestinationIp|cidr: '10.0.0.0/8'` is a network, not a value -- writing it
    verbatim isn't even a valid IP address, so the oracle's own `ipaddress.
    ip_address()` call raises and reports NO_MATCH. `network_address` itself
    is the network identifier, reserved on most real subnets, so +1 is the
    first genuinely assignable host address in the range.
    """
    try:
        network = ipaddress.ip_network(str(expected).strip(), strict=False)
    except ValueError:
        return str(expected)  # not a real network; unresolved rather than guessed
    return str(network.network_address + 1 if network.num_addresses > 1
               else network.network_address)


def _compose(
    existing: str | None,
    modifiers: list[str],
    expected: str,
    field_name: str = "",
    suffix_pinned: bool = False,
) -> str:
    """Fold one constraint into a value already being built for this field."""
    if "cidr" in modifiers:
        # A network, not a substring -- nothing to compose with; it replaces
        # whatever else was being built for this field, the same as equality.
        return _invert_cidr(expected)
    if "startswith" in modifiers:
        if existing and not existing.lower().startswith(expected.lower()):
            return expected + existing
        return existing or expected
    if "endswith" in modifiers:
        if existing and not existing.lower().endswith(expected.lower()):
            return existing + expected
        return existing or expected
    if "contains" in modifiers:
        if existing and expected.lower() in existing.lower():
            return existing
        if existing:
            if suffix_pinned:
                # An endswith constraint pinned the tail; keep it at the end.
                return _insert_preserving_suffix(existing, expected)
            return _append_fragment(existing, expected, field_name)
        return expected
    # Plain equality replaces whatever was there -- it is the strongest claim.
    return expected


def _insert_preserving_suffix(existing: str, addition: str) -> str:
    """Add a substring without disturbing a suffix `endswith` pinned.

    Only correct when a suffix really was pinned -- see _append_fragment for why
    applying it unconditionally is a bug.
    """
    for boundary in (")", "\"", "'"):
        if existing.endswith(boundary):
            return existing[:-1] + addition + boundary
    return existing + " " + addition


# Fields whose value is source code rather than a path or a command line. Their
# fragments are joined with PowerShell's statement separator so the result reads
# as a script, not as one mangled expression.
_CODE_FIELDS = frozenset({"ScriptBlockText", "Payload", "ContextInfo", "Data"})


def _append_fragment(existing: str, addition: str, field_name: str) -> str:
    """Add a fragment to a value whose tail is NOT pinned by `endswith`.

    Splitting this out from _insert_preserving_suffix fixes a real corruption.
    That function inserts before a trailing `)`, `"` or `'` -- correct when an
    `endswith` constraint put the character there, wrong when the character is
    simply the last one of the previous fragment. Applied unconditionally to

        ScriptBlockText|contains|all:
          - '[Ref].Assembly.GetType'
          - 'SetValue($null,$true)'
          - 'NonPublic,Static'

    it produced `[Ref].Assembly.GetType SetValue($null,$trueNonPublic,Static)`
    -- the third fragment spliced inside the second's closing bracket, so NONE
    of the three `contains` constraints hold. The oracle then reports NO_MATCH
    on a rule the generator was asked to satisfy, and `unresolved` stays empty
    so nothing flags it.
    """
    if field_name in _CODE_FIELDS:
        return f"{existing}; {addition}"
    return f"{existing} {addition}"


def _looks_like_path(value: str) -> bool:
    return "\\" in value or value.lower().endswith(".exe") or value.lower().endswith(".dll")


def _expand_partial(field_name: str, value: str, modifiers: list[str]) -> str:
    """Make a fragment look like a real value.

    `Image|endswith: '\\mimikatz.exe'` satisfies the rule as-is, but ingesting a
    bare `\\mimikatz.exe` as an image path produces telemetry no analyst would
    believe -- and Chronicle's parsers may reject it. Prefix a plausible
    directory; the constraint still holds because it only pins the suffix.
    """
    if "endswith" not in modifiers or not value.startswith("\\"):
        return value
    if not _looks_like_path(value):
        return value
    lowered = field_name.lower()
    if "parent" in lowered:
        return "C:\\Windows\\System32" + value
    if "target" in lowered and "image" in lowered:
        return "C:\\Windows\\system32" + value
    return "C:\\Users\\svc_backup\\AppData\\Local\\Temp" + value


# Modifier precedence when several constraints target one field. Equality is the
# strongest claim, anchors come next, and `contains` is folded in last so it
# never overwrites a pinned prefix or suffix. Without this ordering the result
# depends on YAML key order, which is arbitrary.
_MODIFIER_PRIORITY = {"": 0, "startswith": 1, "endswith": 2, "contains": 3}


def _constraint_rank(modifiers: list[str]) -> int:
    for name, rank in sorted(_MODIFIER_PRIORITY.items(), key=lambda kv: kv[1]):
        if name and name in modifiers:
            return rank
    return 0 if not modifiers else 4


# A realistic skeleton for fields where satisfying the constraint alone leaves
# an implausible value. CallTrace is the main one: rules match on a substring,
# but a real CallTrace is a pipe-delimited stack, and a bare "dbgcore.dll"
# is obviously synthetic to anyone reading the alert.
_CALLTRACE_HEAD = "C:\\Windows\\SYSTEM32\\ntdll.dll+9d234"
_CALLTRACE_TAIL = "UNKNOWN(00000000001C119B)"


def _realism_pass(plan: "SelectionPlan") -> None:
    """Repair values that satisfy their constraint but do not look real."""
    for name, value in list(plan.fields.items()):
        if not value:
            continue

        # Sigma writes drive-agnostic prefixes as ':\Windows\...' so the rule
        # matches any drive letter. Restore one.
        if value.startswith(":\\"):
            value = "C" + value

        # A directory fragment ('C:\Perflogs\') is not an image path.
        if value.endswith("\\") and "image" in name.lower():
            value += "rundll32.exe"

        if name == "CallTrace" and "|" not in value:
            frame = (
                f"C:\\Windows\\System32\\{value}+2d81e"
                if value.lower().endswith(".dll")
                else value
            )
            value = f"{_CALLTRACE_HEAD}|{frame}|{_CALLTRACE_TAIL}"

        plan.fields[name] = value


def plan_selection(
    detection: dict[str, Any], condition: str = ""
) -> SelectionPlan:
    """Build concrete field values satisfying a rule's positive selections.

    Blocks named `filter*` are treated as exclusions: their values are recorded
    so the caller can avoid colliding with them, never as things to satisfy.
    """
    plan = SelectionPlan()
    negated = _negated_blocks(detection, condition)

    for block_name, block in detection.items():
        if block_name in negated:
            plan.avoided_filters.append(block_name)
            continue
        for mapping in _iter_maps(block):
            _apply_map(plan, mapping)

    _realism_pass(plan)
    _avoid_filters(plan, detection, negated)
    return plan


def _negated_blocks(detection: dict[str, Any], condition: str) -> set[str]:
    """Selection names the condition negates, e.g. `not filter_legit`."""
    negated = set()
    tokens = (condition or "").replace("(", " ").replace(")", " ").split()
    for index, token in enumerate(tokens):
        if token.lower() == "not" and index + 1 < len(tokens):
            target = tokens[index + 1]
            if target.endswith("*"):
                prefix = target[:-1]
                negated.update(n for n in detection if n.startswith(prefix))
            elif target.lower() not in ("of", "them", "1", "all"):
                negated.add(target)
    # A block named filter* is an exclusion by Sigma convention even when the
    # condition is written in a form this simple parser does not decompose.
    negated.update(n for n in detection if n.startswith("filter"))
    return negated & set(detection)


def _iter_maps(block: Any):
    if isinstance(block, dict):
        yield block
    elif isinstance(block, list):
        for item in block:
            if isinstance(item, dict):
                yield item
            # A bare keyword in a list carries no field to assign it to.


def _apply_map(plan: SelectionPlan, mapping: dict[str, Any]) -> None:
    # Strongest constraints first, so `contains` folds into a value whose prefix
    # and suffix are already pinned rather than fighting them.
    ordered = sorted(mapping.items(), key=lambda kv: _constraint_rank(_split_key(kv[0])[1]))
    for key, raw in ordered:
        field_name, modifiers = _split_key(key)

        if set(modifiers) & _UNINVERTIBLE:
            plan.unresolved.append({
                "field": field_name,
                "constraint": f"{key}: {raw}",
                "reason": (
                    f"the {'/'.join(sorted(set(modifiers) & _UNINVERTIBLE))} "
                    "modifier cannot be inverted into a value automatically"
                ),
            })
            continue

        if raw is None:
            # `field: null` means the field must be absent -- nothing to emit.
            continue

        values = raw if (isinstance(raw, list) and "all" in modifiers) else [
            _first_value(raw, modifiers)
        ]

        for value in values:
            # Sigma escapes (\* \? \\) stand for literal characters. Emitting
            # them verbatim puts a backslash in the event that no host produces.
            expected = _expand_partial(
                field_name, sigma_match.unescape_sigma(value), modifiers)
            current = plan.fields.get(field_name)
            plan.fields[field_name] = _compose(
                current,
                modifiers,
                expected,
                field_name=field_name,
                suffix_pinned=field_name in plan.suffix_pinned,
            )
            plan.constraints.setdefault(field_name, []).append(f"{key}: {value}")

        # Recorded after composing, so a rule pinning both an endswith and a
        # contains on one field still gets the contains folded in ahead of the
        # suffix. _MODIFIER_PRIORITY guarantees endswith is applied first.
        if "endswith" in modifiers:
            plan.suffix_pinned.add(field_name)


def _avoid_filters(
    plan: SelectionPlan, detection: dict[str, Any], negated: set[str]
) -> None:
    """Check planned values against exclusion blocks and fix collisions.

    This is the step that makes `selection and not filter` work. Without it the
    generated event satisfies the selection, trips the filter, and the rule
    never fires -- which reads as a coverage gap rather than a generation bug.
    """
    from ..corpus import match as sigma_match

    for block_name in negated:
        for mapping in _iter_maps(detection.get(block_name)):
            if _map_matches(mapping, plan.fields, sigma_match):
                _break_collision(plan, mapping, block_name, sigma_match)


def _map_matches(mapping: dict[str, Any], fields: dict[str, str], sigma_match) -> bool:
    """Would the planned values trip this exclusion block?"""
    for key, expected in mapping.items():
        field_name, _ = _split_key(key)
        if field_name not in fields:
            return False
        if not sigma_match._match_field(fields, key, expected):
            return False
    return True


def _break_collision(
    plan: SelectionPlan, mapping: dict[str, Any], block_name: str, sigma_match
) -> None:
    """Nudge one planned value so an exclusion block no longer matches.

    Only fields not pinned by a positive constraint are safe to change --
    altering a pinned field would break the detection we are trying to trip.
    """
    for key, expected in mapping.items():
        field_name, modifiers = _split_key(key)
        if field_name not in plan.fields:
            continue
        if plan.constraints.get(field_name):
            continue  # pinned by a positive selection; leave it alone
        candidate = f"C:\\Windows\\Temp\\pt_{field_name.lower()}.exe"
        trial = dict(plan.fields)
        trial[field_name] = candidate
        if not sigma_match._match_field(trial, key, expected):
            plan.fields[field_name] = candidate
            return

    plan.unresolved.append({
        "field": ", ".join(sorted({_split_key(k)[0] for k in mapping})),
        "constraint": f"exclusion block {block_name}",
        "reason": (
            f"planned values also satisfy `{block_name}`, which the condition "
            "negates, so the rule would exclude this event. Every colliding "
            "field is pinned by a positive selection -- choose different values "
            "by hand."
        ),
    })
