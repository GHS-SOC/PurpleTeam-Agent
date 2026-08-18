"""Evaluate a Sigma rule against a single event -- the oracle.

Why this exists: `generate_synthetic_events` is LLM-backed and produces
*realistic* logs, not necessarily logs that satisfy a *specific* detection. If
we skip this check, events that were never going to trip a mimikatz rule look
identical to a genuine coverage gap in the final report. This module tells those
two apart.

Honesty rule, and the reason for the `UNSUPPORTED` verdict: when a construct
cannot be evaluated (a `fieldref` comparison, an unparseable condition), that is
reported as such. It is never silently downgraded to "no match" -- a false "no
match" here reads as a coverage gap and sends someone hunting for a detection
problem that does not exist.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

MATCH = "MATCH"
NO_MATCH = "NO_MATCH"
UNSUPPORTED = "UNSUPPORTED"

# Modifiers that change how a value is compared.
_VALUE_MODIFIERS = {
    "contains", "startswith", "endswith", "re", "i", "cidr", "windash",
    "base64", "base64offset", "utf16", "utf16le", "utf16be", "wide", "expand",
}
# Modifiers we understand but cannot evaluate against a plain event.
_UNSUPPORTED_MODIFIERS = {"fieldref", "expand", "base64", "utf16", "utf16le", "utf16be", "wide"}


@dataclass
class MatchResult:
    """Outcome of evaluating one rule against one event."""

    verdict: str
    rule_id: str = ""
    rule_title: str = ""
    matched_selections: list[str] = field(default_factory=list)
    # Human-readable reason the rule did not match, or why it could not be
    # evaluated. Empty on MATCH.
    reason: str = ""

    @property
    def matched(self) -> bool:
        return self.verdict == MATCH

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "matched_selections": self.matched_selections,
            "reason": self.reason,
        }


# --------------------------------------------------------------------------
# Field lookup
# --------------------------------------------------------------------------
def _lookup(event: dict[str, Any], field_name: str) -> Any:
    """Fetch a field from an event, tolerating shape differences.

    Sigma names Windows event fields flat (`TargetImage`, `CommandLine`).
    Generated events may present them flat, nested under an EventData block, or
    dotted UDM-style. Try each rather than fail on presentation.
    """
    if field_name in event:
        return event[field_name]

    for container in ("EventData", "event_data", "eventData", "data"):
        nested = event.get(container)
        if isinstance(nested, dict) and field_name in nested:
            return nested[field_name]

    # Dotted path, e.g. "principal.process.command_line".
    if "." in field_name:
        current: Any = event
        for part in field_name.split("."):
            if not isinstance(current, dict) or part not in current:
                break
            current = current[part]
        else:
            return current

    # Case-insensitive last resort: Windows field casing varies by source.
    lowered = field_name.lower()
    for key, value in event.items():
        if isinstance(key, str) and key.lower() == lowered:
            return value
    return None


# --------------------------------------------------------------------------
# Value comparison
# --------------------------------------------------------------------------
def _windash_variants(value: str) -> list[str]:
    """All dash spellings Sigma's `windash` modifier treats as equivalent."""
    dashes = ["-", "/", "–", "—", "―"]
    if not value or value[0] not in dashes:
        return [value]
    return [d + value[1:] for d in dashes]


_SIGMA_ESCAPE = re.compile(r"\\([*?\\])")


def unescape_sigma(value: str) -> str:
    r"""Resolve Sigma's escape sequences into the characters they stand for.

    In Sigma, `\*` means a literal asterisk, `\?` a literal question mark, and
    `\\` a single backslash. Treating them as plain text is wrong twice over, and
    the two wrongs cancel out invisibly: the inverter emits `/tn \*` into the
    event, the oracle compares against `/tn \*`, both agree, and the event that
    ships carries a backslash no Windows host would ever produce.

    Found by cross-checking 150 rules against pySigma, the reference
    implementation. Four disagreed, all of them ours-MATCH / pySigma-NO_MATCH,
    and all four were this. A deployed rule would not fire on the events we
    generated for them -- which reads downstream as a coverage gap.
    """
    return _SIGMA_ESCAPE.sub(r"\1", str(value))


def _compare_one(actual: Any, expected: Any, modifiers: list[str]) -> bool:
    """Compare a single actual value against a single expected value."""
    if expected is None:
        return actual is None
    if actual is None:
        return False

    if "cidr" in modifiers:
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(
                str(expected), strict=False
            )
        except ValueError:
            return False

    actual_str = str(actual)
    expected_str = unescape_sigma(expected)

    if "re" in modifiers:
        flags = re.IGNORECASE if "i" in modifiers else 0
        try:
            return re.search(expected_str, actual_str, flags) is not None
        except re.error:
            return False

    if "base64offset" in modifiers:
        # Sigma matches the value at any of three byte alignments.
        encodings = {
            base64.b64encode(prefix + expected_str.encode()).decode()[
                (len(prefix) * 8 + 5) // 6 :
            ]
            for prefix in (b"", b"X", b"XX")
        }
        return any(e and e in actual_str for e in encodings)

    candidates = (
        _windash_variants(expected_str) if "windash" in modifiers else [expected_str]
    )

    # Sigma string comparison is case-insensitive by default.
    actual_low = actual_str.lower()
    for candidate in candidates:
        cand = candidate.lower()
        if "contains" in modifiers:
            if cand in actual_low:
                return True
        elif "startswith" in modifiers:
            if actual_low.startswith(cand):
                return True
        elif "endswith" in modifiers:
            if actual_low.endswith(cand):
                return True
        elif actual_low == cand:
            return True
    return False


def _match_field(event: dict[str, Any], key: str, expected: Any) -> bool | None:
    """Evaluate one `Field|modifiers: value` entry. None means unsupported."""
    parts = key.split("|")
    field_name, modifiers = parts[0], [m.lower() for m in parts[1:]]

    if set(modifiers) & _UNSUPPORTED_MODIFIERS:
        return None

    actual = _lookup(event, field_name)

    # `null` value means "field must be absent or null".
    if expected is None:
        return actual is None

    if isinstance(expected, list):
        # A list is OR by default; `|all` makes it AND.
        results = [_compare_one(actual, item, modifiers) for item in expected]
        return all(results) if "all" in modifiers else any(results)

    return _compare_one(actual, expected, modifiers)


def _match_map(event: dict[str, Any], mapping: dict[str, Any]) -> bool | None:
    """A selection map: every key must match (AND). None means unsupported."""
    for key, expected in mapping.items():
        result = _match_field(event, key, expected)
        if result is None:
            return None
        if not result:
            return False
    return True


def _match_selection(event: dict[str, Any], selection: Any) -> bool | None:
    """Evaluate one named selection block against the event."""
    if isinstance(selection, dict):
        return _match_map(event, selection)
    if isinstance(selection, list):
        # A list of maps is OR. Keywords (bare strings) match anywhere in the
        # serialised event.
        unsupported = False
        for item in selection:
            if isinstance(item, dict):
                result = _match_map(event, item)
            else:
                result = str(item).lower() in _serialise(event).lower()
            if result is None:
                unsupported = True
            elif result:
                return True
        return None if unsupported else False
    if selection is None:
        return False
    return str(selection).lower() in _serialise(event).lower()


def _serialise(event: dict[str, Any]) -> str:
    """Flatten an event to text for keyword-style selections."""
    chunks: list[str] = []

    def walk(node: Any, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                chunks.append(str(key))
                walk(value, depth + 1)
        elif isinstance(node, list):
            for value in node:
                walk(value, depth + 1)
        elif node is not None:
            chunks.append(str(node))

    walk(event)
    return " ".join(chunks)


# --------------------------------------------------------------------------
# Condition evaluation
# --------------------------------------------------------------------------
_CONDITION_TOKEN = re.compile(r"\(|\)|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_*]+")

# `1 of them` / `all of selection_*` etc. -- handled before tokenising.
# The alternatives are ordered longest-first and the wildcard form carries no
# trailing \b: a `*` is a non-word character, so `\b` after it can never match
# and `1 of selection_*` would silently fail to parse.
_QUANTIFIER = re.compile(
    r"\b(1|all)\s+of\s+(them\b|[A-Za-z0-9_]+\*|[A-Za-z0-9_]+\b)", re.IGNORECASE
)


def _resolve_quantifier(
    quantity: str, target: str, results: dict[str, bool | None]
) -> bool | None:
    """Resolve `1 of x*` / `all of them` against evaluated selections."""
    if target.lower() == "them":
        names = list(results)
    elif target.endswith("*"):
        prefix = target[:-1]
        names = [n for n in results if n.startswith(prefix)]
    else:
        names = [n for n in results if n == target]

    if not names:
        return False

    values = [results[n] for n in names]
    if quantity.lower() == "all":
        if any(v is None for v in values):
            return None
        return all(values)
    if any(v is True for v in values):
        return True
    return None if any(v is None for v in values) else False


def _evaluate_condition(
    condition: str, results: dict[str, bool | None]
) -> bool | None:
    """Evaluate a Sigma condition string against evaluated selection results.

    Supports and/or/not, parentheses, and `1 of` / `all of` quantifiers -- which
    covers the overwhelming majority of the corpus. Anything else (aggregations
    like `| count() > 5`, `near`) returns None rather than a guess: those need a
    time window over many events, which a single-event oracle cannot provide.
    """
    if not condition.strip():
        return None

    # Aggregations and correlations operate over event streams, not one event.
    if "|" in condition or " near " in condition.lower():
        return None

    placeholder_values: list[bool | None] = []

    def replace_quantifier(match: re.Match) -> str:
        value = _resolve_quantifier(match.group(1), match.group(2), results)
        placeholder_values.append(value)
        return f"__Q{len(placeholder_values) - 1}__"

    normalised = _QUANTIFIER.sub(replace_quantifier, condition)

    tokens = _CONDITION_TOKEN.findall(normalised)
    if not tokens:
        return None

    saw_unsupported = False
    expression_parts: list[str] = []
    for token in tokens:
        low = token.lower()
        if low in ("and", "or", "not"):
            expression_parts.append(low)
        elif token in ("(", ")"):
            expression_parts.append(token)
        elif token.startswith("__Q") and token.endswith("__"):
            value = placeholder_values[int(token[3:-2])]
            if value is None:
                saw_unsupported = True
                value = False
            expression_parts.append(str(value))
        else:
            if token.endswith("*"):
                value = _resolve_quantifier("1", token, results)
            elif token in results:
                value = results[token]
            else:
                # A name the detection block never defined -- unevaluable.
                return None
            if value is None:
                saw_unsupported = True
                value = False
            expression_parts.append(str(value))

    expression = " ".join(expression_parts)
    if not re.fullmatch(r"[\sA-Za-z()]+", expression):
        return None
    try:
        # Only True/False/and/or/not/parens remain -- no names, no calls.
        outcome = eval(expression, {"__builtins__": {}}, {})  # noqa: S307
    except (SyntaxError, NameError, TypeError):
        return None

    if saw_unsupported and not outcome:
        # An unsupported piece was treated as False; a False result may be an
        # artefact of that, so refuse to claim NO_MATCH.
        return None
    return bool(outcome)


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------
def match_rule(rule, event: dict[str, Any]) -> MatchResult:
    """Evaluate one SigmaRule against one event."""
    results: dict[str, bool | None] = {}
    for name, selection in rule.detection.items():
        results[name] = _match_selection(event, selection)

    outcome = _evaluate_condition(rule.condition, results)
    matched_names = [n for n, v in results.items() if v]

    if outcome is None:
        return MatchResult(
            verdict=UNSUPPORTED,
            rule_id=rule.sigma_id,
            rule_title=rule.title,
            matched_selections=matched_names,
            reason=(
                f"condition `{rule.condition}` uses a construct this oracle "
                "cannot evaluate against a single event (aggregation, "
                "correlation, or an unsupported modifier)"
            ),
        )

    if outcome:
        return MatchResult(
            verdict=MATCH,
            rule_id=rule.sigma_id,
            rule_title=rule.title,
            matched_selections=matched_names,
        )

    unmet = [n for n, v in results.items() if v is False and not n.startswith("filter")]
    filters_hit = [n for n, v in results.items() if v and n.startswith("filter")]
    if filters_hit:
        reason = f"excluded by {', '.join(filters_hit)}"
    elif unmet:
        reason = f"selection(s) not satisfied: {', '.join(unmet)}"
    else:
        reason = f"condition `{rule.condition}` evaluated false"

    return MatchResult(
        verdict=NO_MATCH,
        rule_id=rule.sigma_id,
        rule_title=rule.title,
        matched_selections=matched_names,
        reason=reason,
    )


def match_any(rule, events: list[dict[str, Any]]) -> MatchResult:
    """Evaluate a rule against several events; a rule matches if any event does.

    A MATCH on any event wins. Otherwise UNSUPPORTED outranks NO_MATCH, so an
    unevaluable rule is never reported as a coverage gap.
    """
    if not events:
        return MatchResult(
            verdict=NO_MATCH,
            rule_id=getattr(rule, "sigma_id", ""),
            rule_title=getattr(rule, "title", ""),
            reason="no events supplied",
        )

    best: MatchResult | None = None
    for event in events:
        result = match_rule(rule, event)
        if result.matched:
            return result
        if best is None or (
            result.verdict == UNSUPPORTED and best.verdict == NO_MATCH
        ):
            best = result
    return best  # type: ignore[return-value]
