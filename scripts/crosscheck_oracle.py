"""Cross-check the Sigma oracle against pySigma, the reference implementation.

Every other check in this project marks its own homework. `corpus/match.py` (the
oracle) and `synth/satisfy.py` (the constraint inverter) are the same codebase's
reading of the Sigma spec -- so where they misread it the same way, they agree
with each other, the oracle returns MATCH, `unresolved` stays empty, and the
corpus success rate counts the result as a win.

That is not hypothetical. The first run of this script compared 150 rules and
found 4 disagreements, every one of them ours-MATCH / pySigma-NO_MATCH. All four
were the same bug: neither side resolved Sigma's escape sequences, so `\\*`
(a literal asterisk) was emitted into the event as backslash-asterisk. The
inverter wrote it, the oracle accepted it, and no Windows host would ever produce
it -- meaning a deployed rule could not fire, and the run would have reported a
coverage gap. See `match.unescape_sigma`.

WHAT IS COMPARED

Only the `selection` block, and only its field/modifier semantics. That is
deliberate: the condition layer is our code on both sides, so comparing it would
prove nothing. The value semantics are where a correlated misreading lives, and
pySigma canonicalises each detection item into a wildcard `SigmaString` whose
`to_regex()` is an independent statement of what the rule means.

Rules the reference cannot score -- keyword items, modifiers pySigma renders
differently -- are skipped and counted, never guessed at.

USAGE

    pip install -r requirements-dev.txt
    python scripts/crosscheck_oracle.py --sample 150

Exits non-zero when any rule disagrees, so it can gate a release. It needs the
Sigma index (`scripts/build_index.py`) and the corpus in `vendor/sigma`, but no
tenant and no network.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml

from purple_agent import config
from purple_agent.corpus import match as our_match
from purple_agent.corpus import retrieve
from purple_agent.synth import planner

try:
    from sigma.rule import SigmaRule as ReferenceRule
except ImportError:  # pragma: no cover - dev-only dependency
    sys.exit("pySigma is not installed. pip install -r requirements-dev.txt")


class _Unscorable(Exception):
    """The reference implementation cannot score this rule. Not a disagreement."""


def reference_verdict(rule_path: Path, fields: dict) -> str | None:
    """MATCH / NO_MATCH under pySigma's reading, or None if it cannot be scored."""
    try:
        parsed = ReferenceRule.from_dict(
            yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        )
    except Exception:  # noqa: BLE001 - a rule we cannot parse is not a finding
        return None

    selection = parsed.detection.detections.get("selection")
    if selection is None:
        return None

    actual_by_field = {k.lower(): str(v) for k, v in fields.items()}

    def score_item(item) -> bool:
        if item.field is None:                     # keyword item
            raise _Unscorable
        actual = actual_by_field.get(item.field.lower())
        if actual is None:
            return False
        hits = []
        for value in item.value:
            try:
                pattern = str(value.to_regex().regexp)
            except Exception:  # noqa: BLE001
                raise _Unscorable from None
            hits.append(bool(re.fullmatch(pattern, actual, re.IGNORECASE)))
        need_all = "AND" in str(getattr(item, "value_linking", "")).upper()
        return all(hits) if need_all else any(hits)

    def score(node) -> bool:
        children = getattr(node, "detection_items", None)
        if children is None:
            return score_item(node)
        results = [score(child) for child in children]
        # A selection written as a list of maps is an OR of AND-groups.
        need_all = "AND" in str(getattr(node, "item_linking", "AND")).upper()
        return all(results) if need_all else any(results)

    try:
        return our_match.MATCH if score(selection) else our_match.NO_MATCH
    except _Unscorable:
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sample", type=int, default=150,
                    help="rules to compare (default 150)")
    ap.add_argument("--product", default="windows")
    args = ap.parse_args()

    rules = [r for r in retrieve.search(query="", product=args.product, limit=4000)
             if getattr(r, "filepath", None)]
    print(f"corpus: {len(rules)} {args.product} rules with a source file")

    compared = agreed = 0
    disagreements: list[tuple[str, str, str, str]] = []
    skipped = {"unsupported_by_us": 0, "unscorable_by_reference": 0, "no_event": 0}

    for rule in rules:
        if compared >= args.sample:
            break
        try:
            steps = planner.plan_from_rules([rule.sigma_id]).get("steps") or []
            events = (planner.build_chain(steps, hostname="PT-LAB-XCHECK")["events"]
                      if steps else [])
        except Exception:  # noqa: BLE001
            events = []
        if not events:
            skipped["no_event"] += 1
            continue

        fields = events[0].fields
        result = our_match.match_rule(rule, fields)
        if result.verdict == our_match.UNSUPPORTED:
            skipped["unsupported_by_us"] += 1
            continue

        theirs = reference_verdict(config.SIGMA_REPO_DIR / rule.filepath, fields)
        if theirs is None:
            skipped["unscorable_by_reference"] += 1
            continue

        ours = (our_match.MATCH if "selection" in (result.matched_selections or [])
                else our_match.NO_MATCH)
        compared += 1
        if ours == theirs:
            agreed += 1
        else:
            disagreements.append((rule.sigma_id, rule.title, ours, theirs))

    print(f"\ncompared   {compared}")
    if compared:
        print(f"agreed     {agreed}  ({agreed / compared * 100:.1f}%)")
    print(f"disagreed  {len(disagreements)}")
    for label, count in skipped.items():
        print(f"skipped    {count:<5} {label}")

    if disagreements:
        print("\nDISAGREEMENTS -- one of the two implementations is wrong:")
        for sigma_id, title, ours, theirs in disagreements:
            print(f"  ours={ours:9} reference={theirs:9}  {title[:58]}")
            print(f"      {sigma_id}")
        print("\nA disagreement in the ours-MATCH direction is the dangerous one:")
        print("it means we generated an event the rule does not actually match,")
        print("counted it as a success, and would report the silence as a gap.")
        return 1

    print("\nNo disagreements. The oracle and the reference agree on every rule "
          "the reference could score.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
