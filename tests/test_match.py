"""Tests for the Sigma oracle.

This is the highest-value suite in the project. The oracle is what separates
"the generator produced logs that were never going to match" from "SecOps has a
real coverage gap". A wrong oracle produces confidently wrong verdicts, and
someone acts on them -- either hunting a detection failure that does not exist,
or shipping a gap they think is covered.

Rules are built inline rather than read from the corpus so the tests pin the
oracle's semantics, not SigmaHQ's current content.
"""

from __future__ import annotations

import pytest

from purple_agent.corpus import match as sigma_match
from purple_agent.corpus.loader import SigmaRule
from purple_agent.corpus.match import MATCH, NO_MATCH, UNSUPPORTED, match_any, match_rule


def make_rule(detection: dict, condition: str, **overrides) -> SigmaRule:
    base = dict(
        sigma_id="test-rule",
        title="Test Rule",
        description="",
        status="test",
        level="high",
        author="",
        date="",
        logsource_category="process_access",
        logsource_product="windows",
        logsource_service="",
        detection=detection,
        condition=condition,
    )
    base.update(overrides)
    return SigmaRule(**base)


LSASS_EVENT = {
    "TargetImage": r"C:\Windows\system32\lsass.exe",
    "SourceImage": r"C:\Users\svc_backup\AppData\Local\Temp\mimikatz.exe",
    "GrantedAccess": "0x1410",
    "CallTrace": r"C:\Windows\System32\ntdll.dll+9d234|UNKNOWN(00000000001C119B)",
    "Computer": "PT-LAB-A3F91C2D",
}


class TestModifiers:
    def test_endswith_matches(self):
        rule = make_rule({"selection": {"TargetImage|endswith": r"\lsass.exe"}}, "selection")
        assert match_rule(rule, LSASS_EVENT).verdict == MATCH

    def test_endswith_rejects(self):
        rule = make_rule({"selection": {"TargetImage|endswith": r"\svchost.exe"}}, "selection")
        assert match_rule(rule, LSASS_EVENT).verdict == NO_MATCH

    def test_contains_and_startswith(self):
        rule = make_rule(
            {
                "selection": {
                    "SourceImage|contains": "mimikatz",
                    "CallTrace|startswith": r"C:\Windows\System32\ntdll.dll+",
                }
            },
            "selection",
        )
        assert match_rule(rule, LSASS_EVENT).verdict == MATCH

    def test_comparison_is_case_insensitive(self):
        """Sigma string comparison ignores case; Windows paths vary in casing."""
        rule = make_rule({"selection": {"TargetImage|endswith": r"\LSASS.EXE"}}, "selection")
        assert match_rule(rule, LSASS_EVENT).verdict == MATCH

    def test_list_value_is_or(self):
        rule = make_rule(
            {"selection": {"GrantedAccess|endswith": ["10", "30", "50"]}}, "selection"
        )
        assert match_rule(rule, LSASS_EVENT).verdict == MATCH

    def test_list_value_with_all_is_and(self):
        rule = make_rule(
            {"selection": {"SourceImage|contains|all": ["mimikatz", "Temp"]}}, "selection"
        )
        assert match_rule(rule, LSASS_EVENT).verdict == MATCH

        miss = make_rule(
            {"selection": {"SourceImage|contains|all": ["mimikatz", "System32"]}},
            "selection",
        )
        assert match_rule(miss, LSASS_EVENT).verdict == NO_MATCH

    def test_regex(self):
        rule = make_rule({"selection": {"GrantedAccess|re": r"0x1[04]10"}}, "selection")
        assert match_rule(rule, LSASS_EVENT).verdict == MATCH

    def test_windash_treats_slash_and_dash_alike(self):
        event = {"CommandLine": "procdump.exe /accepteula -ma lsass.exe"}
        rule = make_rule({"selection": {"CommandLine|contains|windash": "-accepteula"}}, "selection")
        assert match_rule(rule, event).verdict == MATCH

    def test_cidr(self):
        event = {"DestinationIp": "10.4.7.9"}
        rule = make_rule({"selection": {"DestinationIp|cidr": "10.4.0.0/16"}}, "selection")
        assert match_rule(rule, event).verdict == MATCH

    def test_null_requires_absent_field(self):
        rule = make_rule({"selection": {"ParentImage": None}}, "selection")
        assert match_rule(rule, LSASS_EVENT).verdict == MATCH
        assert match_rule(rule, {"ParentImage": r"C:\cmd.exe"}).verdict == NO_MATCH


class TestFilterBranch:
    """`selection and not filter` is where naive matching goes wrong: the
    selection matches, so the rule looks satisfied, but the filter excludes it."""

    RULE = make_rule(
        {
            "selection": {"TargetImage|endswith": r"\lsass.exe"},
            "filter": {"SourceImage|endswith": r"\wmiprvse.exe"},
        },
        "selection and not filter",
    )

    def test_matches_when_filter_does_not_apply(self):
        assert match_rule(self.RULE, LSASS_EVENT).verdict == MATCH

    def test_excluded_when_filter_applies(self):
        benign = {**LSASS_EVENT, "SourceImage": r"C:\Windows\System32\wbem\wmiprvse.exe"}
        result = match_rule(self.RULE, benign)
        assert result.verdict == NO_MATCH
        assert "filter" in result.reason


class TestConditions:
    def test_or_condition(self):
        rule = make_rule(
            {
                "selection_a": {"TargetImage|endswith": r"\lsass.exe"},
                "selection_b": {"TargetImage|endswith": r"\nowhere.exe"},
            },
            "selection_a or selection_b",
        )
        assert match_rule(rule, LSASS_EVENT).verdict == MATCH

    def test_and_condition_requires_both(self):
        rule = make_rule(
            {
                "selection_a": {"TargetImage|endswith": r"\lsass.exe"},
                "selection_b": {"TargetImage|endswith": r"\nowhere.exe"},
            },
            "selection_a and selection_b",
        )
        assert match_rule(rule, LSASS_EVENT).verdict == NO_MATCH

    def test_one_of_quantifier(self):
        rule = make_rule(
            {
                "selection_img": {"TargetImage|endswith": r"\lsass.exe"},
                "selection_other": {"TargetImage|endswith": r"\nope.exe"},
            },
            "1 of selection_*",
        )
        assert match_rule(rule, LSASS_EVENT).verdict == MATCH

    def test_all_of_quantifier(self):
        rule = make_rule(
            {
                "selection_img": {"TargetImage|endswith": r"\lsass.exe"},
                "selection_other": {"TargetImage|endswith": r"\nope.exe"},
            },
            "all of selection_*",
        )
        assert match_rule(rule, LSASS_EVENT).verdict == NO_MATCH


class TestUnsupportedIsNeverAGap:
    """An unevaluable rule must never be reported as NO_MATCH.

    A false NO_MATCH reads as a coverage gap in the final report. "I could not
    check this" and "this is not covered" are different claims.
    """

    def test_aggregation_is_unsupported(self):
        rule = make_rule(
            {"selection": {"TargetImage|endswith": r"\lsass.exe"}},
            "selection | count() by SourceImage > 5",
        )
        assert match_rule(rule, LSASS_EVENT).verdict == UNSUPPORTED

    def test_fieldref_modifier_is_unsupported(self):
        rule = make_rule({"selection": {"TargetImage|fieldref": "SourceImage"}}, "selection")
        assert match_rule(rule, LSASS_EVENT).verdict == UNSUPPORTED

    def test_undefined_selection_name_is_unsupported(self):
        rule = make_rule(
            {"selection": {"TargetImage|endswith": r"\lsass.exe"}},
            "selection and not undefined_block",
        )
        assert match_rule(rule, LSASS_EVENT).verdict == UNSUPPORTED

    def test_empty_condition_is_unsupported(self):
        rule = make_rule({"selection": {"TargetImage|endswith": r"\lsass.exe"}}, "")
        assert match_rule(rule, LSASS_EVENT).verdict == UNSUPPORTED


class TestFieldLookup:
    def test_finds_field_nested_under_event_data(self):
        event = {"Computer": "PT-LAB-1", "EventData": {"TargetImage": r"C:\x\lsass.exe"}}
        rule = make_rule({"selection": {"TargetImage|endswith": r"\lsass.exe"}}, "selection")
        assert match_rule(rule, event).verdict == MATCH

    def test_finds_dotted_udm_path(self):
        event = {"principal": {"process": {"command_line": "mimikatz.exe sekurlsa::logonpasswords"}}}
        rule = make_rule(
            {"selection": {"principal.process.command_line|contains": "sekurlsa::"}},
            "selection",
        )
        assert match_rule(rule, event).verdict == MATCH


class TestMatchAny:
    RULE = make_rule({"selection": {"TargetImage|endswith": r"\lsass.exe"}}, "selection")

    def test_matches_if_any_event_matches(self):
        events = [{"TargetImage": r"C:\x\svchost.exe"}, LSASS_EVENT]
        assert match_any(self.RULE, events).verdict == MATCH

    def test_no_events_is_no_match(self):
        assert match_any(self.RULE, []).verdict == NO_MATCH

    def test_unsupported_outranks_no_match(self):
        """With one unevaluable event and one clean miss, report UNSUPPORTED --
        claiming NO_MATCH would understate coverage."""
        rule = make_rule({"selection": {"TargetImage|fieldref": "SourceImage"}}, "selection")
        result = match_any(rule, [{"TargetImage": "a"}, {"TargetImage": "b"}])
        assert result.verdict == UNSUPPORTED


@pytest.mark.parametrize(
    "tags,expected",
    [
        (["attack.t1003.001", "attack.credential-access"], ["T1003.001"]),
        (["attack.s0002"], []),  # software tag, not a technique
        (["attack.t1003", "attack.t1003"], ["T1003"]),  # deduplicated
    ],
)
def test_technique_extraction(tags, expected):
    from purple_agent.corpus.loader import techniques_from_tags

    assert techniques_from_tags(tags) == expected


class TestSigmaEscapeSequences:
    """`\\*` in a Sigma rule means a literal asterisk, not backslash-asterisk.

    Both the oracle and the constraint inverter used to take these verbatim. The
    two wrongs cancelled: the inverter wrote `/tn \\*` into the event, the oracle
    compared against `/tn \\*`, and both agreed -- on a string no Windows host
    emits. A deployed rule cannot fire on it, so the run reports a coverage gap
    that is really a generation bug.

    Invisible to every existing check, because they all share the same parser.
    Found by scripts/crosscheck_oracle.py against pySigma: 4 disagreements in 150
    rules, all of them this. Rules below are the real ones.
    """

    def test_escaped_asterisk_becomes_a_literal_asterisk(self):
        # "Delete All Scheduled Tasks", CommandLine|contains|all
        assert sigma_match.unescape_sigma(r"/tn \*") == "/tn *"

    def test_escaped_backslashes_collapse(self):
        # "Copy From VolumeShadowCopy Via Cmd.EXE"
        assert (sigma_match.unescape_sigma(r"\\\\?\\GLOBALROOT\\Device")
                == r"\\?\GLOBALROOT\Device")

    def test_escaped_question_mark(self):
        assert sigma_match.unescape_sigma(r"file\?.exe") == "file?.exe"

    def test_bare_wildcards_are_left_alone(self):
        """Only escapes are resolved. An unescaped `*` still means whatever the
        matcher takes it to mean."""
        assert sigma_match.unescape_sigma("*lsass.exe") == "*lsass.exe"

    def test_a_lone_backslash_survives(self):
        r"""`C:\Windows` is a path, not an escape."""
        assert sigma_match.unescape_sigma(r"C:\Windows\System32") == r"C:\Windows\System32"

    def test_the_oracle_matches_the_unescaped_value(self):
        """End to end: an event carrying a literal `*` satisfies `\\*`."""
        event = {"CommandLine": "schtasks /delete /tn * /f"}
        assert sigma_match._match_field(event, "CommandLine|contains", r"/tn \*") is True
        assert sigma_match._match_field(event, "CommandLine|contains", r"/tn \\*") is False
