"""A run must never claim a detection that fired on an earlier run's events.

The failure this guards against was observed live, and it is the worst kind this
project can ship: a confident PASS for a technique nothing detected.

Two runs, thirty minutes apart. The first ingested LSASS process-access events at
19:03 and tripped a process-injection rule at 19:03:30, which opened a case at
19:15. The second run ingested PowerShell script-block events at 19:33, searched
the same rule over a window padded an hour either side of its own ingest, found
the FIRST run's detection sitting inside it, matched that detection id to the
case's alert -- the documented ownership check -- and reported PASS.

Every step was individually defensible. The ownership check confirmed the alert
carried a detection id it had genuinely seen. Nothing compared that detection's
time against the run's own ingest, and nothing checked whose events it fired on.
"""

from __future__ import annotations

import time

import pytest

from purple_agent import tools


PREV_RUN_MARKER = "PT-LAB-11111111"
THIS_RUN_MARKER = "PT-LAB-22222222"

# The detection from the earlier run, shaped as Chronicle returns it: the marker
# host is present in the raw record even though it never reaches the SOAR alert.
EARLIER_DETECTION = {
    "id": "de_00000000-0000-0000-0000-000000000001",
    "detectionTime": "2026-08-12T19:03:30Z",
    "createdTime": "2026-08-12T19:08:00Z",
    "detection": [{"ruleName": "LAB_Suspicious_Process_Injection_Activity"}],
    "collectionElements": [
        {"references": [{"event": {"principal": {"hostname":
                                                 f"{PREV_RUN_MARKER}.corp.local"}}}]}
    ],
}

THIS_RUN_DETECTION = {
    "id": "de_1111aaaa-2222-3333-4444-555566667777",
    "detectionTime": "2026-08-12T19:33:50Z",
    "createdTime": "2026-08-12T19:38:00Z",
    "detection": [{"ruleName": "LAB_Suspicious_Process_Injection_Activity"}],
    "collectionElements": [
        {"references": [{"event": {"principal": {"hostname":
                                                 f"{THIS_RUN_MARKER}.corp.local"}}}]}
    ],
}


def _entry(ingested_at: float) -> dict:
    return {"ingested_at": ingested_at}


# 2026-08-12T19:33:36Z, the second run's real ingest moment.
THIS_INGEST = 1786563216.0


class TestAnEarlierRunsDetectionIsRefused:
    """The exact live failure, replayed."""

    def test_detection_from_before_this_ingest_is_excluded(self):
        """Reverting the time floor puts the false PASS straight back."""
        mine, theirs = tools._attribute_detections(
            [EARLIER_DETECTION], _entry(THIS_INGEST), THIS_RUN_MARKER)

        assert mine == [], "an earlier run's detection was offered as this run's evidence"
        assert len(theirs) == 1
        assert "predates" in theirs[0]["excluded_because"]

    def test_this_runs_own_detection_still_counts(self):
        """The guard must not swallow real findings -- that trades a false PASS
        for a false coverage gap, which is the more expensive error."""
        mine, theirs = tools._attribute_detections(
            [THIS_RUN_DETECTION], _entry(THIS_INGEST), THIS_RUN_MARKER)

        assert [d["id"] for d in mine] == [THIS_RUN_DETECTION["id"]]
        assert theirs == []

    def test_both_present_only_ours_survives(self):
        mine, theirs = tools._attribute_detections(
            [EARLIER_DETECTION, THIS_RUN_DETECTION], _entry(THIS_INGEST),
            THIS_RUN_MARKER)

        assert [d["id"] for d in mine] == [THIS_RUN_DETECTION["id"]]
        assert [d["id"] for d in theirs] == [EARLIER_DETECTION["id"]]


class TestTheMarkerIsTheSecondSignal:
    """Time alone is not enough: a rule can fire on someone else's events inside
    our window. The marker is in the raw detection even though it is absent from
    the SOAR alert, which is why the instruction rightly does not demand it there.
    """

    def test_detection_in_window_without_our_marker_is_excluded(self):
        foreign = dict(THIS_RUN_DETECTION)
        foreign["collectionElements"] = [
            {"references": [{"event": {"principal": {
                "hostname": "WKSTN-4471.corp.local"}}}]}
        ]

        mine, theirs = tools._attribute_detections(
            [foreign], _entry(THIS_INGEST), THIS_RUN_MARKER)

        assert mine == []
        assert "does not reference this run's marker" in theirs[0]["excluded_because"]


class TestTheWindowNoLongerReachesOverAnEarlierRun:
    """The root cause. An hour of padding before ingest spans any earlier run in
    the same session; the backdating it exists to survive is three minutes."""

    def test_lower_bound_is_far_tighter_than_the_upper(self):
        assert tools._SEARCH_PAD_BEFORE_SECONDS < tools._SEARCH_PAD_AFTER_SECONDS

    def test_lower_bound_clears_backdating_but_not_a_prior_run(self):
        from purple_agent.synth import scenario
        import inspect

        backdate_minutes = inspect.signature(
            scenario.new_scenario).parameters["minutes_ago"].default
        assert tools._SEARCH_PAD_BEFORE_SECONDS > backdate_minutes * 60, (
            "the window must still reach back past this run's own backdated events")
        assert tools._SEARCH_PAD_BEFORE_SECONDS <= 900, (
            "reaching back further than ~15 min lets a previous run's detections "
            "into this run's window -- the live failure this module exists for")

    def test_search_window_uses_the_asymmetric_pads(self):
        w = tools._search_window(THIS_INGEST)
        assert w["startTime"] == tools._iso(THIS_INGEST - tools._SEARCH_PAD_BEFORE_SECONDS)
        assert w["endTime"] == tools._iso(THIS_INGEST + tools._SEARCH_PAD_AFTER_SECONDS)


class TestWithoutAnIngestedRunNothingIsFiltered:
    """Attribution needs a run to attribute to. With no ingest recorded the tool
    must degrade to reporting everything rather than silently returning nothing,
    which would read as a coverage gap."""

    def test_no_ingest_returns_all_detections(self):
        mine, theirs = tools._attribute_detections(
            [EARLIER_DETECTION, THIS_RUN_DETECTION], {}, THIS_RUN_MARKER)

        assert len(mine) == 2
        assert theirs == []


class TestACaseOpenedBeforeTheRunIsRefused:
    """The second door, found after the first was closed.

    With detections filtered, the model went to `list_cases` instead, found a
    case whose rule name matched the behaviour it had generated, and claimed it.
    That case had opened 22 minutes before the run's own ingest. A matching name
    is not evidence of causation, and in a tenant that raises cases from other
    sources continuously it is barely evidence of anything.

    Timestamps replay the live failure: the case opened at 19:43:18Z; the run
    that wrongly claimed it ingested at 20:05:22Z.
    """

    INGEST = 1786564_522.0                      # 20:05:22Z
    CASE_BEFORE = (1786563_798.0) * 1000        # 19:43:18Z, the earlier run's
    CASE_AFTER = (1786564_703.0) * 1000         # 20:08:23Z, genuinely this run's

    def test_case_opened_before_ingest_predates_the_run(self):
        assert tools._predates_run(self.CASE_BEFORE, self.INGEST) is True

    def test_case_opened_after_ingest_does_not(self):
        assert tools._predates_run(self.CASE_AFTER, self.INGEST) is False

    def test_without_an_ingest_no_case_is_ruled_out(self):
        """No run to compare against must not silently discard every case."""
        assert tools._predates_run(self.CASE_BEFORE, None) is False

    def test_rfc3339_create_times_are_understood_too(self):
        """The API returns epoch millis; a string form must not silently pass."""
        assert tools._predates_run("2026-08-12T19:43:18Z", self.INGEST) is True
        assert tools._predates_run("2026-08-12T20:08:23Z", self.INGEST) is False


class TestCandidateRulesAreFoundByName:
    """The third door: the rule that fired was never a candidate.

    An earlier run targeted Sigma's "DotNet CLR DLL Loaded By Scripting
    Applications" and reported a coverage gap. A company-prefixed tenant rule,
    "LAB_common_CLR_DLL_Loaded_Via_Scripting_Applications", had fired and opened
    a HIGH case. Five tokens in common, never compared, because
    RULE_PAGE_CAP=100 against a tenant with several times that many rules meant
    the model chose candidates from a fraction of the inventory and this one was
    not on the page.

    Matching over the whole inventory is what makes "nothing fired" mean
    anything.
    """

    TARGET = [{"sigma_id": "x",
               "title": "DotNet CLR DLL Loaded By Scripting Applications"}]

    def _rule(self, rid, name):
        return {"name": f"projects/p/locations/l/instances/i/rules/{rid}",
                "displayName": name}

    def test_the_rule_that_actually_fired_is_ranked_first(self):
        rules = [
            self._rule("ru_aaa", "LAB_Suspicious_Process_Injection_Activity"),
            self._rule("ru_bbb", "LAB_Suspicious_Access_to_lsass_Process"),
            self._rule("ru_00000001",
                       "LAB_common_CLR_DLL_Loaded_Via_Scripting_Applications"),
        ]
        ranked = tools._rank_candidate_rules(self.TARGET, rules)

        assert ranked, "the rule that fired was not offered as a candidate"
        assert ranked[0]["ruleId"] == "ru_00000001"
        assert ranked[0]["shared_tokens"] == 5

    def test_the_three_rules_the_model_chose_are_not_candidates(self):
        """They share no meaningful tokens with the target. Choosing them was
        the model doing its best with a truncated list."""
        rules = [
            self._rule("ru_aaa", "LAB_Suspicious_Process_Injection_Activity"),
            self._rule("ru_bbb", "LAB_Suspicious_Access_to_lsass_Process"),
            self._rule("ru_ccc",
                       "LAB_DEMO_suspicious_macro_execution_with_base64_decode"),
        ]
        assert tools._rank_candidate_rules(self.TARGET, rules) == []

    def test_vendor_prefixes_do_not_penalise_a_match(self):
        """Tenant names carry prefixes the Sigma title never has. Overlap
        coefficient, not Jaccard -- a verbosely named rule must not score worse."""
        bare = self._rule("ru_1", "CLR DLL Loaded Scripting Applications")
        prefixed = self._rule("ru_2",
                              "LAB_common_CLR_DLL_Loaded_Via_Scripting_Applications")
        ranked = {r["ruleId"]: r["score"]
                  for r in tools._rank_candidate_rules(self.TARGET, [bare, prefixed])}

        assert ranked["ru_2"] >= 0.8, "prefix noise sank a genuine match"

    def test_a_single_shared_word_is_not_a_candidate(self):
        """'Process' appears in half the inventory. One token is coincidence."""
        rules = [self._rule("ru_x", "Suspicious Process Creation")]
        target = [{"sigma_id": "y", "title": "Process Injection Via Something"}]

        assert tools._rank_candidate_rules(target, rules) == []
