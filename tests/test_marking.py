"""Tests for synthetic-data marking.

Marking is the only thing separating this agent's output from a real intrusion
once it is in the SIEM. If `safe_to_ingest` is ever wrongly true, unmarked
synthetic data lands in a live tenant and someone works it as a genuine
incident.
"""

from __future__ import annotations

import json

from purple_agent import config, marking, tools


class TestRunContext:
    def test_hostname_carries_prefix_and_run_id(self):
        run = marking.new_run()
        assert run.hostname.startswith(config.HOST_PREFIX)
        assert run.run_id in run.hostname

    def test_runs_are_distinct(self):
        assert marking.new_run().run_id != marking.new_run().run_id

    def test_udm_query_targets_the_marker(self):
        run = marking.new_run()
        assert run.hostname in run.udm_query
        assert "principal.hostname" in run.udm_query


class TestHostnameSearchLadder:
    """Events carry the FQDN, so an exact match on the short marker hostname
    misses on a run that ingested perfectly -- and that miss was read as a parse
    failure. The ladder exists so the first query is the one most likely to hit
    and the exact match is only ever the last word."""

    def test_fqdn_is_tried_first(self):
        ladder = marking.udm_query_ladder("PT-LAB-ABC12345", "corp.local")
        assert ladder[0]["step"] == "fqdn"
        assert '"PT-LAB-ABC12345.corp.local"' in ladder[0]["query"]

    def test_regex_then_exact_follow(self):
        steps = [r["step"] for r in marking.udm_query_ladder("PT-LAB-ABC12345", "corp.local")]
        assert steps == ["fqdn", "regex", "exact"]

    def test_regex_rung_is_unanchored(self):
        """It has to match the marker inside whatever suffix the tenant kept."""
        regex = marking.udm_query_ladder("PT-LAB-ABC12345", "corp.local")[1]["query"]
        assert "= /PT-LAB-ABC12345/" in regex

    def test_every_rung_covers_both_hostname_fields(self):
        for rung in marking.udm_query_ladder("PT-LAB-ABC12345", "corp.local"):
            assert "principal.hostname" in rung["query"]
            assert "target.hostname" in rung["query"]

    def test_no_domain_drops_the_fqdn_rung(self):
        """Without a suffix the FQDN rung is just the exact rung again."""
        steps = [r["step"] for r in marking.udm_query_ladder("PT-LAB-ABC12345", "")]
        assert steps == ["regex", "exact"]

    def test_run_context_query_is_the_first_rung(self):
        run = marking.RunContext(
            run_id="ABC12345",
            hostname="PT-LAB-ABC12345",
            started_at="2026-01-01T00:00:00Z",
            dns_domain="corp.local",
        )
        assert run.fqdn == "PT-LAB-ABC12345.corp.local"
        assert run.udm_query == run.udm_queries[0]["query"]
        assert run.fqdn in run.udm_query

    def test_run_context_publishes_the_whole_ladder(self):
        """start_run's caller must see the fallbacks, not just the first query."""
        payload = marking.new_run().to_dict()
        assert [r["step"] for r in payload["udm_queries"]][-1] == "exact"
        assert payload["fqdn"].startswith(payload["hostname"])


class TestCheckEvents:
    def test_all_marked(self):
        report = marking.check_events(
            [{"Computer": "PT-LAB-ABC12345"}, {"principal": {"hostname": "PT-LAB-ABC12345"}}],
            "PT-LAB-ABC12345",
        )
        assert report["safe_to_ingest"] is True
        assert report["marked"] == 2

    def test_unmarked_event_blocks_ingest(self):
        report = marking.check_events(
            [{"Computer": "PT-LAB-ABC12345"}, {"Computer": "DC01.corp.local"}],
            "PT-LAB-ABC12345",
        )
        assert report["safe_to_ingest"] is False
        assert report["unmarked_indexes"] == [1]

    def test_marker_found_in_any_field(self):
        """The host may land in different fields per log type; requiring a
        specific one would reject correctly-marked events."""
        report = marking.check_events(
            [{"nested": {"deep": {"target": {"hostname": "PT-LAB-ABC12345"}}}}],
            "PT-LAB-ABC12345",
        )
        assert report["safe_to_ingest"] is True

    def test_matching_is_case_insensitive(self):
        report = marking.check_events([{"Computer": "pt-lab-abc12345"}], "PT-LAB-ABC12345")
        assert report["safe_to_ingest"] is True

    def test_empty_event_list_is_not_safe(self):
        """Nothing to ingest must never read as 'safe to ingest'."""
        assert marking.check_events([], "PT-LAB-ABC12345")["safe_to_ingest"] is False

    def test_different_run_id_is_not_a_match(self):
        report = marking.check_events([{"Computer": "PT-LAB-99999999"}], "PT-LAB-ABC12345")
        assert report["safe_to_ingest"] is False


class TestRunIdValidation:
    """save_run() joins run_id onto OUT_DIR unescaped. run_id is a tool
    argument the model supplies back to us, not a value we mint and control
    end to end -- without this check, run_id="../../tmp/pwn" walks the write
    straight out of OUT_DIR."""

    def test_the_generated_shape_is_valid(self):
        assert marking.is_valid_run_id(marking.new_run().run_id)

    def test_path_traversal_is_rejected(self):
        assert marking.is_valid_run_id("../../../tmp/pwn") is False

    def test_absolute_path_is_rejected(self):
        assert marking.is_valid_run_id("/etc/passwd") is False

    def test_empty_and_none_are_rejected(self):
        assert marking.is_valid_run_id("") is False
        assert marking.is_valid_run_id(None) is False

    def test_wrong_length_is_rejected(self):
        assert marking.is_valid_run_id("ABC123") is False
        assert marking.is_valid_run_id("ABC123450") is False

    def test_a_trailing_newline_does_not_slip_past_the_shape_check(self):
        """`$` in `re.match` matches just before an optional trailing
        newline, not strictly end-of-string -- the exact bug secops_rest's
        allowlist regex had, missed here on the first pass."""
        assert marking.is_valid_run_id("ABCDEF12\n") is False

    def test_build_events_refuses_a_path_traversal_run_id(self, tmp_path, monkeypatch):
        """End to end: a malicious run_id never reaches the filesystem."""
        monkeypatch.setattr(config, "OUT_DIR", tmp_path)

        result = tools.build_events(
            run_id="../../../tmp/pwn",
            hostname="PT-LAB-ABC12345",
            steps_json=json.dumps([{"event_id": "10", "fields": {}}]),
            sigma_ids=[],
        )

        assert "error" in result
        # save_run() was never reached: OUT_DIR itself has no new children.
        assert list(tmp_path.iterdir()) == []


class TestBuildEventsHostnameMustMatchTheRun:
    """marking.check_events(events, hostname) only proves the events are
    self-consistent with whatever hostname they were built from -- it cannot
    tell a real marker from a plausible-looking one the model made up. Without
    this check, build_events(hostname="DC01", ...) generates events that
    reference "DC01" throughout, marking.safe_to_ingest reports True (every
    event contains "DC01"), and the result is unmarked synthetic data an
    analyst cannot distinguish from a real intrusion."""

    def test_a_hostname_that_does_not_match_the_run_id_is_refused(self):
        run = marking.new_run()
        result = tools.build_events(
            run_id=run.run_id,
            hostname="DC01",  # not this run's PT-LAB-<run_id> marker
            steps_json=json.dumps([{"event_id": "10", "fields": {}}]),
            sigma_ids=[],
        )
        assert "error" in result
        assert run.run_id not in tools._RUNS or "events" not in tools._RUNS.get(run.run_id, {})
        tools._RUNS.pop(run.run_id, None)

    def test_the_real_marker_is_accepted(self):
        from purple_agent.corpus import retrieve

        run = marking.new_run()
        ids = [r.sigma_id for r in retrieve.search(
            "mimikatz lsass", product="windows", category="process_access", limit=1)]
        result = tools.build_events(
            run_id=run.run_id, hostname=run.hostname,
            steps_json=json.dumps(tools.plan_events(ids)["steps"]), sigma_ids=ids,
        )
        assert "error" not in result
        assert result["marking"]["safe_to_ingest"] is True
        tools._RUNS.pop(run.run_id, None)


class TestParseEvents:
    def test_json_array(self):
        events, error = marking.parse_events('[{"a": 1}, {"b": 2}]')
        assert error == ""
        assert len(events) == 2

    def test_single_object(self):
        events, error = marking.parse_events('{"a": 1}')
        assert error == ""
        assert events == [{"a": 1}]

    def test_wrapper_object_is_unwrapped(self):
        events, error = marking.parse_events(json.dumps({"events": [{"a": 1}, {"b": 2}]}))
        assert error == ""
        assert len(events) == 2

    def test_newline_delimited_json(self):
        events, error = marking.parse_events('{"a": 1}\n{"b": 2}')
        assert error == ""
        assert len(events) == 2

    def test_raw_xml_lines_survive_as_strings(self):
        """Raw XML cannot be field-matched, but it must still be markable."""
        events, error = marking.parse_events("<Event>one</Event>\n<Event>two</Event>")
        assert error == ""
        assert len(events) == 2

    def test_empty_input_reports_error(self):
        events, error = marking.parse_events("   ")
        assert events == []
        assert error
