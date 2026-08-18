"""Tests for log synthesis: selector inversion, XML emission, and scenario coherence.

The load-bearing property is the round trip: a value generated to satisfy a
Sigma selector must actually satisfy it when the oracle re-evaluates it. That is
asserted directly in TestRoundTrip rather than by eyeballing strings, because
"looks right" is exactly how generation bugs get reported as coverage gaps.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from purple_agent.corpus.loader import SigmaRule
from purple_agent.corpus.match import MATCH, match_rule
from purple_agent.synth import mapping, satisfy, winevt
from purple_agent.synth.scenario import new_scenario

SCHEMA = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def make_rule(detection: dict, condition: str, category: str = "process_access") -> SigmaRule:
    return SigmaRule(
        sigma_id="t", title="T", description="", status="test", level="high",
        author="", date="", logsource_category=category,
        logsource_product="windows", logsource_service="",
        detection=detection, condition=condition,
    )


class TestMapping:
    def test_category_resolves_to_event_id(self):
        assert mapping.resolve_event_ids("process_access") == (10,)
        assert 1 in mapping.resolve_event_ids("process_creation")

    def test_unknown_category_is_empty(self):
        assert mapping.resolve_event_ids("wmi_event") == ()
        assert mapping.resolve_event_ids("not_a_real_category") == ()

    def test_classic_powershell_channel_stays_unmapped(self):
        """The classic channel emits unnamed <Data> elements, which the XML
        emitter cannot produce. Mapping it would substitute a 4104 -- the
        failure CATEGORY_EVENTS exists to prevent."""
        assert mapping.resolve_event_ids("ps_classic_start") == ()
        assert mapping.resolve_event_ids("ps_classic_provider_start") == ()

    def test_sysmon_and_security_use_different_log_types(self):
        """Combining them into one import_logs call silently yields nothing."""
        assert mapping.template_for(10).log_type == "WINDOWS_SYSMON"
        assert mapping.template_for(4688).log_type == "WINEVTLOG_XML"

    def test_sigma_field_names_pass_through_for_sysmon(self):
        assert mapping.resolve_field(10, "TargetImage") == "TargetImage"

    def test_alias_applies_only_to_security_events(self):
        assert mapping.resolve_field(4688, "Image") == "NewProcessName"
        # Sysmon has a real `Image` field -- rewriting it would break every rule.
        assert mapping.resolve_field(1, "Image") == "Image"

    def test_categories_map_to_the_event_that_carries_them(self):
        """A near-miss event is worse than none.

        These four categories once resolved to whatever neighbouring event was
        already templated -- file_delete to FileCreate, process_tampering to
        process creation. The oracle cannot catch that substitution: it checks
        the rule's field selectors against the fields written, and neighbouring
        Sysmon events share field names. The run then reports a coverage gap
        that does not exist.
        """
        assert mapping.resolve_event_ids("file_delete")[0] == 23
        assert mapping.resolve_event_ids("file_change") == (2,)
        assert mapping.resolve_event_ids("registry_add") == (12,)
        assert mapping.resolve_event_ids("process_tampering") == (25,)
        # FileCreate must never stand in for a deletion or a timestomp.
        assert 11 not in mapping.resolve_event_ids("file_delete")
        assert 11 not in mapping.resolve_event_ids("file_change")

    def test_registry_event_type_names_its_sysmon_event(self):
        """EventType is the only thing separating Sysmon 12, 13 and 14."""
        assert mapping.registry_event_for_type("CreateKey") == 12
        assert mapping.registry_event_for_type("DeleteValue") == 12
        assert mapping.registry_event_for_type("setvalue") == 13
        assert mapping.registry_event_for_type("RenameKey") == 14
        assert mapping.registry_event_for_type("nonsense") == 0

    def test_every_template_field_list_is_unique_and_ordered(self):
        """Duplicate names collapse in the EventData dict, dropping a field."""
        for event_id, template in mapping.TEMPLATES.items():
            assert len(set(template.fields)) == len(template.fields), event_id

    def test_system_service_has_no_default_events(self):
        """`service: system` is the System channel (Service Control Manager
        events like 7045/7036/7040), none of which this project templates.
        It used to point at 4688 -- Security-channel process creation, a
        different channel entirely."""
        assert mapping.resolve_event_ids("", "system") == ()


class TestExplicitEventIdMustMatchItsChannel:
    """A rule pinning `EventID:` is naming a specific event on a specific
    channel. Event IDs repeat across channels -- "EventID: 3" is Sysmon
    network connection on the Sysmon channel and a BITS-Client job-creation
    event on that channel -- so an explicit id must be validated against the
    channel its logsource actually names, not just checked against
    `TEMPLATES` in isolation."""

    def test_explicit_id_on_the_wrong_channel_for_its_service_is_refused(self):
        """service: security, EventID: 4104 is self-contradictory -- 4104 is
        PowerShell script-block logging, not a Security-channel event."""
        assert mapping.resolve_event_ids("", "security", explicit=4104) == ()

    def test_explicit_id_matching_its_services_channel_is_honoured(self):
        assert mapping.resolve_event_ids("", "security", explicit=4768) == (4768,)
        assert mapping.resolve_event_ids("", "security", explicit=4769) == (4769,)

    def test_explicit_id_matching_either_of_a_multi_channel_categorys_channels(self):
        """process_creation spans Sysmon (1) and Security (4688) on purpose."""
        assert mapping.resolve_event_ids("process_creation", explicit=1) == (1,)
        assert mapping.resolve_event_ids("process_creation", explicit=4688) == (4688,)

    def test_a_service_this_project_does_not_template_refuses_rather_than_guesses(self):
        """service: bits-client and service: security-mitigations are real,
        distinct Windows channels this project has no templates for. Their
        own EventID 3 / EventID 11 have nothing to do with Sysmon's EventID 3
        (network connection) or 11 (file created) -- trusting the number
        alone would generate telemetry for the wrong channel entirely, the
        same mistake the security/4104 case makes."""
        assert mapping.resolve_event_ids("", "bits-client", explicit=3) == ()
        assert mapping.resolve_event_ids("", "security-mitigations", explicit=11) == ()

    def test_no_category_or_service_at_all_trusts_the_explicit_id_alone(self):
        """No channel signal to check against -- the same behaviour as before
        this fix, for the one case where nothing else is possible."""
        assert mapping.resolve_event_ids("", "", explicit=10) == (10,)

    def test_an_untemplated_explicit_id_is_refused_regardless_of_logsource(self):
        assert mapping.resolve_event_ids("", "", explicit=9999) == ()


class TestSatisfy:
    def test_endswith_gets_a_plausible_prefix(self):
        plan = satisfy.plan_selection({"selection": {"Image|endswith": r"\mimikatz.exe"}}, "selection")
        value = plan.fields["Image"]
        assert value.lower().endswith(r"\mimikatz.exe")
        assert value.lower().startswith("c:\\")

    def test_drive_agnostic_prefix_is_repaired(self):
        """Sigma writes ':\\Windows\\...' to match any drive; ingesting that
        literally produces a malformed path."""
        plan = satisfy.plan_selection(
            {"selection": {"SourceImage|endswith": r":\Windows\system32\wsmprovhost.exe"}},
            "selection",
        )
        assert plan.fields["SourceImage"].startswith("C:\\")

    def test_directory_fragment_becomes_a_file(self):
        plan = satisfy.plan_selection(
            {"selection": {"SourceImage|contains": "\\Perflogs\\"}}, "selection"
        )
        assert not plan.fields["SourceImage"].endswith("\\")

    def test_calltrace_becomes_a_real_stack(self):
        plan = satisfy.plan_selection(
            {"selection": {"CallTrace|contains": "dbgcore.dll"}}, "selection"
        )
        value = plan.fields["CallTrace"]
        assert "dbgcore.dll" in value
        assert "|" in value, "a real CallTrace is a pipe-delimited stack"

    def test_multiple_constraints_on_one_field_compose(self):
        plan = satisfy.plan_selection(
            {
                "selection": {
                    "CallTrace|startswith": "C:\\Windows\\System32\\ntdll.dll+",
                    "CallTrace|contains": "|UNKNOWN(",
                    "CallTrace|endswith": ")",
                }
            },
            "selection",
        )
        value = plan.fields["CallTrace"]
        assert value.startswith("C:\\Windows\\System32\\ntdll.dll+")
        assert "|UNKNOWN(" in value
        assert value.endswith(")")

    def test_all_modifier_includes_every_value(self):
        plan = satisfy.plan_selection(
            {"selection": {"CommandLine|contains|all": ["sekurlsa", "logonpasswords"]}},
            "selection",
        )
        value = plan.fields["CommandLine"].lower()
        assert "sekurlsa" in value and "logonpasswords" in value

    def test_cidr_produces_a_real_address_inside_the_network(self):
        """`cidr` names a network, not a value -- writing the CIDR string
        itself ("10.0.0.0/8") isn't a valid IP address at all, and the
        oracle's own ipaddress.ip_address() call rejects it. 18 rules in the
        corpus use this modifier."""
        import ipaddress

        plan = satisfy.plan_selection(
            {"selection": {"DestinationIp|cidr": "10.0.0.0/8"}}, "selection"
        )
        value = plan.fields["DestinationIp"]
        assert ipaddress.ip_address(value) in ipaddress.ip_network("10.0.0.0/8")

    def test_cidr_handles_a_single_host_network(self):
        plan = satisfy.plan_selection(
            {"selection": {"DestinationIp|cidr": "192.168.1.5/32"}}, "selection"
        )
        assert plan.fields["DestinationIp"] == "192.168.1.5"

    def test_cidr_handles_ipv6(self):
        import ipaddress

        plan = satisfy.plan_selection(
            {"selection": {"DestinationIp|cidr": "fe80::/10"}}, "selection"
        )
        assert ipaddress.ip_address(plan.fields["DestinationIp"]) in ipaddress.ip_network("fe80::/10")

    def test_regex_is_reported_not_guessed(self):
        plan = satisfy.plan_selection(
            {"selection": {"CommandLine|re": r"foo\d{3}bar"}}, "selection"
        )
        assert "CommandLine" not in plan.fields
        assert any(u["field"] == "CommandLine" for u in plan.unresolved)

    def test_filter_block_is_not_satisfied(self):
        """A filter is an exclusion; generating its values would suppress the rule."""
        plan = satisfy.plan_selection(
            {
                "selection": {"TargetImage|endswith": r"\lsass.exe"},
                "filter": {"SourceImage|endswith": r"\wmiprvse.exe"},
            },
            "selection and not filter",
        )
        assert "TargetImage" in plan.fields
        assert "filter" in plan.avoided_filters
        assert r"\wmiprvse.exe" not in plan.fields.get("SourceImage", "")


class TestWinEvt:
    def test_xml_is_well_formed_and_namespaced(self):
        context = new_scenario("PT-LAB-TEST0001", seed=1)
        event = winevt.build_event(10, context, {"TargetImage": r"C:\W\lsass.exe"})
        root = ET.fromstring(event.xml)
        assert root.tag == f"{SCHEMA}Event"

    def test_field_order_matches_the_template(self):
        """Some Chronicle parsers read positionally; order is not cosmetic."""
        context = new_scenario("PT-LAB-TEST0001", seed=1)
        event = winevt.build_event(10, context)
        root = ET.fromstring(event.xml)
        names = [d.get("Name") for d in root.find(f"{SCHEMA}EventData")]
        assert tuple(names) == mapping.template_for(10).fields

    def test_header_carries_the_right_identity(self):
        context = new_scenario("PT-LAB-TEST0001", seed=1)
        root = ET.fromstring(winevt.build_event(4688, context).xml)
        system = root.find(f"{SCHEMA}System")
        assert system.find(f"{SCHEMA}EventID").text == "4688"
        assert system.find(f"{SCHEMA}Channel").text == "Security"
        assert system.find(f"{SCHEMA}Provider").get("Name") == "Microsoft-Windows-Security-Auditing"

    def test_marker_hostname_is_in_the_xml(self):
        context = new_scenario("PT-LAB-TEST0001", seed=1)
        assert "PT-LAB-TEST0001" in winevt.build_event(10, context).xml

    def test_special_characters_are_escaped(self):
        context = new_scenario("PT-LAB-TEST0001", seed=1)
        event = winevt.build_event(
            1, context, {"CommandLine": 'cmd.exe /c "a<b>c" & echo \'x\''}
        )
        root = ET.fromstring(event.xml)  # must not raise
        values = {d.get("Name"): d.text for d in root.find(f"{SCHEMA}EventData")}
        assert values["CommandLine"] == 'cmd.exe /c "a<b>c" & echo \'x\''

    def test_unsupported_event_id_raises(self):
        """Silently skipping would surface later as an unexplained missing detection."""
        context = new_scenario("PT-LAB-TEST0001", seed=1)
        with pytest.raises(ValueError, match="not supported"):
            winevt.build_event(9999, context)

    def test_impossible_registry_event_is_refused(self):
        """Sysmon 13 only ever emits SetValue.

        A 13 carrying CreateKey is telemetry no host can produce, but it
        satisfies a rule's `EventType: CreateKey` selector, so the oracle would
        return MATCH and the run would blame the SIEM for missing it.
        """
        context = new_scenario("PT-LAB-TEST0001", seed=1)
        with pytest.raises(ValueError, match="event 12"):
            winevt.build_event(13, context, {"EventType": "CreateKey"})

    def test_registry_events_carry_their_own_event_type(self):
        context = new_scenario("PT-LAB-TEST0001", seed=1)
        assert winevt.build_event(12, context).fields["EventType"] == "CreateKey"
        assert winevt.build_event(13, context).fields["EventType"] == "SetValue"
        assert winevt.build_event(14, context).fields["EventType"] == "RenameKey"

    def test_timestomp_event_changes_the_creation_time(self):
        """A Sysmon 2 whose two stamps match describes a change that did not happen."""
        context = new_scenario("PT-LAB-TEST0001", seed=1)
        fields = winevt.build_event(2, context).fields
        assert fields["PreviousCreationUtcTime"] != fields["CreationUtcTime"]

    def test_new_templates_emit_well_formed_xml(self):
        context = new_scenario("PT-LAB-TEST0001", seed=1)
        for event_id in (2, 12, 14, 23, 25, 26):
            event = winevt.build_event(event_id, context)
            root = ET.fromstring(event.xml)
            names = [d.get("Name") for d in root.find(f"{SCHEMA}EventData")]
            assert tuple(names) == mapping.template_for(event_id).fields
            assert event.log_type == "WINDOWS_SYSMON"

    def test_grouping_splits_sysmon_from_security(self):
        context = new_scenario("PT-LAB-TEST0001", seed=1)
        events = [winevt.build_event(10, context), winevt.build_event(4688, context)]
        groups = winevt.group_by_log_type(events)
        assert set(groups) == {"WINDOWS_SYSMON", "WINEVTLOG_XML"}
        assert len(groups["WINDOWS_SYSMON"]) == 1


class TestScenarioCoherence:
    def test_all_events_share_host_user_and_logon(self):
        context = new_scenario("PT-LAB-TEST0001", seed=7)
        events = [winevt.build_event(eid, context) for eid in (4624, 4672, 4688)]
        assert {e.fields["SubjectLogonId"] for e in events} == {context.logon_id}
        assert {e.fields["SubjectUserSid"] for e in events} == {context.user_sid}
        for event in events:
            assert context.hostname in event.xml

    def test_events_are_timestamped_in_the_recent_past(self):
        """Live rules evaluate near-real-time data; a future or long-past event
        may never fall into an evaluated window."""
        from datetime import datetime, timezone

        context = new_scenario("PT-LAB-TEST0001", seed=7)
        delta = datetime.now(timezone.utc) - context.started
        assert 0 < delta.total_seconds() < 3600

    def test_pids_are_distinct_and_increasing(self):
        context = new_scenario("PT-LAB-TEST0001", seed=7)
        pids = [context.new_pid() for _ in range(6)]
        assert pids == sorted(pids)
        assert len(set(pids)) == len(pids)

    def test_target_process_guid_matches_target_process_id(self):
        """new_guid(pid) encodes pid into the GUID's own tag segment.
        TargetProcessGuid used to be built from parent_pid -- a pid that
        Sysmon 8/10 don't even have a ParentProcessId field for -- while
        TargetProcessId got an independent, unrelated pid. The two must
        agree, the same way SourceProcessId/SourceProcessGuid already do."""
        context = new_scenario("PT-LAB-TEST0001", seed=3)
        for event_id, guid_field in ((8, "TargetProcessGuid"), (10, "TargetProcessGUID")):
            event = winevt.build_event(event_id, context)
            pid = int(event.fields["TargetProcessId"])
            tag = event.fields[guid_field].rsplit("-", 1)[1].rstrip("}")
            assert tag == f"{pid:012x}", f"event {event_id}: guid tag != TargetProcessId"


class TestRoundTrip:
    """Generated values must satisfy the selector they were generated from."""

    @pytest.mark.parametrize(
        "detection,condition",
        [
            ({"selection": {"TargetImage|endswith": r"\lsass.exe",
                            "GrantedAccess": "0x1410"}}, "selection"),
            ({"selection": {"CallTrace|startswith": "C:\\Windows\\System32\\ntdll.dll+",
                            "CallTrace|contains": "|UNKNOWN(",
                            "CallTrace|endswith": ")"}}, "selection"),
            ({"selection": {"CommandLine|contains|all": ["sekurlsa", "logonpasswords"]}},
             "selection"),
            ({"selection": {"SourceImage|endswith": r":\Windows\system32\wsmprovhost.exe"}},
             "selection"),
            ({"selection": {"GrantedAccess|endswith": ["10", "30", "50"]}}, "selection"),
            ({"selection": {"DestinationIp|cidr": "10.0.0.0/8"}}, "selection"),
        ],
    )
    def test_plan_satisfies_its_own_rule(self, detection, condition):
        rule = make_rule(detection, condition)
        plan = satisfy.plan_selection(detection, condition)
        assert match_rule(rule, plan.fields).verdict == MATCH

    def test_built_event_satisfies_the_rule(self):
        """End to end: selectors -> values -> XML -> flat fields -> oracle."""
        detection = {"selection": {"TargetImage|endswith": r"\lsass.exe",
                                   "SourceImage|contains": "mimikatz",
                                   "GrantedAccess": "0x1410"}}
        rule = make_rule(detection, "selection")
        plan = satisfy.plan_selection(detection, "selection")
        context = new_scenario("PT-LAB-TEST0001", seed=3)
        event = winevt.build_event(10, context, plan.fields)
        assert match_rule(rule, event.fields).verdict == MATCH

    def test_filter_branch_survives_the_round_trip(self):
        """The generated event must satisfy the selection AND escape the filter."""
        detection = {
            "selection": {"TargetImage|endswith": r"\lsass.exe"},
            "filter": {"SourceImage|endswith": r"\wmiprvse.exe"},
        }
        rule = make_rule(detection, "selection and not filter")
        plan = satisfy.plan_selection(detection, "selection and not filter")
        context = new_scenario("PT-LAB-TEST0001", seed=3)
        event = winevt.build_event(10, context, plan.fields)
        assert match_rule(rule, event.fields).verdict == MATCH
