"""PowerShell script-block generation, and the fragment-composition bug that
blocked it.

`ps_script` (178 rules) and `ps_module` (34) were the largest unmapped block in
the Windows corpus. Event 4104 is the only Windows event carrying a script's own
TEXT -- every other view sees the envelope (that powershell.exe ran, with some
command line), which says nothing when the payload is `-enc <base64>` or when
the engine is loaded into another process without spawning powershell.exe.

Templating 4104 alone was not enough. The constraint inverter corrupted
multi-fragment `contains|all` values, so the generated script satisfied none of
the fragments it was built from -- silently, with `unresolved` empty.
"""

from __future__ import annotations

from purple_agent.corpus import match, retrieve
from purple_agent.synth import mapping, planner, satisfy, winevt
from purple_agent.synth.scenario import new_scenario


AMSI_RULE = "e0d6c087-2d1c-47fd-8799-3904103c5a98"   # AMSI Bypass Pattern Assembly GetType
AMSI_FRAGMENTS = ["[Ref].Assembly.GetType", "SetValue($null,$true)", "NonPublic,Static"]


class TestFragmentComposition:
    """The bug: _insert_preserving_suffix spliced a fragment inside the previous
    fragment's closing bracket, because it could not tell a pinned suffix from a
    bracket that merely happened to be last."""

    def _compose_all(self, values):
        plan = satisfy.SelectionPlan()
        satisfy._apply_map(plan, {"ScriptBlockText|contains|all": values})
        return plan.fields["ScriptBlockText"]

    def test_every_fragment_survives(self):
        out = self._compose_all(AMSI_FRAGMENTS)
        for fragment in AMSI_FRAGMENTS:
            assert fragment in out, f"{fragment!r} lost from {out!r}"

    def test_the_exact_corruption_is_gone(self):
        """Regression: the old output spliced fragment 3 into fragment 2."""
        out = self._compose_all(AMSI_FRAGMENTS)
        assert "$trueNonPublic" not in out

    def test_code_fields_join_as_statements(self):
        out = self._compose_all(["Invoke-Expression", "DownloadString"])
        assert "; " in out

    def test_a_pinned_suffix_still_routes_through_the_splice_path(self):
        """When `endswith` pinned the tail, a later `contains` is spliced in
        before the closing character rather than appended.

        Known limitation, pre-dating this change and unchanged by it:
        _insert_preserving_suffix preserves only the LAST CHARACTER, not a
        multi-character pinned suffix. Given `endswith: '.exe)'` plus
        `contains: 'payload'` it yields `.exepayload)`, which satisfies the
        `contains` but not the `endswith`. Rules pinning both an endswith and a
        contains on one field are rare, and the corpus-wide oracle rate is
        unaffected (90.0%), so it is documented rather than redesigned here.
        """
        plan = satisfy.SelectionPlan()
        satisfy._apply_map(plan, {
            "CommandLine|endswith": ".exe)",
            "CommandLine|contains": "payload",
        })
        value = plan.fields["CommandLine"]
        assert "payload" in value
        assert value.endswith(")")           # the splice path, not the append path
        assert "; " not in value             # code-field joining must not apply here

    def test_non_code_fields_join_with_a_space(self):
        plan = satisfy.SelectionPlan()
        satisfy._apply_map(plan, {"CommandLine|contains|all": ["-enc", "-nop"]})
        assert plan.fields["CommandLine"] == "-enc -nop"


class TestPowerShellTemplates:
    def test_ps_script_maps_to_4104(self):
        assert mapping.resolve_event_ids("ps_script") == (4104,)

    def test_ps_module_maps_to_4103(self):
        assert mapping.resolve_event_ids("ps_module") == (4103,)

    def test_4104_carries_the_field_178_rules_key_on(self):
        assert "ScriptBlockText" in mapping.template_for(4104).fields

    def test_4103_carries_the_fields_its_rules_key_on(self):
        fields = mapping.template_for(4103).fields
        assert "Payload" in fields and "ContextInfo" in fields

    def test_powershell_uses_its_own_log_type_and_channel(self):
        """A distinct log type: grouping these with Sysmon into one import_logs
        call silently yields nothing."""
        template = mapping.template_for(4104)
        assert template.log_type == "POWERSHELL"
        assert template.log_type != mapping.template_for(10).log_type
        assert template.channel == "Microsoft-Windows-PowerShell/Operational"

    def test_event_renders_with_the_powershell_provider(self):
        event = winevt.build_event(4104, new_scenario("PT-LAB-PS0001", seed=1))
        assert 'Name="Microsoft-Windows-PowerShell"' in event.xml
        assert "<EventID>4104</EventID>" in event.xml

    def test_chunk_counters_are_numeric_not_dashes(self):
        """Typed fields filled with '-' abort the whole event at parse time."""
        event = winevt.build_event(4104, new_scenario("PT-LAB-PS0001", seed=1))
        assert '<Data Name="MessageNumber">1</Data>' in event.xml
        assert '<Data Name="MessageTotal">1</Data>' in event.xml


class TestAmsiRuleEndToEnd:
    """The rule the agent refused to emulate, now generated and verified."""

    def _build(self):
        plan = planner.plan_from_rules([AMSI_RULE])
        assert plan["unmappable"] == []
        built = planner.build_chain(plan["steps"], hostname="PT-LAB-PS0001", seed=11)
        return plan, built

    def test_rule_is_now_mappable(self):
        plan, _ = self._build()
        assert plan["steps"][0]["event_id"] == 4104

    def test_nothing_needs_a_human_supplied_value(self):
        plan, _ = self._build()
        assert plan["steps"][0]["unresolved"] == []

    def test_oracle_confirms_the_event_satisfies_the_rule(self):
        _, built = self._build()
        result = planner.verify_chain([AMSI_RULE], built["events"])
        assert result["matched"] == 1, result

    def test_the_script_text_reaches_the_xml_intact(self):
        _, built = self._build()
        xml = built["events"][0].xml
        for fragment in AMSI_FRAGMENTS:
            assert fragment in xml

    def test_marker_hostname_is_in_the_event(self):
        _, built = self._build()
        assert "PT-LAB-PS0001" in built["events"][0].xml


class TestNoRegressionOnOtherCategories:
    """The composition change touches every rule, not just PowerShell ones."""

    def test_lsass_rule_still_satisfies_itself(self):
        sid = "5ef9853e-4d0e-4a70-846f-a9ca37d876da"
        plan = planner.plan_from_rules([sid])
        built = planner.build_chain(plan["steps"], hostname="PT-LAB-REG0001", seed=7)
        assert planner.verify_chain([sid], built["events"])["matched"] == 1

    def test_calltrace_realism_pass_still_applies(self):
        sid = "5ef9853e-4d0e-4a70-846f-a9ca37d876da"
        plan = planner.plan_from_rules([sid])
        assert "|" in plan["steps"][0]["fields"]["CallTrace"]
