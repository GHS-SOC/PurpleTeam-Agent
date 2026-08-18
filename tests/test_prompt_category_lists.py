"""The model-facing category lists in tools.py and agent.py must stay complete.

Both are static text that names which Sigma logsource categories can actually
be generated. Found stale: `search_detections`'s docstring listed 8 of the 17
real categories in `mapping.CATEGORY_EVENTS`, so the model was told to avoid
categories the tool could in fact generate -- a real capability loss, not just
a documentation nit. These tests fail the moment either list drifts from
`mapping.CATEGORY_EVENTS` again, instead of waiting for someone to notice.
"""

from __future__ import annotations

from purple_agent import agent, tools
from purple_agent.synth import mapping


class TestGeneratableCategoriesStayInSyncWithMapping:
    def test_search_detections_docstring_names_every_category(self):
        doc = tools.search_detections.__doc__
        missing = [c for c in mapping.CATEGORY_EVENTS if c not in doc]
        assert not missing, f"search_detections docstring is missing: {missing}"

    def test_agent_instruction_names_every_sysmon_and_powershell_category(self):
        """The instruction's claim is narrower on purpose -- only categories
        that don't depend on the Security-channel parser -- so this checks
        every category whose events are all Sysmon or PowerShell, not the
        full set (process_creation also has a Security-channel candidate)."""
        security_only_or_mixed = {
            cat for cat, ids in mapping.CATEGORY_EVENTS.items()
            if any(mapping.TEMPLATES[i].channel == mapping.SECURITY_CHANNEL
                   for i in ids if i in mapping.TEMPLATES)
        }
        sysmon_or_powershell_only = set(mapping.CATEGORY_EVENTS) - security_only_or_mixed
        missing = [c for c in sysmon_or_powershell_only if c not in agent.INSTRUCTION]
        assert not missing, f"agent.py INSTRUCTION is missing: {missing}"
