"""Technique lookups must be grounded in the corpus, not the model's memory.

Regression for a real miss: asked to emulate T1197 (BITS Jobs), the agent used
its own recall of the technique name ("bi-directional communication"),
free-text-searched that, and generated the wrong scenario. A bare technique id
must resolve through the structured filter, which returns the correct rules.
"""

from __future__ import annotations

import pytest

from purple_agent import config, tools

pytestmark = pytest.mark.skipif(
    not config.SIGMA_DB_PATH.exists(),
    reason="Sigma index not built -- run: python scripts/build_index.py",
)


class TestBareTechniqueIdRouting:
    def test_query_that_is_a_technique_id_routes_to_the_filter(self):
        """query='T1197' must behave like technique_id='T1197', not fuzzy text."""
        by_query = tools.search_detections(query="T1197", limit=15)
        by_filter = tools.search_detections(technique_id="T1197", limit=15)
        assert by_query["count"] == by_filter["count"]
        # every returned rule is genuinely tagged with the technique
        assert all("T1197" in r["techniques"] for r in by_query["rules"])

    def test_free_text_technique_id_does_not_leak_unrelated_rules(self):
        """The bug symptom: a T1110 rule surfacing for a T1197 query."""
        result = tools.search_detections(query="T1197", limit=15)
        for rule in result["rules"]:
            assert "T1197" in rule["techniques"], (
                f"{rule['title']} ({rule['techniques']}) is not a T1197 rule"
            )

    def test_lowercase_and_subtechnique_ids_route_too(self):
        assert tools.search_detections(query="t1197", limit=5)["rules"]
        sub = tools.search_detections(query="T1059.001", limit=5)
        assert all("T1059.001" in r["techniques"] for r in sub["rules"])

    def test_a_real_id_inside_a_sentence_is_still_free_text(self):
        """Only a bare id is a filter; longer text stays a keyword search so it
        can match on tool names too."""
        # Should not raise and should still return something relevant.
        tools.search_detections(query="T1197 bitsadmin transfer", product="windows")


class TestT1197IsBitsJobs:
    def test_generatable_bits_rule_is_reachable(self):
        result = tools.search_detections(
            technique_id="T1197", product="windows", category="process_creation"
        )
        assert result["generatable_count"] >= 1
        titles = " ".join(r["title"].lower() for r in result["rules"])
        assert "bits" in titles or "bitsadmin" in titles

    def test_bits_client_only_result_explains_why_not_generatable(self):
        """The bits-client / proxy rules cannot be synthesised; the tool must say
        so rather than let the agent generate the wrong event type."""
        result = tools.search_detections(
            query="T1197 BITS transfer job remote url suspicious", product="windows"
        )
        if result["generatable_count"] == 0:
            assert "guidance" in result
            assert "generatable" in result["guidance"]


class TestGeneratableCount:
    def test_count_is_reported(self):
        result = tools.search_detections(technique_id="T1003.001", limit=10)
        assert "generatable_count" in result
        assert result["generatable_count"] <= result["count"]
