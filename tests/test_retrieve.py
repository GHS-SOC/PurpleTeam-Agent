"""Tests for hybrid Sigma retrieval.

These run against the built index. They assert retrieval *behaviour* (the right
kind of rule comes back near the top) rather than exact rule ids, because
SigmaHQ content changes between clones and pinning ids would make the suite
fail on corpus updates rather than on real regressions.
"""

from __future__ import annotations

import pytest

from purple_agent import config
from purple_agent.corpus import retrieve

pytestmark = pytest.mark.skipif(
    not config.SIGMA_DB_PATH.exists(),
    reason="Sigma index not built -- run: python scripts/build_index.py",
)


def test_index_is_populated():
    stats = retrieve.stats()
    assert stats["rules"] > 1000
    assert stats["techniques"] > 100


def test_keyword_search_finds_tool_by_name():
    """Exact tool names are the case embeddings handle worst and BM25 best."""
    results = retrieve.search("mimikatz", limit=5)
    assert results
    joined = " ".join(f"{r.title} {r.description}" for r in results).lower()
    assert "mimikatz" in joined


def test_semantic_search_finds_by_intent():
    """No shared vocabulary with the rule text -- this is the embedding layer."""
    results = retrieve.search("dumping credentials from memory", product="windows", limit=8)
    assert results
    categories = {r.logsource_category for r in results}
    assert categories & {"process_access", "process_creation", "file_event", "ps_script"}


def test_structured_filter_is_respected():
    results = retrieve.search("credential access", product="windows",
                              category="process_access", limit=10)
    assert results
    assert all(r.logsource_product == "windows" for r in results)
    assert all(r.logsource_category == "process_access" for r in results)


def test_technique_filter():
    results = retrieve.rules_for_technique("T1003.001", limit=50)
    assert len(results) > 10
    assert all("T1003.001" in r.techniques for r in results)


def test_query_with_fts_operators_does_not_raise():
    """`sekurlsa::logonpasswords` contains FTS5 syntax; unescaped it errors."""
    for query in ["sekurlsa::logonpasswords", "lsass.exe AND", 'a "quoted" (thing)', "*"]:
        retrieve.search(query, limit=3)  # must not raise


def test_empty_query_with_filter_returns_by_severity():
    results = retrieve.search(product="windows", category="process_access", limit=5)
    assert results
    levels = [r.level for r in results]
    ranking = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    scores = [ranking.get(level, 4) for level in levels]
    assert scores == sorted(scores)


def test_empty_query_and_no_filter_returns_nothing():
    """Guards against a bare call silently dumping the whole corpus."""
    assert retrieve.search() == []


def test_get_rule_roundtrip():
    rule = retrieve.search("mimikatz", limit=1)[0]
    fetched = retrieve.get_rule(rule.sigma_id)
    assert fetched is not None
    assert fetched.sigma_id == rule.sigma_id
    assert isinstance(fetched.detection, dict)
    assert fetched.detection, "detection block must survive the roundtrip"


def test_get_rule_unknown_id():
    assert retrieve.get_rule("not-a-real-id") is None
