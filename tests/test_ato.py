"""Tests for ato/nist_controls.py and ato/claude_analyst.py — no real API calls."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from ato.nist_controls import CONTROLS, get_control, get_controls_for_level, families_summary
from ato.claude_analyst import categorize_system, generate_ssp_narrative, AnalystError
from shared.claude_client import ClaudeCallError


# ---------------------------------------------------------------------------
# nist_controls
# ---------------------------------------------------------------------------

class TestNistControls:
    def test_controls_list_not_empty(self):
        assert len(CONTROLS) > 50

    def test_all_controls_have_required_fields(self):
        for c in CONTROLS:
            assert "id" in c, f"Missing id in {c}"
            assert "family" in c
            assert "title" in c
            assert "baseline" in c
            assert "description" in c

    def test_baseline_values_are_valid(self):
        valid = {"L", "M", "H"}
        for c in CONTROLS:
            assert c["baseline"] in valid, f"{c['id']} has invalid baseline {c['baseline']}"

    def test_low_baseline_is_subset_of_moderate(self):
        low = {c["id"] for c in get_controls_for_level("Low")}
        mod = {c["id"] for c in get_controls_for_level("Moderate")}
        assert low.issubset(mod)

    def test_moderate_baseline_is_subset_of_high(self):
        mod = {c["id"] for c in get_controls_for_level("Moderate")}
        high = {c["id"] for c in get_controls_for_level("High")}
        assert mod.issubset(high)

    def test_low_has_fewer_controls_than_moderate(self):
        assert len(get_controls_for_level("Low")) < len(get_controls_for_level("Moderate"))

    def test_get_control_returns_correct_entry(self):
        ac2 = get_control("AC-2")
        assert ac2 is not None
        assert ac2["title"] == "Account Management"
        assert ac2["family"] == "AC"

    def test_get_control_returns_none_for_unknown(self):
        assert get_control("ZZ-99") is None

    def test_families_summary_counts_correctly(self):
        low_controls = get_controls_for_level("Low")
        summary = families_summary(low_controls)
        assert "AC" in summary
        assert "IA" in summary
        assert all(isinstance(v, int) and v > 0 for v in summary.values())

    def test_ac1_in_all_baselines(self):
        for level in ("Low", "Moderate", "High"):
            ids = {c["id"] for c in get_controls_for_level(level)}
            assert "AC-1" in ids, f"AC-1 missing from {level} baseline"

    def test_high_only_control_not_in_low(self):
        high_only = {c["id"] for c in CONTROLS if c["baseline"] == "H"}
        low_ids = {c["id"] for c in get_controls_for_level("Low")}
        assert high_only.isdisjoint(low_ids)


# ---------------------------------------------------------------------------
# claude_analyst — categorize_system
# ---------------------------------------------------------------------------

class TestCategorizeSystem:
    @patch("ato.claude_analyst.call_claude")
    def test_returns_correct_keys(self, mock_call_claude):
        mock_call_claude.return_value = json.dumps({
            "impact_level": "Moderate",
            "confidentiality": "Moderate",
            "integrity": "Low",
            "availability": "Moderate",
            "rationale": "Test rationale.",
        })
        result = categorize_system("TestSys", "A test system", "CUI", "Python/FastAPI")
        assert result["impact_level"] == "Moderate"
        assert result["confidentiality"] == "Moderate"
        assert "rationale" in result

    @patch("ato.claude_analyst.call_claude")
    def test_raises_on_invalid_json(self, mock_call_claude):
        mock_call_claude.return_value = "not json at all"
        with pytest.raises(AnalystError, match="invalid JSON"):
            categorize_system("TestSys", "desc", "data", "stack")

    @patch("ato.claude_analyst.call_claude")
    def test_categorize_system_raises_on_api_error(self, mock_call_claude):
        """
        Regression test (ported from the standalone repo's own Step 0 fix):
        except json.JSONDecodeError previously came AFTER a catch-all except
        Exception, making it unreachable. Now routed through shared
        call_claude()/ClaudeCallError -- a genuine API failure must still be
        reported as "Claude API error", not misrouted through the JSON-decode
        branch.
        """
        mock_call_claude.side_effect = ClaudeCallError("simulated API failure")
        with pytest.raises(AnalystError, match="Claude API error"):
            categorize_system("TestSys", "desc", "data", "stack")

    @patch("ato.claude_analyst.call_claude")
    def test_raises_on_missing_field(self, mock_call_claude):
        mock_call_claude.return_value = json.dumps({
            "impact_level": "Low",
            # missing confidentiality, integrity, availability, rationale
        })
        with pytest.raises(AnalystError, match="missing field"):
            categorize_system("TestSys", "desc", "data", "stack")

    @patch("ato.claude_analyst.call_claude")
    def test_strips_markdown_fences(self, mock_call_claude):
        payload = {
            "impact_level": "Low", "confidentiality": "Low",
            "integrity": "Low", "availability": "Low", "rationale": "r"
        }
        mock_call_claude.return_value = f"```json\n{json.dumps(payload)}\n```"
        result = categorize_system("s", "d", "dt", "ts")
        assert result["impact_level"] == "Low"


# ---------------------------------------------------------------------------
# claude_analyst — generate_ssp_narrative
# ---------------------------------------------------------------------------

class TestGenerateSspNarrative:
    @patch("ato.claude_analyst.call_claude")
    def test_returns_string(self, mock_call_claude):
        mock_call_claude.return_value = "The system implements AC-1 by..."
        result = generate_ssp_narrative(
            "TestSys", "A test system", "AC-1",
            "Policy and Procedures", "Develop access control policy.",
        )
        assert isinstance(result, str)
        assert len(result) > 0

    @patch("ato.claude_analyst.call_claude")
    def test_raises_on_api_error(self, mock_call_claude):
        mock_call_claude.side_effect = ClaudeCallError("API error")
        with pytest.raises(AnalystError):
            generate_ssp_narrative("s", "d", "AC-1", "t", "desc")
