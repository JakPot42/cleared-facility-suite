"""Tests for clearance/claude_advisor.py — mocked, no real API calls."""
import json
from unittest.mock import patch

import pytest

from shared.claude_client import ClaudeCallError


class TestGenerateBriefings:
    @patch("clearance.claude_advisor.call_claude")
    def test_returns_json_string(self, mock_call_claude):
        payload = json.dumps({"B": "Guideline B briefing text.", "F": "Guideline F briefing text."})
        mock_call_claude.return_value = payload

        import clearance.claude_advisor as claude_advisor
        result = claude_advisor.generate_briefings(["B", "F"], "SECRET")

        parsed = json.loads(result)
        assert "B" in parsed
        assert "F" in parsed

    @patch("clearance.claude_advisor.call_claude")
    def test_strips_markdown_fences(self, mock_call_claude):
        mock_call_claude.return_value = '```json\n{"E": "Guideline E explanation."}\n```'

        import clearance.claude_advisor as claude_advisor
        result = claude_advisor.generate_briefings(["E"], "SECRET")

        parsed = json.loads(result)
        assert parsed["E"] == "Guideline E explanation."

    @patch("clearance.claude_advisor.call_claude")
    def test_includes_clearance_level_in_prompt(self, mock_call_claude):
        mock_call_claude.return_value = json.dumps({"G": "Guideline G text."})

        import clearance.claude_advisor as claude_advisor
        claude_advisor.generate_briefings(["G"], "TOP SECRET")

        messages = mock_call_claude.call_args[0][0]
        assert "TOP SECRET" in messages[0]["content"]

    @patch("clearance.claude_advisor.call_claude")
    def test_includes_context_notes_when_provided(self, mock_call_claude):
        mock_call_claude.return_value = json.dumps({"H": "Drug guideline text."})

        import clearance.claude_advisor as claude_advisor
        claude_advisor.generate_briefings(["H"], "SECRET", "Student loan debt")

        messages = mock_call_claude.call_args[0][0]
        assert "Student loan debt" in messages[0]["content"]

    @patch("clearance.claude_advisor.call_claude")
    def test_skips_unknown_codes(self, mock_call_claude):
        mock_call_claude.return_value = json.dumps({"B": "B text."})

        import clearance.claude_advisor as claude_advisor
        claude_advisor.generate_briefings(["B", "Z"], "SECRET")

        messages = mock_call_claude.call_args[0][0]
        assert "Guideline Z" not in messages[0]["content"]

    @patch("clearance.claude_advisor.call_claude")
    def test_raises_advisor_error_when_key_missing(self, mock_call_claude):
        """
        Disclosed behavior change from the standalone clearance_advisor repo:
        a missing ANTHROPIC_API_KEY now surfaces as AdvisorError (via
        shared.claude_client.ClaudeCallError), not a bare RuntimeError --
        this project is now routed through the same shared wrapper as every
        other tool in this merge.
        """
        mock_call_claude.side_effect = ClaudeCallError("ANTHROPIC_API_KEY not set.")

        import clearance.claude_advisor as claude_advisor
        with pytest.raises(claude_advisor.AdvisorError, match="Claude API error"):
            claude_advisor.generate_briefings(["B"], "SECRET")

    @patch("clearance.claude_advisor.call_claude")
    def test_raises_advisor_error_on_invalid_json(self, mock_call_claude):
        """
        Regression test (ported from the standalone repo's own Step 0 fix):
        generate_briefings() previously had no try/except at all around the
        Claude call or the json.loads() validation.
        """
        mock_call_claude.return_value = "not json at all"

        import clearance.claude_advisor as claude_advisor
        with pytest.raises(claude_advisor.AdvisorError, match="invalid JSON"):
            claude_advisor.generate_briefings(["B"], "SECRET")

    @patch("clearance.claude_advisor.call_claude")
    def test_raises_advisor_error_on_api_failure(self, mock_call_claude):
        mock_call_claude.side_effect = ClaudeCallError("simulated API failure")

        import clearance.claude_advisor as claude_advisor
        with pytest.raises(claude_advisor.AdvisorError, match="Claude API error"):
            claude_advisor.generate_briefings(["B"], "SECRET")


class TestGenerateInterviewPrep:
    @patch("clearance.claude_advisor.call_claude")
    def test_returns_markdown_string(self, mock_call_claude):
        mock_call_claude.return_value = "# Interview Prep\n\n## What to expect\n\nInvestigators may ask..."

        import clearance.claude_advisor as claude_advisor
        result = claude_advisor.generate_interview_prep(["B", "F"], "SECRET")

        assert isinstance(result, str)
        assert "Interview Prep" in result

    @patch("clearance.claude_advisor.call_claude")
    def test_includes_guideline_names_in_prompt(self, mock_call_claude):
        mock_call_claude.return_value = "# Interview Prep"

        import clearance.claude_advisor as claude_advisor
        claude_advisor.generate_interview_prep(["F"], "SECRET")

        messages = mock_call_claude.call_args[0][0]
        assert "Financial Considerations" in messages[0]["content"]

    @patch("clearance.claude_advisor.call_claude")
    def test_raises_advisor_error_on_api_failure(self, mock_call_claude):
        mock_call_claude.side_effect = ClaudeCallError("simulated API failure")

        import clearance.claude_advisor as claude_advisor
        with pytest.raises(claude_advisor.AdvisorError, match="Claude API error"):
            claude_advisor.generate_interview_prep(["E"], "SECRET")


class TestStripFences:
    def test_strips_json_fence(self):
        import clearance.claude_advisor as claude_advisor
        raw = '```json\n{"a": 1}\n```'
        assert claude_advisor._strip_fences(raw) == '{"a": 1}'

    def test_strips_plain_fence(self):
        import clearance.claude_advisor as claude_advisor
        raw = '```\n{"b": 2}\n```'
        assert claude_advisor._strip_fences(raw) == '{"b": 2}'

    def test_no_fence_passthrough(self):
        import clearance.claude_advisor as claude_advisor
        raw = '{"c": 3}'
        assert claude_advisor._strip_fences(raw) == '{"c": 3}'
