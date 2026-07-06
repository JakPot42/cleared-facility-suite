"""config.py — RAI Compliance Assistant configuration (Cleared Facility Suite)."""

from __future__ import annotations

from shared.demo_mode import is_demo_mode

# --- App ---
APP_TITLE = "RAI Compliance Assistant"
APP_SUBTITLE = "DoD Responsible AI Principles Assessment Tool"
DEMO_MODE = is_demo_mode()
DEMO_BANNER = "DEMONSTRATION ONLY — SYNTHETIC DATA — NOT FOR OPERATIONAL USE"

# --- Model tokens (used only for the compliance narrative draft's max output length) ---
CLAUDE_MAX_TOKENS = 4000

# --- Autonomy levels (used for risk characterization) ---
AUTONOMY_LEVELS = ["Low", "Medium", "High", "Critical"]

AUTONOMY_DESCRIPTIONS = {
    "Low":      "Human makes all decisions; AI provides information or analysis only",
    "Medium":   "AI recommends actions; human reviews and approves each recommendation",
    "High":     "AI acts autonomously within defined scope; human oversight is periodic",
    "Critical": "AI acts autonomously in high-stakes domain; errors can cause serious harm",
}

# --- Criterion assessment statuses ---
CRITERION_STATUSES = {
    "met":           "Met",
    "partial":       "Partial",
    "not_addressed": "Not Addressed",
    "not_applicable":"Not Applicable",
}

# --- RAI principles ---
RAI_PRINCIPLES = {
    "RE": "Responsible",
    "EQ": "Equitable",
    "TR": "Traceable",
    "RL": "Reliable",
    "GO": "Governable",
}
