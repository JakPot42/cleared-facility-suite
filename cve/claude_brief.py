"""claude_brief.py — Claude drafts the plain-language patch prioritization brief.

DEMO_MODE: returns pre-baked brief from seed_data.DEMO_BRIEFS.
Live mode: calls Claude Haiku (via shared.claude_client) with structured scan +
vulnerability data.

Doctrine: Claude NEVER makes the priority determination — the engine already did that.
Claude explains WHY each CVE landed at its engine-assigned tier, citing KEV and EPSS data.
"""

from shared.claude_client import ClaudeCallError, call_claude

from . import seed_data
from .config import DEMO_MODE

_SYSTEM_PROMPT = """\
You are a cybersecurity analyst writing a patch prioritization brief for a non-technical audience.

The vulnerability assessment engine has already assigned priority tiers (CRITICAL/HIGH/MEDIUM/LOW) \
and scores to each CVE using a deterministic formula based on:
- CISA KEV catalog status (active exploitation confirmed)
- EPSS score (probability of exploitation in next 30 days, from FIRST.org)
- System criticality
- Ransomware campaign use

Your role is to EXPLAIN the engine's decisions in plain language. You do NOT change the tiers. \
You do NOT make compliance determinations.

Structure your brief exactly as follows:
1. Header with system name, date, criticality, and CVE count
2. Executive Summary (2-3 sentences: overall risk posture, most urgent items)
3. One section per priority tier that has CVEs (CRITICAL -> HIGH -> MEDIUM -> LOW)
4. Within each tier: one subsection per CVE explaining WHY it is at that tier, \
   citing the specific KEV date, ransomware status, and EPSS score
5. Recommended Patch Schedule table (CVE | Tier | Component | Action | Target timeframe)
6. Footer with data source attribution

Rules:
- Always cite the KEV date added when a CVE is in KEV
- Always cite the EPSS score and percentile
- Use the required action text from the KEV entry when available
- Flag any references to specific federal directive numbers or deadline dates with VERIFY
- Write for a system administrator audience — specific and actionable, not generic
- Do not use the phrase "as mentioned" or similar self-referential filler
- Target timeframes: CRITICAL=24-48 hours, HIGH=7 days, MEDIUM=30 days, LOW=next maintenance window
"""


class BriefError(Exception):
    pass


def draft_patch_brief(scan, vuln_items: list, demo_key: str = None) -> str:
    """Draft a plain-language patch brief explaining the engine's prioritization.

    demo_key: if set and DEMO_MODE, returns pre-baked brief.
    """
    if DEMO_MODE and demo_key and demo_key in seed_data.DEMO_BRIEFS:
        return seed_data.DEMO_BRIEFS[demo_key]

    user_content = _build_prompt(scan, vuln_items)

    try:
        return call_claude(
            [{"role": "user", "content": user_content}],
            system=_SYSTEM_PROMPT,
            max_tokens=2048,
        )
    except BriefError:
        raise
    except ClaudeCallError as exc:
        raise BriefError(f"Claude API error: {exc}") from exc


def _build_prompt(scan, vuln_items: list) -> str:
    from datetime import date

    lines = [
        f"System: {scan.system_name}",
        f"Type: {scan.system_type}",
        f"Criticality: {scan.system_criticality}",
        f"Assessment date: {date.today().isoformat()}",
        f"Total CVEs: {len(vuln_items)}",
        "",
        "VULNERABILITY LIST (sorted by priority score, highest first):",
    ]

    sorted_items = sorted(vuln_items, key=lambda i: i.priority_score, reverse=True)
    for item in sorted_items:
        lines.append(f"\n## {item.cve_id} — Priority Score: {item.priority_score}/100 -> {item.priority_tier}")
        lines.append(f"  Component: {item.component or 'Unknown'}")
        lines.append(f"  Description: {item.cve_description or 'Not provided'}")
        lines.append(f"  CISA KEV: {'YES' if item.in_kev else 'NO'}")
        if item.in_kev:
            lines.append(f"  KEV Date Added: {item.kev_date_added or 'Unknown'}")
            lines.append(f"  KEV Vulnerability Name: {item.kev_vulnerability_name or 'Unknown'}")
            lines.append(f"  KEV Ransomware Use: {'Known' if item.kev_ransomware_use else 'Unknown'}")
            lines.append(f"  KEV Required Action: {item.kev_required_action or 'See vendor advisory'}")
        lines.append(f"  EPSS Score: {item.epss_score:.4f} ({item.epss_pct}% exploitation probability in 30 days)")
        lines.append(f"  EPSS Percentile: {item.epss_percentile_pct}th percentile")
        lines.append(f"  Engine Rationale: {item.engine_rationale}")

    return "\n".join(lines)
