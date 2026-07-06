"""claude_extractor.py — Claude extracts and normalizes CVE IDs from inventory text.

DEMO_MODE: returns pre-baked extractions from seed_data.DEMO_EXTRACTIONS.
Live mode: calls Claude Haiku (via shared.claude_client) to parse free-text, CVE lists,
or CPE-formatted input.

Output format: list of {cve_id, component, description} dicts.
"""

import json
import re

from shared.claude_client import ClaudeCallError, call_claude

from . import seed_data
from .config import DEMO_MODE

_SYSTEM_PROMPT = """\
You are a cybersecurity analyst extracting CVE identifiers from a software inventory.

The user will provide a software inventory in one of these formats:
- Free text describing software and versions ("Apache Log4j 2.14.1 on app servers...")
- A list of CVE IDs ("CVE-2021-44228, CVE-2022-30190...")
- CPE-formatted components ("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
- A mix of the above

Your task:
1. Extract every CVE ID mentioned or strongly implied by the software versions described.
2. For software versions WITHOUT explicit CVE IDs, extract any well-known CVEs associated with \
that specific version (if you are highly confident the version is vulnerable).
3. Normalize each CVE ID to uppercase format: CVE-YYYY-NNNNN.
4. For each CVE, identify the affected component (software name and version if available).
5. Provide a one-sentence description of what the vulnerability is.

Return ONLY a JSON array. No markdown, no explanation. Example:
[
  {"cve_id": "CVE-2021-44228", "component": "Apache Log4j 2.14.1", \
"description": "Remote code execution via JNDI lookup in log messages."},
  {"cve_id": "CVE-2024-3400", "component": "Palo Alto PAN-OS 10.2.3", \
"description": "OS command injection via GlobalProtect gateway cookies."}
]

Rules:
- Only include CVEs you are highly confident about. Do not guess.
- If a component has no known CVEs or you are uncertain, omit it.
- If the input is already a list of CVE IDs, extract them with minimal component/description inference.
- Deduplicate — include each CVE ID only once.
- Return an empty array [] if no CVEs can be identified.
"""


class ExtractorError(Exception):
    pass


def extract_cve_inventory(inventory_text: str, demo_key: str = None) -> list[dict]:
    """Extract CVE inventory from free-text or CVE list.

    Returns list of {cve_id, component, description} dicts.
    demo_key: if set and DEMO_MODE, returns pre-baked extraction.
    """
    if DEMO_MODE and demo_key and demo_key in seed_data.DEMO_EXTRACTIONS:
        return seed_data.DEMO_EXTRACTIONS[demo_key]

    if DEMO_MODE:
        return _parse_cve_ids_directly(inventory_text)

    try:
        raw = call_claude(
            [{"role": "user", "content": inventory_text}],
            system=_SYSTEM_PROMPT,
            max_tokens=1024,
        )
        return _parse_json_response(raw)
    except ExtractorError:
        raise
    except ClaudeCallError as exc:
        raise ExtractorError(f"Claude API error: {exc}") from exc


def _parse_json_response(text: str) -> list[dict]:
    """Strip markdown fences and parse JSON array."""
    text = re.sub(r"^```(?:json)?\s*", "", text.strip(), flags=re.MULTILINE)
    text = re.sub(r"```\s*$", "", text.strip(), flags=re.MULTILINE)
    text = text.strip()
    try:
        parsed = json.loads(text)
        if not isinstance(parsed, list):
            raise ExtractorError("Claude returned non-array JSON")
        return parsed
    except json.JSONDecodeError as exc:
        raise ExtractorError(f"Claude returned invalid JSON: {exc}") from exc


def _parse_cve_ids_directly(text: str) -> list[dict]:
    """Fallback: extract CVE IDs directly via regex (DEMO_MODE without a demo key)."""
    pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    seen = set()
    results = []
    for match in pattern.finditer(text):
        cve_id = match.group(0).upper()
        if cve_id not in seen:
            seen.add(cve_id)
            results.append({"cve_id": cve_id, "component": "", "description": ""})
    return results
