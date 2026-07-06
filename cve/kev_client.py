"""kev_client.py — CISA KEV catalog client.

DEMO_MODE: returns pre-baked data from seed_data.DEMO_KEV_DATA.
Live mode: fetches full catalog from CISA and returns per-CVE lookup.
"""

import re

from . import seed_data
from .config import KEV_CATALOG_URL


class KEVClientError(Exception):
    pass


def normalize_cve_id(raw: str) -> str:
    """Normalize to uppercase CVE-YYYY-NNNNN format."""
    return raw.strip().upper()


def lookup_kev(cve_id: str, demo_mode: bool = None, catalog: dict = None) -> dict | None:
    """Return KEV entry dict for cve_id, or None if not in KEV.

    demo_mode=None reads from config.DEMO_MODE.
    catalog: pre-fetched catalog dict (live mode only); if None, fetched fresh.
    """
    from .config import DEMO_MODE
    if demo_mode is None:
        demo_mode = DEMO_MODE

    cve_id = normalize_cve_id(cve_id)

    if demo_mode:
        return seed_data.DEMO_KEV_DATA.get(cve_id)

    if catalog is None:
        catalog = fetch_kev_catalog()

    return catalog.get(cve_id)


def fetch_kev_catalog() -> dict:
    """Fetch full CISA KEV catalog. Returns dict keyed by CVE ID."""
    import urllib.request
    import json

    try:
        with urllib.request.urlopen(KEV_CATALOG_URL, timeout=15) as resp:
            data = json.loads(resp.read())
        return {v["cveID"]: v for v in data.get("vulnerabilities", [])}
    except Exception as exc:
        raise KEVClientError(f"Failed to fetch KEV catalog: {exc}") from exc


def is_ransomware_use(kev_entry: dict) -> bool:
    """Return True if KEV entry indicates known ransomware campaign use."""
    if not kev_entry:
        return False
    return kev_entry.get("knownRansomwareCampaignUse", "Unknown").lower() == "known"
