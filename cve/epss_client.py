"""epss_client.py — FIRST.org EPSS (Exploit Prediction Scoring System) client.

EPSS score: probability (0-1) that a CVE will be exploited in the next 30 days.
DEMO_MODE: returns pre-baked data from seed_data.DEMO_EPSS_DATA.
Live mode: fetches from FIRST.org API (supports batch requests).
"""

from . import seed_data
from .config import EPSS_API_URL

_DEFAULT_EPSS = {"epss": 0.0, "percentile": 0.0}


class EPSSClientError(Exception):
    pass


def fetch_epss(cve_id: str, demo_mode: bool = None) -> dict:
    """Return EPSS data dict {epss, percentile} for a single CVE.

    Returns default zeros if CVE is not found or API is unavailable.
    """
    from .config import DEMO_MODE
    if demo_mode is None:
        demo_mode = DEMO_MODE

    cve_id = cve_id.strip().upper()

    if demo_mode:
        return seed_data.DEMO_EPSS_DATA.get(cve_id, dict(_DEFAULT_EPSS))

    return _fetch_live(cve_id)


def fetch_epss_batch(cve_ids: list[str]) -> dict:
    """Fetch EPSS scores for multiple CVEs in one API call (live mode).

    Returns dict keyed by CVE ID.
    """
    from .config import DEMO_MODE
    if DEMO_MODE:
        return {cid.upper(): seed_data.DEMO_EPSS_DATA.get(cid.upper(), dict(_DEFAULT_EPSS))
                for cid in cve_ids}

    if not cve_ids:
        return {}

    import urllib.request
    import json

    ids_param = ",".join(c.upper() for c in cve_ids)
    url = f"{EPSS_API_URL}?cve={ids_param}"

    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read())

        result = {}
        for entry in data.get("data", []):
            result[entry["cve"].upper()] = {
                "epss": float(entry.get("epss", 0)),
                "percentile": float(entry.get("percentile", 0)),
            }
        # Fill any CVE not returned by API with defaults
        for cid in cve_ids:
            if cid.upper() not in result:
                result[cid.upper()] = dict(_DEFAULT_EPSS)
        return result

    except Exception as exc:
        raise EPSSClientError(f"Failed to fetch EPSS scores: {exc}") from exc


def _fetch_live(cve_id: str) -> dict:
    result = fetch_epss_batch([cve_id])
    return result.get(cve_id.upper(), dict(_DEFAULT_EPSS))
