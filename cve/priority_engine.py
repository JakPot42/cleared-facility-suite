"""priority_engine.py — Deterministic CVE priority scoring engine.

Priority score formula (0-100):
  kev_base         = PRIORITY_KEV_BASE (50) if in CISA KEV else 0
  epss_component   = round(epss_score × PRIORITY_EPSS_MULTIPLIER (45))
  ransomware_bonus = PRIORITY_RANSOMWARE_BONUS (5) if known ransomware use else 0
  criticality_bonus= PRIORITY_CRITICALITY_BONUS[system_criticality]
  priority_score   = min(100, kev_base + epss_component + ransomware_bonus + criticality_bonus)

Priority tiers:
  CRITICAL ≥ 75  → Patch within 24-48 hours
  HIGH     ≥ 50  → Patch within 7 days
  MEDIUM   ≥ 25  → Patch within 30 days
  LOW      < 25  → Monitor; schedule at next maintenance window

Doctrine: Claude NEVER makes a priority determination.
The engine runs after human confirmation of the CVE list.
"""

from .config import (
    PRIORITY_CRITICALITY_BONUS,
    PRIORITY_EPSS_MULTIPLIER,
    PRIORITY_KEV_BASE,
    PRIORITY_RANSOMWARE_BONUS,
    PRIORITY_TIER_CRITICAL,
    PRIORITY_TIER_HIGH,
    PRIORITY_TIER_MEDIUM,
)
from . import kev_client


def score_vuln(
    cve_id: str,
    kev_entry: dict | None,
    epss_data: dict,
    system_criticality: str,
) -> dict:
    """Compute priority score and tier for a single CVE.

    Returns dict with: priority_score, priority_tier, in_kev, kev_ransomware_use,
    epss_score, epss_percentile, rationale, and all KEV fields.
    """
    in_kev = kev_entry is not None
    ransomware_use = kev_client.is_ransomware_use(kev_entry) if in_kev else False
    epss_score = float(epss_data.get("epss", 0.0))
    epss_percentile = float(epss_data.get("percentile", 0.0))

    kev_base = PRIORITY_KEV_BASE if in_kev else 0
    epss_component = round(epss_score * PRIORITY_EPSS_MULTIPLIER)
    ransomware_bonus = PRIORITY_RANSOMWARE_BONUS if ransomware_use else 0
    criticality_bonus = PRIORITY_CRITICALITY_BONUS.get(system_criticality, 0)

    raw_score = kev_base + epss_component + ransomware_bonus + criticality_bonus
    priority_score = min(100, raw_score)
    priority_tier = _tier(priority_score)

    rationale = _build_rationale(
        cve_id=cve_id,
        in_kev=in_kev,
        kev_entry=kev_entry,
        ransomware_use=ransomware_use,
        epss_score=epss_score,
        epss_percentile=epss_percentile,
        kev_base=kev_base,
        epss_component=epss_component,
        ransomware_bonus=ransomware_bonus,
        criticality_bonus=criticality_bonus,
        priority_score=priority_score,
        priority_tier=priority_tier,
        system_criticality=system_criticality,
    )

    result = {
        "priority_score": priority_score,
        "priority_tier": priority_tier,
        "in_kev": in_kev,
        "kev_ransomware_use": ransomware_use,
        "epss_score": epss_score,
        "epss_percentile": epss_percentile,
        "rationale": rationale,
    }
    if in_kev:
        result.update({
            "kev_vendor_project": kev_entry.get("vendorProject"),
            "kev_product": kev_entry.get("product"),
            "kev_vulnerability_name": kev_entry.get("vulnerabilityName"),
            "kev_date_added": kev_entry.get("dateAdded"),
            "kev_required_action": kev_entry.get("requiredAction"),
            "kev_due_date": kev_entry.get("dueDate"),
            "kev_short_description": kev_entry.get("shortDescription"),
        })
    return result


def assess_scan(scan, proposed_items: list[dict], kev_catalog: dict = None) -> list:
    """Score all proposed CVE items and return list of VulnItem model instances.

    proposed_items: list of {cve_id, component, description} dicts.
    kev_catalog: pre-fetched full catalog (live mode); None in demo mode.
    """
    from models import VulnItem
    import epss_client
    from config import DEMO_MODE

    cve_ids = [item["cve_id"] for item in proposed_items]
    if DEMO_MODE:
        epss_batch = {cid.upper(): epss_client.fetch_epss(cid, demo_mode=True) for cid in cve_ids}
    else:
        epss_batch = epss_client.fetch_epss_batch(cve_ids)

    items = []
    for item_data in proposed_items:
        cve_id = item_data["cve_id"].strip().upper()
        kev_entry = kev_client.lookup_kev(cve_id, catalog=kev_catalog)
        epss_data = epss_batch.get(cve_id, {"epss": 0.0, "percentile": 0.0})
        result = score_vuln(cve_id, kev_entry, epss_data, scan.system_criticality)

        vuln_item = VulnItem(
            scan_id=scan.id,
            component=item_data.get("component", ""),
            cve_id=cve_id,
            cve_description=item_data.get("description", ""),
            in_kev=result["in_kev"],
            kev_vendor_project=result.get("kev_vendor_project"),
            kev_product=result.get("kev_product"),
            kev_vulnerability_name=result.get("kev_vulnerability_name"),
            kev_date_added=result.get("kev_date_added"),
            kev_ransomware_use=result.get("kev_ransomware_use", False),
            kev_required_action=result.get("kev_required_action"),
            kev_due_date=result.get("kev_due_date"),
            kev_short_description=result.get("kev_short_description"),
            epss_score=result["epss_score"],
            epss_percentile=result["epss_percentile"],
            priority_score=result["priority_score"],
            priority_tier=result["priority_tier"],
            engine_rationale=result["rationale"],
        )
        items.append(vuln_item)

    return items


def _tier(score: int) -> str:
    if score >= PRIORITY_TIER_CRITICAL:
        return "CRITICAL"
    if score >= PRIORITY_TIER_HIGH:
        return "HIGH"
    if score >= PRIORITY_TIER_MEDIUM:
        return "MEDIUM"
    return "LOW"


def _build_rationale(
    cve_id, in_kev, kev_entry, ransomware_use, epss_score, epss_percentile,
    kev_base, epss_component, ransomware_bonus, criticality_bonus,
    priority_score, priority_tier, system_criticality,
) -> str:
    parts = []

    if in_kev:
        date_added = kev_entry.get("dateAdded", "unknown date")
        parts.append(
            f"In CISA KEV catalog (added {date_added}) — active exploitation confirmed in the wild "
            f"(+{kev_base} points)."
        )
        if ransomware_use:
            parts.append(f"Known ransomware campaign use — elevated urgency (+{ransomware_bonus} points).")
    else:
        parts.append("Not in CISA KEV catalog — no confirmed active exploitation as of assessment date.")

    epss_pct = round(epss_score * 100, 1)
    epss_percentile_pct = round(epss_percentile * 100, 1)
    parts.append(
        f"EPSS score {epss_score:.4f} ({epss_pct}% probability of exploitation in next 30 days, "
        f"{epss_percentile_pct}th percentile of all CVEs) (+{epss_component} points)."
    )

    parts.append(
        f"System criticality ({system_criticality}) contributes +{criticality_bonus} points."
    )

    tier_explanations = {
        "CRITICAL": "Total score {score}/100 → CRITICAL tier. Patch within 24–48 hours.",
        "HIGH": "Total score {score}/100 → HIGH tier. Patch within 7 days.",
        "MEDIUM": "Total score {score}/100 → MEDIUM tier. Patch within 30 days.",
        "LOW": "Total score {score}/100 → LOW tier. Schedule at next maintenance window.",
    }
    parts.append(tier_explanations[priority_tier].format(score=priority_score))

    return " ".join(parts)
