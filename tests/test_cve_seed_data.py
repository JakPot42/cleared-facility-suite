from cve.seed_data import load_seed_data, DEMO_SCENARIOS, DEMO_BRIEFS
from cve.models import Scan, VulnItem

SEED_NAMES = ["Aegis", "Vanguard", "Riverside"]


def _seed_scans(db):
    """Return only the 3 demo seed scans by name substring."""
    results = []
    for name in SEED_NAMES:
        s = db.query(Scan).filter(Scan.system_name.ilike(f"%{name.lower()}%")).first()
        if s:
            results.append(s)
    return results


def test_load_seed_data_creates_three_scans(seeded_db):
    scans = _seed_scans(seeded_db)
    assert len(scans) == 3


def test_load_seed_data_idempotent(seeded_db):
    load_seed_data(seeded_db)
    scans = _seed_scans(seeded_db)
    assert len(scans) == 3


def test_aegis_scan_present(seeded_db):
    scan = seeded_db.query(Scan).filter(Scan.system_name.ilike("%aegis%")).first()
    assert scan is not None
    assert scan.status == "BRIEF_READY"


def test_vanguard_scan_present(seeded_db):
    scan = seeded_db.query(Scan).filter(Scan.system_name.ilike("%vanguard%")).first()
    assert scan is not None
    assert scan.status == "BRIEF_READY"


def test_riverside_scan_present(seeded_db):
    scan = seeded_db.query(Scan).filter(Scan.system_name.ilike("%riverside%")).first()
    assert scan is not None
    assert scan.status == "BRIEF_READY"


def test_aegis_has_critical_items(seeded_db):
    scan = seeded_db.query(Scan).filter(Scan.system_name.ilike("%aegis%")).first()
    critical = [i for i in scan.items if i.priority_tier == "CRITICAL"]
    assert len(critical) >= 2


def test_vanguard_has_critical_items(seeded_db):
    scan = seeded_db.query(Scan).filter(Scan.system_name.ilike("%vanguard%")).first()
    critical = [i for i in scan.items if i.priority_tier == "CRITICAL"]
    assert len(critical) >= 3


def test_riverside_has_critical_items(seeded_db):
    scan = seeded_db.query(Scan).filter(Scan.system_name.ilike("%riverside%")).first()
    critical = [i for i in scan.items if i.priority_tier == "CRITICAL"]
    assert len(critical) >= 1


def test_aegis_has_low_tier_item(seeded_db):
    scan = seeded_db.query(Scan).filter(Scan.system_name.ilike("%aegis%")).first()
    low = [i for i in scan.items if i.priority_tier == "LOW"]
    assert len(low) >= 1


def test_vanguard_has_medium_tier_item(seeded_db):
    scan = seeded_db.query(Scan).filter(Scan.system_name.ilike("%vanguard%")).first()
    med = [i for i in scan.items if i.priority_tier == "MEDIUM"]
    assert len(med) >= 1


def test_kev_items_flagged(seeded_db):
    kev_items = seeded_db.query(VulnItem).filter(VulnItem.in_kev == True).all()
    assert len(kev_items) >= 5


def test_brief_present_on_all_scans(seeded_db):
    scans = _seed_scans(seeded_db)
    for scan in scans:
        assert scan.patch_brief_text is not None
        assert len(scan.patch_brief_text) > 200


def test_brief_contains_verify_flag(seeded_db):
    scans = _seed_scans(seeded_db)
    for scan in scans:
        text = scan.patch_brief_text or ""
        assert "VERIFY" in text or "⚠" in text
