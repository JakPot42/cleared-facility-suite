from cve.kev_client import normalize_cve_id, lookup_kev, is_ransomware_use
from cve.seed_data import DEMO_KEV_DATA


def test_normalize_uppercase():
    assert normalize_cve_id("cve-2021-44228") == "CVE-2021-44228"


def test_normalize_strips_whitespace():
    assert normalize_cve_id("  CVE-2021-44228  ") == "CVE-2021-44228"


def test_normalize_already_correct():
    assert normalize_cve_id("CVE-2022-1388") == "CVE-2022-1388"


def test_demo_lookup_found():
    entry = lookup_kev("CVE-2021-44228", demo_mode=True)
    assert entry is not None
    assert entry["vulnerabilityName"] is not None


def test_demo_lookup_not_found():
    entry = lookup_kev("CVE-9999-99999", demo_mode=True)
    assert entry is None


def test_demo_lookup_case_insensitive():
    entry = lookup_kev("cve-2021-44228", demo_mode=True)
    assert entry is not None


def test_is_ransomware_use_known():
    kev_entry = {"knownRansomwareCampaignUse": "Known"}
    assert is_ransomware_use(kev_entry) is True


def test_is_ransomware_use_unknown():
    kev_entry = {"knownRansomwareCampaignUse": "Unknown"}
    assert is_ransomware_use(kev_entry) is False


def test_is_ransomware_use_missing_field():
    assert is_ransomware_use({}) is False


def test_demo_kev_ransomware_entries():
    # Log4Shell should be flagged ransomware in seed data
    entry = DEMO_KEV_DATA.get("CVE-2021-44228")
    assert entry is not None
    assert entry.get("knownRansomwareCampaignUse") == "Known"
