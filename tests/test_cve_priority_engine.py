from cve.priority_engine import score_vuln, assess_scan, _tier, _build_rationale


# -- Tier boundaries ----------------------------------------------------------

def test_tier_critical():
    assert _tier(75) == "CRITICAL"
    assert _tier(100) == "CRITICAL"
    assert _tier(99) == "CRITICAL"


def test_tier_high():
    assert _tier(50) == "HIGH"
    assert _tier(74) == "HIGH"


def test_tier_medium():
    assert _tier(25) == "MEDIUM"
    assert _tier(49) == "MEDIUM"


def test_tier_low():
    assert _tier(0) == "LOW"
    assert _tier(24) == "LOW"


# -- score_vuln formula --------------------------------------------------------

def _kev(ransomware=False):
    return {
        "vendorProject": "Test",
        "product": "Widget",
        "vulnerabilityName": "Test Vuln",
        "dateAdded": "2023-01-01",
        "knownRansomwareCampaignUse": "Known" if ransomware else "Unknown",
        "requiredAction": "Patch",
        "dueDate": "2023-01-15",
        "shortDescription": "Test",
    }


def test_score_kev_only():
    result = score_vuln("CVE-2021-1234", _kev(), {"epss": 0.0, "percentile": 0.0}, "LOW")
    assert result["priority_score"] == 50
    assert result["priority_tier"] == "HIGH"
    assert result["in_kev"] is True


def test_score_epss_only():
    result = score_vuln("CVE-2021-1234", None, {"epss": 1.0, "percentile": 0.99}, "LOW")
    assert result["priority_score"] == 45
    assert result["priority_tier"] == "MEDIUM"


def test_score_kev_plus_epss():
    result = score_vuln("CVE-2021-1234", _kev(), {"epss": 0.5, "percentile": 0.9}, "LOW")
    assert result["priority_score"] == 72
    assert result["priority_tier"] == "HIGH"


def test_score_capped_at_100():
    result = score_vuln("CVE-2021-1234", _kev(ransomware=True), {"epss": 1.0, "percentile": 0.99}, "CRITICAL")
    assert result["priority_score"] == 100


def test_score_ransomware_bonus():
    no_ransom = score_vuln("CVE-X", _kev(False), {"epss": 0.0, "percentile": 0.0}, "LOW")
    with_ransom = score_vuln("CVE-X", _kev(True), {"epss": 0.0, "percentile": 0.0}, "LOW")
    assert with_ransom["priority_score"] == no_ransom["priority_score"] + 5


def test_score_criticality_bonus_critical():
    base = score_vuln("CVE-X", None, {"epss": 0.5, "percentile": 0.9}, "LOW")
    crit = score_vuln("CVE-X", None, {"epss": 0.5, "percentile": 0.9}, "CRITICAL")
    assert crit["priority_score"] == base["priority_score"] + 5


def test_score_criticality_bonus_high():
    base = score_vuln("CVE-X", None, {"epss": 0.5, "percentile": 0.9}, "LOW")
    high = score_vuln("CVE-X", None, {"epss": 0.5, "percentile": 0.9}, "HIGH")
    assert high["priority_score"] == base["priority_score"] + 3


def test_score_criticality_bonus_medium():
    base = score_vuln("CVE-X", None, {"epss": 0.5, "percentile": 0.9}, "LOW")
    med = score_vuln("CVE-X", None, {"epss": 0.5, "percentile": 0.9}, "MEDIUM")
    assert med["priority_score"] == base["priority_score"] + 1


def test_score_no_kev_no_epss_low():
    result = score_vuln("CVE-2021-1234", None, {"epss": 0.0, "percentile": 0.0}, "LOW")
    assert result["priority_score"] == 0
    assert result["priority_tier"] == "LOW"
    assert result["in_kev"] is False


def test_score_returns_rationale():
    result = score_vuln("CVE-2021-1234", _kev(), {"epss": 0.3, "percentile": 0.8}, "HIGH")
    assert "rationale" in result
    assert len(result["rationale"]) > 20


# -- Demo scenario scores (spot-check known values) ---------------------------

def _epss(score):
    return {"epss": score, "percentile": score * 0.9}


def test_aegis_log4shell_score():
    kev = _kev()
    result = score_vuln("CVE-2021-44228", kev, _epss(1.0), "HIGH")
    assert result["priority_score"] == 98
    assert result["priority_tier"] == "CRITICAL"


def test_aegis_cve_2024_3400_score():
    kev = _kev()
    result = score_vuln("CVE-2024-3400", kev, _epss(0.97), "HIGH")
    assert result["priority_score"] == 97
    assert result["priority_tier"] == "CRITICAL"


def test_no_kev_high_epss_medium_crit():
    result = score_vuln("CVE-2023-44487", None, _epss(0.04380), "HIGH")
    assert result["priority_score"] == 5
    assert result["priority_tier"] == "LOW"


# -- Rationale content ----------------------------------------------------------

def test_rationale_mentions_kev():
    result = score_vuln("CVE-X", _kev(), {"epss": 0.1, "percentile": 0.5}, "LOW")
    assert "KEV" in result["rationale"] or "kev" in result["rationale"].lower()


def test_rationale_mentions_epss():
    result = score_vuln("CVE-X", None, {"epss": 0.8, "percentile": 0.95}, "LOW")
    assert "EPSS" in result["rationale"] or "epss" in result["rationale"].lower()


def test_rationale_mentions_ransomware():
    result = score_vuln("CVE-X", _kev(ransomware=True), {"epss": 0.0, "percentile": 0.0}, "LOW")
    assert "ransomware" in result["rationale"].lower()
