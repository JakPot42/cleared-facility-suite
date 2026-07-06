from cve.epss_client import fetch_epss
from cve.seed_data import DEMO_EPSS_DATA


def test_demo_mode_returns_score():
    result = fetch_epss("CVE-2021-44228", demo_mode=True)
    assert "epss" in result
    assert "percentile" in result
    assert isinstance(result["epss"], float)


def test_demo_mode_known_cve_score():
    result = fetch_epss("CVE-2021-44228", demo_mode=True)
    assert result["epss"] == DEMO_EPSS_DATA["CVE-2021-44228"]["epss"]


def test_demo_mode_unknown_cve_returns_default():
    result = fetch_epss("CVE-9999-99999", demo_mode=True)
    assert result == {"epss": 0.0, "percentile": 0.0}


def test_demo_mode_case_normalized():
    result_upper = fetch_epss("CVE-2022-1388", demo_mode=True)
    result_lower = fetch_epss("cve-2022-1388", demo_mode=True)
    assert result_upper == result_lower


def test_demo_mode_score_range():
    for cve_id in DEMO_EPSS_DATA:
        result = fetch_epss(cve_id, demo_mode=True)
        assert 0.0 <= result["epss"] <= 1.0
        assert 0.0 <= result["percentile"] <= 1.0
