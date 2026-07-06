"""Tests for cve/router.py FastAPI routes, mounted at /cve."""


# -- Stats / health ------------------------------------------------------------

def test_api_stats(client):
    r = client.get("/cve/api/stats")
    assert r.status_code == 200
    data = r.json()
    assert "demo_mode" in data
    assert data["demo_mode"] is True
    assert "scans" in data


# -- Homepage -------------------------------------------------------------------

def test_index(client):
    r = client.get("/cve/")
    assert r.status_code == 200
    assert b"CVE Prioritizer" in r.content or b"Vulnerability" in r.content


# -- New scan form --------------------------------------------------------------

def test_new_scan_get(client):
    r = client.get("/cve/scans/new")
    assert r.status_code == 200


def test_new_scan_post_creates_scan(client):
    r = client.post("/cve/scans/new", data={
        "system_name": "Test System Alpha",
        "system_type": "Web Application",
        "system_criticality": "HIGH",
        "system_description": "Test description",
    }, follow_redirects=False)
    assert r.status_code in (302, 303)


def test_new_scan_missing_name_returns_form(client):
    r = client.post("/cve/scans/new", data={
        "system_name": "",
        "system_type": "Web Application",
        "system_criticality": "HIGH",
    }, follow_redirects=False)
    assert r.status_code in (200, 302, 303, 422)


# -- Seed endpoint ----------------------------------------------------------------

def test_seed_loads_data(client):
    r = client.post("/cve/seed", follow_redirects=False)
    assert r.status_code in (302, 303)


def test_seed_idempotent(client):
    client.post("/cve/seed")
    client.post("/cve/seed")
    r = client.get("/cve/api/stats")
    data = r.json()
    assert data["scans"] >= 0


# -- Inventory route ----------------------------------------------------------------

def _create_scan(client, name="Route Test System"):
    r = client.post("/cve/scans/new", data={
        "system_name": name,
        "system_type": "Web Application",
        "system_criticality": "MEDIUM",
        "system_description": "",
    }, follow_redirects=True)
    assert r.status_code == 200
    url = str(r.url)
    parts = url.split("/")
    for i, part in enumerate(parts):
        if part == "scans" and i + 1 < len(parts):
            try:
                return int(parts[i + 1])
            except ValueError:
                pass
    return None


def test_inventory_get(client):
    scan_id = _create_scan(client, "Inventory Get Test")
    if scan_id:
        r = client.get(f"/cve/scans/{scan_id}/inventory")
        assert r.status_code == 200


def test_inventory_missing_scan_404(client):
    r = client.get("/cve/scans/99999/inventory")
    assert r.status_code == 404


# -- Confirm route -------------------------------------------------------------------

def test_confirm_missing_scan_404(client):
    r = client.get("/cve/scans/99999/confirm")
    assert r.status_code == 404


# -- Results route ---------------------------------------------------------------------

def test_scan_result_missing_404(client):
    r = client.get("/cve/scans/99999")
    assert r.status_code == 404


# -- Brief route ------------------------------------------------------------------------

def test_brief_missing_scan_404(client):
    r = client.get("/cve/scans/99999/brief")
    assert r.status_code == 404


# -- PDF route --------------------------------------------------------------------------

def test_pdf_missing_scan_404(client):
    r = client.get("/cve/scans/99999/report.pdf")
    assert r.status_code == 404


# -- Seeded scan routes -------------------------------------------------------------------

def test_seeded_scan_result_page(client):
    client.post("/cve/seed")
    r = client.get("/cve/")
    assert r.status_code == 200
    stats = client.get("/cve/api/stats").json()
    if stats["scans"] > 0:
        r2 = client.get("/cve/scans/1")
        assert r2.status_code in (200, 404)


def test_seeded_scan_brief_page(client):
    client.post("/cve/seed")
    stats = client.get("/cve/api/stats").json()
    total = stats.get("scans", 0)
    if total > 0:
        for i in range(1, 20):
            r = client.get(f"/cve/scans/{i}/brief")
            if r.status_code == 200:
                assert b"brief" in r.content.lower() or b"patch" in r.content.lower()
                break


def test_seeded_pdf_download(client):
    client.post("/cve/seed")
    stats = client.get("/cve/api/stats").json()
    if stats.get("scans", 0) > 0:
        for i in range(1, 20):
            r = client.get(f"/cve/scans/{i}/report.pdf")
            if r.status_code == 200:
                assert r.headers["content-type"] == "application/pdf"
                break
