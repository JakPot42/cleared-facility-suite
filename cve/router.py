"""router.py — CVE Prioritizer routes, mounted at /cve (Cleared Facility Suite)."""

import json
from datetime import datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from database import get_db

from . import seed_data
from .claude_brief import BriefError, draft_patch_brief
from .claude_extractor import ExtractorError, extract_cve_inventory
from .config import CRITICALITY_OPTIONS, DEMO_MODE, SYSTEM_TYPES
from .models import Scan, VulnItem
from .pdf_export import generate_pdf
from .priority_engine import assess_scan

router = APIRouter(prefix="/cve", tags=["cve"])
templates = Jinja2Templates(directory="templates")


def seed_demo_data(db: Session) -> None:
    seed_data.load_seed_data(db)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _demo_key_for(system_name: str) -> str | None:
    name = system_name.lower()
    if "aegis" in name:
        return "aegis"
    if "vanguard" in name:
        return "vanguard"
    if "riverside" in name:
        return "riverside"
    return None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    total_kev = sum(i.in_kev for s in scans for i in s.items)
    critical_vulns = sum(i.priority_tier == "CRITICAL" for s in scans for i in s.items)
    return templates.TemplateResponse(request, "cve/index.html", {
        "scans": scans,
        "total_kev": total_kev,
        "critical_vulns": critical_vulns,
        "demo_mode": DEMO_MODE,
    })


@router.get("/scans/new", response_class=HTMLResponse)
def new_scan_form(request: Request):
    return templates.TemplateResponse(request, "cve/new_scan.html", {
        "system_types": SYSTEM_TYPES,
        "criticality_options": CRITICALITY_OPTIONS,
        "demo_mode": DEMO_MODE,
    })


@router.post("/scans/new")
def new_scan_post(
    request: Request,
    system_name: str = Form(...),
    system_type: str = Form(...),
    system_criticality: str = Form(...),
    system_description: str = Form(""),
    db: Session = Depends(get_db),
):
    if not system_name.strip():
        return templates.TemplateResponse(request, "cve/new_scan.html", {
            "system_types": SYSTEM_TYPES,
            "criticality_options": CRITICALITY_OPTIONS,
            "error": "System name is required.",
            "demo_mode": DEMO_MODE,
        })
    scan = Scan(
        system_name=system_name.strip(),
        system_type=system_type,
        system_criticality=system_criticality,
        system_description=system_description.strip(),
        status="DRAFT",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return RedirectResponse(f"/cve/scans/{scan.id}/inventory", status_code=303)


@router.get("/scans/{scan_id}/inventory", response_class=HTMLResponse)
def inventory_form(scan_id: int, request: Request, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return templates.TemplateResponse(request, "cve/inventory.html", {
        "scan": scan,
        "demo_mode": DEMO_MODE,
    })


_MAX_INVENTORY_CHARS = 10_000

@router.post("/scans/{scan_id}/inventory")
def inventory_post(
    scan_id: int,
    request: Request,
    inventory_text: str = Form(...),
    db: Session = Depends(get_db),
):
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if not inventory_text.strip():
        return templates.TemplateResponse(request, "cve/inventory.html", {
            "scan": scan,
            "error": "Please enter your software inventory.",
            "demo_mode": DEMO_MODE,
        })

    if len(inventory_text) > _MAX_INVENTORY_CHARS:
        return templates.TemplateResponse(request, "cve/inventory.html", {
            "scan": scan,
            "error": f"Inventory too long ({len(inventory_text):,} chars). Maximum is {_MAX_INVENTORY_CHARS:,} characters.",
            "demo_mode": DEMO_MODE,
        })

    demo_key = _demo_key_for(scan.system_name)
    try:
        extracted = extract_cve_inventory(inventory_text.strip(), demo_key=demo_key)
    except ExtractorError as exc:
        return templates.TemplateResponse(request, "cve/inventory.html", {
            "scan": scan,
            "error": f"Extraction failed: {exc}",
            "demo_mode": DEMO_MODE,
        })

    scan.inventory_text = inventory_text.strip()
    scan.extracted_items_json = json.dumps(extracted)
    scan.status = "EXTRACTED"
    db.commit()
    return RedirectResponse(f"/cve/scans/{scan_id}/confirm", status_code=303)


@router.get("/scans/{scan_id}/confirm", response_class=HTMLResponse)
def confirm_form(scan_id: int, request: Request, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    extracted = json.loads(scan.extracted_items_json or "[]")
    return templates.TemplateResponse(request, "cve/confirm.html", {
        "scan": scan,
        "extracted": extracted,
        "demo_mode": DEMO_MODE,
    })


@router.post("/scans/{scan_id}/confirm")
def confirm_post(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    proposed = json.loads(scan.extracted_items_json or "[]")
    if not proposed:
        return RedirectResponse(f"/cve/scans/{scan_id}/inventory", status_code=303)

    # Engine runs on human-confirmed CVE list — Claude NEVER makes priority determination
    kev_catalog = None
    if not DEMO_MODE:
        from . import kev_client
        kev_catalog = kev_client.fetch_kev_catalog()

    items = assess_scan(scan, proposed, kev_catalog=kev_catalog)
    for item in items:
        db.add(item)

    scan.status = "ASSESSED"
    db.commit()
    return RedirectResponse(f"/cve/scans/{scan_id}", status_code=303)


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(scan_id: int, request: Request, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return templates.TemplateResponse(request, "cve/scan.html", {
        "scan": scan,
        "demo_mode": DEMO_MODE,
    })


@router.post("/scans/{scan_id}/brief")
def brief_post(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    demo_key = _demo_key_for(scan.system_name)
    try:
        brief_text = draft_patch_brief(scan, scan.items, demo_key=demo_key)
    except BriefError:
        brief_text = "Brief generation failed. Please try again."

    scan.patch_brief_text = brief_text
    scan.brief_generated_at = datetime.utcnow()
    scan.status = "BRIEF_READY"
    db.commit()
    return RedirectResponse(f"/cve/scans/{scan_id}/brief", status_code=303)


@router.get("/scans/{scan_id}/brief", response_class=HTMLResponse)
def brief_view(scan_id: int, request: Request, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not scan.patch_brief_text:
        return RedirectResponse(f"/cve/scans/{scan_id}", status_code=303)
    return templates.TemplateResponse(request, "cve/brief.html", {
        "scan": scan,
        "demo_mode": DEMO_MODE,
    })


@router.get("/scans/{scan_id}/report.pdf")
def pdf_download(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    pdf_bytes = generate_pdf(scan)
    filename = scan.system_name.lower().replace(" ", "-")
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}-cve-report.pdf"'},
    )


@router.post("/seed")
def seed_route(db: Session = Depends(get_db)):
    seed_data.load_seed_data(db)
    return RedirectResponse("/cve/", status_code=303)


@router.get("/api/stats")
def api_stats(db: Session = Depends(get_db)):
    scans = db.query(Scan).count()
    vulns = db.query(VulnItem).count()
    kev_count = db.query(VulnItem).filter_by(in_kev=True).count()
    critical_count = db.query(VulnItem).filter_by(priority_tier="CRITICAL").count()
    return {
        "status": "ok",
        "demo_mode": DEMO_MODE,
        "scans": scans,
        "vulnerabilities": vulns,
        "kev_confirmed": kev_count,
        "critical_priority": critical_count,
    }
