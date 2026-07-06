"""router.py — Harvest Horizon routes, mounted at /hh (Cleared Facility Suite)."""

from __future__ import annotations

import datetime
import json

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from database import get_db

from .assessment_engine import assess_items, compliance_summary
from .claude_extractor import ExtractorError, extract_crypto_inventory
from .claude_roadmap import RoadmapError, draft_migration_roadmap
from .config import (
    APP_SUBTITLE,
    APP_TITLE,
    DATA_SENSITIVITY_LEVELS,
    DEMO_BANNER,
    DEMO_MODE,
    FIPS_203_NAME,
    FIPS_204_NAME,
    FIPS_205_NAME,
    SCOPE_NOTICE,
    VERIFICATION_DISCLAIMER,
)
from .exposure_engine import compute_hndl_score
from .models import Assessment, CryptoItem
from .pdf_export import generate_pdf

router = APIRouter(prefix="/hh", tags=["hh"])
templates = Jinja2Templates(directory="templates")


def seed_demo_data(db: Session) -> None:
    from .seed_data import load_seed_data
    load_seed_data(db)


# ---------------------------------------------------------------------------
# Template context helper
# ---------------------------------------------------------------------------

def _ctx(extra: dict | None = None) -> dict:
    base = {
        "app_title": APP_TITLE,
        "app_subtitle": APP_SUBTITLE,
        "demo_mode": DEMO_MODE,
        "demo_banner": DEMO_BANNER,
        "scope_notice": SCOPE_NOTICE,
        "disclaimer": VERIFICATION_DISCLAIMER,
        "sensitivity_levels": DATA_SENSITIVITY_LEVELS,
    }
    if extra:
        base.update(extra)
    return base


def _demo_key_for(org_name: str) -> str | None:
    """Map org name to demo key for pre-baked DEMO_MODE responses."""
    _map = {
        "Aegis Defense Systems": "aegis",
        "Meridian Health Systems": "meridian",
        "Apex Technology Corp": "apex",
    }
    return _map.get(org_name)


# ---------------------------------------------------------------------------
# Routes — Dashboard
# ---------------------------------------------------------------------------

@router.get("/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)):
    assessments = db.query(Assessment).order_by(Assessment.created_at.desc()).all()
    return templates.TemplateResponse(request, "hh/index.html", _ctx({
        "assessments": assessments,
        "fips_203": FIPS_203_NAME,
        "fips_204": FIPS_204_NAME,
        "fips_205": FIPS_205_NAME,
    }))


# ---------------------------------------------------------------------------
# Routes — New Assessment
# ---------------------------------------------------------------------------

@router.get("/assessments/new", response_class=HTMLResponse)
def new_assessment_form(request: Request):
    return templates.TemplateResponse(request, "hh/new_assessment.html", _ctx())


@router.post("/assessments/new")
def create_assessment(
    request: Request,
    db: Session = Depends(get_db),
    org_name: str = Form(...),
    org_type: str = Form(default=""),
    org_description: str = Form(default=""),
    data_sensitivity: str = Form(default="INTERNAL"),
    data_retention_years: int = Form(default=5),
):
    if not org_name.strip():
        return templates.TemplateResponse(
            request, "hh/new_assessment.html",
            _ctx({"error": "Organization name is required."}),
            status_code=422,
        )
    assessment = Assessment(
        org_name=org_name.strip(),
        org_type=org_type.strip(),
        org_description=org_description.strip(),
        data_sensitivity=data_sensitivity,
        data_retention_years=max(1, data_retention_years),
        status="DRAFT",
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)
    return RedirectResponse(f"/hh/assessments/{assessment.id}/describe", status_code=303)


# ---------------------------------------------------------------------------
# Routes — Describe Crypto Footprint
# ---------------------------------------------------------------------------

@router.get("/assessments/{assessment_id}/describe", response_class=HTMLResponse)
def describe_form(request: Request, assessment_id: int, db: Session = Depends(get_db)):
    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return templates.TemplateResponse(request, "hh/describe.html", _ctx({"assessment": assessment}))


_MAX_FOOTPRINT_CHARS = 5_000

@router.post("/assessments/{assessment_id}/describe")
def run_extraction(
    request: Request,
    assessment_id: int,
    db: Session = Depends(get_db),
    footprint_description: str = Form(...),
):
    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    footprint_description = footprint_description.strip()
    if len(footprint_description) > _MAX_FOOTPRINT_CHARS:
        return templates.TemplateResponse(
            request, "hh/describe.html",
            _ctx({"assessment": assessment,
                  "error": f"Description too long ({len(footprint_description):,} chars). Maximum is {_MAX_FOOTPRINT_CHARS:,} characters."}),
            status_code=422,
        )

    demo_key = _demo_key_for(assessment.org_name)

    try:
        items = extract_crypto_inventory(footprint_description, demo_key=demo_key)
    except ExtractorError as exc:
        return templates.TemplateResponse(
            request, "hh/describe.html",
            _ctx({"assessment": assessment, "error": str(exc)}),
            status_code=500,
        )

    if not items:
        return templates.TemplateResponse(
            request, "hh/describe.html",
            _ctx({
                "assessment": assessment,
                "error": "No cryptographic algorithms were extracted. Please provide more detail about "
                         "your TLS versions, certificate types, key exchange protocols, and cipher suites.",
            }),
            status_code=422,
        )

    assessment.footprint_description = footprint_description
    assessment.extracted_items_json = json.dumps(items)
    assessment.status = "EXTRACTED"
    db.commit()
    return RedirectResponse(f"/hh/assessments/{assessment_id}/confirm", status_code=303)


# ---------------------------------------------------------------------------
# Routes — Confirm Extracted Inventory (SEAD 3 pattern)
# ---------------------------------------------------------------------------

@router.get("/assessments/{assessment_id}/confirm", response_class=HTMLResponse)
def confirm_form(request: Request, assessment_id: int, db: Session = Depends(get_db)):
    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    if not assessment.extracted_items_json:
        return RedirectResponse(f"/hh/assessments/{assessment_id}/describe", status_code=303)

    proposed = json.loads(assessment.extracted_items_json)
    return templates.TemplateResponse(request, "hh/confirm.html", _ctx({
        "assessment": assessment,
        "proposed": proposed,
    }))


@router.post("/assessments/{assessment_id}/confirm")
def run_assessment(
    request: Request,
    assessment_id: int,
    db: Session = Depends(get_db),
):
    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    if not assessment.extracted_items_json:
        return RedirectResponse(f"/hh/assessments/{assessment_id}/describe", status_code=303)

    # Delete any previous items (re-run scenario)
    db.query(CryptoItem).filter_by(assessment_id=assessment_id).delete()
    db.flush()

    proposed = json.loads(assessment.extracted_items_json)
    items = assess_items(assessment, proposed)
    for item in items:
        db.add(item)
    db.flush()

    # Compute HNDL exposure
    result = compute_hndl_score(items, assessment.data_sensitivity, assessment.data_retention_years)
    assessment.hndl_score = result["score"]
    assessment.hndl_tier = result["tier"]
    assessment.hndl_rationale = result["rationale"]
    assessment.status = "ASSESSED"

    db.commit()
    return RedirectResponse(f"/hh/assessments/{assessment_id}", status_code=303)


# ---------------------------------------------------------------------------
# Routes — Assessment Detail
# ---------------------------------------------------------------------------

@router.get("/assessments/{assessment_id}", response_class=HTMLResponse)
def assessment_detail(request: Request, assessment_id: int, db: Session = Depends(get_db)):
    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    summary = compliance_summary(assessment.items)
    items_sorted = sorted(
        assessment.items,
        key=lambda x: (
            {"NON_COMPLIANT": 0, "DEPRECATED": 1, "REDUCED_SECURITY": 2,
             "UNKNOWN": 3, "QUANTUM_SAFE": 4, "PQC_APPROVED": 5}.get(x.compliance_status, 3)
        ),
    )

    return templates.TemplateResponse(request, "hh/assessment.html", _ctx({
        "assessment": assessment,
        "items": items_sorted,
        "summary": summary,
    }))


# ---------------------------------------------------------------------------
# Routes — Migration Roadmap
# ---------------------------------------------------------------------------

@router.post("/assessments/{assessment_id}/roadmap")
def generate_roadmap(
    request: Request,
    assessment_id: int,
    db: Session = Depends(get_db),
):
    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    critical_algs = [
        f"{i.algorithm} ({i.component})"
        for i in assessment.items
        if i.quantum_vulnerability == "CRITICAL"
    ]
    non_compliant_algs = [
        f"{i.algorithm} ({i.component})"
        for i in assessment.items
        if i.compliance_status in ("NON_COMPLIANT", "DEPRECATED")
    ]
    reduced_algs = [
        f"{i.algorithm} ({i.component})"
        for i in assessment.items
        if i.compliance_status == "REDUCED_SECURITY"
    ]

    demo_key = _demo_key_for(assessment.org_name)

    try:
        roadmap = draft_migration_roadmap(
            org_name=assessment.org_name,
            hndl_tier=assessment.hndl_tier,
            hndl_score=assessment.hndl_score,
            critical_algorithms=critical_algs,
            non_compliant_algorithms=non_compliant_algs,
            reduced_algorithms=reduced_algs,
            data_sensitivity=assessment.data_sensitivity,
            data_retention_years=assessment.data_retention_years,
            demo_key=demo_key,
        )
    except RoadmapError as exc:
        assessment_obj = db.get(Assessment, assessment_id)
        summary = compliance_summary(assessment_obj.items)
        return templates.TemplateResponse(
            request, "hh/assessment.html",
            _ctx({
                "assessment": assessment_obj,
                "items": assessment_obj.items,
                "summary": summary,
                "error": str(exc),
            }),
            status_code=500,
        )

    assessment.roadmap_text = roadmap
    assessment.roadmap_generated_at = datetime.datetime.utcnow()
    assessment.status = "ROADMAP_READY"
    db.commit()
    return RedirectResponse(f"/hh/assessments/{assessment_id}/roadmap", status_code=303)


@router.get("/assessments/{assessment_id}/roadmap", response_class=HTMLResponse)
def view_roadmap(request: Request, assessment_id: int, db: Session = Depends(get_db)):
    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    if not assessment.roadmap_text:
        return RedirectResponse(f"/hh/assessments/{assessment_id}", status_code=303)
    return templates.TemplateResponse(request, "hh/roadmap.html", _ctx({"assessment": assessment}))


# ---------------------------------------------------------------------------
# Routes — PDF Export
# ---------------------------------------------------------------------------

@router.get("/assessments/{assessment_id}/report.pdf")
def download_pdf(assessment_id: int, db: Session = Depends(get_db)):
    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    try:
        pdf_bytes = generate_pdf(assessment)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}")
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="harvest_horizon_{assessment_id}.pdf"'},
    )


# ---------------------------------------------------------------------------
# Routes — Seed & Stats
# ---------------------------------------------------------------------------

@router.post("/seed")
def seed(db: Session = Depends(get_db)):
    seed_demo_data(db)
    first = db.query(Assessment).order_by(Assessment.id).first()
    if first:
        return RedirectResponse(f"/hh/assessments/{first.id}", status_code=303)
    return RedirectResponse("/hh/", status_code=303)


@router.get("/api/stats")
def stats(db: Session = Depends(get_db)):
    total = db.query(Assessment).count()
    items = db.query(CryptoItem).count()
    critical = db.query(CryptoItem).filter_by(quantum_vulnerability="CRITICAL").count()
    pqc = db.query(CryptoItem).filter_by(compliance_status="PQC_APPROVED").count()
    return {
        "status": "ok",
        "demo_mode": DEMO_MODE,
        "assessments": total,
        "crypto_items": items,
        "critical_vulnerabilities": critical,
        "pqc_approved": pqc,
    }
