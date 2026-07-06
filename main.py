"""main.py — Cleared Facility Suite (Phase 6, Cluster 3) merged FastAPI application.

Merges 5 tools into one process/DB, shared infrastructure only (no unifying entity):
ATO Accelerator (/ato), RAI Compliance Assistant (/rai), CVE Prioritizer (/cve),
Harvest Horizon (/hh), Security Clearance Readiness Advisor (/clearance).

sead3_auditor and stig_checker are deliberately NOT part of this process -- see README.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from database import get_db, init_db

import ato.router
import rai.router
import cve.router
import hh.router
import clearance.router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    db = next(get_db())
    try:
        ato.router.seed_demo_data(db)
        rai.router.seed_demo_data(db)
        cve.router.seed_demo_data(db)
        hh.router.seed_demo_data(db)
        clearance.router.seed_demo_data(db)
    finally:
        db.close()
    yield


app = FastAPI(title="Cleared Facility Suite", lifespan=lifespan)

app.mount("/static/ato", StaticFiles(directory="static/ato"), name="static-ato")
app.mount("/static/rai", StaticFiles(directory="static/rai"), name="static-rai")
app.mount("/static/cve", StaticFiles(directory="static/cve"), name="static-cve")
app.mount("/static/hh", StaticFiles(directory="static/hh"), name="static-hh")
app.mount("/static/clearance", StaticFiles(directory="static/clearance"), name="static-clearance")

templates = Jinja2Templates(directory="templates")

app.include_router(ato.router.router)
app.include_router(rai.router.router)
app.include_router(cve.router.router)
app.include_router(hh.router.router)
app.include_router(clearance.router.router)


@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    return templates.TemplateResponse(request, "landing.html", {})
