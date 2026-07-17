# Cleared Facility Suite

**Cleared Facility Suite brings together five compliance and security tools that a cleared defense facility needs, in one web app.** It covers the recurring paperwork and risk work of operating a cleared facility — system authorization, AI-ethics compliance, vulnerability triage, post-quantum crypto planning, and clearance-interview prep — behind a single landing page.

**Live demo:** https://cleared-facility-suite.onrender.com

The demo runs on seeded example data — no login or API key needed.

## The five tools

| Tool | What it does |
|---|---|
| **ATO Accelerator** (`/ato`) | Walks a system through Authority to Operate under NIST 800-53 — FIPS 199 categorization, control-baseline mapping, and drafted System Security Plan narratives |
| **RAI Compliance** (`/rai`) | Scores a system against the Department of Defense's Responsible AI principles on a 20-criteria checklist with drafted compliance narratives |
| **CVE Prioritizer** (`/cve`) | Triages a software inventory's vulnerabilities using CISA's Known Exploited Vulnerabilities catalog and EPSS exploit-probability scores, then drafts a patch brief |
| **Harvest Horizon** (`/hh`) | Assesses a cryptographic footprint for quantum vulnerability and computes "harvest-now-decrypt-later" exposure against the NIST FIPS 203/204/205 standards |
| **Clearance Advisor** (`/clearance`) | Explains the 13 security-clearance adjudicative guidelines and helps a candidate prepare for the clearance interview — explains the process, never predicts an outcome |

Each tool keeps its own data, prompts, and domain logic; only the infrastructure underneath (one web process, one database, a shared AI client) is common. There's no unified data model, because a system under review, a vulnerability scan, and a clearance session aren't the same kind of object.

## Design principles

- **The AI extracts and drafts; deterministic rules decide.** Claude reads and drafts narratives; the categorization, scoring, and compliance determinations come from auditable code citing a specific standard.
- **A human confirms, and outcomes are never predicted.** Clearance Advisor in particular explains what adjudicators evaluate; it never scores a person or predicts a determination.
- **Demo mode by default.** Every tool works with no API key against seeded example data.

## Running locally

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

Open http://localhost:8000. The database auto-seeds on startup. Set `ANTHROPIC_API_KEY` and turn off demo mode to enable live AI analysis.

## About

Cleared Facility Suite combines five independently-built tools — ATO Accelerator, RAI Compliance, CVE Prioritizer, Harvest Horizon, and Clearance Advisor — into one deployment. It is part of a portfolio of national-security and defense-compliance software and is a demonstration of an integrated compliance workflow rather than a certified product.
