# Cleared Facility Suite (Phase 6, Cluster 3)

Merger of 7 of the 8 candidate source projects: ATO Accelerator, RAI
Compliance Assistant, CVE Prioritizer, Harvest Horizon, Clearance Readiness
Advisor, STIG Checker (Rust), Facility Risk Indicator.

**`sead3_auditor` is deliberately excluded from this cluster entirely** --
it exports raw, unmasked SSNs/DOB/passport numbers and, like its 7 siblings
here, has zero authentication on any route. Colocating that in a shared
process/database with unauthenticated institutional-risk tools would widen
the exposed-PII blast radius for no benefit. It stays fully standalone,
untouched, revisited only if real authentication is ever added
portfolio-wide.

**`stig_checker` (Rust) also stays fully standalone** -- confirmed
technical fact, not a preference: it's a synchronous CLI binary with zero
web/async/FFI/Python-interop code anywhere in its source or its 43-package
dependency tree. No existing cross-project bridge in this portfolio
handles compiled-Rust-to-Python (the Python-to-Python `sys.path` tricks
used elsewhere don't apply, and no FFI/subprocess shim exists or is being
built for this). It's linked from wherever this cluster's landing page
ends up, not merged.

That leaves the same two-part shape as Analyst's Desk (Phase 6, Cluster 2):

1. **`shared/`** -- a small, vendored (not pip-installed) reference
   library, copied out into each consuming repo the same way
   `entity_resolver.py` and Analyst's Desk's `claude_client.py` have
   already been.
2. **A web merge** (coming next) of `ato_accelerator`, `rai_compliance`,
   `cve_prioritizer`, `harvest_horizon`, and `clearance_advisor` into one
   deployment -- shared infrastructure, not shared data. None of these
   five share a real entity (a `System` in ATO isn't the same kind of
   object as a `Scan` in CVE Prioritizer, even sharing a naming
   convention), so there's no unifying entity-centric home page here
   either.

`facility_risk_indicator` stays a CLI tool -- it has no persistence and no
web layer to merge; it only receives `shared/claude_client.py` in Step 3.

## `shared/` contents

- **`claude_client.py`** -- one `call_claude()` wrapper pinning
  `claude-haiku-4-5-20251001` and enforcing the broad-`except Exception`
  pattern by construction. Built because two real bugs were found and
  fixed in this cluster's own source projects first (see their commit
  history): `ato_accelerator`'s `categorize_system()` had an unreachable
  `except json.JSONDecodeError` clause placed after a catch-all
  `except Exception`, and `clearance_advisor`'s `claude_advisor.py` had no
  exception handling at all around either Claude call site.
- **`demo_mode.py`** -- one `is_demo_mode()` env-var convention. The 7
  in-scope sources used three different conventions (hardcoded `True` with
  no env read at all, a strict `== "True"` string-equality read, and a
  permissive `.lower() in (...)` read) -- this doesn't force every tool
  onto the same UX, it just stops the strict-vs-permissive drift.

## Status

Step 1 (shared-core reference library) complete: 21 tests passing, all
mocked -- no real network/API calls. Step 2 (the 5-app web merge) and
Step 3 (distributing `claude_client.py` to `facility_risk_indicator`)
haven't started yet.
