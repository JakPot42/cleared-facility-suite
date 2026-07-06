"""
Canonical DEMO_MODE boolean-parsing convention for the Cleared Facility Suite
cluster (Phase 6, Cluster 3).

The 7 in-scope source projects (sead3_auditor excluded per the merge
decision; stig_checker is Rust and has no DEMO_MODE concept) used three
different conventions: hardcoded `True` with no env read at all
(ato_accelerator, rai_compliance -- DEMO_MODE only gates UI banner text,
never branches on it); a strict string-equality env read,
`os.getenv("DEMO_MODE", "True") == "True"` (cve_prioritizer,
clearance_advisor, facility_risk_indicator); and a permissive
`.lower() in ("1", "true", "yes")` read (harvest_horizon). The strict form
silently treats "TRUE", "1", or "yes" as falsy -- a real drift point, same
class of inconsistency the two prior Phase 6 clusters both found in their
own source projects.

is_demo_mode() does not force every tool onto the same UX -- it only
centralizes the parsing convention (permissive, env var, default True) so
the strict-vs-permissive drift stops here.
"""
import os


def is_demo_mode(default: bool = True) -> bool:
    """Read DEMO_MODE from the environment, defaulting to `default` if unset."""
    return os.getenv("DEMO_MODE", str(default)).lower() in ("1", "true", "yes")
