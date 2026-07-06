"""config.py — CVE Prioritizer configuration and scoring constants (Cleared Facility Suite)."""

from shared.demo_mode import is_demo_mode

DEMO_MODE = is_demo_mode()

# Data source URLs (live mode only)
KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# Priority scoring weights — all scoring constants live here
PRIORITY_KEV_BASE = 50           # Points for being in CISA KEV (active exploitation confirmed)
PRIORITY_EPSS_MULTIPLIER = 45    # EPSS score (0-1) × this = exploitation probability component (max 45)
PRIORITY_RANSOMWARE_BONUS = 5    # Additional points for known ransomware campaign use
PRIORITY_CRITICALITY_BONUS = {
    "CRITICAL": 5,
    "HIGH": 3,
    "MEDIUM": 1,
    "LOW": 0,
}

# Priority tier thresholds (score out of 100)
PRIORITY_TIER_CRITICAL = 75   # Patch within 24-48 hours
PRIORITY_TIER_HIGH = 50       # Patch within 7 days
PRIORITY_TIER_MEDIUM = 25     # Patch within 30 days
# Below MEDIUM = LOW: schedule at next maintenance window

# System types for new scan form
SYSTEM_TYPES = [
    "Federal Government IT System",
    "Defense Contractor Network",
    "Critical Infrastructure",
    "Healthcare Information System",
    "Financial Services Platform",
    "State/Local Government IT",
    "Commercial Enterprise System",
    "Industrial Control System (ICS/OT)",
    "Cloud/SaaS Platform",
    "Other",
]

# System criticality levels
CRITICALITY_OPTIONS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
