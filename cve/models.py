"""models.py — SQLAlchemy models for Scan and VulnItem (Cleared Facility Suite)."""

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from database import Base


class Scan(Base):
    __tablename__ = "cve_scans"

    id = Column(Integer, primary_key=True, index=True)
    system_name = Column(String, nullable=False)
    system_type = Column(String, nullable=False)
    system_criticality = Column(String, nullable=False)
    system_description = Column(Text)
    inventory_text = Column(Text)
    extracted_items_json = Column(Text)  # JSON array proposed by Claude, shown for confirmation
    # Status: DRAFT -> EXTRACTED -> CONFIRMED -> ASSESSED -> BRIEF_READY
    status = Column(String, default="DRAFT")
    patch_brief_text = Column(Text)
    brief_generated_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)

    items = relationship("VulnItem", back_populates="scan", cascade="all, delete-orphan",
                         order_by="VulnItem.priority_score.desc()")

    @property
    def critical_count(self):
        return sum(1 for i in self.items if i.priority_tier == "CRITICAL")

    @property
    def high_count(self):
        return sum(1 for i in self.items if i.priority_tier == "HIGH")

    @property
    def medium_count(self):
        return sum(1 for i in self.items if i.priority_tier == "MEDIUM")

    @property
    def low_count(self):
        return sum(1 for i in self.items if i.priority_tier == "LOW")

    @property
    def total_count(self):
        return len(self.items)

    @property
    def kev_count(self):
        return sum(1 for i in self.items if i.in_kev)

    @property
    def criticality_color(self):
        return {
            "CRITICAL": "red",
            "HIGH": "amber",
            "MEDIUM": "blue",
            "LOW": "green",
        }.get(self.system_criticality, "gray")

    @property
    def overall_risk_tier(self):
        if self.critical_count > 0:
            return "CRITICAL"
        if self.high_count > 0:
            return "HIGH"
        if self.medium_count > 0:
            return "MEDIUM"
        return "LOW"


class VulnItem(Base):
    __tablename__ = "cve_vuln_items"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("cve_scans.id"), nullable=False)
    component = Column(String)
    cve_id = Column(String, nullable=False)
    cve_description = Column(Text)

    # CISA KEV fields
    in_kev = Column(Boolean, default=False)
    kev_vendor_project = Column(String)
    kev_product = Column(String)
    kev_vulnerability_name = Column(String)
    kev_date_added = Column(String)
    kev_ransomware_use = Column(Boolean, default=False)
    kev_required_action = Column(Text)
    kev_due_date = Column(String)
    kev_short_description = Column(Text)

    # FIRST.org EPSS fields
    epss_score = Column(Float, default=0.0)
    epss_percentile = Column(Float, default=0.0)

    # Deterministic priority output
    priority_score = Column(Integer, default=0)
    priority_tier = Column(String, default="LOW")
    engine_rationale = Column(Text)

    scan = relationship("Scan", back_populates="items")

    @property
    def tier_color(self):
        return {
            "CRITICAL": "red",
            "HIGH": "amber",
            "MEDIUM": "blue",
            "LOW": "green",
        }.get(self.priority_tier, "gray")

    @property
    def kev_badge(self):
        return "KEV" if self.in_kev else "—"

    @property
    def epss_pct(self):
        return round(self.epss_score * 100, 1)

    @property
    def epss_percentile_pct(self):
        return round(self.epss_percentile * 100, 1)
