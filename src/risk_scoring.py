"""
Composite Risk Scoring Engine.

Produces a weighted 0-100 score from multiple threat intelligence signals:
  - CVSS Base Score  (25%)
  - EPSS Probability (30%)
  - CISA KEV Status  (20%)
  - Vendor Advisory  (10%)
  - Threat Intel / OTX (15%)

The engine is stateless: pass in the raw signal values and get back a RiskScore.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .models import RiskScore, RiskScoreBreakdown

# ── Weight Configuration ──────────────────────────────────────────────────────

_W_CVSS = 25.0
_W_EPSS = 30.0
_W_KEV = 20.0
_W_VENDOR = 10.0
_W_THREAT = 15.0

_RATING_THRESHOLDS = [
    (90, "CRITICAL"),
    (70, "HIGH"),
    (40, "MEDIUM"),
    (20, "LOW"),
    (0, "INFO"),
]


def _rating_for(score: float) -> str:
    for threshold, label in _RATING_THRESHOLDS:
        if score >= threshold:
            return label
    return "INFO"


def _recommendation_for(rating: str, kev: bool) -> str:
    if rating == "CRITICAL":
        if kev:
            return "PATCH IMMEDIATELY — active in-the-wild exploitation confirmed by CISA"
        return "PATCH IMMEDIATELY — extremely high risk of exploitation"
    if rating == "HIGH":
        return "Patch within 7 days — high exploitation likelihood"
    if rating == "MEDIUM":
        return "Patch within 30 days — schedule in next maintenance window"
    if rating == "LOW":
        return "Patch within 90 days — low priority, monitor for changes"
    return "Informational — monitor only, no immediate action required"


# ── Public API ────────────────────────────────────────────────────────────────

def compute_risk_score(
    *,
    cvss_base: float | None = None,
    epss_score: float | None = None,
    in_kev: bool = False,
    kev_due_date: str | None = None,
    vendor_advisory_count: int = 0,
    newest_advisory_age_days: float | None = None,
    otx_pulse_count: int = 0,
) -> RiskScore:
    """
    Compute a composite risk score from multiple threat intelligence signals.

    Args:
        cvss_base: CVSS v3.x base score (0.0-10.0)
        epss_score: EPSS probability (0.0-1.0)
        in_kev: Whether the CVE is in CISA Known Exploited Vulnerabilities
        kev_due_date: KEV remediation due date (ISO string)
        vendor_advisory_count: Number of vendor advisories mentioning this CVE
        newest_advisory_age_days: Days since the most recent vendor advisory
        otx_pulse_count: Number of OTX threat pulses referencing this CVE/IOC
    """
    breakdown: list[RiskScoreBreakdown] = []
    total = 0.0

    # 1. CVSS component (0-25 points)
    if cvss_base is not None and cvss_base > 0:
        cvss_pts = (cvss_base / 10.0) * _W_CVSS
        severity = (
            "CRITICAL" if cvss_base >= 9.0
            else "HIGH" if cvss_base >= 7.0
            else "MEDIUM" if cvss_base >= 4.0
            else "LOW"
        )
        breakdown.append(RiskScoreBreakdown(
            component="CVSS Base Score",
            score=round(cvss_pts, 1),
            max_score=_W_CVSS,
            detail=f"{cvss_base}/10.0 ({severity})",
        ))
        total += cvss_pts
    else:
        breakdown.append(RiskScoreBreakdown(
            component="CVSS Base Score",
            score=0, max_score=_W_CVSS, detail="No CVSS data available",
        ))

    # 2. EPSS component (0-30 points)
    if epss_score is not None:
        epss_pts = epss_score * _W_EPSS
        pct = f"{epss_score * 100:.1f}%"
        breakdown.append(RiskScoreBreakdown(
            component="EPSS Exploitation Probability",
            score=round(epss_pts, 1),
            max_score=_W_EPSS,
            detail=f"{pct} probability of exploitation in next 30 days",
        ))
        total += epss_pts
    else:
        breakdown.append(RiskScoreBreakdown(
            component="EPSS Exploitation Probability",
            score=0, max_score=_W_EPSS, detail="No EPSS data available",
        ))

    # 3. KEV component (0-20 points) — binary but powerful
    if in_kev:
        due_detail = f", remediation due {kev_due_date}" if kev_due_date else ""
        breakdown.append(RiskScoreBreakdown(
            component="CISA KEV Active Exploitation",
            score=_W_KEV,
            max_score=_W_KEV,
            detail=f"Confirmed in-the-wild exploitation{due_detail}",
        ))
        total += _W_KEV
    else:
        breakdown.append(RiskScoreBreakdown(
            component="CISA KEV Active Exploitation",
            score=0, max_score=_W_KEV, detail="Not in CISA KEV catalog",
        ))

    # 4. Vendor Advisory component (0-10 points)
    if vendor_advisory_count > 0:
        freshness_factor = 1.0
        if newest_advisory_age_days is not None:
            if newest_advisory_age_days <= 7:
                freshness_factor = 1.0
            elif newest_advisory_age_days <= 30:
                freshness_factor = 0.7
            elif newest_advisory_age_days <= 90:
                freshness_factor = 0.4
            else:
                freshness_factor = 0.2
        count_factor = min(vendor_advisory_count / 3.0, 1.0)
        vendor_pts = count_factor * freshness_factor * _W_VENDOR
        age_str = f"{int(newest_advisory_age_days)}d ago" if newest_advisory_age_days is not None else "unknown age"
        breakdown.append(RiskScoreBreakdown(
            component="Vendor Advisory Urgency",
            score=round(vendor_pts, 1),
            max_score=_W_VENDOR,
            detail=f"{vendor_advisory_count} advisory(ies), newest {age_str}",
        ))
        total += vendor_pts
    else:
        breakdown.append(RiskScoreBreakdown(
            component="Vendor Advisory Urgency",
            score=0, max_score=_W_VENDOR, detail="No vendor advisories found",
        ))

    # 5. Threat Intel / OTX component (0-15 points)
    if otx_pulse_count > 0:
        # Logarithmic scaling: 1 pulse = ~30%, 10 = ~67%, 50+ = ~100%
        import math
        pulse_factor = min(math.log10(otx_pulse_count + 1) / math.log10(51), 1.0)
        threat_pts = pulse_factor * _W_THREAT
        breakdown.append(RiskScoreBreakdown(
            component="Threat Intelligence Interest",
            score=round(threat_pts, 1),
            max_score=_W_THREAT,
            detail=f"{otx_pulse_count} OTX threat pulse(s) referencing this indicator",
        ))
        total += threat_pts
    else:
        breakdown.append(RiskScoreBreakdown(
            component="Threat Intelligence Interest",
            score=0, max_score=_W_THREAT, detail="No OTX threat pulses found",
        ))

    total = round(min(total, 100.0), 1)
    rating = _rating_for(total)

    return RiskScore(
        total_score=total,
        max_score=100.0,
        rating=rating,
        breakdown=breakdown,
        recommendation=_recommendation_for(rating, in_kev),
    )
