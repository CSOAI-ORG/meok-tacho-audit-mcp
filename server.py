#!/usr/bin/env python3
"""
MEOK Tachograph Audit + OCRS Prevention MCP
==============================================

By MEOK AI Labs · https://haulage.app · MIT
<!-- mcp-name: io.github.CSOAI-ORG/meok-tacho-audit-mcp -->

WHAT THIS DOES
--------------
UK haulage's single biggest £ exposure: **DVSA OCRS Red**.

OCRS (Operator Compliance Risk Score) is DVSA's rolling risk rating. Once an
operator goes Red:
  - Insurance premiums jump 30-200%
  - DVSA roadside check frequency triples
  - Customer FORS Bronze/Silver/Gold gates close
  - Public Inquiry (PI) referral becomes likely
  - Disqualification of the named Transport Manager + revocation of O-licence

This MCP gives Compliance Managers, named TMs, and owner-operators the
callable toolkit to PREVENT OCRS Red by automating the daily compliance work:

  - Smart Tachograph 2 (G2V2) readiness — July 2026 retrofit cliff for 2.5-3.5t
    vans on international journeys
  - EU 561/2006 retained drivers' hours analysis
  - Infringement triage with severity score
  - OCRS forecasting (will we hit amber/red in next 90 days?)
  - Public Inquiry brief generator (the existential threat)
  - DVS PSS 3-star check (London since Oct 2024)
  - CPC 35-hours-per-5-years expiry tracker

TOOLS (10)
----------
- check_smart_tacho_2_readiness(fleet)        → July 2026 cliff readiness
- analyze_drivers_hours(daily_segments)        → 561/2006 + GB Domestic compliance
- summarize_infringements(period_data)         → severity-ranked triage
- calculate_ocrs_band(operator)                → current Green/Amber/Red
- forecast_ocrs_90_day(operator)               → trajectory + risk factors
- generate_public_inquiry_brief(operator)      → PI defence pack
- audit_weekly_downloads(week)                 → driver card + VU cadence
- check_dvs_pss_3_star(vrn)                    → London Direct Vision Standard
- check_drivers_cpc_expiry(driver)             → 35h/5yr renewal alert
- generate_dvsa_visit_pack(operator)           → 24h-before-visit evidence

WHY YOU PAY
-----------
One avoided OCRS Red = £20k-£100k saved (insurance + fines + PI cost).
£29/mo Starter is a rounding error vs the existential risk.

PRICING
-------
Free MIT self-host · £29/mo Starter · £79/mo Pro · £499/mo Fleet · £1,499/mo ER.

REGULATORY BASIS
----------------
EU Regulation 561/2006 — Drivers' Hours (retained in UK law post-Brexit)
EU Regulation 165/2014 — Tachograph (Smart Tacho 2 from Aug 2023, G2V2 from 2024)
GB Domestic Drivers' Hours Rules (DVSA HoR1)
Goods Vehicles (Licensing of Operators) Act 1995
Senior Traffic Commissioner's Statutory Guidance — Public Inquiries
DVSA Operator Compliance Risk Score (OCRS) Guide
Direct Vision Standard (London) Permit Scheme — Oct 2024+ (3-star+)
DCPC (Drivers' Certificate of Professional Competence) Regulations
"""

from __future__ import annotations
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone, date, timedelta
from typing import Optional
from mcp.server.fastmcp import FastMCP


mcp = FastMCP("meok-tacho-audit")
_HMAC_SECRET = os.environ.get("MEOK_HMAC_SECRET", "")


# ──────────────────────────────────────────────────────────────────────
# Regulatory tables
# ──────────────────────────────────────────────────────────────────────

# EU 561/2006 limits (retained UK law)
DRIVERS_HOURS_LIMITS = {
    "max_continuous_driving_min": 270,    # 4h30m before mandatory break
    "min_break_min": 45,                  # 45 min (split: 15+30 ok)
    "max_daily_driving_hr": 9,            # 9h normal (10h x2/wk)
    "max_daily_driving_hr_extended": 10,  # max 2x per week
    "max_weekly_driving_hr": 56,
    "max_fortnightly_driving_hr": 90,
    "min_daily_rest_hr": 11,              # reducible to 9h x3/wk
    "min_weekly_rest_hr": 45,             # reducible to 24h with compensation
}

# OCRS bands (DVSA OCRS Guide)
OCRS_BANDS = {
    "green": "0-3 points / score < 25%",
    "amber": "4-9 points / 25% ≤ score < 75%",
    "red": "10+ points / score ≥ 75%",
}

# Infringement severity weights (rough DVSA OCRS approximation)
INFRINGEMENT_WEIGHTS = {
    "exceeded_4h30_driving": 4,
    "insufficient_45min_break": 3,
    "exceeded_9h_daily": 3,
    "exceeded_10h_extended": 5,
    "exceeded_56h_weekly": 6,
    "exceeded_90h_fortnightly": 8,
    "insufficient_11h_daily_rest": 4,
    "insufficient_45h_weekly_rest": 5,
    "missing_card_data": 2,
    "manual_entry_anomaly": 1,
    "tampering_suspected": 10,
}

# Smart Tachograph 2 (G2V2) readiness — Reg 165/2014 + UK divergence
SMART_TACHO_2_DEADLINES = {
    "trucks_eu_intl_aug_2025": "All HGV >3.5t on international jobs: G2V2 retrofit by 19 Aug 2025",
    "vans_2.5_3.5t_intl_jul_2026": "2.5-3.5t LCVs on international: G2V2 fit-from-new by 1 July 2026",
    "domestic_uk_only": "UK-only domestic: no mandatory retrofit yet (watch DfT consultation)",
}

# DVS PSS — Direct Vision Standard Progressive Safe System
DVS_PSS_LEVELS = {
    "non_compliant_pre_oct_2024": "0-stars without PSS — PCN £550 from Oct 2024",
    "compliant_3star_plus": "3+ stars OR PSS-fitted = ok",
    "5_star_no_pss_required": "Inherently safe — no PSS retrofit",
}

# Public Inquiry trigger reasons (Senior Traffic Commissioner guidance)
PI_TRIGGER_REASONS = [
    "OCRS Red sustained > 6 months",
    "Multiple roadside prohibitions in 12 months",
    "Maintenance investigation finding",
    "Driver-hours systematic non-compliance",
    "Loss of financial standing",
    "Loss of repute of operator/TM",
    "Failure to notify changes within 28 days",
    "DVSA referral for criminal/civil matters",
]


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def _sign(payload: dict) -> str:
    if not _HMAC_SECRET:
        return "unsigned-no-key-configured"
    return hmac.new(
        _HMAC_SECRET.encode(),
        json.dumps(payload, sort_keys=True, default=str).encode(),
        hashlib.sha256,
    ).hexdigest()


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _attestation(payload: dict) -> dict:
    return {**payload, "ts": _ts(), "sig": _sign(payload),
            "issuer": "meok-tacho-audit-mcp", "version": "1.0.0"}


# ──────────────────────────────────────────────────────────────────────
# Tools
# ──────────────────────────────────────────────────────────────────────

@mcp.tool()
def check_smart_tacho_2_readiness(
    vehicles: Optional[list] = None,
) -> dict:
    """Check fleet readiness for Smart Tachograph 2 (G2V2) retrofit deadlines.

    Args:
      vehicles: list of dicts like
        {"vrn": "AB12CDE", "type": "hgv_gt_3_5t", "tacho_gen": "g1",
         "international_use": True}

    type: 'hgv_gt_3_5t' / 'lcv_2_5_3_5t' / 'lcv_lt_2_5t' / 'specialist'
    tacho_gen: 'analogue' / 'digital_g1' / 'smart_g1' / 'smart_g2' / 'smart_g2v2'
    """
    vehicles = vehicles or []
    needs_retrofit = []
    safe_for_now = []
    today = date.today()

    deadline_intl_hgv = date(2025, 8, 19)
    deadline_intl_lcv = date(2026, 7, 1)

    for v in vehicles:
        vrn = v.get("vrn", "")
        vtype = v.get("type", "hgv_gt_3_5t")
        gen = v.get("tacho_gen", "digital_g1")
        intl = v.get("international_use", False)

        if gen == "smart_g2v2":
            safe_for_now.append(vrn); continue

        if vtype == "hgv_gt_3_5t" and intl:
            deadline = deadline_intl_hgv
            why = "EU 165/2014 — HGV intl needs G2V2"
        elif vtype == "lcv_2_5_3_5t" and intl:
            deadline = deadline_intl_lcv
            why = "EU 165/2014 — 2.5-3.5t LCV intl needs G2V2 from 1 Jul 2026"
        else:
            safe_for_now.append(vrn); continue

        days_left = (deadline - today).days
        needs_retrofit.append({
            "vrn": vrn,
            "current_gen": gen,
            "deadline": deadline.isoformat(),
            "days_remaining": days_left,
            "reason": why,
            "overdue": days_left < 0,
        })

    payload = {
        "tool": "check_smart_tacho_2_readiness",
        "fleet_size": len(vehicles),
        "needs_retrofit_count": len(needs_retrofit),
        "needs_retrofit": needs_retrofit,
        "safe_for_now_count": len(safe_for_now),
        "deadlines_reference": SMART_TACHO_2_DEADLINES,
    }
    return _attestation(payload)


@mcp.tool()
def analyze_drivers_hours(
    driver_name: str = "",
    daily_segments: Optional[list] = None,
    week_starting: str = "",
) -> dict:
    """Analyse a driver's week against EU 561/2006 retained.

    Args:
      daily_segments: list of dicts per day, like
        {"date": "2026-06-02", "driving_hr": 9.5, "longest_drive_min": 280,
         "break_min": 45, "daily_rest_hr": 10}
    """
    daily_segments = daily_segments or []
    infringements = []

    weekly_drive = sum(d.get("driving_hr", 0) for d in daily_segments)
    if weekly_drive > DRIVERS_HOURS_LIMITS["max_weekly_driving_hr"]:
        infringements.append({
            "code": "exceeded_56h_weekly",
            "actual_hr": round(weekly_drive, 2),
            "limit_hr": DRIVERS_HOURS_LIMITS["max_weekly_driving_hr"],
            "severity": INFRINGEMENT_WEIGHTS["exceeded_56h_weekly"],
        })

    extended_days = 0
    for d in daily_segments:
        dr = d.get("driving_hr", 0)
        if dr > DRIVERS_HOURS_LIMITS["max_daily_driving_hr_extended"]:
            infringements.append({
                "code": "exceeded_10h_extended", "date": d.get("date"),
                "actual_hr": dr, "severity": INFRINGEMENT_WEIGHTS["exceeded_10h_extended"],
            })
        elif dr > DRIVERS_HOURS_LIMITS["max_daily_driving_hr"]:
            extended_days += 1
            if extended_days > 2:
                infringements.append({
                    "code": "exceeded_9h_daily", "date": d.get("date"),
                    "actual_hr": dr, "severity": INFRINGEMENT_WEIGHTS["exceeded_9h_daily"],
                })
        if d.get("longest_drive_min", 0) > DRIVERS_HOURS_LIMITS["max_continuous_driving_min"]:
            infringements.append({
                "code": "exceeded_4h30_driving", "date": d.get("date"),
                "actual_min": d["longest_drive_min"],
                "severity": INFRINGEMENT_WEIGHTS["exceeded_4h30_driving"],
            })
        if d.get("break_min", 0) < DRIVERS_HOURS_LIMITS["min_break_min"]:
            infringements.append({
                "code": "insufficient_45min_break", "date": d.get("date"),
                "actual_min": d.get("break_min", 0),
                "severity": INFRINGEMENT_WEIGHTS["insufficient_45min_break"],
            })
        if d.get("daily_rest_hr", 24) < DRIVERS_HOURS_LIMITS["min_daily_rest_hr"]:
            infringements.append({
                "code": "insufficient_11h_daily_rest", "date": d.get("date"),
                "actual_hr": d.get("daily_rest_hr"),
                "severity": INFRINGEMENT_WEIGHTS["insufficient_11h_daily_rest"],
            })

    payload = {
        "tool": "analyze_drivers_hours",
        "driver_name": driver_name,
        "week_starting": week_starting,
        "weekly_driving_hr": round(weekly_drive, 2),
        "infringement_count": len(infringements),
        "infringements": infringements,
        "severity_total": sum(i.get("severity", 0) for i in infringements),
    }
    return _attestation(payload)


@mcp.tool()
def summarize_infringements(
    infringements: Optional[list] = None,
    period_label: str = "last_28_days",
) -> dict:
    """Triage and rank infringements by OCRS severity contribution."""
    infringements = infringements or []
    by_code = {}
    for i in infringements:
        c = i.get("code", "unknown")
        by_code.setdefault(c, {"count": 0, "severity_sum": 0})
        by_code[c]["count"] += 1
        by_code[c]["severity_sum"] += INFRINGEMENT_WEIGHTS.get(c, 1)

    ranked = sorted(by_code.items(), key=lambda kv: kv[1]["severity_sum"], reverse=True)

    return _attestation({
        "tool": "summarize_infringements",
        "period": period_label,
        "total": len(infringements),
        "by_code_ranked": [{"code": c, **stats} for c, stats in ranked],
        "top_priority": ranked[0][0] if ranked else None,
    })


@mcp.tool()
def calculate_ocrs_band(
    points_last_3_years: int = 0,
    fleet_size: int = 1,
) -> dict:
    """Compute current OCRS band from accumulated DVSA points.

    DVSA OCRS = rolling 3-year window. Points from roadside checks, PG9
    prohibitions, MoT failures, traffic offences, etc.
    """
    if fleet_size < 1: fleet_size = 1
    score_pct = min(100.0, points_last_3_years / fleet_size * 10.0)

    if score_pct < 25:
        band = "GREEN"
    elif score_pct < 75:
        band = "AMBER"
    else:
        band = "RED"

    return _attestation({
        "tool": "calculate_ocrs_band",
        "points_last_3_years": points_last_3_years,
        "fleet_size": fleet_size,
        "score_pct": round(score_pct, 1),
        "band": band,
        "band_meaning": OCRS_BANDS[band.lower()],
        "next_step": (
            "Schedule internal audit." if band == "GREEN" else
            "Generate corrective-action plan; review weekly." if band == "AMBER" else
            "URGENT: brief Transport Manager; prepare for PI referral; consider voluntary improvement notice."
        ),
    })


@mcp.tool()
def forecast_ocrs_90_day(
    current_points: int = 0,
    recent_trend_points_per_week: float = 0.0,
    fleet_size: int = 1,
) -> dict:
    """Forecast where OCRS will be in 90 days based on current trajectory."""
    future_points = current_points + recent_trend_points_per_week * 13  # ~13 wks
    future_score = min(100.0, future_points / max(1, fleet_size) * 10.0)

    if future_score < 25: future_band = "GREEN"
    elif future_score < 75: future_band = "AMBER"
    else: future_band = "RED"

    weeks_to_red = None
    if recent_trend_points_per_week > 0:
        points_to_red = max(0, (75 * fleet_size / 10.0) - current_points)
        if points_to_red > 0:
            weeks_to_red = round(points_to_red / recent_trend_points_per_week, 1)

    return _attestation({
        "tool": "forecast_ocrs_90_day",
        "current_points": current_points,
        "current_score_pct": round(current_points / max(1, fleet_size) * 10.0, 1),
        "trend_per_week": recent_trend_points_per_week,
        "forecast_90d_score_pct": round(future_score, 1),
        "forecast_90d_band": future_band,
        "weeks_to_red_estimate": weeks_to_red,
        "alert": (
            "TRAJECTORY → RED — escalate to TM + book DVSA Earned Recognition review."
            if future_band == "RED" else "Trajectory contained."
        ),
    })


@mcp.tool()
def generate_public_inquiry_brief(
    operator_name: str,
    licence_number: str = "",
    triggers: Optional[list] = None,
    fleet_size: int = 0,
    transport_manager_name: str = "",
) -> dict:
    """Produce a Public Inquiry defence brief skeleton.

    Args:
      triggers: list of strings from PI_TRIGGER_REASONS
    """
    triggers = triggers or []
    return _attestation({
        "tool": "generate_public_inquiry_brief",
        "operator_name": operator_name,
        "licence_number": licence_number,
        "fleet_size": fleet_size,
        "transport_manager": transport_manager_name,
        "triggers_identified": triggers,
        "brief_sections": [
            {"section": "I. Operator's history + good repute"},
            {"section": "II. Specific triggers + root-cause analysis"},
            {"section": "III. Corrective action plan with evidence (OCRS, audits, training)"},
            {"section": "IV. Transport Manager statement of repute + CPD"},
            {"section": "V. Financial standing evidence (3 months bank statements / standing)"},
            {"section": "VI. Vehicle maintenance evidence (PMI sheets, brake-tests, MoT)"},
            {"section": "VII. Driver-management evidence (CPC, infringement letters, training records)"},
            {"section": "VIII. Proposed undertakings"},
        ],
        "estimated_pi_cost_legal": "£8,000-£25,000 typical solicitor + advocate",
        "estimated_pi_cost_business": "Insurance jump £20k-£100k/yr; lost contracts; potential disqualification",
        "next_action": "Engage Transport-licensing solicitor (Backhouse Jones, Aaron & Partners, JMW). Brief within 14 days.",
    })


@mcp.tool()
def audit_weekly_downloads(
    drivers: Optional[list] = None,
) -> dict:
    """Verify the EU/UK card-download cadence: 28 days for driver card, 90 days
    for vehicle unit.

    Args:
      drivers: list of dicts {"name": "...", "card_last_download": "YYYY-MM-DD",
                              "vu_last_download": "YYYY-MM-DD"}
    """
    drivers = drivers or []
    today = date.today()
    overdue = []
    ok = []
    for d in drivers:
        name = d.get("name", "")
        try:
            card_age = (today - date.fromisoformat(d.get("card_last_download", "2000-01-01"))).days
        except Exception:
            card_age = 9999
        try:
            vu_age = (today - date.fromisoformat(d.get("vu_last_download", "2000-01-01"))).days
        except Exception:
            vu_age = 9999

        flags = []
        if card_age > 28: flags.append(f"driver-card overdue ({card_age}d > 28d)")
        if vu_age > 90: flags.append(f"VU overdue ({vu_age}d > 90d)")
        (overdue if flags else ok).append({"name": name, "card_age_d": card_age,
                                            "vu_age_d": vu_age, "flags": flags})

    return _attestation({
        "tool": "audit_weekly_downloads",
        "drivers_evaluated": len(drivers),
        "overdue": overdue,
        "ok_count": len(ok),
        "advisory": (f"{len(overdue)} drivers overdue — process this week to avoid OCRS hit."
                     if overdue else "All cadence checks pass."),
    })


@mcp.tool()
def check_dvs_pss_3_star(
    vrn: str,
    current_star_rating: int = 0,
    pss_fitted: bool = False,
) -> dict:
    """London Direct Vision Standard PSS check (Oct 2024+).

    Below 3-star without Progressive Safe System (PSS) = £550 PCN per zone entry.
    """
    if current_star_rating >= 3:
        status = "COMPLIANT_3_STAR_PLUS"; pcn_risk = False
    elif pss_fitted:
        status = "COMPLIANT_PSS_FITTED"; pcn_risk = False
    else:
        status = "NON_COMPLIANT"; pcn_risk = True

    return _attestation({
        "tool": "check_dvs_pss_3_star",
        "vrn": vrn,
        "current_star_rating": current_star_rating,
        "pss_fitted": pss_fitted,
        "status": status,
        "pcn_risk_550": pcn_risk,
        "advisory": (
            f"FIT PSS or upgrade vehicle. £550 PCN per zone entry to Greater London."
            if pcn_risk else "OK — meets Oct 2024+ DVS PSS standard."
        ),
    })


@mcp.tool()
def check_drivers_cpc_expiry(
    driver_name: str,
    cpc_expiry_date: str,
    hours_completed_5yr_cycle: float = 0.0,
) -> dict:
    """Driver CPC = 35 hours JAUPT-approved training every 5 years."""
    try:
        exp = date.fromisoformat(cpc_expiry_date)
        days_left = (exp - date.today()).days
    except Exception:
        days_left = -1
    hours_remaining = max(0.0, 35.0 - hours_completed_5yr_cycle)

    alerts = []
    if days_left < 0:
        alerts.append("EXPIRED — driver cannot drive vocational HGV/PSV until renewed (£50 fine + can't drive)")
    elif days_left < 90:
        alerts.append(f"Expires {days_left} days — book remaining {hours_remaining}h JAUPT now")
    if hours_remaining > 14 and days_left < 365:
        alerts.append(f"{hours_remaining}h still to do in last year of cycle — risk of expiry")

    return _attestation({
        "tool": "check_drivers_cpc_expiry",
        "driver_name": driver_name,
        "cpc_expiry": cpc_expiry_date,
        "days_to_expiry": days_left,
        "hours_completed_in_cycle": hours_completed_5yr_cycle,
        "hours_remaining": hours_remaining,
        "alerts": alerts,
    })


@mcp.tool()
def generate_dvsa_visit_pack(
    operator_name: str,
    expected_visit_date: str = "",
) -> dict:
    """Produce the evidence checklist for a DVSA on-site visit (24h prep)."""
    return _attestation({
        "tool": "generate_dvsa_visit_pack",
        "operator_name": operator_name,
        "expected_visit_date": expected_visit_date,
        "evidence_checklist": [
            "O-licence original + copies",
            "Vehicle list cross-referenced to VOL DB",
            "Vehicle maintenance: PMI sheets 6 weeks back, brake-test reports",
            "Tachograph records last 12 months (driver card + VU)",
            "Drivers' CPC certificates + JAUPT records",
            "Driver licences (entitlement check)",
            "Vehicle MOT/AS history",
            "Roadworthiness audit",
            "Forward-planner for PMIs (PMI gaps = killer finding)",
            "Drivers' defect report system + actioned defects",
            "TM contract + hours-of-work record",
            "Earned Recognition data feed (if applicable)",
            "FORS Bronze/Silver/Gold cert (if applicable)",
            "Insurance certificates",
            "Financial standing evidence (£8,400 first vehicle + £4,600 each additional)",
        ],
        "common_findings_to_pre_check": [
            "Missing PMI within 6-week window",
            "Brake test < 65% efficiency",
            "Driver hours infringements not actioned",
            "TM not exercising effective + continuous control",
            "Drivers' defect reports not actioned same-day",
            "Vehicle list / VOL discrepancy",
        ],
    })


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()


# ── MEOK monetization layer (Stripe upgrade · PAYG · pricing) ──────────
# Free tier is zero-config. Upgrade to Pro (unlimited) or pay-as-you-go per call.
import os as _meok_os
MEOK_STRIPE_UPGRADE = "https://buy.stripe.com/5kQ6oJ0xS3ce8sl7ew8k91j"  # Pro (unlimited)
MEOK_PAYG_KEY = _meok_os.environ.get("MEOK_PAYG_KEY", "")  # set to enable PAYG (x402 / ~GBP0.05 per call)
MEOK_PRICING = "https://meok.ai/pricing"


def meok_upsell(tier: str = "free") -> dict:
    """Monetization options for free-tier callers: Pro upgrade, PAYG, or pricing page."""
    if tier != "free":
        return {}
    return {"upgrade_url": MEOK_STRIPE_UPGRADE,
            "payg_enabled": bool(MEOK_PAYG_KEY),
            "pricing": MEOK_PRICING}
