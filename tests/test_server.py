import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from server import (
    check_smart_tacho_2_readiness, analyze_drivers_hours,
    summarize_infringements, calculate_ocrs_band, forecast_ocrs_90_day,
    generate_public_inquiry_brief, audit_weekly_downloads,
    check_dvs_pss_3_star, check_drivers_cpc_expiry, generate_dvsa_visit_pack,
    DRIVERS_HOURS_LIMITS, INFRINGEMENT_WEIGHTS,
)

def _call(t, **kw):
    fn = t.fn if hasattr(t, "fn") else t
    return fn(**kw)

def test_tacho2_lcv_intl_needs_retrofit():
    r = _call(check_smart_tacho_2_readiness, vehicles=[
        {"vrn": "AB12CDE", "type": "lcv_2_5_3_5t", "tacho_gen": "smart_g1", "international_use": True}
    ])
    assert r["needs_retrofit_count"] == 1
    assert "2026-07-01" in r["needs_retrofit"][0]["deadline"]

def test_tacho2_g2v2_safe():
    r = _call(check_smart_tacho_2_readiness, vehicles=[
        {"vrn": "X1", "type": "hgv_gt_3_5t", "tacho_gen": "smart_g2v2", "international_use": True}
    ])
    assert r["safe_for_now_count"] == 1

def test_hours_56h_weekly_breach():
    # 1×11h triggers exceeded_10h_extended; 6 days totalling 61h exceeds 56h weekly
    days = [{"date": "2026-06-02", "driving_hr": 11}]
    days += [{"date": f"2026-06-0{d+3}", "driving_hr": 10} for d in range(5)]
    r = _call(analyze_drivers_hours, driver_name="J", daily_segments=days)
    codes = [i["code"] for i in r["infringements"]]
    assert "exceeded_56h_weekly" in codes
    assert "exceeded_10h_extended" in codes

def test_hours_clean_week():
    r = _call(analyze_drivers_hours, driver_name="K",
              daily_segments=[{"date": "2026-06-02", "driving_hr": 8,
                               "longest_drive_min": 240, "break_min": 60, "daily_rest_hr": 11}])
    assert r["infringement_count"] == 0

def test_summarize_ranks_severity():
    r = _call(summarize_infringements, infringements=[
        {"code": "exceeded_56h_weekly"}, {"code": "exceeded_4h30_driving"},
        {"code": "exceeded_4h30_driving"}, {"code": "missing_card_data"},
    ])
    assert r["top_priority"] in ("exceeded_56h_weekly", "exceeded_4h30_driving")

def test_ocrs_green_band():
    r = _call(calculate_ocrs_band, points_last_3_years=1, fleet_size=10)
    assert r["band"] == "GREEN"

def test_ocrs_red_band():
    r = _call(calculate_ocrs_band, points_last_3_years=80, fleet_size=10)
    assert r["band"] == "RED"
    assert "PI referral" in r["next_step"]

def test_forecast_trajectory_red():
    r = _call(forecast_ocrs_90_day, current_points=50, recent_trend_points_per_week=5, fleet_size=10)
    assert r["forecast_90d_band"] == "RED"
    assert "RED" in r["alert"]

def test_pi_brief_contains_8_sections():
    r = _call(generate_public_inquiry_brief, operator_name="ACME",
              licence_number="OB1234567", triggers=["OCRS Red sustained > 6 months"],
              fleet_size=20, transport_manager_name="J Smith")
    assert len(r["brief_sections"]) == 8
    assert any("FINANCIAL" in s["section"].upper() for s in r["brief_sections"])

def test_weekly_downloads_overdue_flagged():
    r = _call(audit_weekly_downloads, drivers=[
        {"name": "A", "card_last_download": "2025-01-01", "vu_last_download": "2025-01-01"},
        {"name": "B", "card_last_download": "2026-06-01", "vu_last_download": "2026-05-15"},
    ])
    assert any("overdue" in str(f).lower() for f in r["overdue"])

def test_dvs_2_star_no_pss_pcn_risk():
    r = _call(check_dvs_pss_3_star, vrn="HG54XYZ", current_star_rating=2, pss_fitted=False)
    assert r["pcn_risk_550"] is True

def test_dvs_4_star_safe():
    r = _call(check_dvs_pss_3_star, vrn="MX72ABC", current_star_rating=4, pss_fitted=False)
    assert r["pcn_risk_550"] is False

def test_cpc_expiring_soon_alerts():
    from datetime import date, timedelta
    exp = (date.today() + timedelta(days=30)).isoformat()
    r = _call(check_drivers_cpc_expiry, driver_name="D", cpc_expiry_date=exp,
              hours_completed_5yr_cycle=10)
    assert r["hours_remaining"] == 25
    assert any("Expires" in a or "expir" in a.lower() for a in r["alerts"])

def test_cpc_expired_blocks():
    r = _call(check_drivers_cpc_expiry, driver_name="E", cpc_expiry_date="2020-01-01",
              hours_completed_5yr_cycle=35)
    assert any("EXPIRED" in a for a in r["alerts"])

def test_dvsa_visit_pack_has_evidence_list():
    r = _call(generate_dvsa_visit_pack, operator_name="ACME")
    assert len(r["evidence_checklist"]) >= 10
    assert any("PMI" in e for e in r["evidence_checklist"])

def test_attestation_chain():
    r = _call(calculate_ocrs_band, points_last_3_years=5, fleet_size=10)
    assert "sig" in r and "ts" in r and r["issuer"] == "meok-tacho-audit-mcp"

if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
