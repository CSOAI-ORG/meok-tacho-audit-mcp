<!-- mcp-name: io.github.CSOAI-ORG/meok-tacho-audit-mcp -->
[![MCP Scorecard: 84/100](https://img.shields.io/badge/proofof.ai-84%2F100-5b21b6)](https://proofof.ai/scorecard/meok-tacho-audit-mcp.html)

# meok-tacho-audit-mcp

> UK haulage tachograph audit + drivers' hours + DVSA OCRS Red prevention. Smart Tachograph 2 (July 2026 cliff), EU 561/2006 retained, Public Inquiry brief generator. By **MEOK AI Labs**.

## Why this exists

UK haulage's single biggest £ exposure is **DVSA OCRS Red**. Once an operator goes Red:
- Insurance premiums jump 30-200%
- DVSA roadside check frequency triples
- Customer FORS Bronze/Silver/Gold gates close
- **Public Inquiry** (PI) referral becomes likely → potential O-licence revocation
- Named Transport Manager can be personally disqualified

This MCP gives Compliance Managers, named TMs, and owner-operators the callable toolkit to **prevent** OCRS Red.

## Install

```bash
pip install meok-tacho-audit-mcp
```

## Claude Desktop config

```json
{
  "mcpServers": {
    "tacho-audit": {
      "command": "meok-tacho-audit-mcp"
    }
  }
}
```

## Tools (10)

| Tool | Use case |
|------|----------|
| `check_smart_tacho_2_readiness` | Are your 2.5-3.5t vans G2V2-ready for **1 July 2026**? |
| `analyze_drivers_hours` | Weekly EU 561/2006 audit — 4h30 / 9h / 56h / 90h tests |
| `summarize_infringements` | Triage by severity → fix the worst this week |
| `calculate_ocrs_band` | Current Green/Amber/Red from DVSA points |
| `forecast_ocrs_90_day` | Where will you be in 90 days? Will you go Red? |
| `generate_public_inquiry_brief` | PI defence brief skeleton (8 sections) |
| `audit_weekly_downloads` | 28-day driver card + 90-day VU cadence |
| `check_dvs_pss_3_star` | London Direct Vision Standard — £550 PCN risk |
| `check_drivers_cpc_expiry` | 35h/5yr cycle tracking |
| `generate_dvsa_visit_pack` | 24h-before-visit evidence checklist |

## Pricing

- **Free** — MIT self-host
- **Starter** — £29/mo
- **Pro** — £79/mo (multi-driver)
- **Fleet** — £499/mo (50+ trucks, audit-export)
- **Earned Recognition** — £1,499/mo (DVSA ER data feed + SLA)

[Subscribe Pro → £79/mo](https://buy.stripe.com/5kQ6oJ0xS3ce8sl7ew8k91j)

## Regulatory basis

- EU Regulation 561/2006 — Drivers' Hours (retained UK law)
- EU Regulation 165/2014 — Tachograph + Smart Tacho 2 (G2V2)
- GB Domestic Drivers' Hours Rules (DVSA HoR1)
- Goods Vehicles (Licensing of Operators) Act 1995
- Senior Traffic Commissioner's Statutory Guidance — Public Inquiries
- DVSA OCRS Guide
- Direct Vision Standard (London) Permit Scheme — Oct 2024+
- DCPC Regulations

## Sign your responses

```bash
export MEOK_HMAC_SECRET="your-secret"
meok-tacho-audit-mcp
```

## License

MIT © 2026 Nicholas Templeman / MEOK AI Labs · [haulage.app](https://haulage.app)


<!-- GEO-FOOTER:v1 -->

---

### Part of the MEOK constellation

This MCP is one node in a connected ecosystem built by **MEOK AI LABS** around a single
sovereign AI core — governed agents with a hash-chained audit trail, mapped to the CSOAI
compliance charter.

- 🌐 The whole map: **<https://meok.ai/constellation>**
- 🛡️ AI governance & certification: **<https://councilof.ai>** · **<https://csoai.org>**
- ✅ Verify any signed report: **<https://meok.ai/verify>**
