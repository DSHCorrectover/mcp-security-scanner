# MCP Security Scanner

**Scan any MCP server for security risks. 30 seconds. Free.**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Policy-green.svg)](SECURITY.md)

## What it does

Input an MCP server's tool list → get a security risk report with CCS verification.

Based on our census of **229,539 MCP tools** across **42,163 servers**, we identified **5 canonical risk categories** that cover 95% of high-consequence operations.

## Quick Start

```bash
# 1. Get free API key (email required for verification)
# Hosted API is not yet publicly available. The CLI is fully self-hosted:
npx mcp-security-scanner --no-telemetry ./your-project
  -H "Content-Type: application/json" \
  -d '{"email": "you@company.com"}'

# 2. Scan tools
curl -X POST http://localhost:8787/scan  # self-hosted endpoint \
  -H "X-API-Key: mcp_your_key" \
  -H "Content-Type: application/json" \
  -d '{
    "server_url": "https://example-mcp.com",
    "tools": [
      {"name": "transfer_funds", "description": "Transfer money between accounts"},
      {"name": "read_file", "description": "Read a file from disk"},
      {"name": "exec_command", "description": "Execute shell command"}
    ]
  }'
```

## Output

```json
{
  "report_id": "scan_5e64ee2992614aa79d3612fc6a7b9d25",
  "summary": {
    "total_tools": 3,
    "total_matches": 2,
    "grades": { "A": 2, "B": 0, "C": 0, "NONE": 1 },
    "summary_line": "2 tool(s) matched critical-risk indicators. 0 matched elevated indicators. 1 had no matches."
  },
  "tools": [
    {
      "tool": "transfer_funds",
      "overall_grade": "A",
      "grade_label": "CRITICAL INDICATOR",
      "match_count": 1,
      "matcher": "word-boundary v1.3.1",
      "read_only_context": null,
      "matches": [
        {
          "rule": "funds_movement",
          "grade": "A",
          "match_strength": "strong",
          "matched_keywords": ["transfer", "funds"],
          "matched_field": "tool_name_token",
          "banner": "A",
          "downgraded_by_readonly_context": false,
          "can_say": ["Risk indicator matched: \"transfer\" found in tool name", "..."],
          "cannot_say": ["This tool WILL move funds", "..."],
          "false_positive_note": "Match-rate evidence, 16,446-tool census slice (7.16% coverage, retrieved 2026-11-12): ... Residual A-grade false-positive rate is NOT measured."
        }
      ],
      "limitations": [
        "Based on word-boundary matching of tool name tokens and description prose",
        "Does not analyze actual tool behavior or source code",
        "Absence of indicators does not mean absence of risk"
      ]
    }
  ],
  "verification": {
    "ccs_receipt": {
      "receipt_id": "scan_5e64ee2992614aa79d3612fc6a7b9d25",
      "signature": "1a34a185eeb99b9c28842ba9bc1c3ef6",
      "public_key": "correctover_public_key",
      "timestamp": 1731234567890
    },
    "verify_path": "reports/scan_5e64ee2992614aa79d3612fc6a7b9d25.json",
    "upgrade_msg": "2 tools need CCS verification. Upgrade to verify all."
  },
  "critical_trial": {
    "message": "2 CRITICAL risk(s) found. Start 7-day Pro trial to verify and remediate.",
    "trial_url": "https://correctover.com/trial?report=scan_5e64ee2992614aa79d3612fc6a7b9d25&key=mcp_your_key",
    "trial_duration": "7 days",
    "includes": ["Full verification", "Remediation guidance", "Compliance reports"]
  }
}
```

## Risk Categories

Five keyword categories, defined by us. **These are not derived from census statistics** — the census is used for cross-reference in the Pro tier, not to generate these rules.

| Category | Grade ceiling from description-only match | Promoted to A by tool-name token | Keywords |
|----------|-------------------------------------------|----------------------------------|----------|
| Funds Movement | B | A | transfer, payment, withdraw, deposit, ... |
| Command Execution | B | A | exec, run, shell, bash, cmd, ... |
| Credential Handling | C | B | password, token, secret, api_key, ... |
| File/DB Write | C | B | write, create, delete, update, insert, ... |
| Infrastructure Mutation | C | B | deploy, provision, scale, terminate, ... |

Matching is **word-boundary** based and applies an inflection stoplist (`runtime`, `execution`, `buyer`, `withdrawal`, `configured`, … are not treated as matches) plus a read-only-context downgrade.

**We do not publish a false-positive rate.** No FP-rate figure has ever been measured; earlier revisions of this file carried a per-category "False Positive Rate" column with invented numbers, and it has been removed. What has been measured is the match rate on a truncated census slice (16,446 tools, 7.16% coverage, retrieved 2026-11-12): A-grade verdicts fell from 4,547 (27.6%) under substring matching to 507 (3.1%) under word-boundary matching. See [SECURITY.md](SECURITY.md#known-limitations) for the full window and for what remains unmeasured. Manual review is the only way to obtain a false-positive rate.

## Pricing

| Tier | Price | Scans | Features |
|------|-------|-------|----------|
| Free | $0 | 5/month | Basic risk scan, CCS-signed reports, match-rate evidence with window |
| Pro | $49/mo | Unlimited | Full 229K risk DB, manual review, compliance reports (SOC2, ISO42001), API access |
| Enterprise | Custom | Unlimited | Custom rules, on-premise, SLA (99.9%), dedicated support |

**Free tier: no credit card required. Email verification required.**

## Security Features

- **Email validation** — Prevents spam and duplicate accounts
- **IP rate limiting** — 10 keys/hour, 5 registrations/hour per IP
- **IDOR protection** — Reports scoped to API key, no cross-user access
- **UUID report IDs** — 128-bit entropy, not enumerable
- **CCS signatures** — SHA-256 hash ties report to scanning session
- **Match-rate evidence** — Every report states its sample size, coverage percentage and retrieval date, and lists explicitly which rates remain unmeasured

See [SECURITY.md](SECURITY.md) for full details.

## Why CCS?

Every scan report is signed with CCS (Cryptographic Commitment Scheme). This means:
- Reports are tamper-proof
- Can be used as audit evidence
- Verifiable offline
- IETF standard ([draft-correctover-ccs-11](https://datatracker.ietf.org/doc/draft-correctover-ccs/))

**Note:** CCS signatures are commercial integrity markers, not cryptographic attestations of scan accuracy. For production security verification, upgrade to Pro.

## Self-Hosting vs Hosted

**This project is Apache-2.0 licensed.** You can self-host the full scanner.

**Hosted tier** (api.correctover.com) — *not yet publicly available; roadmap*:
- Commercial tracking (API keys, usage, leads)
- Rate limiting
- Email verification
- Upgrade prompts

**Self-hosted**:
- No tracking (you control the data)
- No rate limiting (you configure it)
- No upgrade prompts
- You're responsible for compliance

The tracking code is provided for transparency. If you fork and self-host, document your own data practices.

## CLI Usage

> **Install note — read this before you install.** There is a package called
> `mcp-security-scanner` on the npm registry, but **it is not ours**. That name belongs to a
> different project (maintainer `orhnyldrm`, repository `badchars/mcp-security-scanner`, a
> TypeScript tool with a 55-tool surface and different dependencies). We have never published
> this scanner to npm, and `npm install -g mcp-security-scanner` will install someone else's
> software. Verified against the registry on 2026-11-12. Install from source instead:

```bash
# Install from this repository
git clone https://github.com/DSHCorrectover/mcp-security-scanner.git
cd mcp-security-scanner
npm ci          # installs exactly what package-lock.json pins
npm test        # 19 security tests
npm link        # puts the `mcp-scan` command on your PATH

# Scan a server file
mcp-scan scan ./my-mcp-server.js --api-key mcp_your_key

# Start local server
mcp-scan server --port 3001

# Show pricing
mcp-scan pricing
```

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | No | Health check |
| `/pricing` | GET | No | Pricing tiers |
| `/create-key` | POST | No | Create API key (email required) |
| `/register` | POST | No | Register lead (email + company) |
| `/scan` | POST | Yes | Scan MCP server tools |
| `/scans` | GET | Yes | Get scan history (own only) |
| `/report/:id` | GET | Yes | Get specific report (own only) |

## Links

- [Website](https://correctover.com)
- [CCS Verifier MCP](https://github.com/DSHCorrectover/ccs-verifier-mcp)
- [LangChain Integration](https://github.com/DSHCorrectover/langchain-ccs)
- [IETF Draft](https://datatracker.ietf.org/doc/draft-correctover-ccs/)
- [Security Policy](SECURITY.md)

## License

Apache-2.0. Commercial tracking is part of the hosted free tier, not the self-hosted version.
