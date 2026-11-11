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
curl -X POST https://api.correctover.com/create-key \
  -H "Content-Type: application/json" \
  -d '{"email": "you@company.com"}'

# 2. Scan tools
curl -X POST https://api.correctover.com/scan \
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
    "total_risks": 2,
    "critical": 2,
    "high": 0,
    "ccs_required": 2,
    "calibration": "2 risk(s) detected. Based on our 229K MCP Census data, approximately 0.4 may be false positives. Upgrade to Pro for manual review."
  },
  "tools": [
    {
      "tool": "transfer_funds",
      "risks": [{"rule": "funds_movement", "severity": "CRITICAL", "description": "Tool can move funds. Requires cryptographic verification."}],
      "ccs_required": true
    },
    {
      "tool": "exec_command",
      "risks": [{"rule": "command_execution", "severity": "CRITICAL", "description": "Tool executes commands. High risk."}],
      "ccs_required": true
    }
  ],
  "verification": {
    "ccs_receipt": {
      "receipt_id": "scan_5e64ee2992614aa79d3612fc6a7b9d25",
      "signature": "1a34a185eeb99b9c28842ba9bc1c3ef6",
      "public_key": "correctover_public_key",
      "timestamp": 1731234567890
    },
    "verify_url": "https://api.correctover.com/verify/scan_5e64ee2992614aa79d3612fc6a7b9d25",
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

From our census of **229,539 MCP tools**:

| Category | Severity | Keywords | False Positive Rate |
|----------|----------|----------|---------------------|
| Funds Movement | CRITICAL | transfer, payment, withdraw, deposit | 15% |
| Command Execution | CRITICAL | exec, run, shell, bash, cmd | 10% |
| Credential Handling | HIGH | password, token, secret, api_key | 25% |
| File/DB Write | HIGH | write, create, delete, update, insert | 30% |
| Infrastructure Mutation | HIGH | deploy, provision, scale, terminate | 20% |

**False positive calibration** is included in every report. Upgrade to Pro for manual review.

## Pricing

| Tier | Price | Scans | Features |
|------|-------|-------|----------|
| Free | $0 | 5/month | Basic risk scan, CCS-signed reports, false positive calibration |
| Pro | $49/mo | Unlimited | Full 229K risk DB, manual review, compliance reports (SOC2, ISO42001), API access |
| Enterprise | Custom | Unlimited | Custom rules, on-premise, SLA (99.9%), dedicated support |

**Free tier: no credit card required. Email verification required.**

## Security Features

- **Email validation** — Prevents spam and duplicate accounts
- **IP rate limiting** — 10 keys/hour, 5 registrations/hour per IP
- **IDOR protection** — Reports scoped to API key, no cross-user access
- **UUID report IDs** — 128-bit entropy, not enumerable
- **CCS signatures** — SHA-256 hash ties report to scanning session
- **False positive calibration** — Every report includes estimated FP rate

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

**Hosted free tier** (api.correctover.com):
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

```bash
# Install globally
npm install -g mcp-security-scanner

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
