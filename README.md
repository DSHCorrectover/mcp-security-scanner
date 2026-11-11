# MCP Security Scanner

**Scan any MCP server for security risks. 30 seconds. Free.**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

## What it does

Input an MCP server's tool list → get a security risk report with CCS verification.

```bash
# Install
npm install -g mcp-security-scanner

# Scan
mcp-scan --tools tools.json
```

## Quick Start

```bash
# 1. Get free API key (no credit card)
curl -X POST http://localhost:3001/create-key \
  -H "Content-Type: application/json" \
  -d '{"email": "you@company.com"}'

# 2. Scan tools
curl -X POST http://localhost:3001/scan \
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
  "report_id": "scan_abc123",
  "summary": {
    "total_tools": 3,
    "total_risks": 3,
    "critical": 2,
    "high": 0,
    "ccs_required": 2
  },
  "tools": [
    {
      "tool": "transfer_funds",
      "risks": [{"rule": "funds_movement", "severity": "CRITICAL"}],
      "ccs_required": true
    },
    {
      "tool": "exec_command",
      "risks": [{"rule": "command_execution", "severity": "CRITICAL"}],
      "ccs_required": true
    }
  ],
  "verification": {
    "verify_url": "https://api.correctover.com/verify/scan_abc123",
    "upgrade_msg": "2 tools need CCS verification. Upgrade to verify all."
  }
}
```

## Risk Categories

Based on our census of **229,539 MCP tools**:

| Category | Severity | Examples |
|----------|----------|----------|
| Funds Movement | CRITICAL | transfer, payment, withdraw |
| Command Execution | CRITICAL | exec, shell, bash |
| Credential Handling | HIGH | password, token, secret |
| File/DB Write | HIGH | write, create, delete |
| Infrastructure Mutation | HIGH | deploy, scale, terminate |

## Pricing

| Tier | Price | Scans | Features |
|------|-------|-------|----------|
| Free | $0 | 5/month | Basic risk scan |
| Pro | $49/mo | Unlimited | Full 229K DB, CCS verification, compliance reports |
| Enterprise | Custom | Unlimited | Custom rules, SLA, support |

**Free tier: no credit card required.**

## Why CCS?

Every scan report is signed with CCS (Cryptographic Commitment Scheme). This means:
- Reports are tamper-proof
- Can be used as audit evidence
- Verifiable offline
- IETF standard (draft-correctover-ccs-11)

## Links

- [Website](https://correctover.com)
- [CCS Verifier](https://github.com/DSHCorrectover/ccs-verifier-mcp)
- [IETF Draft](https://datatracker.ietf.org/doc/draft-correctover-ccs/)
