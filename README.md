# MCP Security Scanner

The open-source security scanner for MCP (Model Context Protocol) servers.

Used by Correctover to audit 42,000+ MCP servers. Find vulnerabilities, get security scores, and earn your security badge.

[![MCP Security](https://e58a1155.correctover-web.pages.dev/badges/opensource.svg)](https://correctover.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🚀 Quick Start

```bash
# Install
npm install -g @correctover/mcp-scanner

# Scan your MCP server
mcp-scan https://your-mcp-server.com

# Get detailed report
mcp-scan https://your-mcp-server.com --report json
```

## 🔍 What It Checks

| Category | Check | Severity |
|----------|-------|----------|
| **Authentication** | OAuth 2.1, API keys, token validation | 🔴 Critical |
| **HTTPS/TLS** | Certificate validity, protocol version | 🔴 Critical |
| **Tool Permissions** | Least privilege, scope validation | 🟡 High |
| **Credential Exposure** | API keys, secrets in config | 🔴 Critical |
| **Misconfigurations** | Default settings, open endpoints | 🟡 High |

## 📊 Security Score

Your server gets a score from 0-100:

- **80-100:** ✅ Secure - Ready for production
- **60-79:** ⚠️ Needs improvement - Review warnings
- **0-59:** 🔴 Critical issues - Fix before production

## 🏆 Get Your Badge

After scanning, add this badge to your README:

```markdown
[![MCP Security Score](https://e58a1155.correctover-web.pages.dev/badges/85.svg)](https://correctover.com/scan?url=your-server)
```

Badge preview:

![MCP Security Score](https://e58a1155.correctover-web.pages.dev/badges/85.svg)

## 📈 Industry Benchmarks

Based on our audit of 42,163 MCP servers:

- **48.8%** have zero authentication
- **99%** are misconfigured
- **7,000+** are publicly exposed
- **Average score:** 52/100

Where does your server stand?

## 🛠️ Development

```bash
# Clone
git clone https://github.com/DSHCorrectover/mcp-security-scanner.git

# Install dependencies
npm install

# Run tests
npm test

# Build
npm run build
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🔗 Links

- **Website:** https://correctover.com
- **Free Scanner:** https://e58a1155.correctover-web.pages.dev/scan.html
- **Security Leaderboard:** https://e58a1155.correctover-web.pages.dev/leaderboard.html
- **Report Issues:** https://github.com/DSHCorrectover/mcp-security-scanner/issues

---

**Securing the MCP ecosystem, one server at a time.**
