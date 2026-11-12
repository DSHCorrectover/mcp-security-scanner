# Security Hardening Changelog

## v1.3.1 — Word-Boundary Matcher (self-found revenue-affecting defect)

### Overview
Verification of the v1.3.0 integrity work against real census data found that the keyword matcher itself was broken, and that the breakage fed the paid upsell. This release fixes the matcher and removes every published false-positive rate, because none had ever been measured.

### Measured defect
Source: local truncated census slice (`server_tools.jsonl.gz` partial), **n=16,446 parsed tool rows, 7.16% coverage of the census tool population**. Measured **2026-11-12**. This is a truncated slice and must never be presented as full-census coverage.

| Matcher | A-grade verdicts | Share of slice |
|---|---|---|
| substring (v1.3.0 and earlier) | 4,547 | 27.6% |
| word-boundary (v1.3.1) | 507 | 3.1% |

Of the 4,547 substring verdicts, **1,982 (43.6%)** fired only because the keyword sat inside a longer word: `execution`→`exec`, `runtime`/`runs`/`truncated`→`run`, `configured`→`configure`, `buyer`/`seller`→`buy`/`sell`, `withdrawal`→`withdraw`.

Why this was severe rather than cosmetic: the A-grade count is the exact quantity that triggers the paid Pro-trial prompt in the scanner report. The defect was selling upgrades off a regex artifact.

### Matcher changes (`src/report-integrity.js`)
- **Word-boundary matching replaces substring `includes()`.** Evidence strength is now distinguished: `strong` = match on a token of the tool name; `weak` = whole-word match in description prose.
- **`EXCLUDED_FORMS` inflection stoplist** (39 entries) — `runtime`, `runnable`, `runbook`, `execution`, `executive`, `executable`, `configured`, `configurable`, `buyer`, `seller`, `trading`, `withdrawal`, `tokenizer`, `authorised`, … are no longer treated as capability evidence.
- **`NEGATIVE_CONTEXT` read-only detector** (9 patterns: `read-only`, `never … write`, `disabled`, `cannot run`, `does not execute`, `intent: read`, `view-only`, …). A tool whose own description declares a read-only workflow is capped at C and flagged `downgraded_by_readonly_context`.
- **Grade ladder rebuilt** in `analyzeToolWithGrading()`: description-only evidence caps at B for strong-A rules and C for weak-B rules; only a tool-name token can promote to A. This implements 宁可降级，不可升级 as code rather than prose.
- Full-word distribution (same slice): A 507, B 3,450, C 2,106, NONE 10,383; 213 tools downgraded by read-only context.
- Regression cases pinned: `sap_get_agent_stats` → C (read-only context), `execute_command` → A, `transfer_funds` → A.

### Documentation and copy corrections
- **`SECURITY.md`: deleted the fabricated "10-15% false positive rate for A grade".** Replaced with the measured table above, each figure carrying its source, sample size, coverage and retrieval date, plus an explicit statement that a match-rate drop is not a false-positive-rate measurement.
- **`README.md`: deleted the per-category "False Positive Rate" column (15%/10%/25%/30%/20%).** None of those numbers had ever been measured. The Risk Categories table now states the grade ladder instead, and the section says plainly that we do not publish an FP rate.
- **`README.md`: `ccs_required` removed from the example output and the example rewritten to the actual response shape** (`overall_grade`, `grade_label`, `match_count`, `matcher`, `read_only_context`, `matches[]`, `limitations[]`). The published example had drifted from what the code returns.
- **`src/report-integrity.js`: removed the A-grade `canSay` line "This pattern is associated with {category} operations in our 229K MCP Census"** and moved it into `cannotSay`. We have never computed census co-occurrence statistics, so the claim was unsupported.
- **"False positive calibration" renamed to "match-rate evidence with source, window, and retrieval date"** in the Pro feature list (`scanner.js`), the free-tier feature list (`cli.js`), the pricing table and the security-features list. The old label promised a number we cannot produce.
- **`cli.js`: "5 rules from 229K MCP Census" → "5 keyword categories, defined locally — not derived from census data".** The categories are ours; attributing them to the census was a false provenance.
- Per-tool `limitations` now states that the residual false-positive rate is not measured.
- `createDataProvenance()`: `false_positive_calibration` replaced by `match_rate_evidence` carrying the slice size, coverage, retrieval date, both matcher distributions, and a `not_measured` list. Census tool total now shows both circulating figures (229,539 published headline vs. the 229,827 denominator the slice coverage was computed against) with a note that they are unreconciled.

### Test suite: the 16 failures were never security defects

`tests/security-negative.test.js` had been reported as "16 failing security tests" and carried as known debt. **That reading was wrong, and correcting it matters more than the matcher fix.** With the harness repaired the suite is 19/19 green, twice in a row.

Measured cause of every failure: the suite shared one mutable identity across all tests.

1. All requests came from a single `127.0.0.1`, and `/create-key` is limited to 10 keys/hour/IP — so once the first suites had consumed the budget, every later suite got 429. The suite's very first test deliberately fires 15 `/create-key` calls, which guarantees this.
2. `/create-key` *also* limits by device fingerprint (`User-Agent` + `Accept-Language` + `Accept-Encoding` + `sec-ch-ua`, 5/hour). Converted to `http.request`, the tests sent none of those headers, so all 19 tests collapsed into one fingerprint and hit the device cap regardless of source IP.
3. The suite wrote into the production `data/` directory — test API keys, test leads, test scan records and test rate counters were being committed as if they were commercial tracking.

Fixes:
- **`CCS_DATA_DIR`** env override added to both `src/scanner.js` and `src/rate-limit.js`, so persistent state can be relocated. The test harness now runs against a `mkdtemp` directory removed in `after()`. This is what stops CI from writing into production lead data.
- Per-test source address from the `127.0.0.0/8` range (real TCP peers, not spoofed headers) plus a per-test `User-Agent`, so each test gets its own IP bucket *and* its own device bucket. The rate-limiting test still uses one identity deliberately, which is what it is testing.
- `beforeEach` hooks added per suite; readiness is polled against `/health` instead of a fixed `sleep(2000)`, so slow startup cannot look like a security failure.
- `should reject scan with >50 tools` asserted `data.error.includes('50')`, but the limit lives in `data.details` — `data.error` is the generic `"Invalid request"`. The protection was working; the assertion read the wrong field. Now asserts against the whole body.
- `TRUSTED_PROXIES` for the test server is set to a placeholder that is never a real peer. Note: setting it to `''` does **not** work — the code reads `process.env.TRUSTED_PROXIES || <default>`, so an empty string silently restores the default allowlist.

What this proves about the shipped product, measured directly on a running server (2026-11-12): homoglyph emails rejected with 400 and an explicit reason; `__proto__` in a tool definition accepted as data but `Object.prototype` verifiably unpolluted; cross-user report access denied; HMAC-SHA256 signatures present. The v1.2.0 security claims are true — they were only ever unverifiable because the harness was self-blocking.

### The published repository could not be installed at all (self-found, P1 for a commercial product)

While preparing this release we ran a clean `npm ci` against the files as they are published on `main` (`dfb78cf`). It fails:

```
npm error code EUSAGE
npm error `npm ci` can only install packages when your package.json and package-lock.json or npm-shrinkwrap.json are in sync.
npm error Missing: express@4.22.3 from lock file
npm error Missing: uuid@9.0.1 from lock file
```

Read directly out of the two published files (2026-11-12):

| file as published | name | dependencies |
| --- | --- | --- |
| `package.json` | `mcp-security-scanner` | `express ^4.18.2`, `uuid ^9.0.1` |
| `package-lock.json` | `@correctover/mcp-scanner` | `axios ^1.6.0`, `commander ^11.0.0` |

The lockfile belongs to a different, earlier package (`@correctover/mcp-scanner` does not exist on the npm registry — 404 on 2026-11-12). So `npm ci --production`, the command `SECURITY.md:230` tells operators to run, has never worked on this repo, and plain `npm install` was silently papering over it. This is the same defect class we score other MCP servers for (manifest/lockfile divergence), found in our own product. It is fixed here, not by deleting the lock, but by regenerating it against the real manifest.

Found while verifying that same install path, and a bigger deal than the lockfile:

**`npm install -g mcp-security-scanner` — which our own README said at line 164 — installs a third party's software.** The npm name `mcp-security-scanner` is published by maintainer `orhnyldrm` (email `contact@orhanyildirim.us`), repository `github.com/badchars/mcp-security-scanner`, versions 0.1.0/0.2.0 (March 2026) and 1.0.0–1.1.1 (June 2026, `latest` = 1.1.1). Its dependencies are `@modelcontextprotocol/sdk`, `ts-morph`, `zod` and its description advertises 55 tools — none of this is our codebase, whose runtime deps are `express` + `uuid`. We have never published to npm. Any customer who followed our README got someone else's product, and any security complaint about it would have landed on us.

Fix applied here: the README now states plainly that the npm name is not ours and gives a clone → `npm ci` → `npm test` → `npm link` path from this repository instead. Two decisions are **left to the owner, not made here**: (a) whether to claim a distinct npm name and publish, and (b) whether to raise a name/trademark dispute over the collision.

Dependency changes shipped with this commit, stated plainly rather than smuggled into a diff:
- `package-lock.json` regenerated for `mcp-security-scanner`; resolves `express 4.22.3` and `uuid 14.0.3`. `axios` and `commander` are gone from the lock because nothing in `src/` imports them.
- `uuid` constraint raised `^9.0.1` → `^14.0.3`. `src/scanner.js:38` uses only `v4`; both API-key ids (`scanner.js:121`) and report ids (`scanner.js:185`) go through it. Verified with `npm ci` (exit 0) followed by `npm test` → 19/19 pass.
- `.gitignore` now excludes `data/`, so test runs and local state cannot be committed as commercial tracking again.

### Open decision escalated to the owner (not changed unilaterally)

The shipped `TRUSTED_PROXIES` default is `127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16`. Any client that can reach the scanner from an address inside those ranges — i.e. anything co-located on a Docker or VPC network — can mint unlimited API keys by rotating `X-Forwarded-For`, because the header is believed from those peers. Observed evidence in the old `data/rate-limits.json`: 16 separate `1.2.3.N:/create-key` counters from one test run against the default configuration.

The structural fix is to default to an empty allowlist and require operators to configure their proxy explicitly (安全不靠纪律，靠结构). That changes production behaviour for anyone deployed behind a reverse proxy, so it is flagged rather than applied. `SECURITY.md` already discloses rate limiting as best-effort, which reduces but does not remove the exposure.

### Cleanup performed

`data/` contained test residue (10 API keys, 1 scan, leads, and rate counters including the spoofed `1.2.3.x` buckets). It was copied to `/tmp/state-quarantine/data-pre-cleanup-2026-11-12/` before being reset to empty structures. No production traffic existed in that directory; everything in it was generated by test runs on 2026-11-11 and 2026-11-12.

### Pending
- Re-measure the grade distribution over the full census once the complete `server_tools.jsonl.gz` download finishes. Until then every figure in this release is labelled truncated / 7.16% coverage.
- Decide the `TRUSTED_PROXIES` default (see above).

## v1.3.0 — Report Integrity (CVE-2026-73567 Casebook Integration)

### Overview
Applied lessons from CVE-2026-73567 casebook (19 files, commit 17fe2e0) to enforce structural honesty in every scan report. Three principles: 宁可降级不可升级 / 夸大一次失去所有可信度 / 安全靠结构不靠纪律.

### New: `src/report-integrity.js` Module
- **Forbidden Claims** — 8 machine-checked constraints that run before every report emission
- **A/B/C/NONE Grading** — Each grade has explicit "can say" and "cannot say" wording boundaries
- **Banner Separation** — Banner A (keyword match) and Banner B (census verified) never merge
- **Data Provenance** — Every number carries source, time window, methodology, and limitations
- **Downgrade Principle** — Low confidence automatically downgrades grade
- **Self-Check** — Automated forbidden-claims scan on every report JSON before emission

### Scanner Changes
- `analyzeTools()` now uses `analyzeToolWithGrading()` from integrity module
- `generateReport()` includes full integrity block with grading, provenance, banner separation
- Report `api_key` field replaced with `api_key_hash` (never expose the plaintext API key in a report)
- Summary line changed from "X risks detected" to "X indicators matched" (honest framing)
- All upgrade/trial messages now clarify "indicators are not confirmed vulnerabilities"
- Health endpoint reports v1.3.0 with integrity features

### SECURITY.md Updates
- Added "Report Integrity (v1.3.0)" section with grading table
- Added forbidden claims list (8 items)
- Added banner separation table
- Added data provenance requirements

---

## v1.2.0 — Security Hardening

### Overview
Addressed detailed security review feedback. Replaced superficial fixes with production-grade implementations.

### HMAC-SHA256 Signatures (`src/signature.js`)
- Replaced fake SHA-256 "signatures" with real HMAC-SHA256
- `signReport(reportData)` — canonical string → HMAC-SHA256 → 64-char hex
- `verifySignature()` — constant-time comparison via `crypto.timingSafeEqual`
- `generateVerifyToken()` / `verifyToken()` — short-lived (24hr) tokens for public verify_url

### API Key Hashing
- `hashApiKey(key)` — SHA-256 hash, stored in `api-keys.json`
- Plaintext key returned ONCE at creation, never stored
- All validation compares hashes, not plaintext

### Trusted Proxy IP Parsing (`src/rate-limit.js`)
- `TRUSTED_PROXIES` whitelist: 127.0.0.1, ::1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
- `getClientIP(req)` — only trusts X-Forwarded-For from whitelisted proxy IPs
- `getDeviceFingerprint(req)` — SHA-256 hash of User-Agent + Accept-Language + Accept-Encoding + sec-ch-ua

### Multi-Dimensional Rate Limiting
- Per-IP hourly limit + per-device hourly limit + global daily quota
- Global quotas: keys 100/day, registrations 50/day, scans 1000/day
- File-based atomic locking via `mkdir` (prevents TOCTOU race conditions)

### Input Validation (`src/validation.js`)
- `sanitizeInput(obj)` — removes `__proto__`, `constructor`, `prototype` keys
- `containsHomoglyphs(str)` — detects Cyrillic, Greek, CJK, fullwidth characters in emails
- `validateScanRequest()` — max 50 tools, name/description length limits
- `limitBodySize` middleware — 1MB max request body

### IDOR Protection
- Reports scoped to API key hash owner
- `/report/:reportId` returns 403 for cross-user access
- `verify_url` exposes summary + hash only, not full report details

### CLI (`src/cli.js`)
- `--no-telemetry` flag for self-hosted mode
- Config stored at `~/.mcp-scanner/config.json` with mode 0o600

---

## v1.1.0 — Initial Security Hardening

## 1. Commercial Tracking Bypass Risks - FIXED

### Email Validation
**Issue:** `/create-key` accepted any email format, allowing unlimited free tier abuse.

**Fix:**
- Added `isValidEmail()` function with regex validation
- Email format: `^[^\s@]+@[^\s@]+\.[^\s@]+$` (max 254 chars)
- Duplicate email check prevents same email from registering twice
- Returns 400 for invalid format, 409 for duplicates

**Code:** `src/scanner.js:73-77`

### IP Rate Limiting
**Issue:** No rate limiting on `/create-key` or `/register` endpoints.

**Fix:**
- Added `checkRateLimit()` function with IP + endpoint + hourly window
- `/create-key`: 10 requests per IP per hour
- `/register`: 5 requests per IP per hour
- Returns 429 with `retry_after: 3600` when exceeded
- Rate limit data stored in `data/rate-limits.json`

**Code:** `src/scanner.js:79-103`

### IDOR Protection
**Issue:** `/scans` endpoint could potentially leak other users' scan records.

**Fix:**
- All scan queries filtered by `api_key` (owner-only access)
- Added `/report/:reportId` endpoint with explicit ownership check
- Returns 403 "Access denied" if API key doesn't match scan owner
- API key NOT exposed in scan history responses

**Code:** `src/scanner.js:404-428`

### Report ID Enumeration
**Issue:** Report IDs were truncated (16 chars), reducing entropy.

**Fix:**
- Full UUIDv4 for report IDs: `scan_` + 32 hex chars = 128-bit entropy
- Not sequential, not timestamp-based
- Verify URL requires API key authentication
- CCS signature uses SHA-256 hash of `report_id:api_key:timestamp`

**Code:** `src/scanner.js:180`

## 2. Product-Side Improvements - ADDED

### False Positive Calibration
**Issue:** Static keyword matching produces false positives; users need context.

**Fix:**
- Added `false_positive_rate` to each risk rule (10%-30%)
- Every report includes `summary.calibration` message:
  - "X risk(s) detected. Based on our 229K MCP Census data, approximately Y may be false positives. Upgrade to Pro for manual review."
- Converts uncertainty into upgrade motivation

> **v1.3.1 retraction — kept in place rather than deleted, so the history stays honest.** The 10%-30% rates introduced above were never measured against anything. They were guesses written into shipped report copy, and the resulting `summary.calibration` string quoted a fabricated number to paying prospects. Both were removed in v1.3.1; see the v1.3.1 entry. `summary.calibration` no longer exists in the response shape.

**Code:** `src/scanner.js:45-67, 154-172`

### CRITICAL-Triggered Pro Trial
**Issue:** Highest conversion moment (finding CRITICAL risks) had no trial prompt.

**Fix:**
- Added `critical_trial` field to reports when `analysis.critical > 0`
- Includes:
  - `message`: "X CRITICAL risk(s) found. Start 7-day Pro trial..."
  - `trial_url`: Pre-filled with report ID and API key
  - `trial_duration`: "7 days"
  - `includes`: ["Full verification", "Remediation guidance", "Compliance reports"]
- Only shown when CRITICAL risks detected (highest urgency)

**Code:** `src/scanner.js:207-215`

### Tool Limit per Scan
**Issue:** Free tier could be abused with massive tool lists.

**Fix:**
- Free tier limited to 50 tools per scan
- Returns 400 with upgrade URL if exceeded
- Pro/Enterprise tiers have no limit

**Code:** `src/scanner.js:372-377`

## 3. Open Source vs Tracking Tension - RESOLVED

### SECURITY.md
**Issue:** Security tool without security policy looks hypocritical.

**Fix:**
- Created comprehensive SECURITY.md covering:
  - Supported versions
  - Vulnerability reporting process
  - Commercial tracking transparency (what we collect, what we don't)
  - Data retention policies
  - IDOR protection explanation
  - Report ID entropy
  - Rate limiting table
  - CCS signature clarification (commercial marker, not security guarantee)
  - Open source considerations (self-hosting vs hosted)
  - Known limitations (static matching, no runtime analysis)
  - Security best practices for users
  - Transparency report commitment

**File:** `SECURITY.md`

### README Transparency
**Issue:** Apache-2.0 license + commercial tracking could cause community backlash.

**Fix:**
- Added "Self-Hosting vs Hosted" section explaining:
  - Hosted free tier includes tracking (trade-off for free scans)
  - Self-hosted version has no tracking (you control the data)
  - Tracking code provided for transparency, not obligation
- Updated license note: "Commercial tracking is part of the hosted free tier, not the self-hosted version"
- Added SECURITY.md badge to README header

**File:** `README.md`

### CCS Signature Clarification
**Issue:** CCS signatures could be mistaken for cryptographic security guarantees.

**Fix:**
- SECURITY.md explicitly states: "CCS signatures are commercial integrity markers, not cryptographic attestations of scan accuracy"
- README notes: "For production security verification, upgrade to Pro"
- Signature implementation uses SHA-256 hash (not Ed25519) for commercial tracking

**Files:** `SECURITY.md:67-73`, `README.md:95-101`

## Testing Results

All security fixes verified with comprehensive test suite:

```
✅ Email validation - rejects invalid formats
✅ Duplicate check - blocks same email twice
✅ Rate limiting - blocks after 10 keys/hour per IP
✅ IDOR protection - "Access denied" for wrong API key
✅ CRITICAL trial trigger - shows 7-day Pro trial
✅ False positive calibration - "approximately 0.5 may be false positives"  ← (v1.3.1: this figure was never measured; removed)
✅ CCS signature - real SHA-256 hash, not placeholder
✅ Full UUID report IDs - 128-bit entropy
```

## Deployment

All changes pushed to GitHub:
- `src/scanner.js` - Security hardening (commit 6b9366a)
- `SECURITY.md` - Security policy (commit 48f86a7)
- `README.md` - Transparency updates (commit e7fd966)
- `.gitignore` - Data directory exclusion (commit 6d3b940)
- `tsconfig.json` - Removed (using JavaScript, not TypeScript)

## Version

**v1.1.0** - Security hardening release

## Next Steps

1. Deploy to production (api.correctover.com)
2. Set up email verification service (SendGrid/Mailgun)
3. Implement actual CCS signing (Ed25519, not SHA-256 placeholder)
4. Add Pro trial activation endpoint
5. Publish quarterly transparency report template
6. Submit to awesome-mcp-servers with SECURITY.md highlighted
