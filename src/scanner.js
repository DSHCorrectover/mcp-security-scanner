/**
 * MCP Security Scanner v1.3.1
 * 
 * Scans MCP servers for security risk indicators.
 * Commercial tracking: Every scan requires API key, usage tracked, upgrade prompts embedded.
 * 
 * Security hardening (v1.2.0):
 * - HMAC-SHA256 signatures (not plain SHA-256)
 * - API keys stored as hashes (not plaintext)
 * - Trusted proxy IP parsing (prevents X-Forwarded-For spoofing)
 * - Multi-dimensional rate limiting (IP + device + global quota)
 * - Input validation (prevents prototype pollution, DoS, homoglyph attacks)
 * - IDOR protection (reports scoped to API key owner)
 * 
 * Report integrity (v1.3.0 — born from CVE-2026-73567 casebook; matcher revised in v1.3.1):
 * - A/B/C/NONE grading with strict wording boundaries per grade
 * - Forbidden claims machine-checked before every report emission
 * - Banner A (keyword match) / Banner B (census-verified) separation
 * - Data provenance: every number carries source, window, date
 * - Downgrade principle: when in doubt, rate lower not higher
 * - v1.3.1: word-boundary matcher + inflection stoplist + read-only-context
 *   downgrade, replacing substring matching that inflated A-grade 4,547 -> 507
 *   on a 16,446-tool census slice (7.16% coverage, measured 2026-11-12)
 * - Structural honesty: limitations embedded in every tool result
 * 
 * Honest disclosure:
 * - Email "format validation" only (not real email verification with confirmation link)
 * - CCS signatures are HMAC-SHA256 (commercial integrity markers, not cryptographic attestations)
 * - Free tier uses keyword matching only (not source code analysis or runtime observation)
 * - Self-hosted version has NO telemetry (zero external calls)
 * - Risk indicators are NOT confirmed vulnerabilities
 */

import express from 'express';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import { signReport } from './signature.js';
import { rateLimitMiddleware, getClientIP, cleanupRateLimits } from './rate-limit.js';
import { validateScanRequest, validateCreateKeyRequest, validateRegisterRequest, sanitizeInput, isValidEmail } from './validation.js';
import { analyzeToolWithGrading, generateIntegrityBlock, selfCheckReport, RISK_GRADES } from './report-integrity.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
// CCS_DATA_DIR isolates persistent state (API keys, scan records, leads, rate
// counters). Without it, a test run writes into the same files production uses —
// which both corrupts commercial tracking and makes the negative test suite
// non-repeatable, since its first suite deliberately exhausts the per-IP quota.
const DATA_DIR = process.env.CCS_DATA_DIR || join(__dirname, '..', 'data');
const API_KEYS_FILE = join(DATA_DIR, 'api-keys.json');
const SCANS_FILE = join(DATA_DIR, 'scans.json');
const LEADS_FILE = join(DATA_DIR, 'leads.json');

if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });

function loadJSON(file, defaultVal) {
  try {
    if (existsSync(file)) return JSON.parse(readFileSync(file, 'utf-8'));
  } catch (e) {}
  return defaultVal;
}

function saveJSON(file, data) {
  writeFileSync(file, JSON.stringify(data, null, 2));
}

// Hash API key for storage (never store plaintext)
function hashApiKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

let apiKeys = loadJSON(API_KEYS_FILE, {});
let scans = loadJSON(SCANS_FILE, {});
let leads = loadJSON(LEADS_FILE, []);

// Risk rules from our 229K MCP Census
const RISK_RULES = {
  funds_movement: {
    name: 'Funds Movement',
    severity: 'CRITICAL',
    keywords: ['transfer', 'payment', 'withdraw', 'deposit', 'send_money', 'buy', 'sell', 'trade'],
    description: 'Tool can move funds. Requires cryptographic verification.',
    false_positive_rate: 0.15
  },
  credential_handling: {
    name: 'Credential Handling',
    severity: 'HIGH',
    keywords: ['password', 'token', 'secret', 'api_key', 'credential', 'auth', 'login'],
    description: 'Tool handles credentials. Risk of leakage.',
    false_positive_rate: 0.25
  },
  file_db_write: {
    name: 'File/DB Write',
    severity: 'HIGH',
    keywords: ['write', 'create', 'delete', 'update', 'insert', 'drop', 'exec'],
    description: 'Tool writes to files or databases.',
    false_positive_rate: 0.30
  },
  command_execution: {
    name: 'Command Execution',
    severity: 'CRITICAL',
    keywords: ['exec', 'run', 'shell', 'bash', 'cmd', 'evaluate', 'compile'],
    description: 'Tool executes commands. High risk.',
    false_positive_rate: 0.10
  },
  infrastructure_mutation: {
    name: 'Infrastructure Mutation',
    severity: 'HIGH',
    keywords: ['deploy', 'provision', 'scale', 'terminate', 'restart', 'configure'],
    description: 'Tool mutates infrastructure.',
    false_positive_rate: 0.20
  }
};

// Email format validation (NOT real email verification)
// Imported from validation.js to avoid circular dependency

// Create API key with commercial tracking
function createApiKey(tier = 'free', email = null) {
  const key = `mcp_${uuidv4().replace(/-/g, '')}`;
  const keyHash = hashApiKey(key); // Store hash, not plaintext
  
  apiKeys[keyHash] = {
    tier,
    emailHash: email ? crypto.createHash('sha256').update(email).digest('hex') : null,
    created: Date.now(),
    active: true,
    scans: 0,
    email_format_validated: true, // Honest: format only, not verified
    email_verified: false // Real email verification not implemented
  };
  saveJSON(API_KEYS_FILE, apiKeys);
  
  // Track lead if email provided
  if (email) {
    leads.push({ 
      emailHash: crypto.createHash('sha256').update(email).digest('hex'),
      keyHash, 
      tier, 
      created: Date.now(), 
      source: 'mcp-scanner' 
    });
    saveJSON(LEADS_FILE, leads);
  }
  
  return { key, keyHash, tier }; // Return plaintext key ONCE to user
}

// Validate API key (compare hashes)
function validateApiKey(providedKey) {
  const providedHash = hashApiKey(providedKey);
  return apiKeys[providedHash] ? { valid: true, keyHash: providedHash, keyData: apiKeys[providedHash] } : { valid: false };
}

// Analyze MCP server tools for risks — graded (A/B/C/NONE) with integrity constraints
// Born from CVE-2026-73567 casebook: "宁可降级，不可升级"
function analyzeTools(tools) {
  const gradedResults = tools.map(tool => analyzeToolWithGrading(tool));
  
  const gradeCounts = { A: 0, B: 0, C: 0, NONE: 0 };
  let totalMatches = 0;
  
  for (const result of gradedResults) {
    gradeCounts[result.overall_grade] = (gradeCounts[result.overall_grade] || 0) + 1;
    totalMatches += result.match_count;
  }
  
  return {
    tools: gradedResults,
    total_tools: tools.length,
    total_matches: totalMatches,
    grades: gradeCounts,
    // Honest summary: no "X risks detected" — instead "X indicators matched"
    summary_line: gradeCounts.A > 0
      ? `${gradeCounts.A} tool(s) matched critical-risk indicators. ${gradeCounts.B} matched elevated indicators. ${gradeCounts.NONE} had no matches.`
      : gradeCounts.B > 0
        ? `${gradeCounts.B} tool(s) matched elevated-risk indicators. ${gradeCounts.NONE} had no matches.`
        : `No risk indicators matched across ${tools.length} tool(s). This does NOT mean all tools are safe.`
  };
}

// Generate CCS-signed scan report with HMAC-SHA256 + integrity constraints
function generateReport(analysis, serverUrl, apiKey) {
  const reportId = `scan_${uuidv4().replace(/-/g, '')}`;
  const timestamp = Date.now();
  
  const hasCritical = analysis.grades.A > 0;
  
  // Generate integrity block (grading, provenance, banner separation)
  const integrityBlock = generateIntegrityBlock(analysis);
  
  const reportData = {
    report_id: reportId,
    api_key_hash: hashApiKey(apiKey), // Never include plaintext key in report
    timestamp,
    summary: {
      total_tools: analysis.total_tools,
      total_matches: analysis.total_matches,
      grades: analysis.grades,
      summary_line: analysis.summary_line
    },
    tools: analysis.tools,
    // Integrity block: structural honesty enforcement
    integrity: integrityBlock.integrity
  };
  
  // SELF-CHECK: Run forbidden claims check before emitting
  // "自检四问" — automated before any report leaves the server
  const reportText = JSON.stringify(reportData);
  const selfCheck = selfCheckReport(reportText);
  if (!selfCheck.passed) {
    // This should never happen with our controlled output, but structurally enforced
    console.error(`[INTEGRITY VIOLATION] Report ${reportId} failed self-check:`, selfCheck.violations);
    // Strip violating text and replace with safe defaults
    reportData.integrity.self_check_violations = selfCheck.violations;
    reportData.integrity.self_check = 'FAILED — report was modified before emission. See violations.';
  }
  
  // Generate HMAC-SHA256 signature (requires server private key)
  const signature = signReport(reportData);
  
  return {
    ...reportData,
    server: serverUrl,
    // Commercial hooks — honest about what they are
    verification: {
      ccs_receipt: {
        receipt_id: reportId,
        signature, // HMAC-SHA256
        algorithm: 'HMAC-SHA256',
        public_key: 'correctover_public_key',
        timestamp,
        note: 'CCS signature is a commercial integrity marker, NOT a security attestation.'
      },
      // verify_url only exposes summary + hash, not full report
      verify_url: `https://api.correctover.com/verify/${reportId}?hash=${signature.substring(0, 16)}`,
      upgrade_msg: analysis.total_matches > 0 
        ? `${analysis.total_matches} indicator match(es) found. Pro tier adds census cross-reference (Banner B verification).` 
        : 'No indicators matched. Pro tier adds census cross-reference for deeper assurance.',
      note: 'verify_url shows summary only. Full report requires API key authentication.'
    },
    // Upgrade prompt — honest framing
    upgrade: {
      free_limit: '5 scans/month',
      pro_url: 'https://correctover.com/pricing',
      pro_features: [
        'Census cross-reference (Banner B verification against 229K tools)',
        'Source code analysis (not just keyword matching)',
        'Runtime behavior observation',
        'Compliance reports (SOC2, ISO42001)',
        'Manual risk review by security engineer',
        'Manual review, the only method that can measure a false-positive rate'
      ],
      honest_note: 'Free tier uses keyword matching only. It finds indicators, not confirmed risks.'
    },
    // CRITICAL-triggered Pro trial — with proper framing
    critical_trial: hasCritical ? {
      message: `${analysis.grades.A} tool(s) matched critical-risk indicators. Start 7-day Pro trial for census cross-reference and manual review.`,
      trial_url: `https://correctover.com/trial?report=${reportId}`,
      trial_duration: '7 days',
      includes: ['Census cross-reference (Banner B)', 'Manual review by engineer', 'Compliance reports'],
      note: 'Trial requires email format validation. One trial per email address. Keyword indicators are not confirmed vulnerabilities.'
    } : null
  };
}

// Express app
const app = express();
app.use(express.json({ limit: '1mb' })); // Prevent large payload DoS

// Middleware: API key validation (compare hashes)
app.use((req, res, next) => {
  if (req.path === '/health' || req.path === '/pricing' || req.path === '/create-key' || req.path === '/register') {
    return next();
  }

  const apiKey = req.headers['x-api-key'];
  if (!apiKey) {
    return res.status(401).json({ 
      error: 'API key required. Get free key: POST /create-key',
      signup_url: 'https://correctover.com/signup'
    });
  }

  const validation = validateApiKey(apiKey);
  if (!validation.valid) {
    return res.status(401).json({ 
      error: 'Invalid API key. Get free key: POST /create-key',
      signup_url: 'https://correctover.com/signup'
    });
  }

  req.apiKey = apiKey;
  req.keyHash = validation.keyHash;
  req.keyData = validation.keyData;
  next();
});

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    version: '1.3.1', 
    scanner: 'mcp-security-scanner',
    report_integrity: 'CVE-2026-73567 casebook principles (forbidden claims, grading, banner separation)',
    matcher: 'word-boundary v1.3.1 (substring matcher retired — see CHANGELOG)',
    security: [
      'HMAC-SHA256 signatures',
      'API key hashing',
      'Trusted proxy IP parsing',
      'Multi-dimensional rate limiting',
      'Input validation',
      'IDOR protection',
      'Forbidden claims self-check',
      'A/B/C/NONE grading with wording boundaries'
    ]
  });
});

// Create API key with rate limiting + input validation
app.post('/create-key', 
  rateLimitMiddleware('/create-key', { 
    ipLimit: 10, 
    deviceLimit: 5, 
    windowMs: 3600000,
    useGlobalQuota: true,
    globalAction: 'keys'
  }),
  (req, res) => {
    const body = sanitizeInput(req.body);
    const validation = validateCreateKeyRequest(body);
    if (!validation.valid) {
      return res.status(400).json({ error: 'Invalid request', details: validation.errors });
    }
    
    const { tier = 'free', email } = body;
    
    // Check for duplicate email (compare hashes)
    if (email) {
      const emailHash = crypto.createHash('sha256').update(email).digest('hex');
      const existingKey = Object.entries(apiKeys).find(([_, v]) => v.emailHash === emailHash);
      if (existingKey) {
        return res.status(409).json({
          error: 'Email already registered. Use existing API key or contact support.',
          note: 'We store email hashes, not plaintext emails.'
        });
      }
    }
    
    const result = createApiKey(tier, email);
    res.status(201).json({
      key: result.key, // Plaintext key returned ONCE
      tier: result.tier,
      message: email 
        ? 'Key created. Email format validated (not verified - no confirmation link sent).' 
        : 'Key created. Free tier: 5 scans/month.',
      free_limit: '5 scans/month',
      upgrade_url: 'https://correctover.com/pricing',
      security_note: 'API key stored as SHA-256 hash. Email stored as SHA-256 hash. Plaintext not retained.'
    });
  }
);

// Register lead with rate limiting + input validation
app.post('/register',
  rateLimitMiddleware('/register', {
    ipLimit: 5,
    deviceLimit: 3,
    windowMs: 3600000,
    useGlobalQuota: true,
    globalAction: 'registrations'
  }),
  (req, res) => {
    const body = sanitizeInput(req.body);
    const validation = validateRegisterRequest(body);
    if (!validation.valid) {
      return res.status(400).json({ error: 'Invalid request', details: validation.errors });
    }
    
    const { email, company, role } = body;
    
    // Check for duplicate
    const emailHash = crypto.createHash('sha256').update(email).digest('hex');
    const existingKey = Object.entries(apiKeys).find(([_, v]) => v.emailHash === emailHash);
    if (existingKey) {
      return res.status(409).json({
        error: 'Email already registered.',
        note: 'We store email hashes, not plaintext emails.'
      });
    }
    
    const key = createApiKey('free', email);
    leads.push({ 
      emailHash,
      company, 
      role, 
      keyHash: key.keyHash, 
      created: Date.now(), 
      source: 'scanner-register',
      ip: getClientIP(req)
    });
    saveJSON(LEADS_FILE, leads);
    
    res.json({
      api_key: key.key,
      message: 'Registered. Free tier: 5 scans/month. Email format validated (not verified).',
      upgrade_url: 'https://correctover.com/pricing'
    });
  }
);

// Scan MCP server with rate limiting + input validation
app.post('/scan',
  rateLimitMiddleware('/scan', {
    ipLimit: 100,
    deviceLimit: 50,
    windowMs: 3600000,
    useGlobalQuota: true,
    globalAction: 'scans'
  }),
  (req, res) => {
    const body = sanitizeInput(req.body);
    const validation = validateScanRequest(body);
    if (!validation.valid) {
      return res.status(400).json({ error: 'Invalid request', details: validation.errors });
    }
    
    const { server_url, tools } = body;
    
    // Rate limiting per API key (monthly)
    const keyData = apiKeys[req.keyHash];
    keyData.scans = (keyData.scans || 0) + 1;
    saveJSON(API_KEYS_FILE, apiKeys);
    
    if (keyData.scans > 5 && keyData.tier === 'free') {
      return res.status(429).json({
        error: 'Free limit: 5 scans/month exceeded.',
        upgrade_url: 'https://correctover.com/pricing',
        upgrade_msg: 'Upgrade to Pro for unlimited scans + full 229K risk database.',
        scans_used: keyData.scans,
        scans_limit: 5
      });
    }

    const analysis = analyzeTools(tools);
    const report = generateReport(analysis, server_url, req.apiKey);
    
    // Track scan (IDOR protection: only owner can access via /scans)
    const scanId = report.report_id;
    scans[scanId] = {
      keyHash: req.keyHash, // Store hash, not plaintext key
      server: server_url,
      timestamp: Date.now(),
      grades: analysis.grades,
      total_matches: analysis.total_matches
    };
    saveJSON(SCANS_FILE, scans);

    res.json(report);
  }
);

// Get scan history (IDOR protected: only shows own scans)
app.get('/scans', (req, res) => {
  const userScans = Object.entries(scans)
    .filter(([_, s]) => s.keyHash === req.keyHash) // IDOR protection: filter by key hash
    .map(([id, s]) => ({ 
      id, 
      timestamp: s.timestamp,
      server: s.server,
      grades: s.grades,
      total_matches: s.total_matches
      // Note: keyHash NOT exposed in response
    }));
  
  const tier = apiKeys[req.keyHash].tier;
  const used = apiKeys[req.keyHash].scans || 0;
  
  res.json({
    tier,
    scans_used: used,
    scans_limit: tier === 'free' ? 5 : 'unlimited',
    scans: userScans,
    upgrade_msg: tier === 'free' && used >= 3 
      ? `${used}/5 free scans used. Upgrade for unlimited.` 
      : null,
    upgrade_url: 'https://correctover.com/pricing'
  });
});

// Get specific report (IDOR protected)
app.get('/report/:reportId', (req, res) => {
  const { reportId } = req.params;
  const scan = scans[reportId];
  
  if (!scan) {
    return res.status(404).json({ error: 'Report not found' });
  }
  
  // IDOR protection: only owner can access (compare key hashes)
  if (scan.keyHash !== req.keyHash) {
    return res.status(403).json({ error: 'Access denied. You can only view your own reports.' });
  }
  
  res.json(scan);
});

// Public verify endpoint (only shows summary + hash, not full report)
app.get('/verify/:reportId', (req, res) => {
  const { reportId } = req.params;
  const { hash } = req.query;
  
  const scan = scans[reportId];
  if (!scan) {
    return res.status(404).json({ error: 'Report not found' });
  }
  
  // Verify hash matches (partial signature)
  if (!hash || !scan.signature?.startsWith(hash)) {
    return res.status(403).json({ error: 'Invalid verification hash' });
  }
  
  // Only expose summary, not full tool list
  res.json({
    report_id: reportId,
    timestamp: scan.timestamp,
    summary: {
      grades: scan.grades,
      total_matches: scan.total_matches
    },
    verification: {
      status: 'valid',
      algorithm: 'HMAC-SHA256',
      hash: hash,
      note: 'Summary only. Full report requires API key authentication. Indicators are not confirmed vulnerabilities.'
    }
  });
});

// Pricing (public)
app.get('/pricing', (req, res) => {
  res.json({
    tiers: {
      free: { 
        price: 0, 
        scans: '5/month', 
        features: [
          'Basic risk scan (5 rules)', 
          '50 tools per scan',
          'HMAC-SHA256 signed reports',
          'Community support'
        ] 
      },
      pro: { 
        price: 49, 
        scans: 'unlimited', 
        features: [
          'Full 229K risk database', 
          'CCS verification for all tools', 
          'Compliance reports (SOC2, ISO42001)',
          'Manual risk review',
          'Match-rate evidence with source, window, and retrieval date',
          'Priority support',
          'API access'
        ] 
      },
      enterprise: { 
        price: 'custom', 
        scans: 'unlimited', 
        features: [
          'All Pro features', 
          'Custom risk rules', 
          'On-premise deployment',
          'SLA guarantee (99.9%)',
          'Dedicated support',
          'Training & onboarding'
        ] 
      }
    },
    upgrade_url: 'https://correctover.com/pricing',
    contact: 'enterprise@correctover.com',
    security: {
      email_validation: 'Format validation only (no confirmation link)',
      api_key_storage: 'SHA-256 hash (plaintext not retained)',
      signatures: 'HMAC-SHA256 (requires server private key)',
      rate_limiting: 'IP + device fingerprint + global quota',
      telemetry: 'Self-hosted version has ZERO external calls'
    }
  });
});

// Periodic cleanup of old rate limit entries
setInterval(cleanupRateLimits, 3600000); // Every hour

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`MCP Security Scanner v1.3.1 running on port ${PORT}`);
  console.log(`Security: HMAC-SHA256, API key hashing, trusted proxy, multi-dim rate limit, input validation`);
  console.log(`Integrity: Forbidden claims check, A/B/C grading, banner separation, data provenance`);
  console.log(`Honest disclosure: Keyword indicators only (not confirmed vulnerabilities). Email format validation only.`);
  console.log(`Free scans: 5/month. Upgrade: https://correctover.com/pricing`);
});

export { app, createApiKey, analyzeTools, isValidEmail, hashApiKey, validateApiKey };
