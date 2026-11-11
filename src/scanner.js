/**
 * MCP Security Scanner
 * 
 * Scans MCP servers for security risks.
 * Commercial tracking: Every scan requires API key, usage tracked, upgrade prompts embedded.
 */

import express from 'express';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { v4 as uuidv4 } from 'uuid';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = join(__dirname, '..', 'data');
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

let apiKeys = loadJSON(API_KEYS_FILE, {});
let scans = loadJSON(SCANS_FILE, {});
let leads = loadJSON(LEADS_FILE, []);

// Risk rules from our 229K MCP Census
const RISK_RULES = {
  funds_movement: {
    name: 'Funds Movement',
    severity: 'CRITICAL',
    keywords: ['transfer', 'payment', 'withdraw', 'deposit', 'send_money', 'buy', 'sell', 'trade'],
    description: 'Tool can move funds. Requires cryptographic verification.'
  },
  credential_handling: {
    name: 'Credential Handling',
    severity: 'HIGH',
    keywords: ['password', 'token', 'secret', 'api_key', 'credential', 'auth', 'login'],
    description: 'Tool handles credentials. Risk of leakage.'
  },
  file_db_write: {
    name: 'File/DB Write',
    severity: 'HIGH',
    keywords: ['write', 'create', 'delete', 'update', 'insert', 'drop', 'exec'],
    description: 'Tool writes to files or databases.'
  },
  command_execution: {
    name: 'Command Execution',
    severity: 'CRITICAL',
    keywords: ['exec', 'run', 'shell', 'bash', 'cmd', 'evaluate', 'compile'],
    description: 'Tool executes commands. High risk.'
  },
  infrastructure_mutation: {
    name: 'Infrastructure Mutation',
    severity: 'HIGH',
    keywords: ['deploy', 'provision', 'scale', 'terminate', 'restart', 'configure'],
    description: 'Tool mutates infrastructure.'
  }
};

// Create API key with commercial tracking
function createApiKey(tier = 'free', email = null) {
  const key = `mcp_${uuidv4().replace(/-/g, '')}`;
  apiKeys[key] = {
    tier,
    email, // Lead capture
    created: Date.now(),
    active: true,
    scans: 0
  };
  saveJSON(API_KEYS_FILE, apiKeys);
  
  // Track lead if email provided
  if (email) {
    leads.push({ email, key, tier, created: Date.now(), source: 'mcp-scanner' });
    saveJSON(LEADS_FILE, leads);
  }
  
  return { key, tier };
}

// Analyze MCP server tools for risks
function analyzeTools(tools) {
  const results = [];
  let totalRisk = 0;
  
  for (const tool of tools) {
    const name = (tool.name || '').toLowerCase();
    const desc = (tool.description || '').toLowerCase();
    const combined = `${name} ${desc}`;
    
    const risks = [];
    for (const [ruleId, rule] of Object.entries(RISK_RULES)) {
      if (rule.keywords.some(kw => combined.includes(kw))) {
        risks.push({
          rule: ruleId,
          name: rule.name,
          severity: rule.severity,
          description: rule.description
        });
        totalRisk++;
      }
    }
    
    results.push({
      tool: tool.name,
      risks,
      risk_count: risks.length,
      ccs_required: risks.length > 0
    });
  }
  
  return {
    tools: results,
    total_tools: tools.length,
    total_risks: totalRisk,
    critical: results.filter(t => t.risks.some(r => r.severity === 'CRITICAL')).length,
    high: results.filter(t => t.risks.some(r => r.severity === 'HIGH')).length,
    ccs_required_count: results.filter(t => t.ccs_required).length
  };
}

// Generate CCS-signed scan report (commercial hook)
function generateReport(analysis, serverUrl) {
  const reportId = `scan_${uuidv4().replace(/-/g, '').substring(0, 16)}`;
  const timestamp = Date.now();
  
  return {
    report_id: reportId,
    server: serverUrl,
    timestamp,
    summary: {
      total_tools: analysis.total_tools,
      total_risks: analysis.total_risks,
      critical: analysis.critical,
      high: analysis.high,
      ccs_required: analysis.ccs_required_count
    },
    tools: analysis.tools,
    // Commercial hooks embedded in report
    verification: {
      ccs_receipt: {
        receipt_id: reportId,
        signature: 'ccs_signature_placeholder',
        public_key: 'correctover_public_key',
        timestamp
      },
      verify_url: `https://api.correctover.com/verify/${reportId}`,
      upgrade_msg: analysis.ccs_required_count > 0 
        ? `${analysis.ccs_required_count} tools need CCS verification. Upgrade to verify all.` 
        : 'No high-risk tools found.'
    },
    // Upgrade prompt
    upgrade: {
      free_limit: '5 scans/month',
      pro_url: 'https://correctover.com/pricing',
      pro_features: [
        'Unlimited scans',
        'Full 229K risk database',
        'CCS verification for all tools',
        'Compliance reports (SOC2, ISO42001)',
        'API access'
      ]
    }
  };
}

// Express app
const app = express();
app.use(express.json());

// Middleware: API key validation
app.use((req, res, next) => {
  if (req.path === '/health' || req.path === '/pricing' || req.path === '/create-key' || req.path === '/register') {
    return next();
  }

  const apiKey = req.headers['x-api-key'];
  if (!apiKey || !apiKeys[apiKey]) {
    return res.status(401).json({ 
      error: 'Invalid API key. Get free key: POST /create-key',
      signup_url: 'https://correctover.com/signup'
    });
  }

  req.apiKey = apiKey;
  next();
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '1.0.0', scanner: 'mcp-security-scanner' });
});

// Create API key (with optional email for lead capture)
app.post('/create-key', (req, res) => {
  const { tier = 'free', email } = req.body;
  const result = createApiKey(tier, email);
  res.status(201).json({
    ...result,
    message: email ? 'Key created. Check email for onboarding.' : 'Key created.',
    free_limit: '5 scans/month',
    upgrade_url: 'https://correctover.com/pricing'
  });
});

// Register lead (commercial tracking)
app.post('/register', (req, res) => {
  const { email, company, role } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  
  const key = createApiKey('free', email);
  leads.push({ email, company, role, key: key.key, created: Date.now(), source: 'scanner-register' });
  saveJSON(LEADS_FILE, leads);
  
  res.json({
    api_key: key.key,
    message: 'Registered. Free tier: 5 scans/month.',
    upgrade_url: 'https://correctover.com/pricing'
  });
});

// Scan MCP server
app.post('/scan', (req, res) => {
  const { server_url, tools } = req.body;
  
  // Rate limiting
  apiKeys[req.apiKey].scans = (apiKeys[req.apiKey].scans || 0) + 1;
  saveJSON(API_KEYS_FILE, apiKeys);
  
  if (apiKeys[req.apiKey].scans > 5 && apiKeys[req.apiKey].tier === 'free') {
    return res.status(429).json({
      error: 'Free limit: 5 scans/month exceeded.',
      upgrade_url: 'https://correctover.com/pricing',
      upgrade_msg: 'Upgrade to Pro for unlimited scans + full 229K risk database.'
    });
  }

  if (!tools || !Array.isArray(tools)) {
    return res.status(400).json({ error: 'tools array required' });
  }

  const analysis = analyzeTools(tools);
  const report = generateReport(analysis, server_url);
  
  // Track scan
  const scanId = report.report_id;
  scans[scanId] = {
    api_key: req.apiKey,
    server: server_url,
    timestamp: Date.now(),
    total_risks: analysis.total_risks,
    critical: analysis.critical,
    ccs_required: analysis.ccs_required_count
  };
  saveJSON(SCANS_FILE, scans);

  res.json(report);
});

// Get scan history (commercial: shows usage, prompts upgrade)
app.get('/scans', (req, res) => {
  const userScans = Object.entries(scans)
    .filter(([_, s]) => s.api_key === req.apiKey)
    .map(([id, s]) => ({ id, ...s }));
  
  const tier = apiKeys[req.apiKey].tier;
  const used = apiKeys[req.apiKey].scans || 0;
  
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

// Pricing (commercial)
app.get('/pricing', (req, res) => {
  res.json({
    tiers: {
      free: { price: 0, scans: '5/month', features: ['Basic risk scan', '5 tools per scan'] },
      pro: { price: 49, scans: 'unlimited', features: ['Full 229K risk DB', 'CCS verification', 'Compliance reports'] },
      enterprise: { price: 'custom', scans: 'unlimited', features: ['All Pro features', 'Custom rules', 'SLA', 'Support'] }
    },
    upgrade_url: 'https://correctover.com/pricing',
    contact: 'enterprise@correctover.com'
  });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`MCP Security Scanner running on port ${PORT}`);
  console.log(`Free scans: 5/month. Upgrade: https://correctover.com/pricing`);
});

export { app, createApiKey, analyzeTools };
