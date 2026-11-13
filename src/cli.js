#!/usr/bin/env node

import { spawn } from 'child_process';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { resolve, dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { homedir } from 'os';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONFIG_DIR = join(homedir(), '.mcp-scanner');
const CONFIG_FILE = join(CONFIG_DIR, 'config.json');

// Ensure config directory exists
if (!existsSync(CONFIG_DIR)) {
  mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
}

// Load or create config
function loadConfig() {
  try {
    if (existsSync(CONFIG_FILE)) {
      return JSON.parse(readFileSync(CONFIG_FILE, 'utf-8'));
    }
  } catch (e) {}
  return { telemetry: false, api_url: '' }; // hosted API not yet available; default to self-hosted mode
}

function saveConfig(config) {
  writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), { mode: 0o600 });
}

function printUsage() {
  console.log(`
mcp-scan - MCP Security Scanner

USAGE:
  mcp-scan scan <server.js>          Scan an MCP server file for security risks
  mcp-scan server                    Start the scanner API server
  mcp-scan pricing                   Show pricing tiers
  mcp-scan config [--no-telemetry]   Configure CLI settings
  mcp-scan help                      Show this help message

OPTIONS:
  --api-key KEY         Use specific API key for scanning
  --no-telemetry        Disable all external calls (self-hosted mode)
  --port PORT           Server port (default: 3000)

EXAMPLES:
  mcp-scan scan ./my-mcp-server.js --api-key mcp_your_key
  mcp-scan server --port 3001
  mcp-scan config --no-telemetry

SECURITY SCANNER:
  Scans MCP servers against 5 risk categories from the 229,539-tool MCP Census:
  - Funds movement (CRITICAL)
  - Command execution (CRITICAL)
  - Credential handling (HIGH)
  - File/DB write operations (HIGH)
  - Infrastructure mutation (HIGH)

  Each scan generates an HMAC-SHA256 signed verification report.

PRICING:
  Free:       5 scans/month, basic reports, HMAC-SHA256 signatures
  Pro:        $49/month, unlimited scans, manual review, compliance reports
  Enterprise: Custom pricing, API access, custom rules, on-premise

  Hosted API: NOT YET AVAILABLE. The CLI runs fully self-hosted (no external calls).

TELEMETRY & PRIVACY:
  The CLI runs locally by default; no data leaves your machine.
  Use --no-telemetry to disable all external calls (self-hosted mode).
  Self-hosted version has ZERO telemetry - no data leaves your machine.

  Config file: ~/.mcp-scanner/config.json (permissions: 600)
  API keys stored in config are your responsibility to protect.

SECURITY FEATURES:
  - HMAC-SHA256 signatures (not plain SHA-256)
  - API keys stored as hashes server-side
  - Trusted proxy IP parsing (prevents X-Forwarded-For spoofing)
  - Multi-dimensional rate limiting (IP + device + global quota)
  - Input validation (prevents prototype pollution, DoS, homoglyph attacks)
  - IDOR protection (reports scoped to API key owner)

  Honest disclosure: Email "format validation" only (not real verification).
  See SECURITY.md for full details.

LEARN MORE:
  GitHub: github.com/DSHCorrectover/mcp-security-scanner
  IETF: draft-correctover-ccs-11, draft-correctover-gg-mcp-parameter-risk-01
`);
}

async function scanServer(serverPath, apiKey, noTelemetry) {
  if (!serverPath) {
    console.error('Error: Please provide a server file path');
    console.error('Usage: mcp-scan scan <server.js>');
    process.exit(1);
  }

  const config = loadConfig();
  
  if (noTelemetry || !config.telemetry) {
    console.log('⚠️  Telemetry disabled - using local scanner only');
    console.log('   Start local server: mcp-scan server');
    console.log('   Then scan: mcp-scan scan <server.js> --api-key YOUR_KEY');
    process.exit(0);
  }

  try {
    const serverCode = readFileSync(resolve(serverPath), 'utf-8');
    
    // Extract tool definitions using pattern matching
    const toolPatterns = [
      /name:\s*["']([^"']+)["']/g,
      /tool\.register\(["']([^"']+)["']/g,
      /server\.tool\(["']([^"']+)["']/g,
      /@tool\s+def\s+(\w+)/g,
      /def\s+(\w+_tool)\s*\(/g,
    ];

    const tools = [];
    const seen = new Set();

    for (const pattern of toolPatterns) {
      let match;
      while ((match = pattern.exec(serverCode)) !== null) {
        const toolName = match[1];
        if (!seen.has(toolName)) {
          seen.add(toolName);
          tools.push({ name: toolName, description: '' });
        }
      }
    }

    if (tools.length === 0) {
      console.log('No MCP tools found in the server file.');
      console.log('Make sure the file contains tool definitions (e.g., server.tool(), @tool, etc.)');
      process.exit(0);
    }

    console.log(`Found ${tools.length} tool(s). Scanning...`);

    // Call the scanner API
    const apiUrl = config.api_url || ''; // hosted API not yet available
    const url = `${apiUrl}/scan`;
    
    const headers = { 'Content-Type': 'application/json' };
    if (apiKey) {
      headers['X-API-Key'] = apiKey;
    }

    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({ tools, server_url: serverPath }),
    });

    const result = await response.json();

    if (!response.ok) {
      console.error(`Error: ${result.error}`);
      if (result.details) {
        console.error('Details:', result.details.join(', '));
      }
      if (result.upgrade_url) {
        console.log(`\nUpgrade to continue scanning: ${result.upgrade_url}`);
      }
      process.exit(1);
    }

    // Display results
    console.log('\n=== MCP Security Scan Report ===\n');
    console.log(`Report ID: ${result.report_id}`);
    console.log(`Server: ${result.server || serverPath}`);
    console.log(`Tools Scanned: ${result.summary.total_tools}`);
    console.log(`Total Risks: ${result.summary.total_risks}`);
    console.log(`Critical: ${result.summary.critical}`);
    console.log(`High: ${result.summary.high}`);
    console.log(`Timestamp: ${new Date(result.timestamp).toISOString()}`);
    
    if (result.summary.calibration) {
      console.log(`\n📊 Calibration: ${result.summary.calibration}`);
    }
    
    if (result.tools && result.tools.length > 0) {
      console.log('\n--- Risks Found ---\n');
      for (const tool of result.tools) {
        if (tool.risks && tool.risks.length > 0) {
          console.log(`Tool: ${tool.tool}`);
          for (const risk of tool.risks) {
            console.log(`  [${risk.severity}] ${risk.name}`);
            console.log(`    ${risk.description}`);
          }
          console.log('');
        }
      }
    } else {
      console.log('\n✓ No security risks detected.');
    }

    console.log('--- Verification ---\n');
    console.log(`Algorithm: ${result.verification.ccs_receipt.algorithm}`);
    console.log(`Signature: ${result.verification.ccs_receipt.signature}`);
    console.log(`Verify URL: ${result.verification.verify_url}`);
    console.log(`Note: ${result.verification.note}`);
    
    if (result.critical_trial) {
      console.log('\n🚨 CRITICAL RISKS DETECTED');
      console.log(result.critical_trial.message);
      console.log(`Start 7-day Pro trial: ${result.critical_trial.trial_url}`);
      console.log(`Includes: ${result.critical_trial.includes.join(', ')}`);
    }
    
    if (result.upgrade && result.upgrade.free_limit) {
      console.log(`\n📈 Usage: ${result.upgrade.free_limit}`);
      console.log(`Upgrade: ${result.upgrade.pro_url}`);
    }

  } catch (error) {
    if (error.code === 'ENOENT') {
      console.error(`Error: File not found: ${serverPath}`);
    } else if (error.code === 'ECONNREFUSED') {
      console.error('Error: Cannot connect to scanner API.');
      console.error('Check your internet connection or start local server: mcp-scan server');
    } else {
      console.error(`Error: ${error.message}`);
    }
    process.exit(1);
  }
}

function startServer(port) {
  const serverPort = port || process.env.PORT || 3000;
  console.log(`Starting MCP Security Scanner API on port ${serverPort}...`);
  console.log('Self-hosted mode: ZERO telemetry, all data stays local.\n');
  
  const server = spawn('node', [resolve(__dirname, 'scanner.js')], {
    env: { ...process.env, PORT: serverPort.toString() },
    stdio: 'inherit',
  });

  server.on('exit', (code) => {
    process.exit(code || 0);
  });

  process.on('SIGINT', () => {
    server.kill('SIGINT');
  });
}

function showPricing() {
  console.log(`
=== MCP Security Scanner Pricing ===

FREE TIER - $0/month
  • 5 scans per month
  • Basic risk scan (5 keyword categories, defined locally — not derived from census data)
  • 50 tools per scan
  • HMAC-SHA256 signed reports
  • Match-rate evidence with source, window, and retrieval date
  • Community support

PRO TIER - $49/month
  • Unlimited scans
  • Full 229K risk database
  • CCS verification for all tools
  • Manual risk review
  • Compliance reports (SOC2, ISO42001)
  • Priority support
  • API access

ENTERPRISE - Custom pricing
  • All Pro features
  • Custom risk rules
  • On-premise deployment
  • SLA guarantee (99.9%)
  • Dedicated support
  • Training & onboarding

SECURITY FEATURES (all tiers):
  • HMAC-SHA256 signatures (not plain SHA-256)
  • API keys stored as SHA-256 hashes
  • Trusted proxy IP parsing
  • Multi-dimensional rate limiting
  • Input validation (prototype pollution, DoS, homoglyph protection)
  • IDOR protection

HONEST DISCLOSURE:
  • Email "format validation" only (not real verification with confirmation link)
  • CCS signatures are HMAC-SHA256 (commercial integrity markers)
  • Self-hosted version has ZERO telemetry

Get your API key:
  curl -X POST https://api.correctover.com/create-key \\
    -H "Content-Type: application/json" \\
    -d '{"email": "you@company.com"}'

Learn more: github.com/DSHCorrectover/mcp-security-scanner
`);
}

function configureCLI(args) {
  const config = loadConfig();
  let changed = false;
  
  if (args.includes('--no-telemetry')) {
    config.telemetry = false;
    console.log('✓ Telemetry disabled');
    console.log('  All external calls disabled. Self-hosted mode active.');
    changed = true;
  }
  
  if (args.includes('--telemetry')) {
    config.telemetry = true;
    console.log('✓ Telemetry enabled');
    console.log('  CLI runs in self-hosted mode; hosted API is not yet available.');
    changed = true;
  }
  
  if (args.includes('--api-url')) {
    const urlIndex = args.indexOf('--api-url');
    if (urlIndex !== -1 && args[urlIndex + 1]) {
      config.api_url = args[urlIndex + 1];
      console.log(`✓ API URL set to: ${config.api_url}`);
      changed = true;
    }
  }
  
  if (changed) {
    saveConfig(config);
    console.log(`\nConfig saved to: ${CONFIG_FILE}`);
    console.log('Permissions: 600 (owner read/write only)');
  } else {
    console.log('Current configuration:');
    console.log(`  Telemetry: ${config.telemetry ? 'enabled' : 'disabled'}`);
    console.log(`  API URL: ${config.api_url}`);
    console.log(`  Config file: ${CONFIG_FILE}`);
    console.log('\nUsage:');
    console.log('  mcp-scan config --no-telemetry    Disable external calls');
    console.log('  mcp-scan config --telemetry       Enable external calls');
    console.log('  mcp-scan config --api-url URL     Set custom API URL');
  }
}

// Main CLI logic
const args = process.argv.slice(2);
const command = args[0];

switch (command) {
  case 'scan':
    const serverPath = args[1];
    const apiKeyFlag = args.indexOf('--api-key');
    const apiKey = apiKeyFlag !== -1 ? args[apiKeyFlag + 1] : undefined;
    const noTelemetry = args.includes('--no-telemetry');
    scanServer(serverPath, apiKey, noTelemetry);
    break;

  case 'server':
    const portFlag = args.indexOf('--port');
    const port = portFlag !== -1 ? args[portFlag + 1] : undefined;
    startServer(port);
    break;

  case 'pricing':
    showPricing();
    break;

  case 'config':
    configureCLI(args.slice(1));
    break;

  case 'help':
  case '--help':
  case '-h':
  case undefined:
    printUsage();
    break;

  default:
    console.error(`Unknown command: ${command}`);
    printUsage();
    process.exit(1);
}
