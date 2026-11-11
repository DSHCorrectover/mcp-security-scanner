#!/usr/bin/env node

import { spawn } from 'child_process';
import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createInterface } from 'readline';

const __dirname = dirname(fileURLToPath(import.meta.url));

function printUsage() {
  console.log(`
mcp-scan - MCP Security Scanner

USAGE:
  mcp-scan scan <server.js>     Scan an MCP server file for security risks
  mcp-scan server               Start the scanner API server
  mcp-scan pricing              Show pricing tiers
  mcp-scan help                 Show this help message

EXAMPLES:
  mcp-scan scan ./my-mcp-server.js
  mcp-scan scan ./server.js --api-key YOUR_KEY
  mcp-scan server --port 3001

SECURITY SCANNER:
  Scans MCP servers against 5 risk categories from the 229,539-tool MCP Census:
  - Funds movement
  - Credential handling
  - File/DB write operations
  - Command execution
  - Infrastructure mutation

  Each scan generates a CCS-signed verification report.

PRICING:
  Free:       5 scans/month, basic reports
  Pro:        $49/month, unlimited scans, export formats
  Enterprise: Custom pricing, API access, custom rules

  Get your API key: curl -X POST http://localhost:3000/create-key

LEARN MORE:
  GitHub: github.com/DSHCorrectover/mcp-security-scanner
  IETF: draft-correctover-ccs-11, draft-correctover-gg-mcp-parameter-risk-01
`);
}

async function scanServer(serverPath, apiKey) {
  if (!serverPath) {
    console.error('Error: Please provide a server file path');
    console.error('Usage: mcp-scan scan <server.js>');
    process.exit(1);
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
          tools.push({ name: toolName });
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
    const port = process.env.SCANNER_PORT || 3000;
    const url = `http://localhost:${port}/scan`;
    
    const headers = { 'Content-Type': 'application/json' };
    if (apiKey) {
      headers['X-API-Key'] = apiKey;
    }

    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({ tools, server_name: serverPath }),
    });

    const result = await response.json();

    if (!response.ok) {
      console.error(`Error: ${result.error}`);
      if (result.upgrade_url) {
        console.log(`\nUpgrade to continue scanning: ${result.upgrade_url}`);
      }
      process.exit(1);
    }

    // Display results
    console.log('\n=== MCP Security Scan Report ===\n');
    console.log(`Server: ${result.server_name}`);
    console.log(`Scan ID: ${result.scan_id}`);
    console.log(`Tools Scanned: ${result.tools_scanned}`);
    console.log(`Tools with Risks: ${result.tools_with_risks}`);
    console.log(`Risk Level: ${result.risk_level.toUpperCase()}`);
    console.log(`Timestamp: ${result.timestamp}`);
    
    if (result.risks.length > 0) {
      console.log('\n--- Risks Found ---\n');
      for (const risk of result.risks) {
        console.log(`Tool: ${risk.tool}`);
        console.log(`  Category: ${risk.category}`);
        console.log(`  Level: ${risk.level}`);
        console.log(`  Description: ${risk.description}`);
        console.log(`  Recommendation: ${risk.recommendation}`);
        console.log('');
      }
    } else {
      console.log('\nNo security risks detected.');
    }

    console.log('--- Verification ---\n');
    console.log(`CCS Receipt: ${result.ccs.receipt}`);
    console.log(`Verify URL: ${result.ccs.verify_url}`);
    console.log(`Standard: draft-correctover-ccs-11`);
    
    if (result.upgrade_msg) {
      console.log(`\n${result.upgrade_msg}`);
      if (result.pro_features) {
        console.log('Pro features:', result.pro_features.join(', '));
      }
    }

  } catch (error) {
    if (error.code === 'ENOENT') {
      console.error(`Error: File not found: ${serverPath}`);
    } else if (error.code === 'ECONNREFUSED') {
      console.error('Error: Scanner API server is not running.');
      console.error('Start it with: mcp-scan server');
    } else {
      console.error(`Error: ${error.message}`);
    }
    process.exit(1);
  }
}

function startServer() {
  const port = process.env.PORT || 3000;
  console.log(`Starting MCP Security Scanner API on port ${port}...`);
  
  const server = spawn('node', [resolve(__dirname, 'scanner.js')], {
    env: { ...process.env, PORT: port.toString() },
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
  • Basic risk reports
  • CCS-signed verification
  • Community support

PRO TIER - $49/month
  • Unlimited scans
  • Export to JSON/CSV
  • Historical tracking
  • Priority support
  • Custom risk rules

ENTERPRISE - Custom pricing
  • API access
  • On-premise deployment
  • Custom integrations
  • SLA guarantee
  • Dedicated support

Get your API key:
  curl -X POST http://localhost:3000/create-key \\
    -H "Content-Type: application/json" \\
    -d '{"email": "you@company.com"}'

Learn more: github.com/DSHCorrectover/mcp-security-scanner
`);
}

// Main CLI logic
const args = process.argv.slice(2);
const command = args[0];

switch (command) {
  case 'scan':
    const serverPath = args[1];
    const apiKeyFlag = args.indexOf('--api-key');
    const apiKey = apiKeyFlag !== -1 ? args[apiKeyFlag + 1] : undefined;
    scanServer(serverPath, apiKey);
    break;

  case 'server':
    startServer();
    break;

  case 'pricing':
    showPricing();
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
