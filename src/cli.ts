#!/usr/bin/env node

import { Command } from 'commander';
import { scanMcpServer, ScanResult } from './scanner';

const program = new Command();

program
  .name('mcp-scan')
  .description('Security scanner for MCP servers')
  .version('1.0.0');

program
  .argument('<url>', 'MCP server URL to scan')
  .option('-r, --report <format>', 'Output format (json, text)', 'text')
  .option('-v, --verbose', 'Verbose output')
  .action(async (url: string, options: { report?: string; verbose?: boolean }) => {
    try {
      console.log(`🔍 Scanning ${url}...\n`);
      
      const result = await scanMcpServer(url);
      
      if (options.report === 'json') {
        console.log(JSON.stringify(result, null, 2));
      } else {
        printReport(result);
      }
    } catch (error: unknown) {
      const err = error as Error;
      console.error('❌ Scan failed:', err.message);
      process.exit(1);
    }
  });

function printReport(result: ScanResult) {
  console.log('═'.repeat(50));
  console.log('MCP Security Scan Report');
  console.log('═'.repeat(50));
  console.log();
  
  // Security Score
  const score = result.score;
  const scoreIcon = score >= 80 ? '✅' : score >= 60 ? '⚠️' : '🔴';
  console.log(`${scoreIcon} Security Score: ${score}/100`);
  console.log();
  
  // Categories
  console.log('Categories:');
  for (const [category, check] of Object.entries(result.categories)) {
    const icon = check.passed ? '✅' : check.warning ? '⚠️' : '❌';
    console.log(`  ${icon} ${category}: ${check.message}`);
  }
  console.log();
  
  // Issues
  if (result.issues.length > 0) {
    console.log('Issues Found:');
    result.issues.forEach((issue: { severity: string; description: string; fix?: string }, i: number) => {
      console.log(`  ${i + 1}. [${issue.severity}] ${issue.description}`);
      if (issue.fix) {
        console.log(`     Fix: ${issue.fix}`);
      }
    });
    console.log();
  }
  
  // Badge
  console.log('═'.repeat(50));
  console.log('Add this badge to your README:');
  console.log();
  console.log(`[![MCP Security Score](https://e58a1155.correctover-web.pages.dev/badges/${score}.svg)](https://correctover.com/scan?url=${result.url})`);
  console.log();
  console.log('═'.repeat(50));
}

program.parse();
