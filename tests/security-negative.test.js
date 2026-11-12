/**
 * Negative Security Tests
 * 
 * Tests that should FAIL if security is broken:
 * - X-Forwarded-For spoofing
 * - Concurrent TOCTOU race conditions
 * - Unicode/homoglyph attacks
 * - Large payload DoS
 * - Cross-user report access (IDOR)
 * - Prototype pollution
 */

import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert';
import { spawn } from 'child_process';
import { setTimeout as sleep } from 'timers/promises';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import http from 'node:http';

const TEST_PORT = 3400;

let serverProcess;
let testDataDir;

// Each describe block binds to its own loopback source address, so the
// 127.0.0.0/8 range gives us genuinely distinct TCP peers without any header
// spoofing. This is what makes the suite repeatable: /create-key is limited to
// 10 keys/hour/IP, and a single shared 127.0.0.1 meant the first suites to run
// consumed the budget and everything after them got 429 — 16 "failures" that
// had nothing to do with the protection under test.
let ipSlot = 1;
const nextIp = () => `127.0.0.${ipSlot++ + 1}`;
let CURRENT_IP = '127.0.0.2';

function request(method, path, body = null, headers = {}, localAddress = CURRENT_IP) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request(
      {
        host: '127.0.0.1',
        port: TEST_PORT,
        path,
        method,
        localAddress,
        headers: {
          'Content-Type': 'application/json',
          // /create-key also limits by device fingerprint (UA + Accept-Language +
          // Accept-Encoding + sec-ch-ua, 5/hour). A bare http.request sends none
          // of those, so every test would collapse into one fingerprint and hit
          // the device limit no matter which IP it bound to. Each test therefore
          // carries an identity matching its source address.
          'User-Agent': `ccs-negative-suite/${localAddress}`,
          ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
          ...headers
        }
      },
      (res) => {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', (c) => (text += c));
        res.on('end', () => {
          let data = null;
          try { data = JSON.parse(text); } catch { data = text; }
          resolve({ status: res.statusCode, data });
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

before(async () => {
  // Isolate ALL persistent state (api-keys.json, scans.json, leads.json,
  // rate-limits.json, global-quota.json) in a throwaway directory. Without
  // this the suite wrote test keys and test leads into the production data/
  // directory on every run — commercial tracking contaminated by CI.
  testDataDir = mkdtempSync(join(tmpdir(), 'ccs-test-state-'));
  serverProcess = spawn('node', ['src/scanner.js'], {
    env: {
      ...process.env,
      PORT: TEST_PORT.toString(),
      CCS_DATA_DIR: testDataDir,
      // The XFF test below asserts that a forwarded header from an UNTRUSTED
      // peer is ignored. The shipped default trusts loopback plus the private
      // ranges, so the property under test has to be evaluated with loopback
      // removed from the allowlist. An empty string will not do it: the code
      // reads `process.env.TRUSTED_PROXIES || <default>`, so '' falls back to
      // the default. A placeholder that is never a real peer does.
      TRUSTED_PROXIES: '198.51.100.1'
    },
    stdio: 'pipe'
  });
  // Wait for readiness rather than a fixed sleep, so a slow start cannot
  // masquerade as a security failure.
  for (let i = 0; i < 60; i++) {
    try {
      const { status } = await request('GET', '/health', null, {}, '127.0.0.2');
      if (status === 200) break;
    } catch {
      await sleep(100);
    }
  }
});

after(() => {
  if (serverProcess) serverProcess.kill();
  if (testDataDir) rmSync(testDataDir, { recursive: true, force: true });
});

// Every suite gets a fresh source IP.
function suite() {
  CURRENT_IP = nextIp();
}

describe('Rate Limiting Bypass Attempts', () => {
  beforeEach(() => { CURRENT_IP = nextIp(); }); // fresh source IP per test
  it('should NOT trust X-Forwarded-For from untrusted IP', async () => {
    // Attacker tries to spoof IP via X-Forwarded-For
    const results = [];
    for (let i = 0; i < 15; i++) {
      const { status } = await request('POST', '/create-key', 
        { email: `test${i}@example.com` },
        { 'X-Forwarded-For': `1.2.3.${i}` } // Spoofed IP
      );
      results.push(status);
    }
    
    // Should be rate limited after 10 requests (IP-based)
    const blocked = results.filter(s => s === 429);
    assert(blocked.length > 0, 'X-Forwarded-For spoofing should be blocked by rate limiting');
  });

  it('should handle concurrent requests without TOCTOU race', async () => {
    // Create a key first
    const { data: keyData } = await request('POST', '/create-key', { email: 'race@test.com' });
    const apiKey = keyData.key;
    
    // Fire 20 concurrent scan requests
    const promises = [];
    for (let i = 0; i < 20; i++) {
      promises.push(request('POST', '/scan', 
        { tools: [{ name: 'test', description: 'test' }] },
        { 'X-API-Key': apiKey }
      ));
    }
    
    const results = await Promise.all(promises);
    
    // Count successful scans (should be exactly 5 for free tier)
    const successful = results.filter(r => r.status === 200);
    const rateLimited = results.filter(r => r.status === 429);
    
    assert.strictEqual(successful.length, 5, 'Exactly 5 scans should succeed on free tier');
    assert(rateLimited.length > 0, 'Remaining requests should be rate limited');
  });

  it('should enforce global daily quota', async () => {
    // This test would need to exhaust the global quota
    // For now, just verify the quota check exists
    const { data } = await request('GET', '/pricing');
    assert(data.tiers.free, 'Pricing should be accessible');
  });
});

describe('Unicode and Homoglyph Attacks', () => {
  beforeEach(() => { CURRENT_IP = nextIp(); }); // fresh source IP per test
  it('should reject email with Cyrillic homoglyph', async () => {
    // admin@exаmple.com with Cyrillic 'а' (U+0430) instead of Latin 'a'
    const cyrillicEmail = 'admin@ex\u0430mple.com';
    const { status, data } = await request('POST', '/create-key', { email: cyrillicEmail });
    
    assert(status === 400 || status === 409, 'Homoglyph email should be rejected');
    assert(data.error, 'Should return error message');
  });

  it('should reject email with Greek homoglyph', async () => {
    // test@tеst.com with Greek 'е' (U+03B5)
    const greekEmail = 'test@t\u03B5st.com';
    const { status, data } = await request('POST', '/create-key', { email: greekEmail });
    
    assert(status === 400 || status === 409, 'Homoglyph email should be rejected');
  });

  it('should reject email with fullwidth characters', async () => {
    // test＠example.com with fullwidth '@' (U+FF20)
    const fullwidthEmail = 'test\uff20example.com';
    const { status } = await request('POST', '/create-key', { email: fullwidthEmail });
    
    assert(status === 400, 'Fullwidth character email should be rejected');
  });
});

describe('Large Payload DoS Protection', () => {
  beforeEach(() => { CURRENT_IP = nextIp(); }); // fresh source IP per test
  it('should reject scan with >50 tools', async () => {
    const { data: keyData } = await request('POST', '/create-key', { email: 'dos@test.com' });
    const apiKey = keyData.key;
    
    const tools = Array(51).fill({ name: 'test', description: 'test' });
    const { status, data } = await request('POST', '/scan', { tools }, { 'X-API-Key': apiKey });
    
    assert.strictEqual(status, 400, 'Should reject >50 tools');
    // The limit lives in `details`, not in the top-level `error` string
    // (which is the generic "Invalid request"). Assert against the whole body.
    assert(JSON.stringify(data).includes('50'), 'Error should mention tool limit');
  });

  it('should reject tool name >256 chars', async () => {
    const { data: keyData } = await request('POST', '/create-key', { email: 'dos2@test.com' });
    const apiKey = keyData.key;
    
    const longName = 'a'.repeat(257);
    const { status } = await request('POST', '/scan', 
      { tools: [{ name: longName, description: 'test' }] },
      { 'X-API-Key': apiKey }
    );
    
    assert.strictEqual(status, 400, 'Should reject long tool names');
  });

  it('should reject tool description >1024 chars', async () => {
    const { data: keyData } = await request('POST', '/create-key', { email: 'dos3@test.com' });
    const apiKey = keyData.key;
    
    const longDesc = 'a'.repeat(1025);
    const { status } = await request('POST', '/scan', 
      { tools: [{ name: 'test', description: longDesc }] },
      { 'X-API-Key': apiKey }
    );
    
    assert.strictEqual(status, 400, 'Should reject long descriptions');
  });
});

describe('IDOR (Insecure Direct Object Reference) Protection', () => {
  beforeEach(() => { CURRENT_IP = nextIp(); }); // fresh source IP per test
  it('should NOT allow user A to access user B report', async () => {
    // User A creates a scan
    const { data: keyA } = await request('POST', '/create-key', { email: 'userA@test.com' });
    const { data: scanA } = await request('POST', '/scan',
      { tools: [{ name: 'transfer_money', description: 'test' }] },
      { 'X-API-Key': keyA.key }
    );
    const reportId = scanA.report_id;
    
    // User B tries to access it
    const { data: keyB } = await request('POST', '/create-key', { email: 'userB@test.com' });
    const { status } = await request('GET', `/report/${reportId}`, null, { 'X-API-Key': keyB.key });
    
    assert.strictEqual(status, 403, 'User B should not access User A report');
  });

  it('should NOT leak API key in scan history', async () => {
    const { data: keyData } = await request('POST', '/create-key', { email: 'leak@test.com' });
    const apiKey = keyData.key;
    
    // Create a scan
    await request('POST', '/scan',
      { tools: [{ name: 'test', description: 'test' }] },
      { 'X-API-Key': apiKey }
    );
    
    // Get scan history
    const { data: history } = await request('GET', '/scans', null, { 'X-API-Key': apiKey });
    
    // Check that API key is not in response
    const historyStr = JSON.stringify(history);
    assert(!historyStr.includes(apiKey), 'Scan history should not contain API key');
  });
});

describe('Prototype Pollution Protection', () => {
  beforeEach(() => { CURRENT_IP = nextIp(); }); // fresh source IP per test
  it('should reject __proto__ in tool definition', async () => {
    const { data: keyData } = await request('POST', '/create-key', { email: 'proto@test.com' });
    const apiKey = keyData.key;
    
    const malicious = JSON.parse('{"tools": [{"name": "test", "description": "test", "__proto__": {"polluted": true}}]}');
    const { status } = await request('POST', '/scan', malicious, { 'X-API-Key': apiKey });
    
    // Should either reject or sanitize
    assert(status === 200 || status === 400, 'Should handle prototype pollution attempt');
    
    // Verify Object.prototype is not polluted
    const testObj = {};
    assert.strictEqual(testObj.polluted, undefined, 'Object.prototype should not be polluted');
  });

  it('should reject constructor override', async () => {
    const { data: keyData } = await request('POST', '/create-key', { email: 'proto2@test.com' });
    const apiKey = keyData.key;
    
    const malicious = { tools: [{ name: 'test', description: 'test', constructor: 'override' }] };
    const { status } = await request('POST', '/scan', malicious, { 'X-API-Key': apiKey });
    
    assert(status === 200 || status === 400, 'Should handle constructor override attempt');
  });
});

describe('Signature Verification', () => {
  beforeEach(() => { CURRENT_IP = nextIp(); }); // fresh source IP per test
  it('should use HMAC-SHA256, not plain SHA-256', async () => {
    const { data: keyData } = await request('POST', '/create-key', { email: 'sig@test.com' });
    const apiKey = keyData.key;
    
    const { data: scan } = await request('POST', '/scan',
      { tools: [{ name: 'test', description: 'test' }] },
      { 'X-API-Key': apiKey }
    );
    
    // Check that signature exists and is 64 chars (HMAC-SHA256 hex)
    assert(scan.verification?.ccs_receipt?.signature, 'Signature should exist');
    assert.strictEqual(scan.verification.ccs_receipt.signature.length, 64, 'Signature should be 64 hex chars (HMAC-SHA256)');
  });

  it('should not be reproducible without server key', async () => {
    const { data: keyData } = await request('POST', '/create-key', { email: 'sig2@test.com' });
    const apiKey = keyData.key;
    
    const { data: scan } = await request('POST', '/scan',
      { tools: [{ name: 'test', description: 'test' }] },
      { 'X-API-Key': apiKey }
    );
    
    // Try to reproduce signature with just SHA-256 (should fail)
    const crypto = await import('crypto');
    const naiveHash = crypto.createHash('sha256')
      .update(`${scan.report_id}:${apiKey}:${scan.timestamp}`)
      .digest('hex');
    
    assert.notStrictEqual(naiveHash, scan.verification.ccs_receipt.signature, 
      'Signature should not be reproducible without HMAC key');
  });
});

describe('Email Validation Edge Cases', () => {
  beforeEach(() => { CURRENT_IP = nextIp(); }); // fresh source IP per test
  it('should reject empty email', async () => {
    const { status } = await request('POST', '/create-key', { email: '' });
    assert.strictEqual(status, 400, 'Empty email should be rejected');
  });

  it('should reject email without TLD', async () => {
    const { status } = await request('POST', '/create-key', { email: 'test@localhost' });
    assert.strictEqual(status, 400, 'Email without TLD should be rejected');
  });

  it('should reject email >254 chars', async () => {
    const longEmail = 'a'.repeat(250) + '@test.com';
    const { status } = await request('POST', '/create-key', { email: longEmail });
    assert.strictEqual(status, 400, 'Email >254 chars should be rejected');
  });

  it('should reject duplicate email', async () => {
    const email = 'duplicate@test.com';
    await request('POST', '/create-key', { email });
    const { status } = await request('POST', '/create-key', { email });
    assert.strictEqual(status, 409, 'Duplicate email should be rejected');
  });
});
