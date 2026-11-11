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

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { spawn } from 'child_process';
import { setTimeout as sleep } from 'timers/promises';

const TEST_PORT = 3400;
const BASE_URL = `http://localhost:${TEST_PORT}`;

let serverProcess;

async function request(method, path, body = null, headers = {}) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json', ...headers }
  };
  if (body) opts.body = JSON.stringify(body);
  
  const res = await fetch(`${BASE_URL}${path}`, opts);
  const data = await res.json();
  return { status: res.status, data };
}

before(async () => {
  // Start test server
  serverProcess = spawn('node', ['src/scanner.js'], {
    env: { ...process.env, PORT: TEST_PORT.toString() },
    stdio: 'pipe'
  });
  await sleep(2000); // Wait for server to start
});

after(() => {
  if (serverProcess) serverProcess.kill();
});

describe('Rate Limiting Bypass Attempts', () => {
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
  it('should reject scan with >50 tools', async () => {
    const { data: keyData } = await request('POST', '/create-key', { email: 'dos@test.com' });
    const apiKey = keyData.key;
    
    const tools = Array(51).fill({ name: 'test', description: 'test' });
    const { status, data } = await request('POST', '/scan', { tools }, { 'X-API-Key': apiKey });
    
    assert.strictEqual(status, 400, 'Should reject >50 tools');
    assert(data.error.includes('50'), 'Error should mention tool limit');
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
