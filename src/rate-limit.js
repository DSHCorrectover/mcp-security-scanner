/**
 * Rate Limiting Middleware with Trusted Proxy Support
 * 
 * Fixes three bypass vectors:
 * 1. X-Forwarded-For spoofing - only trust proxies in whitelist
 * 2. In-memory counters - uses file persistence (Redis-ready interface)
 * 3. Proxy pools - adds global quota + device fingerprint fallback
 */

import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = join(__dirname, '..', 'data');
const RATE_LIMIT_FILE = join(DATA_DIR, 'rate-limits.json');
const GLOBAL_QUOTA_FILE = join(DATA_DIR, 'global-quota.json');

// Trusted proxy IPs (only these X-Forwarded-For headers are believed)
// In production, load from environment
const TRUSTED_PROXIES = (process.env.TRUSTED_PROXIES || '127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16')
  .split(',')
  .map(ip => ip.trim());

// Global quota (prevents proxy pool attacks)
const GLOBAL_QUOTA = {
  keys_per_day: parseInt(process.env.GLOBAL_KEYS_PER_DAY || '100'),
  registrations_per_day: parseInt(process.env.GLOBAL_REGISTRATIONS_PER_DAY || '50'),
  scans_per_day: parseInt(process.env.GLOBAL_SCANS_PER_DAY || '1000')
};

function loadJSON(file, defaultVal) {
  try {
    if (existsSync(file)) return JSON.parse(readFileSync(file, 'utf-8'));
  } catch (e) {}
  return defaultVal;
}

function saveJSON(file, data) {
  writeFileSync(file, JSON.stringify(data, null, 2));
}

/**
 * Check if an IP is in the trusted proxy list
 * Supports CIDR notation for private ranges
 */
function isTrustedProxy(ip) {
  if (!ip) return false;
  
  // Direct match
  if (TRUSTED_PROXIES.includes(ip)) return true;
  
  // CIDR match for private ranges
  for (const cidr of TRUSTED_PROXIES) {
    if (cidr.includes('/')) {
      if (ipInCIDR(ip, cidr)) return true;
    }
  }
  
  return false;
}

/**
 * Check if IP is within CIDR range
 * Simplified implementation for common private ranges
 */
function ipInCIDR(ip, cidr) {
  const [network, mask] = cidr.split('/');
  const maskBits = parseInt(mask);
  
  // Convert IPs to 32-bit integers
  const ipInt = ipToInt(ip);
  const networkInt = ipToInt(network);
  
  // Create mask
  const maskInt = ~(2 ** (32 - maskBits) - 1) >>> 0;
  
  return (ipInt & maskInt) === (networkInt & maskInt);
}

function ipToInt(ip) {
  // Handle IPv4-mapped IPv6 addresses
  if (ip.startsWith('::ffff:')) {
    ip = ip.substring(7);
  }
  
  // Only handle IPv4 for now
  if (!ip.includes('.') || ip.includes(':')) {
    return 0;
  }
  
  return ip.split('.').reduce((int, octet) => (int << 8) + parseInt(octet), 0) >>> 0;
}

/**
 * Extract real client IP from request
 * Only trusts X-Forwarded-For if request comes from trusted proxy
 */
export function getClientIP(req) {
  const remoteAddress = req.connection?.remoteAddress || req.ip;
  
  // If request is from trusted proxy, check X-Forwarded-For
  if (isTrustedProxy(remoteAddress)) {
    const xff = req.headers['x-forwarded-for'];
    if (xff) {
      // X-Forwarded-For: client, proxy1, proxy2
      // Take the first IP (original client)
      const ips = xff.split(',').map(ip => ip.trim());
      return ips[0];
    }
    
    // Also check X-Real-IP (common in nginx)
    const realIP = req.headers['x-real-ip'];
    if (realIP) return realIP;
  }
  
  // Not from trusted proxy, use direct connection IP
  return remoteAddress;
}

/**
 * Generate device fingerprint from request headers
 * Used as fallback when IP is unreliable (proxy pools)
 */
export function getDeviceFingerprint(req) {
  const components = [
    req.headers['user-agent'] || '',
    req.headers['accept-language'] || '',
    req.headers['accept-encoding'] || '',
    req.headers['sec-ch-ua'] || ''
  ];
  
  const combined = components.join('|');
  return crypto.createHash('sha256').update(combined).digest('hex').substring(0, 16);
}

/**
 * Rate limiter with multiple dimensions
 * 
 * @param {string} key - Rate limit key (IP, device, or global)
 * @param {string} endpoint - Endpoint being rate limited
 * @param {number} limit - Maximum requests per window
 * @param {number} windowMs - Window size in milliseconds
 * @returns {Object} { allowed: boolean, remaining: number, reset: number }
 */
export function checkRateLimit(key, endpoint, limit, windowMs) {
  const rateLimits = loadJSON(RATE_LIMIT_FILE, {});
  const now = Date.now();
  const rateKey = `${key}:${endpoint}`;
  
  if (!rateLimits[rateKey]) {
    rateLimits[rateKey] = { count: 1, reset: now + windowMs };
    saveJSON(RATE_LIMIT_FILE, rateLimits);
    return { allowed: true, remaining: limit - 1, reset: now + windowMs };
  }
  
  // Window expired, reset
  if (now > rateLimits[rateKey].reset) {
    rateLimits[rateKey] = { count: 1, reset: now + windowMs };
    saveJSON(RATE_LIMIT_FILE, rateLimits);
    return { allowed: true, remaining: limit - 1, reset: now + windowMs };
  }
  
  // Check limit
  if (rateLimits[rateKey].count >= limit) {
    return {
      allowed: false,
      remaining: 0,
      reset: rateLimits[rateKey].reset,
      retry_after: Math.ceil((rateLimits[rateKey].reset - now) / 1000)
    };
  }
  
  // Increment
  rateLimits[rateKey].count++;
  saveJSON(RATE_LIMIT_FILE, rateLimits);
  
  return {
    allowed: true,
    remaining: limit - rateLimits[rateKey].count,
    reset: rateLimits[rateKey].reset
  };
}

/**
 * Check global quota (prevents proxy pool attacks)
 * 
 * @param {string} action - 'keys', 'registrations', or 'scans'
 * @returns {Object} { allowed: boolean, remaining: number }
 */
export function checkGlobalQuota(action) {
  const quotas = loadJSON(GLOBAL_QUOTA_FILE, {});
  const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
  
  if (!quotas[today]) {
    quotas[today] = { keys: 0, registrations: 0, scans: 0 };
  }
  
  const quotaKey = `${action}_per_day`;
  const currentCount = quotas[today][action] || 0;
  const limit = GLOBAL_QUOTA[quotaKey];
  
  if (currentCount >= limit) {
    return {
      allowed: false,
      remaining: 0,
      limit,
      used: currentCount,
      reset: 'tomorrow (UTC)'
    };
  }
  
  // Increment
  quotas[today][action] = currentCount + 1;
  saveJSON(GLOBAL_QUOTA_FILE, quotas);
  
  return {
    allowed: true,
    remaining: limit - (currentCount + 1),
    limit,
    used: currentCount + 1
  };
}

/**
 * Express middleware for rate limiting
 * 
 * Combines IP-based, device-based, and global quotas
 */
export function rateLimitMiddleware(endpoint, options = {}) {
  const {
    ipLimit = 10,
    deviceLimit = 5,
    windowMs = 3600000, // 1 hour
    useGlobalQuota = true,
    globalAction = null
  } = options;
  
  return (req, res, next) => {
    const ip = getClientIP(req);
    const device = getDeviceFingerprint(req);
    
    // Check IP-based rate limit
    const ipResult = checkRateLimit(ip, endpoint, ipLimit, windowMs);
    if (!ipResult.allowed) {
      return res.status(429).json({
        error: 'Rate limit exceeded (IP).',
        retry_after: ipResult.retry_after,
        limit: ipLimit,
        window: '1 hour'
      });
    }
    
    // Check device-based rate limit (fallback for proxy pools)
    const deviceResult = checkRateLimit(device, endpoint, deviceLimit, windowMs);
    if (!deviceResult.allowed) {
      return res.status(429).json({
        error: 'Rate limit exceeded (device).',
        retry_after: deviceResult.retry_after,
        limit: deviceLimit,
        window: '1 hour'
      });
    }
    
    // Check global quota
    if (useGlobalQuota && globalAction) {
      const globalResult = checkGlobalQuota(globalAction);
      if (!globalResult.allowed) {
        return res.status(429).json({
          error: 'Daily global quota exceeded.',
          limit: globalResult.limit,
          used: globalResult.used,
          reset: globalResult.reset
        });
      }
    }
    
    // Attach rate limit info to request
    req.rateLimit = {
      ip,
      device,
      remaining: Math.min(ipResult.remaining, deviceResult.remaining)
    };
    
    next();
  };
}

/**
 * Clean up old rate limit entries (call periodically)
 */
export function cleanupRateLimits() {
  const rateLimits = loadJSON(RATE_LIMIT_FILE, {});
  const now = Date.now();
  
  for (const key of Object.keys(rateLimits)) {
    if (now > rateLimits[key].reset) {
      delete rateLimits[key];
    }
  }
  
  saveJSON(RATE_LIMIT_FILE, rateLimits);
  
  // Also clean up old global quotas (keep last 7 days)
  const quotas = loadJSON(GLOBAL_QUOTA_FILE, {});
  const sevenDaysAgo = new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
  
  for (const date of Object.keys(quotas)) {
    if (date < sevenDaysAgo) {
      delete quotas[date];
    }
  }
  
  saveJSON(GLOBAL_QUOTA_FILE, quotas);
}

export default {
  getClientIP,
  getDeviceFingerprint,
  checkRateLimit,
  checkGlobalQuota,
  rateLimitMiddleware,
  cleanupRateLimits,
  isTrustedProxy,
  TRUSTED_PROXIES,
  GLOBAL_QUOTA
};
