/**
 * Input Validation and Schema Checking
 * 
 * Prevents:
 * - Prototype pollution
 * - DoS via large payloads
 * - Unicode/homograph attacks
 * - Invalid JSON structures
 */

// Maximum payload sizes
const MAX_TOOLS_PER_SCAN = 50;
const MAX_TOOL_NAME_LENGTH = 256;
const MAX_TOOL_DESCRIPTION_LENGTH = 1024;
const MAX_REQUEST_BODY_SIZE = 1024 * 1024; // 1MB

// Email validation (moved here to break circular dependency)
export function isValidEmail(email) {
  if (!email) return false;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 254;
}

/**
 * Validate scan request body
 */
export function validateScanRequest(body) {
  const errors = [];
  
  // Check body exists
  if (!body || typeof body !== 'object') {
    return { valid: false, errors: ['Request body must be a JSON object'] };
  }
  
  // Check tools array
  if (!body.tools) {
    errors.push('Missing required field: tools');
  } else if (!Array.isArray(body.tools)) {
    errors.push('tools must be an array');
  } else {
    // Check tools count
    if (body.tools.length === 0) {
      errors.push('tools array cannot be empty');
    } else if (body.tools.length > MAX_TOOLS_PER_SCAN) {
      errors.push(`tools array exceeds maximum size (${MAX_TOOLS_PER_SCAN})`);
    }
    
    // Validate each tool
    for (let i = 0; i < body.tools.length; i++) {
      const tool = body.tools[i];
      const prefix = `tools[${i}]`;
      
      if (!tool || typeof tool !== 'object') {
        errors.push(`${prefix} must be an object`);
        continue;
      }
      
      // Check for prototype pollution attempts
      if (tool.__proto__ !== undefined && tool.__proto__ !== Object.prototype) {
        errors.push(`${prefix} contains invalid prototype`);
        continue;
      }
      
      // Validate name
      if (!tool.name) {
        errors.push(`${prefix}.name is required`);
      } else if (typeof tool.name !== 'string') {
        errors.push(`${prefix}.name must be a string`);
      } else {
        if (tool.name.length > MAX_TOOL_NAME_LENGTH) {
          errors.push(`${prefix}.name exceeds maximum length (${MAX_TOOL_NAME_LENGTH})`);
        }
        if (!/^[\w\s\-\.]+$/.test(tool.name)) {
          errors.push(`${prefix}.name contains invalid characters (only alphanumeric, underscore, hyphen, period, space allowed)`);
        }
      }
      
      // Validate description
      if (tool.description !== undefined) {
        if (typeof tool.description !== 'string') {
          errors.push(`${prefix}.description must be a string`);
        } else if (tool.description.length > MAX_TOOL_DESCRIPTION_LENGTH) {
          errors.push(`${prefix}.description exceeds maximum length (${MAX_TOOL_DESCRIPTION_LENGTH})`);
        }
      }
    }
  }
  
  // Validate server_url if provided
  if (body.server_url !== undefined) {
    if (typeof body.server_url !== 'string') {
      errors.push('server_url must be a string');
    } else if (body.server_url.length > 2048) {
      errors.push('server_url exceeds maximum length (2048)');
    } else {
      try {
        new URL(body.server_url);
      } catch (e) {
        errors.push('server_url must be a valid URL');
      }
    }
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Validate create-key request body
 */
export function validateCreateKeyRequest(body) {
  const errors = [];
  
  if (!body || typeof body !== 'object') {
    return { valid: false, errors: ['Request body must be a JSON object'] };
  }
  
  // Validate tier
  if (body.tier !== undefined) {
    if (!['free', 'pro', 'enterprise'].includes(body.tier)) {
      errors.push('tier must be one of: free, pro, enterprise');
    }
  }
  
  // Validate email
  if (body.email !== undefined) {
    if (typeof body.email !== 'string') {
      errors.push('email must be a string');
    } else if (!isValidEmail(body.email)) {
      errors.push('email format is invalid');
    } else if (containsHomoglyphs(body.email)) {
      errors.push('email contains suspicious characters (homoglyphs not allowed)');
    }
  }
  
  // Validate source
  if (body.source !== undefined) {
    if (typeof body.source !== 'string') {
      errors.push('source must be a string');
    } else if (body.source.length > 64) {
      errors.push('source exceeds maximum length (64)');
    }
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Validate register request body
 */
export function validateRegisterRequest(body) {
  const errors = [];
  
  if (!body || typeof body !== 'object') {
    return { valid: false, errors: ['Request body must be a JSON object'] };
  }
  
  // Email is required
  if (!body.email) {
    errors.push('email is required');
  } else if (typeof body.email !== 'string') {
    errors.push('email must be a string');
  } else if (!isValidEmail(body.email)) {
    errors.push('email format is invalid');
  } else if (containsHomoglyphs(body.email)) {
    errors.push('email contains suspicious characters (homoglyphs not allowed)');
  }
  
  // Validate company
  if (body.company !== undefined) {
    if (typeof body.company !== 'string') {
      errors.push('company must be a string');
    } else if (body.company.length > 256) {
      errors.push('company exceeds maximum length (256)');
    }
  }
  
  // Validate role
  if (body.role !== undefined) {
    if (typeof body.role !== 'string') {
      errors.push('role must be a string');
    } else if (body.role.length > 128) {
      errors.push('role exceeds maximum length (128)');
    }
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Check for homoglyph attacks (Unicode characters that look like ASCII)
 * Common in phishing: admin@exаmple.com (Cyrillic 'а' instead of Latin 'a')
 */
function containsHomoglyphs(str) {
  // Common homoglyph ranges
  const homoglyphRanges = [
    /[\u0400-\u04FF]/, // Cyrillic
    /[\u0370-\u03FF]/, // Greek
    /[\u2E80-\u2EFF]/, // CJK Radicals
    /[\u3000-\u303F]/, // CJK Symbols
    /[\uFF00-\uFFEF]/, // Fullwidth Forms
  ];
  
  return homoglyphRanges.some(range => range.test(str));
}

/**
 * Sanitize input to prevent prototype pollution
 */
export function sanitizeInput(obj) {
  if (obj === null || typeof obj !== 'object') {
    return obj;
  }
  
  if (Array.isArray(obj)) {
    return obj.map(sanitizeInput);
  }
  
  const sanitized = {};
  for (const key of Object.keys(obj)) {
    // Skip dangerous keys
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;
    }
    sanitized[key] = sanitizeInput(obj[key]);
  }
  
  return sanitized;
}

/**
 * Express middleware for request body size limiting
 */
export function limitBodySize(req, res, next) {
  let bodySize = 0;
  
  req.on('data', (chunk) => {
    bodySize += chunk.length;
    if (bodySize > MAX_REQUEST_BODY_SIZE) {
      res.status(413).json({
        error: 'Request body too large',
        limit: MAX_REQUEST_BODY_SIZE
      });
      req.destroy();
    }
  });
  
  next();
}

/**
 * Express middleware for input validation
 */
export function validateInput(validator) {
  return (req, res, next) => {
    // Sanitize input first
    req.body = sanitizeInput(req.body);
    
    // Validate
    const result = validator(req.body);
    if (!result.valid) {
      return res.status(400).json({
        error: 'Invalid request',
        details: result.errors
      });
    }
    
    next();
  };
}

export default {
  validateScanRequest,
  validateCreateKeyRequest,
  validateRegisterRequest,
  sanitizeInput,
  limitBodySize,
  validateInput,
  containsHomoglyphs,
  MAX_TOOLS_PER_SCAN,
  MAX_REQUEST_BODY_SIZE
};
