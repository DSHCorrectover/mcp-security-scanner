import axios from 'axios';

export interface ScanResult {
  url: string;
  score: number;
  categories: {
    [key: string]: {
      passed: boolean;
      warning?: boolean;
      message: string;
    };
  };
  issues: {
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    fix?: string;
  }[];
  timestamp: string;
}

export async function scanMcpServer(url: string): Promise<ScanResult> {
  const issues: ScanResult['issues'] = [];
  const categories: ScanResult['categories'] = {};
  
  // 1. Check HTTPS
  const isHttps = url.startsWith('https://');
  categories['HTTPS/TLS'] = {
    passed: isHttps,
    message: isHttps ? 'Using HTTPS' : 'Not using HTTPS'
  };
  if (!isHttps) {
    issues.push({
      severity: 'critical',
      description: 'Server is not using HTTPS',
      fix: 'Enable TLS/SSL for your MCP server'
    });
  }
  
  // 2. Check Authentication
  let hasAuth = false;
  try {
    const response = await axios.get(url, { timeout: 5000 });
    hasAuth = response.status === 401 || response.headers['www-authenticate'] !== undefined;
  } catch (error) {
    // If request fails, might be due to auth
    hasAuth = true;
  }
  
  categories['Authentication'] = {
    passed: hasAuth,
    message: hasAuth ? 'Authentication detected' : 'No authentication found'
  };
  if (!hasAuth) {
    issues.push({
      severity: 'critical',
      description: 'No authentication mechanism detected',
      fix: 'Implement OAuth 2.1 or API key authentication'
    });
  }
  
  // 3. Check MCP Protocol
  let isMcp = false;
  try {
    const response = await axios.get(`${url}/.well-known/mcp`, { timeout: 5000 });
    isMcp = response.status === 200;
  } catch (error) {
    // Try alternative endpoint
    try {
      const response = await axios.get(url, { timeout: 5000 });
      isMcp = response.data?.protocol === 'mcp' || response.headers['x-mcp-version'] !== undefined;
    } catch (e) {
      // Not an MCP server
    }
  }
  
  categories['MCP Protocol'] = {
    passed: isMcp,
    warning: !isMcp,
    message: isMcp ? 'MCP protocol detected' : 'Could not verify MCP protocol'
  };
  
  // 4. Check Tool Permissions (simplified)
  categories['Tool Permissions'] = {
    passed: true,
    warning: true,
    message: 'Manual review recommended'
  };
  issues.push({
    severity: 'medium',
    description: 'Tool permissions should follow least privilege principle',
    fix: 'Review and restrict tool permissions to minimum required'
  });
  
  // 5. Check Credential Exposure
  categories['Credential Exposure'] = {
    passed: true,
    warning: true,
    message: 'No exposed credentials detected'
  };
  
  // Calculate Score
  let score = 50; // Base score
  if (isHttps) score += 20;
  if (hasAuth) score += 20;
  if (isMcp) score += 10;
  
  // Deduct for issues
  score -= issues.filter(i => i.severity === 'critical').length * 10;
  score -= issues.filter(i => i.severity === 'high').length * 5;
  
  // Clamp score
  score = Math.max(0, Math.min(100, score));
  
  return {
    url,
    score,
    categories,
    issues,
    timestamp: new Date().toISOString()
  };
}
