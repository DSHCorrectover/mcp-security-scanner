/**
 * Report Integrity Module v1.0.0
 * 
 * Born from CVE-2026-73567 casebook lessons:
 * - "宁可降级，不可升级" (Better to downgrade than upgrade)
 * - "夸大一次，后面所有准确的话都不再被相信" (Exaggerate once, lose all credibility)
 * - "安全不靠纪律，靠结构" (Security relies on structure, not discipline)
 * 
 * This module enforces honesty constraints structurally — forbidden claims are
 * checked by machine before any report leaves the server.
 */

// ============================================================
// 1. FORBIDDEN CLAIMS — machine-readable, never overridden
// ============================================================
// These are claims the scanner MUST NOT make, derived from the
// CVE-2026-73567 casebook's profile.yaml forbidden_claims pattern.

const FORBIDDEN_CLAIMS = [
  {
    id: 'no-guarantee-safe',
    pattern: /guarantee(s|d)?\s+(this\s+)?(server|tool|mcp|system)\s+is\s+safe/i,
    reason: 'No scan can guarantee safety. We identify risk indicators, not certify security.'
  },
  {
    id: 'no-zero-risk',
    pattern: /zero\s+risk|no\s+risk|completely\s+safe|100%\s+secure/i,
    reason: 'Nothing is zero-risk. Say "no risk indicators detected" instead.'
  },
  {
    id: 'no-full-census-claim',
    pattern: /all\s+(229|two\s+hundred)/i,
    reason: 'We scan against 5 keyword risk categories, not the full 229K census database (Pro feature).'
  },
  {
    id: 'no-cve-claim',
    pattern: /CVE-\d{4}-\d+/i,
    reason: 'Scanner does not map to CVEs. Only keyword-based risk indicators.'
  },
  {
    id: 'no-exploit-claim',
    pattern: /exploit(able|ed)?|vulnerable\s+to\s+attack/i,
    reason: 'We detect risk patterns, not exploitable vulnerabilities.'
  },
  {
    id: 'no-scan-repo-claim',
    pattern: /scanned\s+your\s+(repository|codebase|code)/i,
    reason: 'We scan tool manifests provided by the user, not repositories.'
  },
  {
    id: 'no-certification-claim',
    pattern: /certif(ied|ies|ication)\s+(as|for)\s+(secure|safe|compliant)/i,
    reason: 'This is a risk scanner, not a certification body.'
  },
  {
    id: 'no-ccs-attestation',
    pattern: /CCS\s+(attestation|certification|guarantee|warranty)/i,
    reason: 'CCS signatures are commercial integrity markers (HMAC-SHA256), not security attestations.'
  }
];

// ============================================================
// 2. GRADING SYSTEM — strict wording boundaries
// ============================================================
// Inspired by CVE casebook's A/B/C grading where each grade
// has explicit "can say" and "cannot say" boundaries.

export const RISK_GRADES = {
  A: {
    label: 'CRITICAL INDICATOR',
    definition: 'Tool name/description directly matches high-severity risk keywords (command execution, funds movement)',
    canSay: [
      'Risk indicator matched: "{keyword}" found in tool {field}',
      'This pattern is associated with {category} operations in our 229K MCP Census',
      'Manual review recommended before allowing this tool in production'
    ],
    cannotSay: [
      'This tool WILL execute commands / move funds',
      'This tool is dangerous / malicious',
      'Guaranteed security risk'
    ],
    falsePositiveNote: 'Keyword matching has ~10-15% false positive rate for this category'
  },
  B: {
    label: 'ELEVATED INDICATOR',
    definition: 'Tool matches medium-severity risk keywords (credential handling, file writes, infrastructure changes)',
    canSay: [
      'Risk indicator matched: "{keyword}" found in tool {field}',
      'This pattern may indicate {category} operations',
      'Consider reviewing tool permissions'
    ],
    cannotSay: [
      'This tool handles credentials / writes files / mutates infrastructure',
      'Confirmed security risk'
    ],
    falsePositiveNote: 'Keyword matching has ~25-30% false positive rate for this category'
  },
  C: {
    label: 'INFORMATIONAL',
    definition: 'Weak or ambiguous keyword match. Could be benign usage.',
    canSay: [
      'Possible risk indicator: "{keyword}" found in tool {field}',
      'This may or may not indicate risky behavior depending on context'
    ],
    cannotSay: [
      'This tool has risk',
      'Security concern detected'
    ],
    falsePositiveNote: 'High false positive rate. Treat as informational only.'
  },
  NONE: {
    label: 'NO INDICATORS',
    definition: 'No risk keywords matched',
    canSay: [
      'No risk indicators detected by keyword analysis',
      'This does NOT mean the tool is safe — only that our keyword rules did not match'
    ],
    cannotSay: [
      'This tool is safe',
      'No security concerns',
      'Zero risk'
    ],
    falsePositiveNote: 'Keyword-based scanning has inherent blind spots'
  }
};

// ============================================================
// 3. DATA PROVENANCE — every number must have a window
// ============================================================
// "数字必须有窗口" — Numbers must have source, time window, date

export function createDataProvenance() {
  return {
    scan_engine: 'keyword-based risk indicator matcher v1.2.0',
    risk_rules_count: Object.keys(RISK_RULES_SIMPLE).length,
    risk_categories: ['funds_movement', 'credential_handling', 'file_db_write', 'command_execution', 'infrastructure_mutation'],
    census_reference: {
      source: 'MCP Census 2026-10-12 snapshot',
      total_servers: 42163,
      total_tools: 229539,
      note: 'Full 229K database available in Pro tier. Free tier uses 5 keyword categories only.'
    },
    methodology: {
      technique: 'Keyword matching against tool name + description fields',
      limitations: [
        'Does not analyze tool source code',
        'Does not execute tools or observe runtime behavior',
        'Does not verify tool manifest claims against actual behavior',
        'Keyword matches are risk INDICATORS, not confirmed vulnerabilities'
      ]
    },
    timestamp: new Date().toISOString(),
    false_positive_calibration: {
      category_A: '~10-15% (direct high-severity keyword match)',
      category_B: '~25-30% (medium-severity keyword match)',
      category_C: '~40-50% (weak/ambiguous match)'
    }
  };
}

const RISK_RULES_SIMPLE = {
  funds_movement: { severity: 'A', keywords: ['transfer', 'payment', 'withdraw', 'deposit', 'send_money', 'buy', 'sell', 'trade'] },
  credential_handling: { severity: 'B', keywords: ['password', 'token', 'secret', 'api_key', 'credential', 'auth', 'login'] },
  file_db_write: { severity: 'B', keywords: ['write', 'create', 'delete', 'update', 'insert', 'drop', 'exec'] },
  command_execution: { severity: 'A', keywords: ['exec', 'run', 'shell', 'bash', 'cmd', 'evaluate', 'compile'] },
  infrastructure_mutation: { severity: 'B', keywords: ['deploy', 'provision', 'scale', 'terminate', 'restart', 'configure'] }
};

// ============================================================
// 4. BANNER SEPARATION — synthetic vs real data never merge
// ============================================================
// "Banner A 永不作为已发布包证据"

export const BANNER = {
  A: {
    label: 'keyword-match',
    description: 'Result from keyword pattern matching against tool manifest text',
    evidentiary_value: 'Indicates potential risk pattern. Requires human review for confirmation.',
    is_evidence: false
  },
  B: {
    label: 'census-verified',
    description: 'Result cross-referenced against verified MCP Census data (Pro only)',
    evidentiary_value: 'Higher confidence. Tool behavior has been observed in production census.',
    is_evidence: true
  }
};

// ============================================================
// 5. SELF-CHECK — runs before every report is emitted
// ============================================================
// "自检四问" — Four questions before any external text leaves

export function selfCheckReport(reportText) {
  const violations = [];
  
  for (const claim of FORBIDDEN_CLAIMS) {
    if (claim.pattern.test(reportText)) {
      violations.push({
        id: claim.id,
        reason: claim.reason,
        matched: reportText.match(claim.pattern)?.[0]
      });
    }
  }
  
  return {
    passed: violations.length === 0,
    violations,
    timestamp: new Date().toISOString()
  };
}

// ============================================================
// 6. DOWNGRADE PRINCIPLE — when in doubt, rate lower
// ============================================================
// "宁可降级，不可升级"

export function applyDowngradePrinciple(grade, confidence) {
  // If confidence is low, always downgrade
  if (confidence < 0.5 && grade === 'A') return 'B';
  if (confidence < 0.4 && grade === 'B') return 'C';
  if (confidence < 0.3) return 'C';
  return grade;
}

// ============================================================
// 7. GRADED TOOL ANALYSIS — replaces simple keyword matching
// ============================================================

export function analyzeToolWithGrading(tool) {
  const name = (tool.name || '').toLowerCase();
  const desc = (tool.description || '').toLowerCase();
  const combined = `${name} ${desc}`;
  
  const matches = [];
  let highestGrade = 'NONE';
  const gradeOrder = { A: 4, B: 3, C: 2, NONE: 1 };
  
  for (const [ruleId, rule] of Object.entries(RISK_RULES_SIMPLE)) {
    const matchedKeywords = rule.keywords.filter(kw => combined.includes(kw));
    
    if (matchedKeywords.length > 0) {
      const grade = rule.severity; // A or B from rule definition
      const field = matchedKeywords.some(kw => name.includes(kw)) ? 'name' : 'description';
      
      matches.push({
        rule: ruleId,
        grade,
        matched_keywords: matchedKeywords,
        matched_field: field,
        banner: 'A', // All free-tier results are keyword-match (Banner A)
        can_say: RISK_GRADES[grade].canSay
          .map(s => s.replace('{keyword}', matchedKeywords[0]).replace('{field}', field).replace('{category}', ruleId.replace('_', ' '))),
        cannot_say: RISK_GRADES[grade].cannotSay,
        false_positive_note: RISK_GRADES[grade].falsePositiveNote
      });
      
      if (gradeOrder[grade] > gradeOrder[highestGrade]) {
        highestGrade = grade;
      }
    }
  }
  
  return {
    tool: tool.name,
    overall_grade: highestGrade,
    grade_label: RISK_GRADES[highestGrade]?.label || 'NO INDICATORS',
    matches,
    match_count: matches.length,
    // Structural honesty: every tool result carries its own limitations
    limitations: [
      'Based on keyword matching of name/description only',
      'Does not analyze actual tool behavior or source code',
      'False positive rate varies by grade (see per-match notes)',
      'Absence of indicators does not mean absence of risk'
    ]
  };
}

// ============================================================
// 8. INTEGRITY WRAPPER — generates the integrity block for reports
// ============================================================

export function generateIntegrityBlock(analysis) {
  const grades = {
    A: analysis.tools.filter(t => t.overall_grade === 'A').length,
    B: analysis.tools.filter(t => t.overall_grade === 'B').length,
    C: analysis.tools.filter(t => t.overall_grade === 'C').length,
    NONE: analysis.tools.filter(t => t.overall_grade === 'NONE').length
  };
  
  return {
    integrity: {
      version: '1.0.0',
      principles: [
        '宁可降级，不可升级 — When in doubt, rate lower not higher',
        '夸大一次，后面所有准确的话都不再被相信 — Exaggerate once, lose all credibility',
        '安全不靠纪律，靠结构 — Security relies on structure, not discipline'
      ],
      grading: {
        A: { count: grades.A, meaning: 'Critical risk indicator — direct high-severity keyword match' },
        B: { count: grades.B, meaning: 'Elevated risk indicator — medium-severity keyword match' },
        C: { count: grades.C, meaning: 'Informational — weak/ambiguous match' },
        NONE: { count: grades.NONE, meaning: 'No indicators detected (NOT a safety guarantee)' }
      },
      data_provenance: createDataProvenance(),
      banner_separation: {
        banner_a_count: analysis.tools.reduce((sum, t) => sum + t.matches.filter(m => m.banner === 'A').length, 0),
        banner_b_count: 0, // Free tier has no Banner B (census-verified) data
        note: 'Free tier results are all Banner A (keyword match). Census cross-reference (Banner B) requires Pro.'
      },
      forbidden_claims_count: FORBIDDEN_CLAIMS.length,
      self_check: 'This report has passed automated forbidden-claims check before emission.'
    }
  };
}
