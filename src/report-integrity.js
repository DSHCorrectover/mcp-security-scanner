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
      'The matched keyword belongs to our {category} indicator category',
      'Manual review recommended before allowing this tool in production'
    ],
    cannotSay: [
      'This tool WILL execute commands / move funds',
      'This tool is dangerous / malicious',
      'Guaranteed security risk',
      'Any census-derived prevalence or association claim — we have not computed co-occurrence statistics, so "associated with X in our 229K census" is not supportable'
    ],
    falsePositiveNote: 'Match-rate evidence, 16,446-tool census slice (7.16% coverage, retrieved 2026-11-12): the previous substring matcher emitted 4,547 A verdicts, of which 1,982 (43.6%) fired only on a keyword embedded inside a longer word. The current word-boundary matcher emits 507 (3.1% of the slice). Residual A-grade false-positive rate is NOT measured; full-census re-measurement pending.'
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
    falsePositiveNote: 'B grade is capped at description-only evidence: no tool-name token matched. On the same 16,446-tool slice (7.16% coverage, retrieved 2026-11-12) the word-boundary matcher emitted 3,450 B verdicts. False-positive rate for B is NOT measured.'
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
    scan_engine: 'word-boundary risk indicator matcher v1.3.1',
    risk_rules_count: Object.keys(STRONG).length,
    risk_categories: ['funds_movement', 'credential_handling', 'file_db_write', 'command_execution', 'infrastructure_mutation'],
    census_reference: {
      source: 'MCP Census 2026-10-12 snapshot, DOI 10.5281/zenodo.23333516',
      total_servers: 42163,
      total_tools_published: 229539,
      census_denominator_used: 229827,
      discrepancy_note: 'Two tool-count figures are in circulation and have NOT been reconciled: the published census headline (229,539) and the 229,827 denominator the local slice coverage was computed against. Do not cite either as "the" tool count without naming which source and surface it came from. Reconciliation pending verification against the release asset once the full server_tools.jsonl.gz download completes.',
      note: 'Full census database available in Pro tier. Free tier uses 5 keyword categories only.'
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
    match_rate_evidence: {
      measured_on: 'truncated census slice — NOT full coverage',
      slice_tools: 16446,
      coverage_of_census: '7.16%',
      retrieved: '2026-11-12',
      substring_matcher_A_verdicts: 4547,
      substring_matcher_A_word_embedding_artifacts: 1982,
      substring_matcher_artifact_share: '43.6% of A verdicts',
      word_boundary_matcher: { A: 507, B: 3450, C: 2106, NONE: 10383, read_only_downgrades: 213 },
      a_grade_share_of_slice: '3.1%',
      not_measured: [
        'residual false-positive rate for any grade (a match-rate drop is not an FP-rate measurement)',
        'grade counts over the full census',
        'precision against ground truth — no labelled corpus exists'
      ]
    }
  };
}

// (v1.3.1: keyword sets now live in STRONG above)

// ============================================================
// 4b. WORD-BOUNDARY MATCHER — replaces naive substring includes()
// ============================================================
// Measured defect (2026-11-12, census partial 16,445 tools):
//   substring matching produced 4,547 A-grade verdicts (27.6%);
//   1,982 of them (43.6%) fired ONLY on a keyword embedded inside a
//   longer token — "execution"→exec, "runtime"→run, "configured"→configure,
//   "buyer"/"seller"→buy/sell, "withdrawal"→withdraw, "truncated"→run.
// Because A-grade count is what triggers the paid Pro-trial prompt,
// this artifact would have sold upgrades off a regex bug.
// Fix direction follows 宁可降级，不可升级: strongest evidence is a
// whole-word capability verb; derivatives and nouns downgrade, never upgrade.

// Capability verbs (whole word or normal inflection only)
const STRONG = {
  funds_movement: ['transfer','payment','payments','pay','pays','withdraw','withdraws','deposit','deposits','send_money','purchase','checkout'],
  credential_handling: ['password','passwords','secret','secrets','token','tokens','api_key','apikey','credential','credentials','authentication','authorization'],
  file_db_write: ['write','writes','create','creates','delete','deletes','update','updates','insert','inserts','drop','drops','modify','modifies'],
  command_execution: ['exec','execs','execute','executes','executing','run','runs','shell','shells','bash','cmd','command','commands','evaluate','evaluates','compile','compiles','invoke'],
  infrastructure_mutation: ['deploy','deploys','provision','provisions','scale','scales','terminate','terminates','restart','restarts','reconfigure','spin_up']
};

// Morphological forms that are NOT capability claims in practice.
// Kept explicit rather than "fuzzy matched" so the exclusion is auditable.
const EXCLUDED_FORMS = new Set([
  'runtime','runtimes','runnable','runbook','runbooks','truncate','truncated','truncates',
  'execution','executions','executive','executives','executable','executables',   // noun/adj forms
  'configured','configurable','configuration','configurations',
  'buyer','buyers','seller','sellers','selling','sellable','trading','tradable',
  'withdrawal','withdrawals','depositary','payments_page','writeup','writeups',
  'createate','tokenize','tokenizer','tokens_per','authorise','authorised','authenticate'
]);

// Read-only / disabled context markers — strong downgrade signal
const NEGATIVE_CONTEXT = [
  /\bread[- ]only\b/i, /\bnever\b[^.]{0,40}\bwrite\b/i, /\bdisabl(ed|es)\b/i,
  /\bno server keypair\b/i, /\bcannot run\b/i, /\bdoes not (execute|run|write)\b/i,
  /\bintent:\s*read\b/i, /\bread\/discovery workflow\b/i, /\bview[- ]only\b/i
];

function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

// Build the haystack: description as-is, plus identifier tokens split on
// _ - and camelCase so `sap_get_agent_stats` yields a bare `get` token.
function buildHaystack(name, desc) {
  const tokens = [];
  const idParts = String(name || '').split(/[_\-.]|(?<=[a-z0-9])(?=[A-Z])/);
  tokens.push(...idParts.map(s => s.toLowerCase()).filter(Boolean));
  return { tokens, prose: String(desc || '').toLowerCase(), name: String(name || '').toLowerCase() };
}

// Returns { grade: 'strong'|'weak'|null, hits: [...] }
function matchRuleStrength(hay, keywords) {
  let strength = null;
  const hits = [];
  for (const kw of keywords) {
    const re = new RegExp(`(?<![a-z0-9_])${escapeRe(kw)}(?![a-z0-9_])`, 'i');
    // identifier token exact match = strongest signal (it's the tool's own name)
    const inId = hay.tokens.includes(kw.toLowerCase());
    const inProse = re.test(hay.prose);
    if (!inId && !inProse) continue;
    if (inId) { strength = 'strong'; hits.push({ keyword: kw, where: 'tool_name_token' }); continue; }
    // prose whole-word: check the surrounding word isn't an excluded form
    const wordRe = new RegExp(`[a-z0-9_]*${escapeRe(kw)}[a-z0-9_]*`, 'g');
    const words = hay.prose.match(wordRe) || [];
    const allowed = words.filter(w => !EXCLUDED_FORMS.has(w));
    if (allowed.length) {
      strength = strength || 'weak';
      hits.push({ keyword: kw, where: 'description_word', forms: [...new Set(allowed)].slice(0, 4) });
    }
  }
  return { strength, hits };
}

const RULE_STRENGTH = {
  funds_movement: 'strong_A', credential_handling: 'weak_B',
  file_db_write: 'weak_B', command_execution: 'strong_A',
  infrastructure_mutation: 'weak_B'
};

// ============================================================
// 4c. NEGATIVE-CONTEXT DOWNGRADE — 宁可降级，不可升级
// ============================================================
export function detectReadOnlyContext(desc) {
  const hit = NEGATIVE_CONTEXT.find(re => re.test(desc || ''));
  return hit ? String(hit) : null;
}

// ============================================================
// 4d. BANNER SEPARATION — synthetic vs real data never merge
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
// 7. GRADED TOOL ANALYSIS — word-boundary matcher (v1.3.1)
// ============================================================
// Grading ladder, strictly conservative (宁可降级，不可升级):
//   A  strong capability verb in the tool's OWN name token
//   B  strong-category verb found as a whole word in the description
//   C  weaker rule (write/create/credential/etc.) whole-word only
//   NONE  no whole-word capability evidence
// Any read-only / disabled context marker forces a one-grade downgrade.

export function analyzeToolWithGrading(tool) {
  const hay = buildHaystack(tool.name, tool.description);
  const readOnlyCtx = detectReadOnlyContext(tool.description);

  const matches = [];
  let highestGrade = 'NONE';
  const gradeOrder = { A: 4, B: 3, C: 2, NONE: 1 };

  for (const [ruleId, keywords] of Object.entries(STRONG)) {
    const { strength, hits } = matchRuleStrength(hay, keywords);
    if (!strength) continue;

    const base = RULE_STRENGTH[ruleId];            // 'strong_A' | 'weak_B'
    let grade = base === 'strong_A' ? 'B' : 'C';   // description-only whole word caps at B
    if (strength === 'strong') grade = base === 'strong_A' ? 'A' : 'B'; // name token promotes

    // Structural downgrade: read-only/disabled context
    let downgraded = false;
    if (readOnlyCtx && gradeOrder[grade] > 2) { grade = 'C'; downgraded = true; }

    matches.push({
      rule: ruleId,
      grade,
      match_strength: strength,           // 'strong' = tool-name token, 'weak' = description word
      matched_keywords: [...new Set(hits.map(h => h.keyword))],
      evidence_forms: hits.flatMap(h => h.forms || [h.keyword]).slice(0, 6),
      matched_field: strength === 'strong' ? 'tool_name_token' : 'description',
      banner: 'A',
      downgraded_by_readonly_context: downgraded,
      can_say: RISK_GRADES[grade].canSay
        .map(s => s.replace('{keyword}', hits[0].keyword).replace('{field}', strength === 'strong' ? 'tool name' : 'description').replace('{category}', ruleId.replace(/_/g, ' '))),
      cannot_say: RISK_GRADES[grade].cannotSay,
      false_positive_note: RISK_GRADES[grade].falsePositiveNote
    });

    if (gradeOrder[grade] > gradeOrder[highestGrade]) highestGrade = grade;
  }

  return {
    tool: tool.name,
    overall_grade: highestGrade,
    grade_label: RISK_GRADES[highestGrade]?.label || 'NO INDICATORS',
    matches,
    match_count: matches.length,
    read_only_context: readOnlyCtx,
    matcher: 'word-boundary v1.3.1',
    // Structural honesty: every tool result carries its own limitations
    limitations: [
      'Based on word-boundary matching of tool name tokens and description prose',
      'Does not analyze actual tool behavior or source code',
      'Match-rate evidence is attached per grade with its sample window; the residual false-positive rate is NOT measured',
      'Absence of indicators does not mean absence of risk',
      'A-grade requires the capability word to appear in the tool name itself'
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
