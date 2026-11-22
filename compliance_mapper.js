'use strict';

/**
 * Aegis Web Console v3.0 — Defensive Compliance & Remediation Mapping Engine
 * Maps passive security findings to OWASP Top 10:2021, OWASP ASVS v4.0, CWE,
 * priority tier (P1/P2/P3) and estimated remediation effort.
 */

const MODULE_COMPLIANCE_MAP = {
  'csp-auditor': {
    owasp_top10: 'A03:2021 - Injection / XSS Defense',
    asvs: 'V14.4.3',
    cwe: 'CWE-693',
    control: 'Content Security Policy',
    effort: 'Médio (30–60 min)'
  },
  'hsts-tls-checker': {
    owasp_top10: 'A02:2021 - Cryptographic Failures',
    asvs: 'V9.1.1 / V14.4.5',
    cwe: 'CWE-319',
    control: 'HTTPS & HSTS Transport',
    effort: 'Rápido (< 15 min)'
  },
  'cookie-session-auditor': {
    owasp_top10: 'A07:2021 - Identification & Authentication Failures',
    asvs: 'V3.4.1–V3.4.5',
    cwe: 'CWE-614',
    control: 'Session Cookie Hardening',
    effort: 'Rápido (< 15 min)'
  },
  'cors-samesite-auditor': {
    owasp_top10: 'A01:2021 - Broken Access Control',
    asvs: 'V14.5.3',
    cwe: 'CWE-942',
    control: 'CORS Policy Hygiene',
    effort: 'Rápido (< 15 min)'
  },
  'cross-origin-isolation': {
    owasp_top10: 'A05:2021 - Security Misconfiguration',
    asvs: 'V14.4.7',
    cwe: 'CWE-693',
    control: 'Cross-Origin Isolation (COOP/COEP/CORP)',
    effort: 'Médio (30 min)'
  },
  'clickjacking-guard': {
    owasp_top10: 'A05:2021 - Security Misconfiguration',
    asvs: 'V14.4.7',
    cwe: 'CWE-1021',
    control: 'Anti-Clickjacking Guard',
    effort: 'Rápido (< 10 min)'
  },
  'rate-limit-hygiene': {
    owasp_top10: 'A04:2021 - Insecure Design',
    asvs: 'V11.1.4',
    cwe: 'CWE-770',
    control: 'Rate Limiting & Abuse Controls',
    effort: 'Médio (30–60 min)'
  },
  'passive-leak-detector': {
    owasp_top10: 'A02:2021 - Cryptographic Failures',
    asvs: 'V7.4.1 / V14.3.3',
    cwe: 'CWE-200',
    control: 'Secret & Stack Disclosure Prevention',
    effort: 'Imediato (Crítico)'
  },
  'static-script-reviewer': {
    owasp_top10: 'A08:2021 - Software & Data Integrity Failures',
    asvs: 'V14.2.3',
    cwe: 'CWE-353',
    control: 'Subresource Integrity (SRI)',
    effort: 'Rápido (< 15 min)'
  },
  'html-link-hygiene': {
    owasp_top10: 'A05:2021 - Security Misconfiguration',
    asvs: 'V5.3.3',
    cwe: 'CWE-1022',
    control: 'DOM, Tabnabbing & Iframe Sandbox',
    effort: 'Rápido (< 15 min)'
  },
  'token-entropy': {
    owasp_top10: 'A07:2021 - Identification & Authentication Failures',
    asvs: 'V3.2.2',
    cwe: 'CWE-330',
    control: 'Cryptographic Token Entropy',
    effort: 'Médio (30 min)'
  },
  'runtime-header-review': {
    owasp_top10: 'A05:2021 - Security Misconfiguration',
    asvs: 'V14.3.3',
    cwe: 'CWE-200',
    control: 'Server Banner Suppression',
    effort: 'Rápido (< 10 min)'
  },
  'cdn-cache-review': {
    owasp_top10: 'A05:2021 - Security Misconfiguration',
    asvs: 'V8.2.1',
    cwe: 'CWE-525',
    control: 'Cache-Control Directives',
    effort: 'Rápido (< 15 min)'
  },
  'ingress-hygiene': {
    owasp_top10: 'A05:2021 - Security Misconfiguration',
    asvs: 'V14.3.3',
    cwe: 'CWE-200',
    control: 'Gateway & Upstream Header Hygiene',
    effort: 'Rápido (< 15 min)'
  },
  'json-schema-check': {
    owasp_top10: 'A05:2021 - Security Misconfiguration',
    asvs: 'V14.4.1',
    cwe: 'CWE-16',
    control: 'MIME Sniffing & JSON Hygiene',
    effort: 'Rápido (< 10 min)'
  },
  'openapi-contract-check': {
    owasp_top10: 'A04:2021 - Insecure Design',
    asvs: 'V13.1.1',
    cwe: 'CWE-1059',
    control: 'OpenAPI Contract & Auth Spec',
    effort: 'Médio (30–60 min)'
  },
  'cert-inspector': {
    owasp_top10: 'A02:2021 - Cryptographic Failures',
    asvs: 'V9.1.2',
    cwe: 'CWE-295',
    control: 'TLS Protocol & Certificate Lifecycle',
    effort: 'Médio (30 min)'
  },
  'tls-cipher-hardening': {
    owasp_top10: 'A02:2021 - Cryptographic Failures',
    asvs: 'V9.1.3',
    cwe: 'CWE-327',
    control: 'AEAD Cipher Suites & TLS 1.3',
    effort: 'Médio (30 min)'
  },
  'tls-chain-ocsp-auditor': {
    owasp_top10: 'A02:2021 - Cryptographic Failures',
    asvs: 'V9.2.1',
    cwe: 'CWE-295',
    control: 'Certificate Chain & Key Strength',
    effort: 'Médio (30–60 min)'
  },
  'form-hygiene': {
    owasp_top10: 'A05:2021 - Security Misconfiguration',
    asvs: 'V14.4.6',
    cwe: 'CWE-116',
    control: 'Referrer, Permissions & Form Actions',
    effort: 'Rápido (< 15 min)'
  },
  'dns-email-auth-check': {
    owasp_top10: 'A05:2021 - Security Misconfiguration',
    asvs: 'V14.1.1',
    cwe: 'CWE-290',
    control: 'DNS CAA / SPF / DMARC Posture',
    effort: 'Rápido (< 20 min)'
  },
  'dns-advanced-posture': {
    owasp_top10: 'A02:2021 - Cryptographic Failures',
    asvs: 'V9.2.2',
    cwe: 'CWE-290',
    control: 'DNS MX / MTA-STS / DKIM',
    effort: 'Médio (30 min)'
  },
  'dns-bimi-dangling-audit': {
    owasp_top10: 'A05:2021 - Security Misconfiguration',
    asvs: 'V14.1.4',
    cwe: 'CWE-350',
    control: 'DNS Resilience, BIMI & Dangling CNAME',
    effort: 'Médio (30 min)'
  },
  'security-txt-auditor': {
    owasp_top10: 'A05:2021 - Security Misconfiguration',
    asvs: 'V14.1.1',
    cwe: 'CWE-1059',
    control: 'RFC 9116 Vulnerability Disclosure',
    effort: 'Rápido (< 10 min)'
  },
  'robots-sitemap-hygiene': {
    owasp_top10: 'A01:2021 - Broken Access Control',
    asvs: 'V14.3.2',
    cwe: 'CWE-200',
    control: 'Robots.txt Path Disclosure',
    effort: 'Rápido (< 15 min)'
  },
  'redirect-chain-auditor': {
    owasp_top10: 'A02:2021 - Cryptographic Failures',
    asvs: 'V9.1.1',
    cwe: 'CWE-319',
    control: 'HTTPS Redirect Integrity',
    effort: 'Rápido (< 15 min)'
  },
  'subresource-thirdparty-audit': {
    owasp_top10: 'A08:2021 - Software & Data Integrity Failures',
    asvs: 'V14.2.3',
    cwe: 'CWE-829',
    control: 'Third-Party Supply-Chain Footprint',
    effort: 'Estrutural'
  },
  'api-auth-hygiene': {
    owasp_top10: 'A07:2021 - Identification & Authentication Failures',
    asvs: 'V13.1.3 / V13.2.1',
    cwe: 'CWE-287',
    control: 'API Auth, Methods & Error Hygiene',
    effort: 'Médio (30 min)'
  },
  'graphql-api-hygiene': {
    owasp_top10: 'A05:2021 - Security Misconfiguration',
    asvs: 'V13.4.1',
    cwe: 'CWE-200',
    control: 'GraphQL & API Docs Exposure',
    effort: 'Rápido (< 20 min)'
  },
  'pwa-manifest-serviceworker-audit': {
    owasp_top10: 'A05:2021 - Security Misconfiguration',
    asvs: 'V14.4.1',
    cwe: 'CWE-319',
    control: 'PWA Manifest & Service Worker TLS',
    effort: 'Rápido (< 15 min)'
  },
  'supply-chain-tech-fingerprint': {
    owasp_top10: 'A06:2021 - Vulnerable & Outdated Components',
    asvs: 'V14.2.1',
    cwe: 'CWE-1104',
    control: 'Client-Side Component Lifecycle',
    effort: 'Estrutural'
  },
  'privacy-consent-tracker-audit': {
    owasp_top10: 'A05:2021 - Security Misconfiguration',
    asvs: 'V8.3.4',
    cwe: 'CWE-359',
    control: 'LGPD / GDPR Privacy & Tracker Hygiene',
    effort: 'Médio (30–60 min)'
  }
};

const DEFAULT_MAPPING = {
  owasp_top10: 'A05:2021 - Security Misconfiguration',
  asvs: 'V14.4.1',
  cwe: 'CWE-693',
  control: 'Web Hardening Baseline',
  effort: 'Rápido (< 15 min)'
};

function priorityFromSeverity(sev) {
  const s = String(sev || 'info').toLowerCase();
  if (s === 'high') return 'P1';
  if (s === 'medium') return 'P2';
  return 'P3';
}

function enrichFindingWithCompliance(finding) {
  const modId = String(finding.module_id || '');
  const meta = MODULE_COMPLIANCE_MAP[modId] || DEFAULT_MAPPING;
  return {
    ...finding,
    owasp_top10: finding.owasp_top10 || meta.owasp_top10,
    asvs: finding.asvs || meta.asvs,
    cwe: finding.cwe || meta.cwe,
    control: finding.control || meta.control,
    priority: finding.priority || priorityFromSeverity(finding.severity),
    effort: finding.effort || meta.effort
  };
}

function buildComplianceMatrix(findings) {
  const enriched = (findings || []).map(enrichFindingWithCompliance);
  const byOwasp = new Map();
  const byCwe = new Map();
  const byPriority = { P1: 0, P2: 0, P3: 0 };

  for (const f of enriched) {
    byPriority[f.priority] = (byPriority[f.priority] || 0) + 1;

    if (!byOwasp.has(f.owasp_top10)) {
      byOwasp.set(f.owasp_top10, { category: f.owasp_top10, high: 0, medium: 0, low: 0, info: 0, total: 0, cwes: new Set() });
    }
    const row = byOwasp.get(f.owasp_top10);
    const sev = String(f.severity || 'info').toLowerCase();
    if (sev in row) row[sev]++;
    else row.info++;
    row.total++;
    if (f.cwe) row.cwes.add(f.cwe);

    if (f.cwe) {
      byCwe.set(f.cwe, (byCwe.get(f.cwe) || 0) + 1);
    }
  }

  const owaspSummary = [...byOwasp.values()]
    .map(r => ({ ...r, cwes: [...r.cwes].sort() }))
    .sort((a, b) => (b.high * 10 + b.medium * 4 + b.total) - (a.high * 10 + a.medium * 4 + a.total));

  const topCwes = [...byCwe.entries()]
    .map(([cwe, count]) => ({ cwe, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 12);

  const remediationPlan = {
    P1: enriched.filter(f => f.priority === 'P1').map(f => ({
      module_id: f.module_id,
      cwe: f.cwe,
      owasp_top10: f.owasp_top10,
      item: f.item,
      recommendation: f.recommendation,
      effort: f.effort
    })),
    P2: enriched.filter(f => f.priority === 'P2').map(f => ({
      module_id: f.module_id,
      cwe: f.cwe,
      owasp_top10: f.owasp_top10,
      item: f.item,
      recommendation: f.recommendation,
      effort: f.effort
    })),
    P3: enriched.filter(f => f.priority === 'P3').map(f => ({
      module_id: f.module_id,
      cwe: f.cwe,
      owasp_top10: f.owasp_top10,
      item: f.item,
      recommendation: f.recommendation,
      effort: f.effort
    }))
  };

  return {
    priority_counts: byPriority,
    owasp_top10: owaspSummary,
    top_cwes: topCwes,
    remediation_plan: remediationPlan
  };
}

module.exports = {
  MODULE_COMPLIANCE_MAP,
  enrichFindingWithCompliance,
  buildComplianceMatrix,
  priorityFromSeverity
};
