#!/usr/bin/env node
'use strict';

/**
 * Aegis CLI v3.0 — Standalone Passive HTTP/TLS/DNS Security Audit & CI/CD Quality Gate
 * Usage:
 *   node aegis-cli.js audit <url> [--method GET|HEAD|OPTIONS] [--preset essential|api-qa|compliance-full|all-on]
 *                                 [--min-score 80] [--max-high 0] [--format json|sarif|csv|md|html|pdf] [--out file]
 */

const dns = require('dns').promises;
const fs = require('fs');
const http = require('http');
const https = require('https');
const net = require('net');
const path = require('path');
const { runActiveModules } = require('./module_engine');
const {
  buildValidPdfBuffer,
  buildHtmlReport,
  buildMarkdownReport,
  buildSarifReport,
  buildCsvReport,
  computeReportSummary
} = require('./report_generator');

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const k = a.slice(2);
      const next = argv[i + 1];
      if (!next || next.startsWith('--')) {
        args[k] = true;
      } else {
        args[k] = next;
        i++;
      }
    } else {
      args._.push(a);
    }
  }
  return args;
}

function fetchHop(targetUrl, method) {
  return new Promise((resolve, reject) => {
    const lib = targetUrl.protocol === 'https:' ? https : http;
    const started = Date.now();
    const req = lib.request(
      targetUrl,
      { method, timeout: 10000, rejectUnauthorized: true, headers: { 'User-Agent': 'AegisCLI-PassiveAudit/3.0', Accept: 'text/html,application/json;q=0.9,*/*;q=0.8' } },
      (res) => {
        const chunks = [];
        let bytes = 0;
        let tlsInfo = null;
        if (targetUrl.protocol === 'https:' && res.socket && typeof res.socket.getPeerCertificate === 'function') {
          try {
            const cert = res.socket.getPeerCertificate(true);
            const cipher = typeof res.socket.getCipher === 'function' ? res.socket.getCipher() : null;
            const proto = typeof res.socket.getProtocol === 'function' ? res.socket.getProtocol() : null;
            if (cert && Object.keys(cert).length > 0) {
              const validToMs = cert.valid_to ? Date.parse(cert.valid_to) : NaN;
              const daysRemaining = Number.isFinite(validToMs) ? Math.floor((validToMs - Date.now()) / (1000 * 60 * 60 * 24)) : null;
              const sanList = cert.subjectaltname ? String(cert.subjectaltname).split(',').map(s => s.trim()).filter(Boolean) : [];
              let depth = 1;
              let cur = cert;
              const seen = new Set([cert.fingerprint256 || cert.fingerprint || 'leaf']);
              while (cur && cur.issuerCertificate && depth < 8) {
                const nxt = cur.issuerCertificate;
                const fp = nxt.fingerprint256 || nxt.fingerprint || '';
                if (!fp || seen.has(fp)) break;
                seen.add(fp);
                depth++;
                cur = nxt;
              }
              tlsInfo = {
                protocol: proto || null,
                cipher: cipher ? cipher.name : null,
                subject: cert.subject ? (cert.subject.CN || JSON.stringify(cert.subject)) : null,
                issuer: cert.issuer ? (cert.issuer.O || cert.issuer.CN || JSON.stringify(cert.issuer)) : null,
                validFrom: cert.valid_from || null,
                validTo: cert.valid_to || null,
                daysRemaining,
                sanCount: sanList.length,
                keyBits: cert.bits || null,
                keyType: cert.asn1Curve ? 'EC' : (cert.modulus ? 'RSA' : null),
                chainDepth: depth,
                selfSigned: Boolean(cert.subject && cert.issuer && JSON.stringify(cert.subject) === JSON.stringify(cert.issuer)),
                wildcardSan: sanList.some(s => s.includes('*.'))
              };
            }
          } catch {}
        }
        res.on('data', c => {
          if (bytes < 192 * 1024) chunks.push(c.subarray(0, Math.min(c.length, 192 * 1024 - bytes)));
          bytes += c.length;
          if (bytes > 256 * 1024) res.destroy();
        });
        const done = () => {
          const rawHeaders = res.headers || {};
          const flatHeaders = {};
          for (const [k, v] of Object.entries(rawHeaders)) flatHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join('; ') : String(v);
          const bodyText = Buffer.concat(chunks).toString('utf8');
          resolve({
            url: targetUrl,
            method,
            statusCode: res.statusCode,
            durationMs: Date.now() - started,
            contentType: flatHeaders['content-type'] || 'desconhecido',
            headers: flatHeaders,
            rawHeaders,
            bodyText,
            bodyPreview: bodyText.slice(0, 2400),
            tlsInfo
          });
        };
        res.on('end', done);
        res.on('close', () => { if (!res.complete) done(); });
      }
    );
    req.on('timeout', () => req.destroy(new Error('Timeout (10s)')));
    req.on('error', reject);
    req.end();
  });
}

async function fetchDns(host) {
  if (!host || net.isIP(host) !== 0 || host === 'localhost' || !host.includes('.')) {
    return { skipped: true, reason: 'Alvo IP/local' };
  }
  const t = (p, ms = 2500) => Promise.race([p.catch(() => null), new Promise(r => setTimeout(() => r(null), ms))]);
  const [caaRes, txtRes, dmarcRes, mxRes, mtaRes, nsRes, aaaaRes, bimiRes] = await Promise.all([
    t(dns.resolveCaa(host)),
    t(dns.resolveTxt(host)),
    t(dns.resolveTxt(`_dmarc.${host}`)),
    t(dns.resolveMx(host)),
    t(dns.resolveTxt(`_mta-sts.${host}`)),
    t(dns.resolveNs(host)),
    t(dns.resolve6(host)),
    t(dns.resolveTxt(`default._bimi.${host}`))
  ]);
  const flat = r => (Array.isArray(r) ? r.map(c => c.join('')) : []);
  return {
    skipped: false,
    domain: host,
    caa: Array.isArray(caaRes) ? caaRes.map(r => `${r.critical || 0} ${r.issue || r.issuewild || ''}`) : [],
    spf: flat(txtRes).find(s => /^v=spf1\b/i.test(s.trim())) || null,
    dmarc: flat(dmarcRes).find(s => /^v=dmarc1\b/i.test(s.trim())) || null,
    advancedChecked: true,
    mx: Array.isArray(mxRes) ? mxRes.map(r => `${r.priority} ${r.exchange}`) : [],
    mtaSts: flat(mtaRes).find(s => /^v=STSv1\b/i.test(s.trim())) || null,
    dkimSelectors: [],
    resilienceChecked: true,
    ns: Array.isArray(nsRes) ? nsRes : [],
    aaaa: Array.isArray(aaaaRes) ? aaaaRes : [],
    cname: [],
    bimi: flat(bimiRes).find(s => /^v=BIMI1\b/i.test(s.trim())) || null,
    danglingCnameRisk: false
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0];
  const rawTarget = args._[1];

  if (!cmd || cmd === 'help' || args.help || !rawTarget) {
    console.log([
      'Aegis CLI v3.0 — Auditoria Passiva OWASP, TLS, DNS & Quality Gate CI/CD',
      '',
      'Uso:',
      '  node aegis-cli.js audit <url> [opções]',
      '',
      'Opções:',
      '  --method <GET|HEAD|OPTIONS>     Método HTTP passivo (padrão: GET)',
      '  --min-score <0-100>             Nota mínima OWASP para aprovar gate (padrão: 0)',
      '  --max-high <N>                  Máximo permitido de achados HIGH (padrão: ilimitado)',
      '  --format <text|json|sarif|csv|md|html|pdf>  Formato de saída (padrão: text)',
      '  --out <arquivo>                 Grava relatório formatado em arquivo'
    ].join('\n'));
    process.exit(cmd && !rawTarget ? 1 : 0);
  }

  const normalized = /^https?:\/\//i.test(rawTarget) ? rawTarget : `https://${rawTarget}`;
  const startUrl = new URL(normalized);
  const method = ['GET', 'HEAD', 'OPTIONS'].includes(String(args.method || 'GET').toUpperCase())
    ? String(args.method || 'GET').toUpperCase()
    : 'GET';

  let curUrl = startUrl;
  const chain = [];
  let snap = null;
  for (let i = 0; i <= 5; i++) {
    snap = await fetchHop(curUrl, method);
    const loc = snap.headers.location || null;
    chain.push({ url: curUrl.href, host: curUrl.host, protocol: curUrl.protocol, statusCode: snap.statusCode, location: loc });
    if ([301, 302, 303, 307, 308].includes(snap.statusCode) && loc && i < 5) {
      try {
        const nextUrl = new URL(loc, curUrl);
        if (nextUrl.protocol === 'http:' || nextUrl.protocol === 'https:') { curUrl = nextUrl; continue; }
      } catch { break; }
    }
    break;
  }
  snap.redirectChain = chain;
  snap.dnsPosture = await fetchDns(snap.url.hostname);
  snap.wellKnown = {
    securityTxt: { skipped: true, reason: 'Modo CLI rápido' },
    robotsTxt: { skipped: true, reason: 'Modo CLI rápido' }
  };

  const mods = JSON.parse(fs.readFileSync(path.join(__dirname, 'modules.json'), 'utf8')).installed.map(m => ({ ...m, active: true }));
  const execOut = runActiveModules(snap, mods);

  const record = {
    timestamp: new Date().toISOString(),
    target: snap.url.href,
    host: snap.url.host,
    method: snap.method,
    status_code: snap.statusCode,
    duration_ms: snap.durationMs,
    redirect_chain: chain,
    tls_info: snap.tlsInfo,
    dns_posture: snap.dnsPosture,
    response_headers: snap.headers,
    executed_modules_count: execOut.executed_count,
    skipped_modules_count: execOut.skipped_count,
    module_results: execOut.module_results,
    owasp_score: execOut.owasp_score,
    owasp_grade: execOut.owasp_grade,
    findings_count: execOut.findings.length,
    findings: execOut.findings,
    hardening_snippets: execOut.hardening_snippets,
    compliance_matrix: execOut.compliance_matrix
  };

  const fmt = String(args.format || 'text').toLowerCase();
  const reportOpts = {
    title: `Relatório Aegis CLI — ${snap.url.host}`,
    org: 'CI/CD Security Gate',
    classification: 'Interno',
    minSeverity: 'info',
    includeModules: true,
    includeSnippets: true,
    includeHeaders: false,
    generatedAt: record.timestamp
  };
  const reportCtx = {
    appName: 'Aegis Web Console CLI',
    currentMode: 'cli',
    aiConfig: { ai_type: 'none' },
    modulesInstalled: mods,
    hosts: [{
      host: record.host,
      protocol: snap.url.protocol,
      last_status: record.status_code,
      owasp_grade: record.owasp_grade,
      owasp_score: record.owasp_score,
      findings_count: record.findings_count,
      tls_protocol: snap.tlsInfo ? snap.tlsInfo.protocol : null,
      dns_summary: null
    }],
    inspectionHistory: [record]
  };

  let outputBuf = null;
  if (fmt === 'json') outputBuf = JSON.stringify({ summary: computeReportSummary([record], reportCtx.hosts, mods, 'info'), record }, null, 2);
  else if (fmt === 'sarif') outputBuf = JSON.stringify(buildSarifReport(reportOpts, reportCtx), null, 2);
  else if (fmt === 'csv') outputBuf = buildCsvReport(reportOpts, reportCtx);
  else if (fmt === 'md') outputBuf = buildMarkdownReport(reportOpts, reportCtx);
  else if (fmt === 'html') outputBuf = buildHtmlReport(reportOpts, reportCtx);
  else if (fmt === 'pdf') outputBuf = buildValidPdfBuffer(reportOpts, reportCtx);

  if (args.out && outputBuf !== null) {
    fs.writeFileSync(args.out, outputBuf);
    console.log(`Relatório (${fmt.toUpperCase()}) gravado em: ${args.out}`);
  } else if (outputBuf !== null && fmt !== 'pdf') {
    console.log(outputBuf);
  } else {
    const highCount = execOut.findings.filter(f => f.severity === 'high').length;
    const medCount = execOut.findings.filter(f => f.severity === 'medium').length;
    const lowCount = execOut.findings.filter(f => f.severity === 'low').length;
    console.log(`[AEGIS CLI v3.0] ${record.method} ${record.status_code} ${record.target} (${record.duration_ms}ms)`);
    console.log(`OWASP: ${record.owasp_grade} (${record.owasp_score}/100) | Módulos: ${record.executed_modules_count} | Achados: ${record.findings_count} (H:${highCount} M:${medCount} L:${lowCount})`);
    for (const f of execOut.findings.slice(0, 15)) {
      console.log(`  [${f.priority}/${f.severity.toUpperCase()} · ${f.cwe} · ${f.module_id}] ${f.item}`);
    }
  }

  const minScore = args['min-score'] !== undefined ? Number(args['min-score']) : 0;
  const maxHigh = args['max-high'] !== undefined ? Number(args['max-high']) : Infinity;
  const highTotal = execOut.findings.filter(f => f.severity === 'high').length;

  const violations = [];
  if (record.owasp_score < minScore) violations.push(`Nota OWASP ${record.owasp_score} < mínimo ${minScore}`);
  if (highTotal > maxHigh) violations.push(`Achados HIGH ${highTotal} > máximo ${maxHigh}`);

  if (violations.length > 0) {
    console.error(`QUALITY GATE FAILED: ${violations.join(' | ')}`);
    process.exit(1);
  }
}

main().catch(err => {
  console.error(`Erro Aegis CLI: ${err.message}`);
  process.exit(2);
});
