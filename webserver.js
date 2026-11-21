#!/usr/bin/env node
'use strict';

const dns = require('dns').promises;
const express = require('express');
const fs = require('fs');
const http = require('http');
const https = require('https');
const net = require('net');
const path = require('path');
const {
  runActiveModules,
  autoSelectModulesForContext,
  analyzeCspHeader,
  validateJsonAgainstSchema,
  auditOpenApiSpec
} = require('./module_engine');

const APP_NAME = 'Aegis Web Console';
const APP_SLUG = 'aegis-web';
const PORT = Number(process.env.PORT) || 3002;
const ALLOWED_MODES = new Set(['manual', 'ai-automation']);
const ALLOWED_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const ALLOWED_AI_TYPES = new Set(['ollama', 'none']);
const ALLOWED_CUSTOM_HEADERS = new Set(['accept', 'accept-language', 'origin', 'cache-control']);
const MODEL_RE = /^[a-zA-Z0-9._:/-]{1,128}$/;
const SEVERITY_RANK = { info: 1, low: 2, medium: 3, high: 4 };

const PRESET_SETS = {
  essential: new Set([
    'csp-auditor',
    'hsts-tls-checker',
    'cookie-session-auditor',
    'cors-samesite-auditor',
    'clickjacking-guard',
    'header-extractor',
    'json-schema-check',
    'cert-inspector',
    'token-entropy',
    'decoder-encoder',
    'response-comparer',
    'url-parser',
    'http-history',
    'request-inspector',
    'owasp-compliance'
  ]),
  'api-qa': new Set([
    'request-inspector',
    'header-extractor',
    'http-history',
    'json-schema-check',
    'openapi-contract-check',
    'cors-samesite-auditor',
    'rate-limit-hygiene',
    'hsts-tls-checker',
    'cert-inspector',
    'tls-cipher-hardening',
    'runtime-header-review',
    'passive-leak-detector',
    'decoder-encoder',
    'token-entropy',
    'owasp-compliance'
  ]),
  'compliance-full': new Set([
    'request-inspector',
    'header-extractor',
    'http-history',
    'csp-auditor',
    'hsts-tls-checker',
    'cert-inspector',
    'tls-cipher-hardening',
    'cookie-session-auditor',
    'cors-samesite-auditor',
    'cross-origin-isolation',
    'clickjacking-guard',
    'rate-limit-hygiene',
    'form-hygiene',
    'static-script-reviewer',
    'html-link-hygiene',
    'runtime-header-review',
    'passive-leak-detector',
    'cdn-cache-review',
    'ingress-hygiene',
    'json-schema-check',
    'openapi-contract-check',
    'dns-email-auth-check',
    'host-inventory',
    'owasp-compliance'
  ])
};

const MAX_HISTORY = 30;
const CONFIG_PATH = path.join(__dirname, 'ai_config.json');
const MODULES_PATH = path.join(__dirname, 'modules.json');
const INDEX_PATH = path.join(__dirname, 'index.html');

let currentMode = 'manual';
let inspectionHistory = [];
const hostInventory = new Map();

let aiConfig = {
  ai_type: 'ollama',
  ai_endpoint: 'http://127.0.0.1:11434',
  ai_model: 'deepseek-v4-heretic:9b'
};

let modulesConfig = { installed: [] };

function atomicWriteJson(filePath, data) {
  const tmpPath = `${filePath}.tmp`;
  fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2) + '\n', 'utf8');
  fs.renameSync(tmpPath, filePath);
}

function isValidHttpUrl(input) {
  try {
    const u = new URL(input);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

function normalizeTargetUrl(rawTarget) {
  const trimmed = String(rawTarget || '').trim();
  if (!trimmed || trimmed.length > 2048) return null;
  const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    const u = new URL(candidate);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    if (!u.hostname) return null;
    return u;
  } catch {
    return null;
  }
}

function sanitizeFilenamePart(raw) {
  const cleaned = String(raw || `${APP_SLUG}-report`)
    .replace(/[^a-zA-Z0-9._-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 64);
  return cleaned || `${APP_SLUG}-report`;
}

function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function loadAiConfig() {
  try {
    const raw = fs.readFileSync(CONFIG_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object') {
      if (ALLOWED_AI_TYPES.has(parsed.ai_type)) aiConfig.ai_type = parsed.ai_type;
      if (typeof parsed.ai_endpoint === 'string' && isValidHttpUrl(parsed.ai_endpoint)) {
        aiConfig.ai_endpoint = parsed.ai_endpoint.replace(/\/+$/, '');
      }
      if (typeof parsed.ai_model === 'string' && MODEL_RE.test(parsed.ai_model)) {
        aiConfig.ai_model = parsed.ai_model;
      }
    }
  } catch (err) {
    console.warn('Usando configuração padrão de IA:', err.message);
  }
}

function saveAiConfig() {
  atomicWriteJson(CONFIG_PATH, aiConfig);
}

function loadModules() {
  try {
    const raw = fs.readFileSync(MODULES_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    if (parsed && Array.isArray(parsed.installed)) {
      modulesConfig.installed = parsed.installed
        .map(item => ({
          id: String(item.id || '').trim(),
          name: String(item.name || item.id || '').trim(),
          description: String(item.description || '').trim(),
          category: String(item.category || 'general').trim(),
          active: Boolean(item.active)
        }))
        .filter(m => m.id.length > 0);
    }
  } catch (err) {
    console.error('Erro ao carregar modules.json:', err.message);
    modulesConfig.installed = [
      { id: 'csp-auditor', name: 'CSP Policy Auditor', description: 'Analisa Content-Security-Policy', category: 'headers', active: true },
      { id: 'decoder-encoder', name: 'Decoder / Encoder & JWT', description: 'Decodificação utilitária', category: 'workbench', active: true },
      { id: 'http-history', name: 'Inspection History Ledger', description: 'Histórico de inspeções', category: 'workbench', active: true }
    ];
  }
}

function saveModules() {
  atomicWriteJson(MODULES_PATH, modulesConfig);
}

function applyModuleSelection(selectedIds) {
  const validIds = new Set(modulesConfig.installed.map(m => m.id));
  const chosen = new Set([...selectedIds].filter(id => validIds.has(id)));
  if (chosen.size === 0) return [];
  for (const mod of modulesConfig.installed) {
    mod.active = chosen.has(mod.id);
  }
  saveModules();
  return [...chosen];
}

// Consulta DNS pública estritamente passiva (CAA, SPF e DMARC) com timeout curto
async function fetchPassiveDnsPosture(hostname) {
  const host = String(hostname || '').trim().toLowerCase().replace(/\.$/, '');
  if (!host || net.isIP(host) !== 0 || host === 'localhost' || host.endsWith('.local') || !host.includes('.')) {
    return { skipped: true, reason: 'Alvo IP ou hostname local (sem DNS público)' };
  }
  const withTimeout = (promise, ms) => Promise.race([
    promise.catch(() => null),
    new Promise(resolve => setTimeout(() => resolve(null), ms))
  ]);

  const [caaRes, txtRes, dmarcRes] = await Promise.all([
    withTimeout(dns.resolveCaa(host), 2500),
    withTimeout(dns.resolveTxt(host), 2500),
    withTimeout(dns.resolveTxt(`_dmarc.${host}`), 2500)
  ]);

  const flatTxt = Array.isArray(txtRes) ? txtRes.map(chunks => chunks.join('')) : [];
  const flatDmarc = Array.isArray(dmarcRes) ? dmarcRes.map(chunks => chunks.join('')) : [];
  const spf = flatTxt.find(t => /^v=spf1\b/i.test(t.trim())) || null;
  const dmarc = flatDmarc.find(t => /^v=dmarc1\b/i.test(t.trim())) || null;
  const caa = Array.isArray(caaRes) ? caaRes.map(r => `${r.critical || 0} ${r.issue ? `issue "${r.issue}"` : (r.issuewild ? `issuewild "${r.issuewild}"` : JSON.stringify(r))}`) : [];

  return {
    skipped: false,
    domain: host,
    caa,
    spf,
    dmarc
  };
}

// Requisição HTTP passiva controlada (GET / HEAD / OPTIONS) com captura de metadados TLS
function fetchPassiveSnapshot(targetUrl, method = 'GET', customHeaders = {}) {
  return new Promise((resolve, reject) => {
    const safeMethod = ALLOWED_METHODS.has(method) ? method : 'GET';
    const lib = targetUrl.protocol === 'https:' ? https : http;
    const reqHeaders = {
      'User-Agent': 'AegisWebConsole-PassiveAudit/1.1',
      'Accept': 'text/html,application/json;q=0.9,*/*;q=0.8'
    };

    let sentOrigin = null;
    if (customHeaders && typeof customHeaders === 'object') {
      for (const [k, v] of Object.entries(customHeaders)) {
        const lk = String(k).toLowerCase().trim();
        const val = String(v || '').replace(/[\r\n]/g, '').trim().slice(0, 256);
        if (ALLOWED_CUSTOM_HEADERS.has(lk) && val) {
          reqHeaders[lk] = val;
          if (lk === 'origin') sentOrigin = val;
        }
      }
    }

    const started = Date.now();
    const req = lib.request(
      targetUrl,
      {
        method: safeMethod,
        timeout: 10000,
        rejectUnauthorized: true,
        headers: reqHeaders
      },
      (res) => {
        const chunks = [];
        let totalBytes = 0;
        const maxCapture = 192 * 1024;

        let tlsInfo = null;
        if (targetUrl.protocol === 'https:' && res.socket && typeof res.socket.getPeerCertificate === 'function') {
          try {
            const cert = res.socket.getPeerCertificate();
            const cipher = typeof res.socket.getCipher === 'function' ? res.socket.getCipher() : null;
            const proto = typeof res.socket.getProtocol === 'function' ? res.socket.getProtocol() : null;
            if (cert && Object.keys(cert).length > 0) {
              const validToMs = cert.valid_to ? Date.parse(cert.valid_to) : NaN;
              const daysRemaining = Number.isFinite(validToMs)
                ? Math.floor((validToMs - Date.now()) / (1000 * 60 * 60 * 24))
                : null;
              const sanList = cert.subjectaltname
                ? String(cert.subjectaltname).split(',').map(s => s.trim()).filter(Boolean)
                : [];
              tlsInfo = {
                protocol: proto || null,
                cipher: cipher ? cipher.name : null,
                subject: cert.subject ? (cert.subject.CN || JSON.stringify(cert.subject)) : null,
                issuer: cert.issuer ? (cert.issuer.O || cert.issuer.CN || JSON.stringify(cert.issuer)) : null,
                validFrom: cert.valid_from || null,
                validTo: cert.valid_to || null,
                daysRemaining,
                sanCount: sanList.length,
                sansSample: sanList.slice(0, 8)
              };
            }
          } catch {
            tlsInfo = null;
          }
        }

        res.on('data', chunk => {
          if (totalBytes < maxCapture) {
            const sliceLen = Math.min(chunk.length, maxCapture - totalBytes);
            chunks.push(chunk.subarray(0, sliceLen));
          }
          totalBytes += chunk.length;
          if (totalBytes > 256 * 1024) res.destroy();
        });

        const finalize = () => {
          const durationMs = Date.now() - started;
          const rawHeaders = res.headers || {};
          const flatHeaders = {};
          for (const [k, v] of Object.entries(rawHeaders)) {
            flatHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join('; ') : String(v);
          }
          const bodyText = Buffer.concat(chunks).toString('utf8');
          resolve({
            url: targetUrl,
            method: safeMethod,
            sentOrigin,
            statusCode: res.statusCode,
            durationMs,
            contentType: flatHeaders['content-type'] || 'desconhecido',
            headers: flatHeaders,
            rawHeaders,
            bodyText,
            bodyPreview: bodyText.slice(0, 2400),
            tlsInfo
          });
        };

        res.on('end', finalize);
        res.on('close', () => {
          if (!res.complete) finalize();
        });
      }
    );

    req.on('timeout', () => req.destroy(new Error('Tempo limite excedido (10s) ao consultar o alvo.')));
    req.on('error', err => reject(err));
    req.end();
  });
}

function filterFindingsBySeverity(findings, minSeverity) {
  const minRank = SEVERITY_RANK[String(minSeverity || 'info').toLowerCase()] || 1;
  return (findings || []).filter(f => (SEVERITY_RANK[String(f.severity || 'info').toLowerCase()] || 1) >= minRank);
}

// Gerador PDF 1.4 válido e independente com opções de personalização
function pdfEscapeText(str) {
  return String(str || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^\x20-\x7E]/g, ' ')
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)');
}

function wrapText(text, maxChars) {
  const words = String(text || '').split(/\s+/);
  const lines = [];
  let cur = '';
  for (const w of words) {
    if (!cur) cur = w;
    else if (cur.length + 1 + w.length <= maxChars) cur += ' ' + w;
    else {
      lines.push(cur);
      cur = w;
    }
  }
  if (cur) lines.push(cur);
  return lines.length ? lines : [''];
}

function buildValidPdfBuffer(opts) {
  const lines = [];
  lines.push({ text: opts.title, size: 15, bold: true });
  lines.push({ text: `Organizacao: ${opts.org} | Classificacao: ${opts.classification}`, size: 9.5, bold: true });
  lines.push({ text: `Gerado em: ${opts.generatedAt} | Filtro Severidade >= ${opts.minSeverity.toUpperCase()}`, size: 8.8, bold: false });
  lines.push({ text: `Plataforma: ${APP_NAME} | Modo: ${currentMode} | IA: ${aiConfig.ai_type} (${aiConfig.ai_model})`, size: 8.8, bold: false });
  lines.push({ text: '--------------------------------------------------------------------------', size: 9, bold: false });

  if (opts.includeModules) {
    const activeMods = modulesConfig.installed.filter(m => m.active);
    lines.push({ text: `Modulos Defensivos Ativos (${activeMods.length}/${modulesConfig.installed.length}):`, size: 11, bold: true });
    if (activeMods.length === 0) {
      lines.push({ text: '  - Nenhum modulo ativo no momento.', size: 9, bold: false });
    } else {
      for (const mod of activeMods) {
        for (const wrapped of wrapText(`- ${mod.name} (${mod.id} | ${mod.category}): ${mod.description}`, 84)) {
          lines.push({ text: `  ${wrapped}`, size: 8.6, bold: false });
        }
      }
    }
    lines.push({ text: '', size: 7, bold: false });
  }

  lines.push({ text: `Inspecoes Passivas OWASP (${inspectionHistory.length}):`, size: 11, bold: true });
  if (inspectionHistory.length === 0) {
    lines.push({ text: '  - Nenhuma inspecao executada nesta sessao.', size: 9, bold: false });
  } else {
    for (const insp of inspectionHistory.slice(0, 10)) {
      const filtFindings = filterFindingsBySeverity(insp.findings, opts.minSeverity);
      lines.push({
        text: `  * [${insp.method} ${insp.status_code}] ${insp.target} (${insp.duration_ms}ms) | OWASP: ${insp.owasp_grade} (${insp.owasp_score}/100) | Achados: ${filtFindings.length}`,
        size: 9,
        bold: true
      });
      if (insp.tls_info) {
        lines.push({
          text: `      TLS: ${insp.tls_info.protocol || 'n/a'} / ${insp.tls_info.cipher || 'n/a'} | CN: ${insp.tls_info.subject || 'n/a'} | Expira em: ${insp.tls_info.daysRemaining ?? '?'}d`,
          size: 8.2,
          bold: false
        });
      }
      if (insp.dns_posture && !insp.dns_posture.skipped) {
        lines.push({
          text: `      DNS: CAA=${insp.dns_posture.caa.length ? 'OK' : 'ausente'} | SPF=${insp.dns_posture.spf ? 'OK' : 'ausente'} | DMARC=${insp.dns_posture.dmarc ? 'OK' : 'ausente'}`,
          size: 8.2,
          bold: false
        });
      }
      for (const f of filtFindings.slice(0, 12)) {
        for (const wrapped of wrapText(`[${f.severity.toUpperCase()} | ${f.module_id}] ${f.item} -> ${f.recommendation}`, 80)) {
          lines.push({ text: `      ${wrapped}`, size: 8.2, bold: false });
        }
      }
      if (opts.includeSnippets && insp.hardening_snippets && insp.hardening_snippets.missing_count > 0) {
        lines.push({ text: '      Hardening Nginx sugerido:', size: 8.3, bold: true });
        for (const sLine of String(insp.hardening_snippets.nginx || '').split('\n').slice(0, 10)) {
          for (const wrapped of wrapText(sLine, 78)) {
            lines.push({ text: `        ${wrapped}`, size: 7.8, bold: false });
          }
        }
      }
      if (opts.includeHeaders && insp.response_headers) {
        lines.push({ text: '      Cabecalhos Recebidos (amostra):', size: 8.3, bold: true });
        for (const [hk, hv] of Object.entries(insp.response_headers).slice(0, 12)) {
          for (const wrapped of wrapText(`${hk}: ${hv}`, 78)) {
            lines.push({ text: `        ${wrapped}`, size: 7.8, bold: false });
          }
        }
      }
    }
  }

  const pages = [];
  let currentPageOps = [];
  let y = 790;
  for (const item of lines) {
    const lineH = item.size + 4.8;
    if (y - lineH < 50) {
      pages.push(currentPageOps.join('\n'));
      currentPageOps = [];
      y = 790;
    }
    const fontKey = item.bold ? '/F2' : '/F1';
    currentPageOps.push(`BT ${fontKey} ${item.size} Tf 48 ${y} Td (${pdfEscapeText(item.text)}) Tj ET`);
    y -= lineH;
  }
  if (currentPageOps.length || pages.length === 0) pages.push(currentPageOps.join('\n'));

  const objects = [];
  const addObj = (content) => {
    objects.push(content);
    return objects.length;
  };

  const fontRegularId = addObj('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
  const fontBoldId = addObj('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>');
  const pageIds = [];
  const pagesObjId = addObj('');

  for (const stream of pages) {
    const streamBuf = Buffer.from(stream, 'ascii');
    const contentId = addObj(`<< /Length ${streamBuf.length} >>\nstream\n${stream}\nendstream`);
    const pageId = addObj(
      `<< /Type /Page /Parent ${pagesObjId} 0 R /MediaBox [0 0 595 842] ` +
      `/Resources << /Font << /F1 ${fontRegularId} 0 R /F2 ${fontBoldId} 0 R >> >> ` +
      `/Contents ${contentId} 0 R >>`
    );
    pageIds.push(pageId);
  }

  objects[pagesObjId - 1] = `<< /Type /Pages /Kids [${pageIds.map(id => `${id} 0 R`).join(' ')}] /Count ${pageIds.length} >>`;
  const catalogId = addObj(`<< /Type /Catalog /Pages ${pagesObjId} 0 R >>`);
  const infoId = addObj(`<< /Title (${pdfEscapeText(opts.title)}) /Author (${pdfEscapeText(opts.org)}) /Producer (${pdfEscapeText(APP_NAME)}) >>`);

  let pdf = '%PDF-1.4\n';
  const offsets = [0];
  for (let i = 0; i < objects.length; i++) {
    offsets.push(Buffer.byteLength(pdf, 'utf8'));
    pdf += `${i + 1} 0 obj\n${objects[i]}\nendobj\n`;
  }
  const xrefOffset = Buffer.byteLength(pdf, 'utf8');
  pdf += `xref\n0 ${objects.length + 1}\n`;
  pdf += '0000000000 65535 f \n';
  for (let i = 1; i <= objects.length; i++) {
    pdf += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root ${catalogId} 0 R /Info ${infoId} 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
  return Buffer.from(pdf, 'utf8');
}

function buildHtmlReport(opts) {
  const activeMods = modulesConfig.installed.filter(m => m.active);
  const inspBlocks = inspectionHistory.map(insp => {
    const filt = filterFindingsBySeverity(insp.findings, opts.minSeverity);
    const findingsHtml = filt.length
      ? `<ul>${filt.map(f => `<li><span class="sev sev-${escapeHtml(f.severity)}">${escapeHtml(f.severity.toUpperCase())}</span> <strong>[${escapeHtml(f.module_id)}]</strong> ${escapeHtml(f.item)} — <em>${escapeHtml(f.recommendation)}</em></li>`).join('')}</ul>`
      : '<p>Nenhuma observação acima da severidade selecionada.</p>';
    const tlsHtml = insp.tls_info
      ? `<p><strong>TLS:</strong> ${escapeHtml(insp.tls_info.protocol || 'n/a')} (${escapeHtml(insp.tls_info.cipher || 'n/a')}) · CN: ${escapeHtml(insp.tls_info.subject || 'n/a')} · Expira em ${escapeHtml(insp.tls_info.daysRemaining ?? '?')} dias</p>`
      : '';
    const dnsHtml = insp.dns_posture && !insp.dns_posture.skipped
      ? `<p><strong>Postura DNS:</strong> CAA=${insp.dns_posture.caa.length ? 'OK' : 'ausente'} · SPF=${insp.dns_posture.spf ? 'OK' : 'ausente'} · DMARC=${insp.dns_posture.dmarc ? 'OK' : 'ausente'}</p>`
      : '';
    const snippetsHtml = opts.includeSnippets && insp.hardening_snippets && insp.hardening_snippets.missing_count > 0
      ? `<h4>Snippets de Hardening Sugeridos</h4><pre>${escapeHtml(insp.hardening_snippets.nginx)}</pre><pre>${escapeHtml(insp.hardening_snippets.express)}</pre>`
      : '';
    const headersHtml = opts.includeHeaders && insp.response_headers
      ? `<h4>Cabeçalhos HTTP Recebidos</h4><pre>${escapeHtml(Object.entries(insp.response_headers).map(([k, v]) => `${k}: ${v}`).join('\n'))}</pre>`
      : '';
    return `<section class="card"><h3>[${escapeHtml(insp.method)} ${escapeHtml(insp.status_code)}] ${escapeHtml(insp.target)} <span class="grade">OWASP ${escapeHtml(insp.owasp_grade)} (${escapeHtml(insp.owasp_score)}/100)</span></h3><p>Latência: ${escapeHtml(insp.duration_ms)}ms · Módulos executados: ${escapeHtml(insp.executed_modules_count)}</p>${tlsHtml}${dnsHtml}${findingsHtml}${snippetsHtml}${headersHtml}</section>`;
  }).join('') || '<section class="card"><p>Nenhuma inspeção executada nesta sessão.</p></section>';

  const modsHtml = opts.includeModules
    ? `<section class="card"><h2>Módulos Defensivos Ativos (${activeMods.length}/${modulesConfig.installed.length})</h2><ul>${activeMods.map(m => `<li><strong>${escapeHtml(m.name)}</strong> (${escapeHtml(m.id)} · ${escapeHtml(m.category)}): ${escapeHtml(m.description)}</li>`).join('') || '<li>Nenhum módulo ativo.</li>'}</ul></section>`
    : '';

  return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><title>${escapeHtml(opts.title)}</title><style>body{font-family:system-ui,sans-serif;max-width:980px;margin:2rem auto;padding:0 1rem;color:#0f172a;background:#f8fafc}header{background:#0b132b;color:#fff;padding:1.4rem;border-radius:8px;margin-bottom:1.2rem}header h1{margin:0 0 .4rem;font-size:1.4rem}.meta{font-size:.86rem;color:#cbd5e1}.card{background:#fff;border:1px solid #e2e8f0;border-left:4px solid #0f766e;border-radius:8px;padding:1rem 1.2rem;margin-bottom:1rem}.grade{background:#0f766e;color:#fff;padding:.15rem .55rem;border-radius:999px;font-size:.8rem;margin-left:.5rem}.sev{display:inline-block;padding:.1rem .45rem;border-radius:4px;font-size:.75rem;font-weight:700}.sev-high{background:#fee2e2;color:#991b1b}.sev-medium{background:#ffedd5;color:#9a3412}.sev-low{background:#fef3c7;color:#92400e}.sev-info{background:#e0f2fe;color:#075985}pre{background:#0b132b;color:#e2e8f0;padding:.8rem;border-radius:6px;overflow-x:auto;font-size:.8rem}@media print{body{background:#fff}}</style></head><body><header><h1>${escapeHtml(opts.title)}</h1><div class="meta">Organização: ${escapeHtml(opts.org)} · Classificação: ${escapeHtml(opts.classification)} · Gerado em: ${escapeHtml(opts.generatedAt)} · Severidade mínima: ${escapeHtml(opts.minSeverity.toUpperCase())}</div></header>${modsHtml}${inspBlocks}</body></html>`;
}

function buildMarkdownReport(opts) {
  const lines = [
    `# ${opts.title}`,
    '',
    `- **Organização:** ${opts.org}`,
    `- **Classificação:** ${opts.classification}`,
    `- **Plataforma:** ${APP_NAME} (Modo: \`${currentMode}\`)`,
    `- **Gerado em:** ${opts.generatedAt}`,
    `- **Filtro de severidade mínima:** \`${opts.minSeverity.toUpperCase()}\``,
    ''
  ];

  if (opts.includeModules) {
    const activeMods = modulesConfig.installed.filter(m => m.active);
    lines.push(`## Módulos Defensivos Ativos (${activeMods.length}/${modulesConfig.installed.length})`, '');
    for (const m of activeMods) {
      lines.push(`- **${m.name}** (\`${m.id}\` · ${m.category}): ${m.description}`);
    }
    lines.push('');
  }

  lines.push(`## Inspeções Passivas OWASP (${inspectionHistory.length})`, '');
  if (inspectionHistory.length === 0) {
    lines.push('_Nenhuma inspeção executada nesta sessão._');
  } else {
    for (const insp of inspectionHistory) {
      const filt = filterFindingsBySeverity(insp.findings, opts.minSeverity);
      lines.push(`### [${insp.method} ${insp.status_code}] ${insp.target}`);
      lines.push(`- **Nota OWASP:** **${insp.owasp_grade} (${insp.owasp_score}/100)** | **Latência:** ${insp.duration_ms}ms | **Módulos executados:** ${insp.executed_modules_count}`);
      if (insp.tls_info) {
        lines.push(`- **TLS:** ${insp.tls_info.protocol || 'n/a'} / ${insp.tls_info.cipher || 'n/a'} | CN: \`${insp.tls_info.subject || 'n/a'}\` | Expira em: ${insp.tls_info.daysRemaining ?? '?'} dias`);
      }
      if (insp.dns_posture && !insp.dns_posture.skipped) {
        lines.push(`- **DNS:** CAA=${insp.dns_posture.caa.length ? 'OK' : 'ausente'} | SPF=${insp.dns_posture.spf ? 'OK' : 'ausente'} | DMARC=${insp.dns_posture.dmarc ? 'OK' : 'ausente'}`);
      }
      lines.push('');
      if (filt.length > 0) {
        lines.push('#### Observações & Recomendações');
        for (const f of filt) {
          lines.push(`- **[${f.severity.toUpperCase()} · \`${f.module_id}\`]** ${f.item} — ${f.recommendation}`);
        }
        lines.push('');
      }
      if (opts.includeSnippets && insp.hardening_snippets && insp.hardening_snippets.missing_count > 0) {
        lines.push('#### Hardening Nginx Sugerido', '```nginx', insp.hardening_snippets.nginx, '```', '');
      }
      if (opts.includeHeaders && insp.response_headers) {
        lines.push('#### Cabeçalhos HTTP Recebidos', '```http');
        for (const [k, v] of Object.entries(insp.response_headers)) lines.push(`${k}: ${v}`);
        lines.push('```', '');
      }
    }
  }
  return lines.join('\n');
}

async function callAI(message, config) {
  if (config.ai_type !== 'ollama') {
    throw new Error('Somente provedor local Ollama está habilitado nesta instalação standalone.');
  }
  const model = config.ai_model || 'deepseek-v4-heretic:9b';
  const endpoint = (config.ai_endpoint || 'http://127.0.0.1:11434').replace(/\/+$/, '');

  const prompt = [
    `Você é o assistente defensivo de engenharia web e OWASP da plataforma ${APP_NAME}.`,
    'Responda sempre em Português do Brasil (pt-BR), de forma direta, técnica e objetiva.',
    'Forneça apenas recomendações defensivas, análise de cabeçalhos, cookies, TLS, OpenAPI e seleção enxuta de módulos defensivos; nunca gere payloads ofensivos.',
    'Sempre recomende ativar apenas o subconjunto mínimo de módulos necessários para economizar CPU/memória.',
    `Solicitação do operador: ${message}`
  ].join('\n');

  const resp = await fetch(`${endpoint}/api/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model, prompt, stream: false }),
    signal: AbortSignal.timeout(45000)
  });

  if (!resp.ok) throw new Error(`Endpoint Ollama retornou HTTP ${resp.status}`);
  const data = await resp.json();
  return data.response || '';
}

loadAiConfig();
loadModules();

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'");
  const start = Date.now();
  res.on('finish', () => {
    console.log(`${req.method} ${req.path} ${res.statusCode} ${Date.now() - start}ms`);
  });
  next();
});

app.get(['/', '/index.html'], (req, res) => {
  res.sendFile(INDEX_PATH);
});

app.get(['/inspector', '/workbench', '/modules', '/inventory', '/ai', '/reports'], (req, res) => {
  const section = req.path.replace('/', '') || 'home';
  res.redirect(`/#${section}`);
});

// Status geral
app.get('/api/status', (req, res) => {
  const activeCount = modulesConfig.installed.filter(m => m.active).length;
  const last = inspectionHistory[0] || null;
  res.json({
    app: APP_NAME,
    slug: APP_SLUG,
    mode: currentMode,
    ai_active: aiConfig.ai_type !== 'none',
    ai_config: {
      ai_type: aiConfig.ai_type,
      ai_endpoint: aiConfig.ai_endpoint,
      ai_model: aiConfig.ai_model
    },
    modules_active: activeCount,
    modules_total: modulesConfig.installed.length,
    inspections_count: inspectionHistory.length,
    hosts_count: hostInventory.size,
    last_grade: last ? last.owasp_grade : null,
    last_score: last ? last.owasp_score : null,
    timestamp: new Date().toISOString()
  });
});

app.post('/api/mode', (req, res) => {
  const mode = String((req.body && req.body.mode) || '').trim();
  if (!ALLOWED_MODES.has(mode)) {
    return res.status(400).json({ error: 'Modo inválido. Use "manual" ou "ai-automation".' });
  }
  currentMode = mode;
  res.json({ success: true, mode: currentMode });
});

// Endpoints defensivos de QA: validação OpenAPI/JSON Schema e auditoria offline de CSP
app.post('/api/qa/validate-schema', (req, res) => {
  const { mode, payload, schema } = req.body || {};
  const m = String(mode || 'openapi').trim().toLowerCase();

  try {
    const parsedPayload = typeof payload === 'string' ? JSON.parse(payload) : payload;
    if (m === 'openapi') {
      const result = auditOpenApiSpec(parsedPayload);
      return res.json({ success: true, mode: 'openapi', ...result });
    }
    if (m === 'json-schema') {
      const parsedSchema = typeof schema === 'string' ? JSON.parse(schema) : schema;
      if (!parsedSchema || typeof parsedSchema !== 'object') {
        return res.status(400).json({ error: 'Informe um JSON Schema válido.' });
      }
      const errors = validateJsonAgainstSchema(parsedPayload, parsedSchema);
      return res.json({
        success: true,
        mode: 'json-schema',
        valid: errors.length === 0,
        error_count: errors.length,
        errors
      });
    }
    return res.status(400).json({ error: 'Modo inválido. Use "openapi" ou "json-schema".' });
  } catch (err) {
    return res.status(400).json({ error: `Erro ao interpretar JSON: ${err.message}` });
  }
});

app.post('/api/qa/audit-csp', (req, res) => {
  const csp = String((req.body && req.body.csp) || '').trim();
  if (!csp) return res.status(400).json({ error: 'Informe um cabeçalho Content-Security-Policy para auditar.' });
  const result = analyzeCspHeader(csp, Boolean(req.body && req.body.report_only));
  res.json({ success: true, ...result });
});

// Configuração e chat IA local
app.get('/api/ai/config', (req, res) => {
  res.json({ success: true, config: aiConfig });
});

app.post('/api/ai/config', (req, res) => {
  const { ai_type, ai_endpoint, ai_model } = req.body || {};
  if (ai_type !== undefined) {
    if (!ALLOWED_AI_TYPES.has(ai_type)) {
      return res.status(400).json({ error: 'Tipo de IA inválido. Use "ollama" ou "none".' });
    }
    aiConfig.ai_type = ai_type;
  }
  if (ai_endpoint !== undefined) {
    if (!isValidHttpUrl(ai_endpoint)) {
      return res.status(400).json({ error: 'Endpoint de IA inválido (use http:// ou https://).' });
    }
    aiConfig.ai_endpoint = String(ai_endpoint).replace(/\/+$/, '');
  }
  if (ai_model !== undefined) {
    if (!MODEL_RE.test(String(ai_model))) {
      return res.status(400).json({ error: 'Nome de modelo inválido.' });
    }
    aiConfig.ai_model = String(ai_model);
  }
  saveAiConfig();
  res.json({ success: true, config: aiConfig });
});

app.post('/api/ai/chat', async (req, res) => {
  const { message, mode } = req.body || {};
  if (!message || !String(message).trim()) {
    return res.status(400).json({ error: 'Mensagem necessária.' });
  }

  const effectiveMode = ALLOWED_MODES.has(mode) ? mode : currentMode;
  const lowMsg = String(message).toLowerCase();
  const explicitRequest = lowMsg.includes('analis') || lowMsg.includes('analyze') || lowMsg.includes('verif') || lowMsg.includes('teste') || lowMsg.includes('recomend');
  const shouldAnalyze = aiConfig.ai_type !== 'none' && (effectiveMode === 'ai-automation' || explicitRequest);

  if (!shouldAnalyze) {
    return res.json({
      response: 'IA sob demanda desativada para este contexto. Ative o modo "ai-automation" ou solicite explicitamente uma análise.',
      ai_active: false
    });
  }

  try {
    const response = await callAI(String(message), aiConfig);
    res.json({ response, ai_active: true, model: aiConfig.ai_model });
  } catch (err) {
    res.status(502).json({ error: `Erro ao consultar IA local: ${err.message}` });
  }
});

app.post('/api/ai/recommend-modules', async (req, res) => {
  const { context, apply } = req.body || {};
  const ctxText = String(context || '').trim();
  if (!ctxText) {
    return res.status(400).json({ error: 'Descreva o contexto da aplicação para recomendar módulos.' });
  }

  const catalog = modulesConfig.installed.map(m => `${m.id}: ${m.description}`).join('\n');
  let selectedIds = [];
  let rationale = '';

  if (aiConfig.ai_type === 'ollama') {
    try {
      const prompt = [
        'Escolha entre 5 e 9 IDs de módulos defensivos desta lista que melhor atendam ao contexto informado (para evitar sobrecarga).',
        'Retorne primeiro uma linha iniciando com "IDS:" seguida dos IDs separados por vírgula, e depois uma explicação curta em pt-BR.',
        `Catálogo:\n${catalog}`,
        `Contexto do operador: ${ctxText}`
      ].join('\n');
      rationale = await callAI(prompt, aiConfig);
      const validSet = new Set(modulesConfig.installed.map(m => m.id));
      const match = rationale.match(/IDS\s*:\s*([^\n]+)/i);
      if (match) {
        selectedIds = match[1]
          .split(/[,;\s]+/)
          .map(s => s.trim().replace(/^`|`$/g, ''))
          .filter(id => validSet.has(id));
      }
      if (selectedIds.length === 0) {
        for (const mod of modulesConfig.installed) {
          if (rationale.includes(mod.id)) selectedIds.push(mod.id);
        }
      }
    } catch (err) {
      rationale = `Seleção determinística aplicada (IA local indisponível: ${err.message}).`;
    }
  }

  if (selectedIds.length === 0) {
    const low = ctxText.toLowerCase();
    const picks = new Set(['request-inspector', 'header-extractor', 'csp-auditor', 'owasp-compliance']);
    if (low.includes('jwt') || low.includes('token') || low.includes('auth') || low.includes('sess')) {
      picks.add('decoder-encoder');
      picks.add('token-entropy');
      picks.add('cookie-session-auditor');
    }
    if (low.includes('api') || low.includes('json') || low.includes('rest') || low.includes('openapi') || low.includes('swagger')) {
      picks.add('json-schema-check');
      picks.add('openapi-contract-check');
      picks.add('cors-samesite-auditor');
      picks.add('rate-limit-hygiene');
    }
    if (low.includes('tls') || low.includes('https') || low.includes('cert')) {
      picks.add('hsts-tls-checker');
      picks.add('cert-inspector');
      picks.add('tls-cipher-hardening');
    }
    if (low.includes('cdn') || low.includes('cache') || low.includes('proxy') || low.includes('ingress')) {
      picks.add('cdn-cache-review');
      picks.add('ingress-hygiene');
    }
    if (low.includes('html') || low.includes('site') || low.includes('form') || low.includes('web')) {
      picks.add('clickjacking-guard');
      picks.add('static-script-reviewer');
      picks.add('form-hygiene');
      picks.add('html-link-hygiene');
      picks.add('cross-origin-isolation');
    }
    if (low.includes('dns') || low.includes('dmarc') || low.includes('spf') || low.includes('caa') || low.includes('domínio') || low.includes('dominio')) {
      picks.add('dns-email-auth-check');
    }
    selectedIds = [...picks];
    if (!rationale) rationale = 'Subconjunto defensivo selecionado automaticamente para evitar sobrecarga.';
  }

  const applied = apply ? applyModuleSelection(selectedIds) : [];
  res.json({ success: true, recommended_ids: selectedIds, applied_ids: applied, rationale });
});

// Gerenciador de Módulos (30 extensões defensivas plugáveis)
app.get('/api/modules', (req, res) => {
  const byCategory = {};
  for (const mod of modulesConfig.installed) {
    byCategory[mod.category] = (byCategory[mod.category] || 0) + 1;
  }
  res.json({
    installed: modulesConfig.installed,
    stats: {
      total: modulesConfig.installed.length,
      active: modulesConfig.installed.filter(m => m.active).length,
      categories: byCategory
    }
  });
});

app.post('/api/modules/bulk', (req, res) => {
  const preset = String((req.body && req.body.preset) || '').trim();
  const validPresets = new Set(['all-off', 'all-on', 'essential', 'api-qa', 'compliance-full']);
  if (!validPresets.has(preset)) {
    return res.status(400).json({ error: 'Preset inválido. Use essential, api-qa, compliance-full, all-on ou all-off.' });
  }
  for (const mod of modulesConfig.installed) {
    if (preset === 'all-off') mod.active = false;
    else if (preset === 'all-on') mod.active = true;
    else mod.active = PRESET_SETS[preset].has(mod.id);
  }
  saveModules();
  res.json({
    success: true,
    preset,
    active: modulesConfig.installed.filter(m => m.active).length,
    total: modulesConfig.installed.length
  });
});

app.post('/api/modules/:id', (req, res) => {
  const id = String(req.params.id || '').trim();
  const mode = String((req.body && req.body.mode) || 'toggle').trim();
  const mod = modulesConfig.installed.find(m => m.id === id);

  if (!mod) return res.status(404).json({ error: `Módulo "${id}" não encontrado.` });
  if (mode === 'toggle') mod.active = !mod.active;
  else if (mode === 'activate') mod.active = true;
  else if (mode === 'deactivate') mod.active = false;
  else return res.status(400).json({ error: 'Modo inválido. Use toggle, activate ou deactivate.' });

  saveModules();
  res.json({ success: true, id: mod.id, active: mod.active, mode });
});

// Motor de Inspeção Passiva Modular (executa APENAS os módulos defensivos ativos)
app.post('/api/inspect/run', async (req, res) => {
  const { target, mode, method, custom_headers } = req.body || {};
  const parsedUrl = normalizeTargetUrl(target);
  if (!parsedUrl) {
    return res.status(400).json({ error: 'Informe uma URL ou hostname HTTP/HTTPS válido.' });
  }

  const reqMethod = String(method || 'GET').toUpperCase();
  if (!ALLOWED_METHODS.has(reqMethod)) {
    return res.status(400).json({ error: 'Método inválido. Use GET, HEAD ou OPTIONS (inspeção passiva).' });
  }

  const effectiveMode = ALLOWED_MODES.has(mode) ? mode : currentMode;
  const dnsActive = effectiveMode === 'ai-automation' || modulesConfig.installed.some(m => m.id === 'dns-email-auth-check' && m.active);

  try {
    const [snapshot, dnsPosture] = await Promise.all([
      fetchPassiveSnapshot(parsedUrl, reqMethod, custom_headers),
      dnsActive ? fetchPassiveDnsPosture(parsedUrl.hostname) : Promise.resolve({ skipped: true, reason: 'Módulo DNS inativo' })
    ]);
    snapshot.dnsPosture = dnsPosture;

    const recommendedIds = autoSelectModulesForContext(snapshot);
    let activatedModules = null;

    if (effectiveMode === 'ai-automation') {
      activatedModules = applyModuleSelection(recommendedIds);
    }

    const execOut = runActiveModules(snapshot, modulesConfig.installed);

    const record = {
      task_id: `aegis-${Date.now()}`,
      timestamp: new Date().toISOString(),
      target: snapshot.url.href,
      host: snapshot.url.host,
      method: snapshot.method,
      mode: effectiveMode,
      status_code: snapshot.statusCode,
      duration_ms: snapshot.durationMs,
      content_type: snapshot.contentType,
      tls_info: snapshot.tlsInfo,
      dns_posture: snapshot.dnsPosture,
      response_headers: snapshot.headers,
      body_preview: snapshot.bodyPreview,
      executed_modules_count: execOut.executed_count,
      skipped_modules_count: execOut.skipped_count,
      module_results: execOut.module_results,
      recommended_modules: recommendedIds,
      activated_modules: activatedModules,
      owasp_score: execOut.owasp_score,
      owasp_grade: execOut.owasp_grade,
      findings_count: execOut.findings.length,
      findings: execOut.findings,
      hardening_snippets: execOut.hardening_snippets,
      status: 'completed'
    };

    if (effectiveMode === 'ai-automation' && aiConfig.ai_type === 'ollama') {
      try {
        const summaryPrompt = `Resuma em até 4 tópicos objetivos e defensivos (pt-BR) as melhorias prioritárias para esta inspeção passiva (Nota OWASP ${record.owasp_grade} / ${record.owasp_score}):\n${JSON.stringify({
          target: record.target,
          status_code: record.status_code,
          modules_executed: record.module_results.map(m => `${m.module_id}:${m.status}`),
          findings: record.findings.slice(0, 12)
        })}`;
        record.ai_summary = await callAI(summaryPrompt, aiConfig);
      } catch (aiErr) {
        record.ai_summary = `IA local indisponível no momento (${aiErr.message}).`;
      }
    }

    const historyModActive = modulesConfig.installed.some(m => m.id === 'http-history' && m.active);
    if (historyModActive || inspectionHistory.length === 0) {
      inspectionHistory.unshift(record);
      if (inspectionHistory.length > MAX_HISTORY) {
        inspectionHistory = inspectionHistory.slice(0, MAX_HISTORY);
      }
    }

    hostInventory.set(snapshot.url.host, {
      host: snapshot.url.host,
      protocol: snapshot.url.protocol,
      last_status: snapshot.statusCode,
      owasp_grade: record.owasp_grade,
      owasp_score: record.owasp_score,
      findings_count: record.findings_count,
      tls_protocol: snapshot.tlsInfo ? snapshot.tlsInfo.protocol : null,
      dns_summary: dnsPosture && !dnsPosture.skipped
        ? `CAA:${dnsPosture.caa.length ? 'OK' : '-'} SPF:${dnsPosture.spf ? 'OK' : '-'} DMARC:${dnsPosture.dmarc ? 'OK' : '-'}`
        : null,
      last_seen: record.timestamp
    });

    res.json({ success: true, ...record });
  } catch (err) {
    res.status(502).json({ error: `Falha ao inspecionar alvo: ${err.message}` });
  }
});

app.get('/api/inspect/history', (req, res) => {
  res.json({ history: inspectionHistory });
});

app.delete('/api/inspect/history', (req, res) => {
  inspectionHistory = [];
  hostInventory.clear();
  res.json({ success: true });
});

app.get('/api/inventory', (req, res) => {
  res.json({ hosts: [...hostInventory.values()] });
});

// Relatórios personalizáveis (PDF 1.4, HTML estilizado, Markdown e JSON)
app.get('/api/report', (req, res) => {
  const format = String(req.query.format || 'pdf').toLowerCase();
  const titleText = String(req.query.title || `Relatório de Inspeção Passiva — ${APP_NAME}`).trim().slice(0, 120);
  const orgText = String(req.query.org || 'Equipe de Engenharia & Segurança').trim().slice(0, 80);
  const classification = String(req.query.classification || 'Interno').trim().slice(0, 32);
  const minSeverity = ['info', 'low', 'medium', 'high'].includes(String(req.query.min_severity || '').toLowerCase())
    ? String(req.query.min_severity).toLowerCase()
    : 'info';
  const includeModules = req.query.include_modules !== 'false';
  const includeSnippets = req.query.include_snippets !== 'false';
  const includeHeaders = req.query.include_headers === 'true';

  const safeBase = sanitizeFilenamePart(req.query.filename || titleText || `${APP_SLUG}-report`);
  const stamp = new Date().toISOString().slice(0, 10);
  const reportOpts = {
    title: titleText,
    org: orgText,
    classification,
    minSeverity,
    includeModules,
    includeSnippets,
    includeHeaders,
    generatedAt: new Date().toISOString()
  };

  if (format === 'json') {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${safeBase}-${stamp}.json"`);
    return res.json({
      platform: APP_NAME,
      report: reportOpts,
      mode: currentMode,
      modules_active: includeModules ? modulesConfig.installed.filter(m => m.active) : undefined,
      hosts: [...hostInventory.values()],
      inspections: inspectionHistory.map(i => ({
        ...i,
        findings: filterFindingsBySeverity(i.findings, minSeverity),
        response_headers: includeHeaders ? i.response_headers : undefined,
        hardening_snippets: includeSnippets ? i.hardening_snippets : undefined
      }))
    });
  }

  if (format === 'md' || format === 'markdown') {
    const md = buildMarkdownReport(reportOpts);
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${safeBase}-${stamp}.md"`);
    return res.send(md);
  }

  if (format === 'html') {
    const docHtml = buildHtmlReport(reportOpts);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${safeBase}-${stamp}.html"`);
    return res.send(docHtml);
  }

  const pdfBuffer = buildValidPdfBuffer(reportOpts);
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${safeBase}-${stamp}.pdf"`);
  return res.send(pdfBuffer);
});

app.use('/api', (req, res) => {
  res.status(404).json({ error: 'Endpoint de API não encontrado.' });
});

app.listen(PORT, () => {
  console.log(`${APP_NAME} (${APP_SLUG}) rodando na porta ${PORT} (${modulesConfig.installed.length} módulos)`);
  console.log(`IA Config: ${aiConfig.ai_type} / ${aiConfig.ai_model}`);
});
