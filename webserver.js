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
  computeInspectionDelta,
  analyzeCspHeader,
  validateJsonAgainstSchema,
  auditOpenApiSpec
} = require('./module_engine');
const {
  filterFindingsBySeverity,
  computeReportSummary,
  buildValidPdfBuffer,
  buildHtmlReport,
  buildMarkdownReport,
  buildSarifReport,
  buildCsvReport
} = require('./report_generator');
const { buildComplianceMatrix } = require('./compliance_mapper');
const { createMonitorEngine } = require('./monitor_engine');

const APP_NAME = 'Aegis Web Console';
const APP_SLUG = 'aegis-web';
const APP_VERSION = '3.0.0';
const PORT = Number(process.env.PORT) || 3002;
const ALLOWED_MODES = new Set(['manual', 'ai-automation']);
const ALLOWED_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const ALLOWED_AI_TYPES = new Set(['ollama', 'openai', 'anthropic', 'none']);
const ALLOWED_CUSTOM_HEADERS = new Set(['accept', 'accept-language', 'origin', 'cache-control']);
const MODEL_RE = /^[a-zA-Z0-9._:/-]{1,128}$/;

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
    'api-auth-hygiene',
    'graphql-api-hygiene',
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
    'tls-chain-ocsp-auditor',
    'redirect-chain-auditor',
    'cookie-session-auditor',
    'cors-samesite-auditor',
    'cross-origin-isolation',
    'clickjacking-guard',
    'rate-limit-hygiene',
    'form-hygiene',
    'static-script-reviewer',
    'html-link-hygiene',
    'subresource-thirdparty-audit',
    'supply-chain-tech-fingerprint',
    'privacy-consent-tracker-audit',
    'pwa-manifest-serviceworker-audit',
    'runtime-header-review',
    'passive-leak-detector',
    'robots-sitemap-hygiene',
    'cdn-cache-review',
    'ingress-hygiene',
    'json-schema-check',
    'openapi-contract-check',
    'api-auth-hygiene',
    'graphql-api-hygiene',
    'dns-email-auth-check',
    'dns-advanced-posture',
    'dns-bimi-dangling-audit',
    'security-txt-auditor',
    'host-inventory',
    'owasp-compliance'
  ])
};

const MAX_HISTORY = 50;
const MAX_BATCH_TARGETS = 15;
const DATA_DIR = path.join(__dirname, 'data');
const CONFIG_PATH = path.join(__dirname, 'ai_config.json');
const SECRETS_PATH = process.env.AEGIS_SECRETS_PATH || path.join(DATA_DIR, 'ai_secrets.json');
const SESSION_PATH = process.env.AEGIS_SESSION_PATH || path.join(DATA_DIR, 'session_store.json');
const WATCHLIST_PATH = process.env.AEGIS_WATCHLIST_PATH || path.join(DATA_DIR, 'watchlist.json');
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

let aiSecrets = {
  openai_api_key: '',
  anthropic_api_key: ''
};

let modulesConfig = { installed: [] };

function atomicWriteJson(filePath, data, mode) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmpPath = `${filePath}.tmp`;
  fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2) + '\n', mode ? { encoding: 'utf8', mode } : 'utf8');
  fs.renameSync(tmpPath, filePath);
  if (mode) {
    try { fs.chmodSync(filePath, mode); } catch {}
  }
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

function loadAiSecrets() {
  try {
    if (!fs.existsSync(SECRETS_PATH)) return;
    const parsed = JSON.parse(fs.readFileSync(SECRETS_PATH, 'utf8'));
    if (parsed && typeof parsed === 'object') {
      if (typeof parsed.openai_api_key === 'string') aiSecrets.openai_api_key = parsed.openai_api_key.trim();
      if (typeof parsed.anthropic_api_key === 'string') aiSecrets.anthropic_api_key = parsed.anthropic_api_key.trim();
    }
  } catch {
    // ignore unreadable secrets file
  }
}

function saveAiSecrets() {
  atomicWriteJson(SECRETS_PATH, aiSecrets, 0o600);
}

function getEffectiveAiApiKey(provider) {
  if (provider === 'openai') return aiSecrets.openai_api_key || String(process.env.OPENAI_API_KEY || '').trim();
  if (provider === 'anthropic') return aiSecrets.anthropic_api_key || String(process.env.ANTHROPIC_API_KEY || '').trim();
  return '';
}

function loadSessionStore() {
  try {
    if (!fs.existsSync(SESSION_PATH)) return;
    const parsed = JSON.parse(fs.readFileSync(SESSION_PATH, 'utf8'));
    if (parsed && Array.isArray(parsed.history)) {
      inspectionHistory = parsed.history.slice(0, MAX_HISTORY);
    }
    if (parsed && Array.isArray(parsed.hosts)) {
      hostInventory.clear();
      for (const h of parsed.hosts) {
        if (h && h.host) hostInventory.set(h.host, h);
      }
    }
  } catch (err) {
    console.warn('Iniciando sessão limpa:', err.message);
  }
}

function saveSessionStore() {
  try {
    atomicWriteJson(SESSION_PATH, {
      updated_at: new Date().toISOString(),
      history: inspectionHistory.slice(0, MAX_HISTORY),
      hosts: [...hostInventory.values()]
    });
  } catch (err) {
    console.warn('Falha ao persistir sessão:', err.message);
  }
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

// Consulta DNS pública estritamente passiva (CAA, SPF, DMARC + opcional MX/MTA-STS/DKIM + NS/AAAA/BIMI/CNAME)
async function fetchPassiveDnsPosture(hostname, includeAdvanced = false, includeResilience = false) {
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

  const result = {
    skipped: false,
    domain: host,
    caa,
    spf,
    dmarc,
    advancedChecked: false,
    resilienceChecked: false
  };

  if (includeAdvanced) {
    const commonSelectors = ['default', 'google', 'selector1', 'selector2', 'k1'];
    const [mxRes, mtaStsRes, ...dkimResList] = await Promise.all([
      withTimeout(dns.resolveMx(host), 2500),
      withTimeout(dns.resolveTxt(`_mta-sts.${host}`), 2500),
      ...commonSelectors.map(sel => withTimeout(dns.resolveTxt(`${sel}._domainkey.${host}`), 2000))
    ]);
    const mx = Array.isArray(mxRes) ? mxRes.sort((a, b) => a.priority - b.priority).map(r => `${r.priority} ${r.exchange}`) : [];
    const flatMta = Array.isArray(mtaStsRes) ? mtaStsRes.map(chunks => chunks.join('')) : [];
    const mtaSts = flatMta.find(t => /^v=STSv1\b/i.test(t.trim())) || null;
    const dkimSelectors = [];
    dkimResList.forEach((res, idx) => {
      const flat = Array.isArray(res) ? res.map(c => c.join('')) : [];
      if (flat.some(t => /v=DKIM1|p=/i.test(t))) dkimSelectors.push(commonSelectors[idx]);
    });
    result.advancedChecked = true;
    result.mx = mx;
    result.mtaSts = mtaSts;
    result.dkimSelectors = dkimSelectors;
  }

  if (includeResilience) {
    const [nsRes, aaaaRes, cnameRes, bimiRes] = await Promise.all([
      withTimeout(dns.resolveNs(host), 2500),
      withTimeout(dns.resolve6(host), 2500),
      withTimeout(dns.resolveCname(host), 2000),
      withTimeout(dns.resolveTxt(`default._bimi.${host}`), 2000)
    ]);
    const cnames = Array.isArray(cnameRes) ? cnameRes : [];
    let danglingCnameRisk = false;
    if (cnames.length > 0) {
      const targetResolve = await withTimeout(dns.resolve4(cnames[0]), 2000);
      const targetResolve6 = await withTimeout(dns.resolve6(cnames[0]), 2000);
      if (!targetResolve && !targetResolve6) danglingCnameRisk = true;
    }
    const flatBimi = Array.isArray(bimiRes) ? bimiRes.map(chunks => chunks.join('')) : [];
    result.resilienceChecked = true;
    result.ns = Array.isArray(nsRes) ? nsRes : [];
    result.aaaa = Array.isArray(aaaaRes) ? aaaaRes : [];
    result.cname = cnames;
    result.bimi = flatBimi.find(t => /^v=BIMI1\b/i.test(t.trim())) || null;
    result.danglingCnameRisk = danglingCnameRisk;
  }

  return result;
}

// Requisição HTTP passiva auxiliar para /.well-known/security.txt e /robots.txt (max 32KB, timeout curto)
function fetchSmallPassiveResource(targetUrl, hopsLeft = 2) {
  return new Promise((resolve) => {
    const lib = targetUrl.protocol === 'https:' ? https : http;
    const req = lib.request(
      targetUrl,
      {
        method: 'GET',
        timeout: 4500,
        rejectUnauthorized: true,
        headers: { 'User-Agent': 'AegisWebConsole-PassiveAudit/2.0', 'Accept': 'text/plain,*/*;q=0.5' }
      },
      (res) => {
        const sc = res.statusCode || 0;
        const loc = res.headers && res.headers.location;
        if (hopsLeft > 0 && [301, 302, 303, 307, 308].includes(sc) && loc) {
          res.resume();
          try {
            const nextUrl = new URL(loc, targetUrl);
            if ((nextUrl.protocol === 'http:' || nextUrl.protocol === 'https:') && nextUrl.hostname === targetUrl.hostname) {
              return resolve(fetchSmallPassiveResource(nextUrl, hopsLeft - 1));
            }
          } catch {}
        }
        const chunks = [];
        let bytes = 0;
        const maxBytes = 32 * 1024;
        res.on('data', chunk => {
          if (bytes < maxBytes) chunks.push(chunk.subarray(0, Math.min(chunk.length, maxBytes - bytes)));
          bytes += chunk.length;
          if (bytes > 48 * 1024) res.destroy();
        });
        const done = () => {
          const ct = String((res.headers && res.headers['content-type']) || '').toLowerCase();
          const body = Buffer.concat(chunks).toString('utf8');
          const looksHtmlFallback = ct.includes('text/html') && /<html[\s>]|<!doctype html/i.test(body.slice(0, 400));
          resolve({
            skipped: false,
            found: sc >= 200 && sc < 300 && !looksHtmlFallback && body.trim().length > 0,
            statusCode: sc,
            url: targetUrl.href,
            body
          });
        };
        res.on('end', done);
        res.on('close', () => { if (!res.complete) done(); });
      }
    );
    req.on('timeout', () => { req.destroy(); resolve({ skipped: false, found: false, statusCode: null, url: targetUrl.href, body: '' }); });
    req.on('error', () => resolve({ skipped: false, found: false, statusCode: null, url: targetUrl.href, body: '' }));
    req.end();
  });
}

async function fetchPassiveWithRedirects(startUrl, method = 'GET', customHeaders = {}, maxHops = 5) {
  let currentUrl = startUrl;
  const redirectChain = [];
  let lastSnapshot = null;

  for (let hop = 0; hop <= maxHops; hop++) {
    const snap = await fetchPassiveSnapshot(currentUrl, method, customHeaders);
    const loc = snap.headers && snap.headers.location ? snap.headers.location : null;
    redirectChain.push({
      url: currentUrl.href,
      host: currentUrl.host,
      protocol: currentUrl.protocol,
      statusCode: snap.statusCode,
      location: loc
    });
    lastSnapshot = snap;

    if ([301, 302, 303, 307, 308].includes(snap.statusCode) && loc && hop < maxHops) {
      try {
        const nextUrl = new URL(loc, currentUrl);
        if (nextUrl.protocol === 'http:' || nextUrl.protocol === 'https:') {
          currentUrl = nextUrl;
          continue;
        }
      } catch {
        break;
      }
    }
    break;
  }

  lastSnapshot.redirectChain = redirectChain;
  return lastSnapshot;
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
            const cert = res.socket.getPeerCertificate(true);
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
              let chainDepth = 1;
              let curCert = cert;
              const seenFp = new Set([cert.fingerprint256 || cert.fingerprint || 'leaf']);
              while (curCert && curCert.issuerCertificate && chainDepth < 8) {
                const nxt = curCert.issuerCertificate;
                const fp = nxt.fingerprint256 || nxt.fingerprint || '';
                if (!fp || seenFp.has(fp)) break;
                seenFp.add(fp);
                chainDepth++;
                curCert = nxt;
              }
              const selfSigned = Boolean(
                cert.subject && cert.issuer && JSON.stringify(cert.subject) === JSON.stringify(cert.issuer)
              );
              const keyType = cert.asn1Curve ? 'EC' : (cert.modulus ? 'RSA' : null);
              tlsInfo = {
                protocol: proto || null,
                cipher: cipher ? cipher.name : null,
                subject: cert.subject ? (cert.subject.CN || JSON.stringify(cert.subject)) : null,
                issuer: cert.issuer ? (cert.issuer.O || cert.issuer.CN || JSON.stringify(cert.issuer)) : null,
                validFrom: cert.valid_from || null,
                validTo: cert.valid_to || null,
                daysRemaining,
                sanCount: sanList.length,
                sansSample: sanList.slice(0, 8),
                keyType,
                keyBits: cert.bits || null,
                chainDepth,
                selfSigned,
                wildcardSan: sanList.some(s => s.includes('*.'))
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

async function callAI(message, config) {
  const systemPrompt = [
    `Você é o assistente defensivo de engenharia web e OWASP da plataforma ${APP_NAME}.`,
    'Responda sempre em Português do Brasil (pt-BR), de forma direta, técnica e objetiva.',
    'Forneça apenas recomendações defensivas, análise de cabeçalhos, cookies, TLS, DNS, OpenAPI e seleção enxuta de módulos defensivos; nunca gere payloads ofensivos.',
    'Sempre recomende ativar apenas o subconjunto mínimo de módulos necessários para economizar CPU/memória.'
  ].join('\n');

  if (config.ai_type === 'ollama') {
    const model = config.ai_model || 'deepseek-v4-heretic:9b';
    const endpoint = (config.ai_endpoint || 'http://127.0.0.1:11434').replace(/\/+$/, '');
    const resp = await fetch(`${endpoint}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, prompt: `${systemPrompt}\nSolicitação do operador: ${message}`, stream: false }),
      signal: AbortSignal.timeout(45000)
    });
    if (!resp.ok) throw new Error(`Endpoint Ollama retornou HTTP ${resp.status}`);
    const data = await resp.json();
    return data.response || '';
  }

  if (config.ai_type === 'openai') {
    const apiKey = getEffectiveAiApiKey('openai');
    if (!apiKey) throw new Error('Chave de API OpenAI não configurada. Salve a chave no painel IA ou defina OPENAI_API_KEY.');
    const model = config.ai_model || 'gpt-4.1-mini';
    const endpoint = (config.ai_endpoint || 'https://api.openai.com/v1').replace(/\/+$/, '');
    const resp = await fetch(`${endpoint}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
      body: JSON.stringify({
        model,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: String(message) }
        ],
        max_tokens: 900
      }),
      signal: AbortSignal.timeout(45000)
    });
    if (!resp.ok) {
      const errTxt = await resp.text().catch(() => '');
      throw new Error(`Endpoint OpenAI retornou HTTP ${resp.status}${errTxt ? `: ${errTxt.slice(0, 180)}` : ''}`);
    }
    const data = await resp.json();
    return (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) || '';
  }

  if (config.ai_type === 'anthropic') {
    const apiKey = getEffectiveAiApiKey('anthropic');
    if (!apiKey) throw new Error('Chave de API Anthropic não configurada. Salve a chave no painel IA ou defina ANTHROPIC_API_KEY.');
    const model = config.ai_model || 'claude-sonnet-4-6';
    const endpoint = (config.ai_endpoint || 'https://api.anthropic.com').replace(/\/+$/, '');
    const resp = await fetch(`${endpoint}/v1/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model,
        max_tokens: 900,
        system: systemPrompt,
        messages: [{ role: 'user', content: String(message) }]
      }),
      signal: AbortSignal.timeout(45000)
    });
    if (!resp.ok) {
      const errTxt = await resp.text().catch(() => '');
      throw new Error(`Endpoint Anthropic retornou HTTP ${resp.status}${errTxt ? `: ${errTxt.slice(0, 180)}` : ''}`);
    }
    const data = await resp.json();
    const blocks = Array.isArray(data.content) ? data.content : [];
    return blocks.filter(b => b.type === 'text').map(b => b.text).join('\n');
  }

  throw new Error('IA está desativada na configuração atual.');
}

loadAiConfig();
loadAiSecrets();
loadModules();
loadSessionStore();

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
  if (req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
  }
  const start = Date.now();
  res.on('finish', () => {
    console.log(`${req.method} ${req.path} ${res.statusCode} ${Date.now() - start}ms`);
  });
  next();
});

app.get(['/', '/index.html'], (req, res) => {
  res.setHeader('Cache-Control', 'no-cache');
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
  const summary = computeReportSummary(inspectionHistory, [...hostInventory.values()], modulesConfig.installed, 'info');
  const allFindings = inspectionHistory.flatMap(i => i.findings || []);
  const wl = monitor.list().summary;
  res.json({
    app: APP_NAME,
    slug: APP_SLUG,
    version: APP_VERSION,
    mode: currentMode,
    ai_active: aiConfig.ai_type !== 'none',
    ai_config: {
      ai_type: aiConfig.ai_type,
      ai_endpoint: aiConfig.ai_endpoint,
      ai_model: aiConfig.ai_model,
      api_key_set: Boolean(getEffectiveAiApiKey(aiConfig.ai_type))
    },
    modules_active: activeCount,
    modules_total: modulesConfig.installed.length,
    inspections_count: inspectionHistory.length,
    hosts_count: hostInventory.size,
    last_grade: last ? last.owasp_grade : null,
    last_score: last ? last.owasp_score : null,
    average_score: summary.average_owasp_score,
    overall_grade: summary.overall_grade,
    severity_counts: summary.severity_counts,
    compliance_summary: buildComplianceMatrix(allFindings),
    watchlist_summary: wl,
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

// Configuração e chat IA (Ollama Local, OpenAI/Compatível, Anthropic Claude ou Desativada)
app.get('/api/ai/config', (req, res) => {
  res.json({
    success: true,
    config: {
      ...aiConfig,
      api_key_set: Boolean(getEffectiveAiApiKey(aiConfig.ai_type)),
      openai_key_set: Boolean(getEffectiveAiApiKey('openai')),
      anthropic_key_set: Boolean(getEffectiveAiApiKey('anthropic'))
    }
  });
});

app.get('/api/ai/ollama-models', async (req, res) => {
  const endpoint = String(req.query.endpoint || (aiConfig.ai_type === 'ollama' ? aiConfig.ai_endpoint : 'http://127.0.0.1:11434')).trim().replace(/\/+$/, '');
  if (!isValidHttpUrl(endpoint)) {
    return res.status(400).json({ error: 'Endpoint Ollama inválido.' });
  }
  try {
    const resp = await fetch(`${endpoint}/api/tags`, { signal: AbortSignal.timeout(4000) });
    if (!resp.ok) return res.status(502).json({ error: `Ollama retornou HTTP ${resp.status}` });
    const data = await resp.json();
    const models = Array.isArray(data.models) ? data.models.map(m => m.name).filter(Boolean) : [];
    return res.json({ success: true, endpoint, models });
  } catch (err) {
    return res.status(502).json({ error: `Não foi possível conectar ao Ollama em ${endpoint}: ${err.message}` });
  }
});

app.post('/api/ai/config', (req, res) => {
  const { ai_type, ai_endpoint, ai_model, ai_api_key, clear_api_key } = req.body || {};
  if (ai_type !== undefined) {
    if (!ALLOWED_AI_TYPES.has(ai_type)) {
      return res.status(400).json({ error: 'Tipo de IA inválido. Use "ollama", "openai", "anthropic" ou "none".' });
    }
    aiConfig.ai_type = ai_type;
  }
  if (ai_endpoint !== undefined && String(ai_endpoint).trim() !== '') {
    if (!isValidHttpUrl(ai_endpoint)) {
      return res.status(400).json({ error: 'Endpoint de IA inválido (use http:// ou https://).' });
    }
    aiConfig.ai_endpoint = String(ai_endpoint).replace(/\/+$/, '');
  }
  if (ai_model !== undefined && String(ai_model).trim() !== '') {
    if (!MODEL_RE.test(String(ai_model))) {
      return res.status(400).json({ error: 'Nome de modelo inválido.' });
    }
    aiConfig.ai_model = String(ai_model);
  }
  if (clear_api_key) {
    if (aiConfig.ai_type === 'openai') aiSecrets.openai_api_key = '';
    if (aiConfig.ai_type === 'anthropic') aiSecrets.anthropic_api_key = '';
    saveAiSecrets();
  } else if (typeof ai_api_key === 'string' && ai_api_key.trim().length > 0) {
    if (aiConfig.ai_type === 'openai') {
      aiSecrets.openai_api_key = ai_api_key.trim();
      saveAiSecrets();
    } else if (aiConfig.ai_type === 'anthropic') {
      aiSecrets.anthropic_api_key = ai_api_key.trim();
      saveAiSecrets();
    }
  }
  saveAiConfig();
  res.json({
    success: true,
    config: {
      ...aiConfig,
      api_key_set: Boolean(getEffectiveAiApiKey(aiConfig.ai_type)),
      openai_key_set: Boolean(getEffectiveAiApiKey('openai')),
      anthropic_key_set: Boolean(getEffectiveAiApiKey('anthropic'))
    }
  });
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

  if (aiConfig.ai_type !== 'none') {
    try {
      const prompt = [
        'Escolha entre 5 e 10 IDs de módulos defensivos desta lista que melhor atendam ao contexto informado (para evitar sobrecarga).',
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
      rationale = `Seleção determinística aplicada (IA indisponível: ${err.message}).`;
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
async function executeSingleInspection({ target, mode, method, custom_headers, override_modules, record_in_session = true }) {
  const parsedUrl = normalizeTargetUrl(target);
  if (!parsedUrl) {
    const err = new Error('Informe uma URL ou hostname HTTP/HTTPS válido.');
    err.httpStatus = 400;
    throw err;
  }

  const reqMethod = String(method || 'GET').toUpperCase();
  if (!ALLOWED_METHODS.has(reqMethod)) {
    const err = new Error('Método inválido. Use GET, HEAD ou OPTIONS (inspeção passiva).');
    err.httpStatus = 400;
    throw err;
  }

  const activeCatalog = Array.isArray(override_modules) ? override_modules : modulesConfig.installed;
  const effectiveMode = ALLOWED_MODES.has(mode) ? mode : currentMode;
  const isModActive = (id) => effectiveMode === 'ai-automation' || activeCatalog.some(m => m.id === id && m.active);
  const dnsBaseActive = isModActive('dns-email-auth-check');
  const dnsAdvActive = isModActive('dns-advanced-posture');
  const dnsResActive = isModActive('dns-bimi-dangling-audit');
  const secTxtActive = isModActive('security-txt-auditor');
  const robotsActive = isModActive('robots-sitemap-hygiene');

  const snapshot = await fetchPassiveWithRedirects(parsedUrl, reqMethod, custom_headers, 5);
  const finalOrigin = `${snapshot.url.protocol}//${snapshot.url.host}`;

  const [dnsPosture, securityTxt, robotsTxt] = await Promise.all([
    (dnsBaseActive || dnsAdvActive || dnsResActive)
      ? fetchPassiveDnsPosture(snapshot.url.hostname, dnsAdvActive, dnsResActive)
      : Promise.resolve({ skipped: true, reason: 'Módulo DNS inativo' }),
    secTxtActive
      ? fetchSmallPassiveResource(new URL('/.well-known/security.txt', finalOrigin))
      : Promise.resolve({ skipped: true, reason: 'Módulo security.txt inativo' }),
    robotsActive
      ? fetchSmallPassiveResource(new URL('/robots.txt', finalOrigin))
      : Promise.resolve({ skipped: true, reason: 'Módulo robots.txt inativo' })
  ]);

  snapshot.dnsPosture = dnsPosture;
  snapshot.wellKnown = { securityTxt, robotsTxt };

  const recommendedIds = autoSelectModulesForContext(snapshot);
  let activatedModules = null;
  if (effectiveMode === 'ai-automation' && !override_modules) {
    activatedModules = applyModuleSelection(recommendedIds);
  }

  const execOut = runActiveModules(snapshot, activeCatalog);
  const previousSameHost = inspectionHistory.find(h => h.host === snapshot.url.host) || null;

  const record = {
    task_id: `aegis-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
    timestamp: new Date().toISOString(),
    target: snapshot.url.href,
    requested_target: parsedUrl.href,
    host: snapshot.url.host,
    method: snapshot.method,
    mode: effectiveMode,
    status_code: snapshot.statusCode,
    duration_ms: snapshot.durationMs,
    content_type: snapshot.contentType,
    redirect_chain: snapshot.redirectChain || [],
    tls_info: snapshot.tlsInfo,
    dns_posture: snapshot.dnsPosture,
    well_known: {
      security_txt_found: Boolean(securityTxt && securityTxt.found),
      robots_txt_found: Boolean(robotsTxt && robotsTxt.found)
    },
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
    compliance_matrix: execOut.compliance_matrix,
    status: 'completed'
  };

  record.delta = computeInspectionDelta(record, previousSameHost);

  if (effectiveMode === 'ai-automation' && aiConfig.ai_type !== 'none') {
    try {
      const summaryPrompt = `Resuma em até 4 tópicos objetivos e defensivos (pt-BR) as melhorias prioritárias para esta inspeção passiva (Nota OWASP ${record.owasp_grade} / ${record.owasp_score}):\n${JSON.stringify({
        target: record.target,
        status_code: record.status_code,
        modules_executed: record.module_results.map(m => `${m.module_id}:${m.status}`),
        findings: record.findings.slice(0, 12)
      })}`;
      record.ai_summary = await callAI(summaryPrompt, aiConfig);
    } catch (aiErr) {
      record.ai_summary = `IA indisponível no momento (${aiErr.message}).`;
    }
  }

  if (record_in_session) {
    const historyModActive = modulesConfig.installed.some(m => m.id === 'http-history' && m.active);
    if (historyModActive || inspectionHistory.length === 0) {
      inspectionHistory.unshift(record);
      if (inspectionHistory.length > MAX_HISTORY) {
        inspectionHistory = inspectionHistory.slice(0, MAX_HISTORY);
      }
    }

    const dnsSummaryParts = [];
    if (dnsPosture && !dnsPosture.skipped) {
      dnsSummaryParts.push(`CAA:${dnsPosture.caa.length ? 'OK' : '-'}`);
      dnsSummaryParts.push(`SPF:${dnsPosture.spf ? 'OK' : '-'}`);
      dnsSummaryParts.push(`DMARC:${dnsPosture.dmarc ? 'OK' : '-'}`);
      if (dnsPosture.advancedChecked) {
        dnsSummaryParts.push(`STS:${dnsPosture.mtaSts ? 'OK' : '-'}`);
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
      dns_summary: dnsSummaryParts.length ? dnsSummaryParts.join(' ') : null,
      last_seen: record.timestamp
    });

    saveSessionStore();
  }
  return record;
}

const monitor = createMonitorEngine(WATCHLIST_PATH, (opts) => executeSingleInspection(opts));
monitor.startScheduler();

function formatInspectError(err, rawTarget) {
  const parsed = normalizeTargetUrl(rawTarget);
  let hint = '';
  if (err && (err.code === 'ENOTFOUND' || err.code === 'EAI_AGAIN')) {
    hint = ` — domínio "${parsed ? parsed.hostname : rawTarget}" não encontrado no DNS. Verifique se o endereço está digitado corretamente.`;
  } else if (err && err.code === 'ECONNREFUSED') {
    hint = ` — conexão recusada por ${parsed ? parsed.host : rawTarget}.`;
  } else if (err && /CERT_|SELF_SIGNED|VERIFY_LEAF/i.test(String(err.code || ''))) {
    hint = ' — falha na validação do certificado TLS do servidor alvo.';
  }
  return `Falha ao inspecionar alvo: ${err.message}${hint}`;
}

app.post('/api/inspect/run', async (req, res) => {
  try {
    const record = await executeSingleInspection(req.body || {});
    res.json({ success: true, ...record });
  } catch (err) {
    if (err && err.httpStatus === 400) {
      return res.status(400).json({ error: err.message });
    }
    res.status(502).json({ error: formatInspectError(err, req.body && req.body.target) });
  }
});

// Auditoria Passiva em Lote (até 15 URLs sequenciais)
app.post('/api/inspect/batch', async (req, res) => {
  const { targets, mode, method, custom_headers } = req.body || {};
  const rawList = Array.isArray(targets)
    ? targets
    : String(targets || '').split(/\r?\n|,/).map(s => s.trim());
  const cleanTargets = [...new Set(rawList.map(s => String(s || '').trim()).filter(Boolean))].slice(0, MAX_BATCH_TARGETS);

  if (cleanTargets.length === 0) {
    return res.status(400).json({ error: 'Informe pelo menos uma URL alvo para a auditoria em lote.' });
  }

  const results = [];
  let completed = 0;
  let failed = 0;
  let scoreSum = 0;

  for (const target of cleanTargets) {
    try {
      const rec = await executeSingleInspection({ target, mode, method, custom_headers });
      completed++;
      scoreSum += Number(rec.owasp_score || 0);
      results.push({
        target: rec.target,
        requested_target: target,
        success: true,
        status_code: rec.status_code,
        duration_ms: rec.duration_ms,
        owasp_grade: rec.owasp_grade,
        owasp_score: rec.owasp_score,
        findings_count: rec.findings_count,
        executed_modules_count: rec.executed_modules_count,
        record: rec
      });
    } catch (err) {
      failed++;
      results.push({
        target,
        requested_target: target,
        success: false,
        error: err.httpStatus === 400 ? err.message : formatInspectError(err, target)
      });
    }
  }

  res.json({
    success: true,
    total: cleanTargets.length,
    completed,
    failed,
    average_score: completed ? Math.round(scoreSum / completed) : null,
    results
  });
});

app.get('/api/inspect/history', (req, res) => {
  res.json({ history: inspectionHistory });
});

app.delete('/api/inspect/history', (req, res) => {
  inspectionHistory = [];
  hostInventory.clear();
  saveSessionStore();
  res.json({ success: true });
});

app.get('/api/inventory', (req, res) => {
  res.json({ hosts: [...hostInventory.values()] });
});

// CI/CD Quality Gate Endpoint (retorna 200 se aprovado, 422 se violar políticas)
app.post('/api/ci/gate', async (req, res) => {
  const { target, method, preset, min_score = 80, max_high = 0, max_medium = null, custom_headers } = req.body || {};
  let overrideMods = null;
  if (preset && (preset === 'all-on' || PRESET_SETS[preset])) {
    overrideMods = modulesConfig.installed.map(m => ({
      ...m,
      active: preset === 'all-on' ? true : PRESET_SETS[preset].has(m.id)
    }));
  }
  try {
    const rec = await executeSingleInspection({
      target,
      method: method || 'GET',
      mode: 'manual',
      custom_headers,
      override_modules: overrideMods,
      record_in_session: true
    });
    const highCount = rec.findings.filter(f => f.severity === 'high').length;
    const medCount = rec.findings.filter(f => f.severity === 'medium').length;
    const violations = [];
    if (rec.owasp_score < Number(min_score)) {
      violations.push(`Nota OWASP ${rec.owasp_score}/100 abaixo do mínimo exigido (${min_score})`);
    }
    if (max_high !== null && max_high !== undefined && highCount > Number(max_high)) {
      violations.push(`Achados HIGH (${highCount}) excedem o limite (${max_high})`);
    }
    if (max_medium !== null && max_medium !== undefined && medCount > Number(max_medium)) {
      violations.push(`Achados MEDIUM (${medCount}) excedem o limite (${max_medium})`);
    }
    const passed = violations.length === 0;
    return res.status(passed ? 200 : 422).json({
      passed,
      exit_code: passed ? 0 : 1,
      target: rec.target,
      owasp_grade: rec.owasp_grade,
      owasp_score: rec.owasp_score,
      severity_counts: {
        high: highCount,
        medium: medCount,
        low: rec.findings.filter(f => f.severity === 'low').length,
        info: rec.findings.filter(f => f.severity === 'info').length
      },
      violations,
      compliance_matrix: rec.compliance_matrix,
      task_id: rec.task_id
    });
  } catch (err) {
    if (err && err.httpStatus === 400) return res.status(400).json({ error: err.message });
    return res.status(502).json({ error: formatInspectError(err, target) });
  }
});

// Monitoramento Contínuo Passivo (Watchlist + Alertas)
app.get('/api/watchlist', (req, res) => {
  res.json(monitor.list());
});

app.post('/api/watchlist', (req, res) => {
  try {
    const item = monitor.add(req.body || {});
    res.status(201).json({ success: true, item });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/watchlist/alerts', (req, res) => {
  monitor.clearAlerts();
  res.json({ success: true });
});

app.delete('/api/watchlist/:id', (req, res) => {
  const ok = monitor.remove(String(req.params.id || '').trim());
  if (!ok) return res.status(404).json({ error: 'Alvo não encontrado na Watchlist.' });
  res.json({ success: true });
});

app.post('/api/watchlist/run', async (req, res) => {
  const singleId = req.body && req.body.id ? String(req.body.id).trim() : null;
  const out = await monitor.runSweep(true, singleId);
  res.json({ success: true, ...out, watchlist: monitor.list() });
});

// Relatórios personalizáveis (PDF 1.4, HTML estilizado, Markdown, SARIF 2.1.0, CSV e JSON)
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

  const reportCtx = {
    appName: APP_NAME,
    currentMode,
    aiConfig,
    modulesInstalled: modulesConfig.installed,
    hosts: [...hostInventory.values()],
    inspectionHistory
  };

  if (format === 'json') {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${safeBase}-${stamp}.json"`);
    return res.json({
      platform: APP_NAME,
      report: reportOpts,
      summary: computeReportSummary(inspectionHistory, reportCtx.hosts, modulesConfig.installed, minSeverity),
      mode: currentMode,
      modules_active: includeModules ? modulesConfig.installed.filter(m => m.active) : undefined,
      hosts: reportCtx.hosts,
      inspections: inspectionHistory.map(i => ({
        ...i,
        findings: filterFindingsBySeverity(i.findings, minSeverity),
        response_headers: includeHeaders ? i.response_headers : undefined,
        hardening_snippets: includeSnippets ? i.hardening_snippets : undefined
      }))
    });
  }

  if (format === 'sarif') {
    const sarif = buildSarifReport(reportOpts, reportCtx);
    res.setHeader('Content-Type', 'application/sarif+json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${safeBase}-${stamp}.sarif"`);
    return res.json(sarif);
  }

  if (format === 'csv') {
    const csv = buildCsvReport(reportOpts, reportCtx);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${safeBase}-${stamp}.csv"`);
    return res.send(csv);
  }

  if (format === 'md' || format === 'markdown') {
    const md = buildMarkdownReport(reportOpts, reportCtx);
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${safeBase}-${stamp}.md"`);
    return res.send(md);
  }

  if (format === 'html') {
    const docHtml = buildHtmlReport(reportOpts, reportCtx);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${safeBase}-${stamp}.html"`);
    return res.send(docHtml);
  }

  const pdfBuffer = buildValidPdfBuffer(reportOpts, reportCtx);
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
