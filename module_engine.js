'use strict';

/**
 * Aegis Web Console — Modular Passive & Defensive Inspection Engine (30 Modules)
 * Strictly passive HTTP/TLS/DNS/Schema QA checks + defensive hardening generators.
 */

function parseCookies(rawHeader) {
  const list = Array.isArray(rawHeader) ? rawHeader : (rawHeader ? [rawHeader] : []);
  return list.map(raw => {
    const parts = raw.split(';').map(p => p.trim());
    const [nameVal, ...attrs] = parts;
    const eqIdx = nameVal.indexOf('=');
    const name = eqIdx >= 0 ? nameVal.slice(0, eqIdx).trim() : nameVal.trim();
    const value = eqIdx >= 0 ? nameVal.slice(eqIdx + 1).trim() : '';
    const attrLow = attrs.map(a => a.toLowerCase());
    const sameSiteAttr = attrs.find(a => a.toLowerCase().startsWith('samesite='));
    const pathAttr = attrs.find(a => a.toLowerCase().startsWith('path='));
    const domainAttr = attrs.find(a => a.toLowerCase().startsWith('domain='));
    const maxAgeAttr = attrs.find(a => a.toLowerCase().startsWith('max-age='));
    return {
      name,
      valueLength: value.length,
      secure: attrLow.includes('secure'),
      httpOnly: attrLow.includes('httponly'),
      sameSite: sameSiteAttr ? sameSiteAttr.split('=')[1].trim() : null,
      path: pathAttr ? pathAttr.split('=')[1].trim() : null,
      domain: domainAttr ? domainAttr.split('=')[1].trim() : null,
      maxAge: maxAgeAttr ? Number(maxAgeAttr.split('=')[1].trim()) : null,
      hasHostPrefix: name.startsWith('__Host-'),
      hasSecurePrefix: name.startsWith('__Secure-')
    };
  });
}

function shannonEntropy(str) {
  if (!str) return { bitsPerChar: 0, totalBits: 0 };
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  for (const count of Object.values(freq)) {
    const p = count / str.length;
    h -= p * Math.log2(p);
  }
  return {
    bitsPerChar: Number(h.toFixed(3)),
    totalBits: Number((h * str.length).toFixed(1))
  };
}

function analyzeCspHeader(cspRaw, isReportOnly = false) {
  const directives = {};
  const parts = String(cspRaw || '').split(';').map(s => s.trim()).filter(Boolean);
  for (const part of parts) {
    const tokens = part.split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    const key = tokens[0].toLowerCase();
    if (!directives[key]) directives[key] = tokens.slice(1);
  }

  const findings = [];
  const weakPoints = [];
  const scriptVals = directives['script-src'] || directives['default-src'] || [];
  const styleVals = directives['style-src'] || directives['default-src'] || [];
  const defaultVals = directives['default-src'] || [];

  if (isReportOnly) {
    weakPoints.push('apenas Report-Only (não bloqueia violações)');
    findings.push({
      severity: 'medium',
      item: 'Apenas Content-Security-Policy-Report-Only está ativa (sem política enforcing)',
      recommendation: 'Após validar relatórios CSP, promover a política para o cabeçalho Content-Security-Policy.'
    });
  }
  if (!directives['default-src']) {
    weakPoints.push('default-src ausente');
    findings.push({
      severity: 'medium',
      item: 'Diretiva default-src ausente na CSP',
      recommendation: "Definir default-src 'self' como linha de base restritiva."
    });
  }
  if (scriptVals.some(v => v.toLowerCase() === "'unsafe-inline'")) {
    weakPoints.push("script-src com 'unsafe-inline'");
    findings.push({
      severity: 'medium',
      item: "CSP permite 'unsafe-inline' em scripts",
      recommendation: "Substituir 'unsafe-inline' em script-src por nonces ou hashes SHA-256."
    });
  }
  if (scriptVals.some(v => v.toLowerCase() === "'unsafe-eval'")) {
    weakPoints.push("script-src com 'unsafe-eval'");
    findings.push({
      severity: 'medium',
      item: "CSP permite 'unsafe-eval' em scripts",
      recommendation: "Remover 'unsafe-eval' eliminando uso de eval()/new Function()."
    });
  }
  if (scriptVals.some(v => v === '*' || v.toLowerCase() === 'http:' || v.toLowerCase() === 'data:')) {
    weakPoints.push('script-src com wildcard/http:/data:');
    findings.push({
      severity: 'high',
      item: 'CSP permite origem excessivamente ampla (*, http: ou data:) em scripts',
      recommendation: 'Restringir script-src a origens HTTPS explícitas confiáveis.'
    });
  }
  if (defaultVals.some(v => v === '*')) {
    weakPoints.push('wildcard (*) em default-src');
    findings.push({
      severity: 'medium',
      item: 'Wildcard (*) configurado em default-src',
      recommendation: "Restringir default-src para 'self' ou 'none' e liberar somente domínios necessários."
    });
  }
  if (styleVals.some(v => v.toLowerCase() === "'unsafe-inline'")) {
    weakPoints.push("style-src com 'unsafe-inline'");
  }
  if (!directives['object-src'] || !directives['object-src'].some(v => v.toLowerCase() === "'none'")) {
    weakPoints.push("object-src 'none' ausente");
    findings.push({
      severity: 'low',
      item: "Diretiva object-src 'none' ausente na CSP",
      recommendation: "Adicionar object-src 'none' para bloquear plugins legados (Flash/Java)."
    });
  }
  if (!directives['base-uri']) {
    weakPoints.push('base-uri ausente');
    findings.push({
      severity: 'low',
      item: 'Diretiva base-uri ausente na CSP',
      recommendation: "Adicionar base-uri 'self' (ou 'none') para prevenir reescrita de URLs relativas."
    });
  }
  if (!directives['frame-ancestors']) {
    weakPoints.push('frame-ancestors ausente');
  }
  if (!directives['form-action']) {
    weakPoints.push('form-action ausente');
    findings.push({
      severity: 'info',
      item: 'Diretiva form-action ausente na CSP',
      recommendation: "Considerar adicionar form-action 'self' para restringir destinos de envio de formulários."
    });
  }
  if (!directives['upgrade-insecure-requests']) {
    weakPoints.push('upgrade-insecure-requests ausente');
  }

  return {
    directives,
    directive_count: Object.keys(directives).length,
    weak_points: weakPoints,
    findings
  };
}

function validateJsonAgainstSchema(data, schema, pathPrefix = '$') {
  const errors = [];
  if (!schema || typeof schema !== 'object') return errors;

  const actualType = data === null ? 'null' : (Array.isArray(data) ? 'array' : typeof data);
  if (schema.type) {
    const allowed = Array.isArray(schema.type) ? schema.type : [schema.type];
    const typeOk = allowed.some(t => {
      if (t === 'integer') return typeof data === 'number' && Number.isInteger(data);
      return actualType === t;
    });
    if (!typeOk) {
      errors.push({ path: pathPrefix, message: `Esperado tipo "${allowed.join('|')}", recebido "${actualType}".` });
      return errors;
    }
  }

  if (Array.isArray(schema.enum) && !schema.enum.some(v => JSON.stringify(v) === JSON.stringify(data))) {
    errors.push({ path: pathPrefix, message: `Valor fora do conjunto enum permitido (${schema.enum.join(', ')}).` });
  }

  if (typeof data === 'string') {
    if (typeof schema.minLength === 'number' && data.length < schema.minLength) {
      errors.push({ path: pathPrefix, message: `Comprimento ${data.length} menor que minLength (${schema.minLength}).` });
    }
    if (typeof schema.maxLength === 'number' && data.length > schema.maxLength) {
      errors.push({ path: pathPrefix, message: `Comprimento ${data.length} maior que maxLength (${schema.maxLength}).` });
    }
    if (typeof schema.pattern === 'string') {
      try {
        if (!new RegExp(schema.pattern).test(data)) {
          errors.push({ path: pathPrefix, message: `Texto não corresponde ao padrão "${schema.pattern}".` });
        }
      } catch {
        errors.push({ path: pathPrefix, message: `Regex inválida no schema: "${schema.pattern}".` });
      }
    }
    if (schema.format === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data)) {
      errors.push({ path: pathPrefix, message: 'Formato de e-mail inválido.' });
    }
    if (schema.format === 'uri') {
      try { new URL(data); } catch { errors.push({ path: pathPrefix, message: 'Formato URI inválido.' }); }
    }
  }

  if (typeof data === 'number') {
    if (typeof schema.minimum === 'number' && data < schema.minimum) {
      errors.push({ path: pathPrefix, message: `Valor ${data} menor que minimum (${schema.minimum}).` });
    }
    if (typeof schema.maximum === 'number' && data > schema.maximum) {
      errors.push({ path: pathPrefix, message: `Valor ${data} maior que maximum (${schema.maximum}).` });
    }
  }

  if (Array.isArray(data)) {
    if (typeof schema.minItems === 'number' && data.length < schema.minItems) {
      errors.push({ path: pathPrefix, message: `Array possui ${data.length} itens (minItems=${schema.minItems}).` });
    }
    if (typeof schema.maxItems === 'number' && data.length > schema.maxItems) {
      errors.push({ path: pathPrefix, message: `Array possui ${data.length} itens (maxItems=${schema.maxItems}).` });
    }
    if (schema.items && typeof schema.items === 'object') {
      data.slice(0, 100).forEach((item, idx) => {
        errors.push(...validateJsonAgainstSchema(item, schema.items, `${pathPrefix}[${idx}]`));
      });
    }
  }

  if (data && typeof data === 'object' && !Array.isArray(data)) {
    if (Array.isArray(schema.required)) {
      for (const reqKey of schema.required) {
        if (!(reqKey in data)) {
          errors.push({ path: `${pathPrefix}.${reqKey}`, message: `Campo obrigatório "${reqKey}" ausente.` });
        }
      }
    }
    const props = schema.properties && typeof schema.properties === 'object' ? schema.properties : {};
    for (const [k, v] of Object.entries(data)) {
      if (props[k]) {
        errors.push(...validateJsonAgainstSchema(v, props[k], `${pathPrefix}.${k}`));
      } else if (schema.additionalProperties === false) {
        errors.push({ path: `${pathPrefix}.${k}`, message: `Propriedade adicional não permitida: "${k}".` });
      }
    }
  }

  return errors;
}

function auditOpenApiSpec(spec) {
  const findings = [];
  if (!spec || typeof spec !== 'object' || Array.isArray(spec)) {
    return {
      is_openapi: false,
      summary: 'Objeto JSON não é uma especificação OpenAPI/Swagger.',
      metrics: {},
      findings: [{ severity: 'low', item: 'Documento JSON inválido para auditoria OpenAPI', recommendation: 'Fornecer um objeto OpenAPI 3.x ou Swagger 2.0 válido.' }]
    };
  }

  const version = spec.openapi || spec.swagger || null;
  if (!version) {
    return {
      is_openapi: false,
      summary: 'Chave "openapi" ou "swagger" ausente.',
      metrics: {},
      findings: [{ severity: 'info', item: 'Documento não declara versão OpenAPI/Swagger', recommendation: 'Incluir campo openapi: "3.1.0" ou "3.0.3" no contrato da API.' }]
    };
  }

  const isV3 = String(version).startsWith('3.');
  if (!isV3) {
    findings.push({
      severity: 'low',
      item: `Especificação legada detectada (${version})`,
      recommendation: 'Migrar o contrato de Swagger 2.0 para OpenAPI 3.0.3 ou 3.1.0.'
    });
  }

  const servers = Array.isArray(spec.servers) ? spec.servers : [];
  const insecureServers = servers.filter(s => s && typeof s.url === 'string' && /^http:\/\//i.test(s.url) && !/^http:\/\/(localhost|127\.0\.0\.1)/i.test(s.url));
  if (insecureServers.length > 0) {
    findings.push({
      severity: 'medium',
      item: `${insecureServers.length} servidor(es) declarados via HTTP sem TLS na especificação OpenAPI`,
      recommendation: 'Utilizar exclusivamente endpoints HTTPS em produção no bloco servers.'
    });
  }

  const secSchemes = (spec.components && spec.components.securitySchemes) || spec.securityDefinitions || {};
  const schemeNames = Object.keys(secSchemes);
  if (schemeNames.length === 0) {
    findings.push({
      severity: 'medium',
      item: 'Nenhum securityScheme definido no contrato OpenAPI',
      recommendation: 'Documentar mecanismos de autenticação (Bearer/OAuth2/OIDC/API Key) em components.securitySchemes.'
    });
  }
  for (const [name, def] of Object.entries(secSchemes)) {
    if (def && def.type === 'apiKey' && def.in === 'query') {
      findings.push({
        severity: 'medium',
        item: `SecurityScheme "${name}" transmite API Key na query string`,
        recommendation: 'Mover API Keys para cabeçalho HTTP (Authorization ou header dedicado) para evitar vazamento em logs/Referrer.'
      });
    }
    if (def && def.type === 'http' && String(def.scheme || '').toLowerCase() === 'basic') {
      findings.push({
        severity: 'low',
        item: `SecurityScheme "${name}" usa HTTP Basic Auth`,
        recommendation: 'Preferir OAuth2/OIDC ou tokens Bearer de curta duração sobre HTTPS.'
      });
    }
  }

  const pathsObj = spec.paths && typeof spec.paths === 'object' ? spec.paths : {};
  const pathKeys = Object.keys(pathsObj);
  const globalSecurity = Array.isArray(spec.security) && spec.security.length > 0;
  let operationsCount = 0;
  let unprotectedOps = 0;
  let missingResponseSchema = 0;

  const httpVerbs = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options']);
  for (const pKey of pathKeys) {
    const item = pathsObj[pKey];
    if (!item || typeof item !== 'object') continue;
    for (const [verb, op] of Object.entries(item)) {
      if (!httpVerbs.has(verb.toLowerCase()) || !op || typeof op !== 'object') continue;
      operationsCount++;
      const hasOpSecurity = Array.isArray(op.security) ? op.security.length > 0 : globalSecurity;
      if (!hasOpSecurity && !/\/(health|ready|live|metrics|status|ping)$/i.test(pKey)) {
        unprotectedOps++;
      }
      const responses = op.responses || {};
      const okResp = responses['200'] || responses['201'] || responses['204'];
      if (!okResp) {
        missingResponseSchema++;
      }
    }
  }

  if (unprotectedOps > 0) {
    findings.push({
      severity: 'low',
      item: `${unprotectedOps} de ${operationsCount} operação(ões) sem requisito de segurança explícito`,
      recommendation: 'Definir bloco global security ou declarar segurança operação por operação (marcando rotas públicas explicitamente).'
    });
  }
  if (missingResponseSchema > 0) {
    findings.push({
      severity: 'info',
      item: `${missingResponseSchema} operação(ões) sem resposta 2xx documentada`,
      recommendation: 'Documentar códigos 2xx e modelos de erro (4xx/5xx) com schemas JSON validáveis.'
    });
  }

  const score = computeOwaspScore(findings);
  return {
    is_openapi: true,
    version: String(version),
    title: (spec.info && spec.info.title) || 'Sem título',
    api_version: (spec.info && spec.info.version) || 'n/a',
    summary: `OpenAPI ${version} · ${pathKeys.length} path(s), ${operationsCount} operação(ões), ${schemeNames.length} securityScheme(s)`,
    metrics: {
      paths: pathKeys.length,
      operations: operationsCount,
      security_schemes: schemeNames,
      unprotected_operations: unprotectedOps,
      missing_2xx_responses: missingResponseSchema,
      servers_count: servers.length,
      qa_score: score.score,
      qa_grade: score.grade
    },
    findings
  };
}

const MODULE_RUNNERS = {
  'csp-auditor': (ctx) => {
    const csp = ctx.headers['content-security-policy'] || '';
    const cspRo = ctx.headers['content-security-policy-report-only'] || '';
    if (!csp && !cspRo) {
      return {
        status: 'warn',
        summary: 'CSP não configurada',
        details: { present: false, report_only: false },
        findings: [{
          severity: 'medium',
          item: 'Content-Security-Policy ausente',
          recommendation: "Definir Content-Security-Policy com default-src 'self', object-src 'none', base-uri 'self' e frame-ancestors 'none'."
        }]
      };
    }
    const analysis = analyzeCspHeader(csp || cspRo, !csp && Boolean(cspRo));
    return {
      status: analysis.findings.some(f => f.severity !== 'info') ? 'warn' : 'pass',
      summary: analysis.findings.length
        ? `CSP (${analysis.directive_count} diretivas) com ${analysis.weak_points.length} ponto(s) de melhoria`
        : `CSP bem configurada (${analysis.directive_count} diretivas)`,
      details: {
        present: Boolean(csp),
        report_only: Boolean(cspRo),
        directive_count: analysis.directive_count,
        weak_directives: analysis.weak_points,
        raw: (csp || cspRo).slice(0, 320)
      },
      findings: analysis.findings
    };
  },

  'hsts-tls-checker': (ctx) => {
    const findings = [];
    const isHttps = ctx.url.protocol === 'https:';
    const hsts = ctx.headers['strict-transport-security'] || '';
    if (!isHttps) {
      findings.push({
        severity: 'medium',
        item: 'Transporte HTTP sem criptografia TLS',
        recommendation: 'Migrar o endpoint para HTTPS com redirecionamento 301 e cabeçalho HSTS.'
      });
      return { status: 'warn', summary: 'Endpoint em HTTP claro', details: { https: false, hsts: null }, findings };
    }
    let maxAge = 0;
    let includeSubDomains = false;
    let preload = false;
    if (!hsts) {
      findings.push({
        severity: 'medium',
        item: 'Strict-Transport-Security (HSTS) ausente em HTTPS',
        recommendation: 'Adicionar Strict-Transport-Security: max-age=31536000; includeSubDomains.'
      });
    } else {
      const m = hsts.match(/max-age\s*=\s*(\d+)/i);
      maxAge = m ? Number(m[1]) : 0;
      includeSubDomains = /includeSubDomains/i.test(hsts);
      preload = /\bpreload\b/i.test(hsts);
      if (maxAge < 15768000) {
        findings.push({
          severity: 'low',
          item: `HSTS max-age curto (${maxAge}s)`,
          recommendation: 'Aumentar max-age para pelo menos 31536000 (1 ano).'
        });
      }
      if (!includeSubDomains) {
        findings.push({
          severity: 'info',
          item: 'HSTS sem diretiva includeSubDomains',
          recommendation: 'Avaliar incluir includeSubDomains após garantir HTTPS em todos os subdomínios.'
        });
      }
    }
    return {
      status: findings.some(f => f.severity !== 'info') ? 'warn' : 'pass',
      summary: hsts ? `HTTPS + HSTS (max-age=${maxAge}s${includeSubDomains ? ', subdomínios' : ''}${preload ? ', preload' : ''})` : 'HTTPS sem HSTS',
      details: { https: true, hsts: hsts || null, max_age: maxAge, include_subdomains: includeSubDomains, preload },
      findings
    };
  },

  'cookie-session-auditor': (ctx) => {
    const cookies = parseCookies(ctx.rawHeaders['set-cookie']);
    const findings = [];
    for (const c of cookies) {
      const missing = [];
      if (!c.secure) missing.push('Secure');
      if (!c.httpOnly) missing.push('HttpOnly');
      if (!c.sameSite) missing.push('SameSite');
      if (missing.length > 0) {
        findings.push({
          severity: 'low',
          item: `Cookie "${c.name}" sem flags: ${missing.join(', ')}`,
          recommendation: 'Aplicar Secure, HttpOnly e SameSite=Lax ou Strict em cookies sensíveis.'
        });
      }
      if (c.sameSite && c.sameSite.toLowerCase() === 'none' && !c.secure) {
        findings.push({
          severity: 'medium',
          item: `Cookie "${c.name}" usa SameSite=None sem flag Secure`,
          recommendation: 'Cookies com SameSite=None exigem obrigatoriamente a flag Secure.'
        });
      }
      if (c.hasHostPrefix && (!c.secure || c.domain || c.path !== '/')) {
        findings.push({
          severity: 'low',
          item: `Cookie "${c.name}" com prefixo __Host- viola requisitos (exige Secure, Path=/ e sem Domain)`,
          recommendation: 'Ajustar atributos do cookie __Host- conforme RFC 6265bis.'
        });
      }
      if (c.hasSecurePrefix && !c.secure) {
        findings.push({
          severity: 'low',
          item: `Cookie "${c.name}" com prefixo __Secure- não possui flag Secure`,
          recommendation: 'Incluir flag Secure obrigatória para cookies __Secure-.'
        });
      }
    }
    return {
      status: findings.length ? 'warn' : 'pass',
      summary: cookies.length ? `${cookies.length} cookie(s) auditado(s)` : 'Nenhum Set-Cookie emitido nesta resposta',
      details: { cookies },
      findings
    };
  },

  'cors-samesite-auditor': (ctx) => {
    const acao = ctx.headers['access-control-allow-origin'] || null;
    const acac = ctx.headers['access-control-allow-credentials'] || null;
    const acam = ctx.headers['access-control-allow-methods'] || null;
    const acma = ctx.headers['access-control-max-age'] || null;
    const vary = ctx.headers['vary'] || '';
    const findings = [];

    if (acao === '*' && String(acac).toLowerCase() === 'true') {
      findings.push({
        severity: 'high',
        item: 'CORS inseguro: Allow-Origin "*" combinado com Allow-Credentials: true',
        recommendation: 'Definir lista explícita de origens confiáveis ao utilizar credenciais CORS.'
      });
    } else if (acao === '*') {
      findings.push({
        severity: 'info',
        item: 'Access-Control-Allow-Origin aberto (*)',
        recommendation: 'Confirmar se o recurso é estritamente público; caso contrário, restringir origens.'
      });
    } else if (acao && acao !== '*' && !/\borigin\b/i.test(vary)) {
      findings.push({
        severity: 'low',
        item: 'CORS dinâmico sem cabeçalho Vary: Origin',
        recommendation: 'Adicionar Vary: Origin quando Access-Control-Allow-Origin varia conforme a origem para evitar cache cruzado.'
      });
    }

    if (ctx.sentOrigin && acao === ctx.sentOrigin && String(acac).toLowerCase() === 'true') {
      findings.push({
        severity: 'medium',
        item: `Origem enviada (${ctx.sentOrigin}) refletida com Allow-Credentials: true`,
        recommendation: 'Validar estritamente a origem contra allowlist fixa antes de refletir ACAO com credenciais.'
      });
    }

    return {
      status: findings.some(f => f.severity !== 'info') ? 'warn' : 'pass',
      summary: acao ? `ACAO=${acao}${acac ? ` · ACAC=${acac}` : ''}` : 'Sem cabeçalho CORS permissivo',
      details: { acao, acac, allow_methods: acam, max_age: acma, vary: vary || null },
      findings
    };
  },

  'cross-origin-isolation': (ctx) => {
    const coop = ctx.headers['cross-origin-opener-policy'] || null;
    const coep = ctx.headers['cross-origin-embedder-policy'] || null;
    const corp = ctx.headers['cross-origin-resource-policy'] || null;
    const oac = ctx.headers['origin-agent-cluster'] || null;
    const xpcdp = ctx.headers['x-permitted-cross-domain-policies'] || null;
    const findings = [];

    if (!coop) {
      findings.push({
        severity: 'info',
        item: 'Cross-Origin-Opener-Policy (COOP) ausente',
        recommendation: 'Definir Cross-Origin-Opener-Policy: same-origin para isolar o grupo de navegação.'
      });
    }
    if (!corp) {
      findings.push({
        severity: 'info',
        item: 'Cross-Origin-Resource-Policy (CORP) ausente',
        recommendation: 'Definir Cross-Origin-Resource-Policy: same-origin (ou same-site) para evitar carregamento indevido por terceiros.'
      });
    }
    if (!coep) {
      findings.push({
        severity: 'info',
        item: 'Cross-Origin-Embedder-Policy (COEP) ausente',
        recommendation: 'Considerar Cross-Origin-Embedder-Policy: require-corp ou credentialless quando aplicável.'
      });
    }

    const present = [coop, coep, corp].filter(Boolean).length;
    return {
      status: present >= 2 ? 'pass' : 'info',
      summary: `${present}/3 cabeçalhos de isolamento Cross-Origin presentes (COOP/COEP/CORP)`,
      details: { coop, coep, corp, origin_agent_cluster: oac, x_permitted_cross_domain_policies: xpcdp },
      findings
    };
  },

  'clickjacking-guard': (ctx) => {
    const xfo = ctx.headers['x-frame-options'] || null;
    const csp = ctx.headers['content-security-policy'] || '';
    const hasFrameAncestors = /frame-ancestors\s+/i.test(csp);
    const findings = [];
    if (!xfo && !hasFrameAncestors) {
      findings.push({
        severity: 'low',
        item: 'Proteção anti-clickjacking ausente (X-Frame-Options / frame-ancestors)',
        recommendation: 'Definir X-Frame-Options: DENY (ou SAMEORIGIN) e/ou frame-ancestors na CSP.'
      });
    }
    return {
      status: findings.length ? 'warn' : 'pass',
      summary: xfo ? `X-Frame-Options: ${xfo}` : (hasFrameAncestors ? 'Protegido via CSP frame-ancestors' : 'Sem proteção anti-clickjacking'),
      details: { x_frame_options: xfo, csp_frame_ancestors: hasFrameAncestors },
      findings
    };
  },

  'rate-limit-hygiene': (ctx) => {
    const rlHeaders = {};
    for (const [k, v] of Object.entries(ctx.headers)) {
      if (/^(ratelimit|x-ratelimit|retry-after|x-rate-limit)/i.test(k)) {
        rlHeaders[k] = v;
      }
    }
    const keys = Object.keys(rlHeaders);
    const findings = [];
    const isApi = (ctx.contentType || '').toLowerCase().includes('application/json') || /\/api\b/i.test(ctx.url.pathname);
    if (keys.length === 0 && isApi) {
      findings.push({
        severity: 'info',
        item: 'Endpoint de API sem cabeçalhos visíveis de Rate-Limit',
        recommendation: 'Publicar cabeçalhos padrão RateLimit-Limit / RateLimit-Remaining / RateLimit-Reset e aplicar controle de taxa no gateway.'
      });
    }
    return {
      status: keys.length > 0 ? 'pass' : (isApi ? 'warn' : 'info'),
      summary: keys.length ? `${keys.length} cabeçalho(s) de Rate-Limit detectado(s)` : (isApi ? 'API sem cabeçalhos RateLimit-*' : 'Sem cabeçalhos RateLimit-* nesta resposta'),
      details: { rate_limit_headers: rlHeaders, detected_api: isApi },
      findings
    };
  },

  'header-extractor': (ctx) => {
    const keys = Object.keys(ctx.headers);
    const securityKeys = keys.filter(k =>
      /^(strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy|cross-origin|access-control|ratelimit|x-ratelimit)/i.test(k)
    );
    return {
      status: 'pass',
      summary: `${keys.length} cabeçalhos recebidos (${securityKeys.length} de segurança)`,
      details: { total_headers: keys.length, security_headers_found: securityKeys },
      findings: []
    };
  },

  'passive-leak-detector': (ctx) => {
    const findings = [];
    const body = ctx.bodyText || '';
    const patterns = [
      { label: 'Bloco de chave privada PEM', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
      { label: 'Possível chave de API AWS', re: /\bAKIA[0-9A-Z]{16}\b/ },
      { label: 'Possível token GitHub', re: /\bgh[pousr]_[A-Za-z0-9_]{36,}\b/ },
      { label: 'Stack trace / erro detalhado de aplicação', re: /(?:Traceback \(most recent call last\)|Fatal error:.*on line \d+|at Object\.<anonymous> \(.*\.js:\d+)/i }
    ];
    const hits = [];
    for (const p of patterns) {
      if (p.re.test(body)) {
        hits.push(p.label);
        findings.push({
          severity: 'high',
          item: `Possível exposição passiva detectada na resposta: ${p.label}`,
          recommendation: 'Remover artefatos sensíveis/stack traces de respostas públicas e rotacionar credenciais expostas.'
        });
      }
    }
    return {
      status: findings.length ? 'warn' : 'pass',
      summary: hits.length ? `${hits.length} padrão(ões) de exposição detectado(s)` : 'Nenhum vazamento passivo evidente no corpo analisado',
      details: { inspected_bytes: body.length, hits },
      findings
    };
  },

  'static-script-reviewer': (ctx) => {
    const body = ctx.bodyText || '';
    const findings = [];
    const extScripts = [...body.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["'][^>]*>/gi)];
    let missingSri = 0;
    let mixedContent = 0;
    for (const m of extScripts) {
      const tag = m[0];
      const src = m[1];
      const isRemote = /^https?:\/\//i.test(src) || src.startsWith('//');
      if (isRemote && !/\bintegrity=/i.test(tag)) missingSri++;
      if (ctx.url.protocol === 'https:' && /^http:\/\//i.test(src)) mixedContent++;
    }
    if (mixedContent > 0) {
      findings.push({
        severity: 'medium',
        item: `${mixedContent} script(s) carregado(s) via HTTP em página HTTPS (Mixed Content)`,
        recommendation: 'Carregar todos os scripts externos exclusivamente via HTTPS.'
      });
    }
    if (missingSri > 0) {
      findings.push({
        severity: 'low',
        item: `${missingSri} script(s) externo(s) sem atributo integrity (SRI)`,
        recommendation: 'Adicionar Subresource Integrity (integrity + crossorigin) para scripts de CDNs externas.'
      });
    }
    return {
      status: findings.length ? 'warn' : 'pass',
      summary: `${extScripts.length} script(s) externo(s) revisado(s)`,
      details: { external_scripts: extScripts.length, missing_sri: missingSri, mixed_content: mixedContent },
      findings
    };
  },

  'html-link-hygiene': (ctx) => {
    const body = ctx.bodyText || '';
    const findings = [];
    const blankLinks = [...body.matchAll(/<a\b([^>]*\btarget=["']_blank["'][^>]*)>/gi)];
    let missingNoopener = 0;
    for (const m of blankLinks) {
      const attrs = m[1];
      if (!/\brel=["'][^"']*noopener/i.test(attrs)) missingNoopener++;
    }
    const iframes = [...body.matchAll(/<iframe\b([^>]*)>/gi)];
    let unsandboxedIframes = 0;
    for (const m of iframes) {
      if (!/\bsandbox\b/i.test(m[1])) unsandboxedIframes++;
    }
    const jsHrefs = [...body.matchAll(/\bhref=["']\s*javascript:/gi)].length;

    if (missingNoopener > 0) {
      findings.push({
        severity: 'low',
        item: `${missingNoopener} link(s) target="_blank" sem rel="noopener noreferrer"`,
        recommendation: 'Adicionar rel="noopener noreferrer" em todos os links externos com target="_blank".'
      });
    }
    if (unsandboxedIframes > 0) {
      findings.push({
        severity: 'low',
        item: `${unsandboxedIframes} <iframe> sem atributo sandbox`,
        recommendation: 'Aplicar o atributo sandbox restritivo em iframes embutidos.'
      });
    }
    if (jsHrefs > 0) {
      findings.push({
        severity: 'info',
        item: `${jsHrefs} link(s) com esquema inline javascript:`,
        recommendation: 'Substituir href="javascript:..." por event listeners seguros compatíveis com CSP restritiva.'
      });
    }
    return {
      status: findings.some(f => f.severity !== 'info') ? 'warn' : 'pass',
      summary: `${blankLinks.length} link(s) _blank · ${iframes.length} iframe(s) auditado(s)`,
      details: { blank_links: blankLinks.length, missing_noopener: missingNoopener, iframes: iframes.length, unsandboxed_iframes: unsandboxedIframes, js_hrefs: jsHrefs },
      findings
    };
  },

  'token-entropy': (ctx) => {
    const cookies = parseCookies(ctx.rawHeaders['set-cookie']);
    const findings = [];
    const analyzed = [];
    const rawList = Array.isArray(ctx.rawHeaders['set-cookie']) ? ctx.rawHeaders['set-cookie'] : (ctx.rawHeaders['set-cookie'] ? [ctx.rawHeaders['set-cookie']] : []);
    for (const raw of rawList) {
      const pair = raw.split(';')[0];
      const idx = pair.indexOf('=');
      if (idx <= 0) continue;
      const name = pair.slice(0, idx).trim();
      const val = pair.slice(idx + 1).trim();
      if (val.length >= 8) {
        const ent = shannonEntropy(val);
        analyzed.push({ name, length: val.length, ...ent });
        if (/(sess|token|auth|sid|jwt)/i.test(name) && ent.totalBits < 64) {
          findings.push({
            severity: 'medium',
            item: `Cookie de sessão "${name}" com entropia estimada baixa (${ent.totalBits} bits)`,
            recommendation: 'Gerar identificadores de sessão com CSPRNG (>= 128 bits de entropia).'
          });
        }
      }
    }
    return {
      status: findings.length ? 'warn' : 'pass',
      summary: analyzed.length ? `${analyzed.length} token(s) em cookies avaliado(s)` : 'Utilitário de entropia ativo (nenhum cookie longo nesta resposta)',
      details: { cookies_seen: cookies.length, analyzed },
      findings
    };
  },

  'decoder-encoder': () => ({
    status: 'pass',
    summary: 'Utilitário Decoder/Encoder, HTML Entities, SHA-256 e JWT ativo na bancada',
    details: { tools: ['base64', 'url', 'html', 'hex', 'jwt', 'sha256'] },
    findings: []
  }),

  'response-comparer': () => ({
    status: 'pass',
    summary: 'Comparador visual linha a linha ativo na bancada (integrado ao histórico)',
    details: { mode: 'line-diff' },
    findings: []
  }),

  'url-parser': (ctx) => {
    const params = {};
    for (const [k, v] of ctx.url.searchParams.entries()) params[k] = v;
    return {
      status: 'pass',
      summary: `URL analisada: ${ctx.url.protocol}//${ctx.url.host}${ctx.url.pathname}`,
      details: {
        protocol: ctx.url.protocol,
        hostname: ctx.url.hostname,
        port: ctx.url.port || (ctx.url.protocol === 'https:' ? '443' : '80'),
        pathname: ctx.url.pathname,
        query_count: Object.keys(params).length
      },
      findings: []
    };
  },

  'http-history': () => ({
    status: 'pass',
    summary: 'Registro em histórico da sessão ativo',
    details: { ledger: 'in-memory-session' },
    findings: []
  }),

  'request-inspector': (ctx) => ({
    status: 'pass',
    summary: `${ctx.method} ${ctx.url.href} → HTTP ${ctx.statusCode} (${ctx.durationMs}ms)`,
    details: { method: ctx.method, status_code: ctx.statusCode, duration_ms: ctx.durationMs, content_type: ctx.contentType },
    findings: []
  }),

  'rest-api': () => ({
    status: 'pass',
    summary: 'API REST local ativa (/api/inspect/run, /api/qa/validate-schema, /api/modules, /api/report)',
    details: { endpoints: ['/api/status', '/api/inspect/run', '/api/qa/validate-schema', '/api/modules', '/api/inventory', '/api/report'] },
    findings: []
  }),

  'runtime-header-review': (ctx) => {
    const findings = [];
    const exposed = {};
    for (const key of ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator']) {
      if (ctx.headers[key]) exposed[key] = ctx.headers[key];
    }
    const genMatch = (ctx.bodyText || '').match(/<meta\s+name=["']generator["']\s+content=["']([^"']+)["']/i);
    if (genMatch) exposed['meta-generator'] = genMatch[1];

    for (const [k, v] of Object.entries(exposed)) {
      findings.push({
        severity: k === 'server' ? 'info' : 'low',
        item: `Divulgação de stack via ${k}: ${v}`,
        recommendation: `Suprimir ou mascarar "${k}" para reduzir fingerprinting de versão.`
      });
    }
    return {
      status: findings.length ? 'warn' : 'pass',
      summary: Object.keys(exposed).length ? `${Object.keys(exposed).length} identificador(es) de stack exposto(s)` : 'Sem cabeçalhos de stack expostos',
      details: { exposed },
      findings
    };
  },

  'cdn-cache-review': (ctx) => {
    const cc = ctx.headers['cache-control'] || null;
    const pragma = ctx.headers['pragma'] || null;
    const etag = ctx.headers['etag'] || null;
    const via = ctx.headers['via'] || null;
    const xCache = ctx.headers['x-cache'] || ctx.headers['cf-cache-status'] || null;
    const findings = [];
    if (!cc) {
      findings.push({
        severity: 'info',
        item: 'Cabeçalho Cache-Control ausente',
        recommendation: 'Definir diretivas explícitas de Cache-Control (ex.: no-store para conteúdo sensível/autenticado).'
      });
    } else if (/public/i.test(cc) && ctx.rawHeaders['set-cookie']) {
      findings.push({
        severity: 'medium',
        item: 'Cache-Control: public combinado com emissão de Set-Cookie',
        recommendation: 'Evitar cache compartilhado (public) em respostas que emitem cookies de sessão; usar private, no-store.'
      });
    }
    return {
      status: findings.some(f => f.severity !== 'info') ? 'warn' : 'pass',
      summary: cc ? `Cache-Control: ${cc}` : 'Cache-Control não definido',
      details: { cache_control: cc, pragma, etag, via, x_cache: xCache },
      findings
    };
  },

  'ingress-hygiene': (ctx) => {
    const proxyHeaders = {};
    for (const [k, v] of Object.entries(ctx.headers)) {
      if (/^(via|x-envoy|x-served-by|x-backend|x-amzn-trace-id|x-request-id|x-forwarded)/i.test(k)) {
        proxyHeaders[k] = v;
      }
    }
    const findings = [];
    if (proxyHeaders['x-backend-server'] || proxyHeaders['x-served-by']) {
      findings.push({
        severity: 'info',
        item: 'Metadados de nó interno/backend expostos em cabeçalhos de gateway',
        recommendation: 'Sanitizar cabeçalhos internos de upstream no proxy reverso/ingress.'
      });
    }
    return {
      status: findings.length ? 'warn' : 'pass',
      summary: `${Object.keys(proxyHeaders).length} cabeçalho(s) de proxy/ingress observado(s)`,
      details: { proxy_headers: proxyHeaders },
      findings
    };
  },

  'json-schema-check': (ctx) => {
    const findings = [];
    const nosniff = (ctx.headers['x-content-type-options'] || '').toLowerCase() === 'nosniff';
    if (!nosniff) {
      findings.push({
        severity: 'low',
        item: 'X-Content-Type-Options: nosniff ausente',
        recommendation: 'Definir X-Content-Type-Options: nosniff para evitar MIME sniffing no navegador.'
      });
    }
    const ctLow = (ctx.contentType || '').toLowerCase();
    const isJson = ctLow.includes('application/json') || ctLow.includes('+json');
    let validJson = null;
    let topLevelType = null;
    if (isJson) {
      if (!ctLow.includes('charset=utf-8')) {
        findings.push({
          severity: 'info',
          item: 'Content-Type JSON sem declaração explícita de charset=utf-8',
          recommendation: 'Declarar Content-Type: application/json; charset=utf-8.'
        });
      }
      if (ctx.bodyText) {
        try {
          const parsed = JSON.parse(ctx.bodyText);
          validJson = true;
          topLevelType = Array.isArray(parsed) ? 'array' : typeof parsed;
        } catch {
          validJson = false;
          findings.push({
            severity: 'low',
            item: 'Resposta declarada como application/json contém JSON inválido',
            recommendation: 'Validar serialização JSON no backend.'
          });
        }
      }
    }
    return {
      status: findings.some(f => f.severity !== 'info') ? 'warn' : 'pass',
      summary: isJson ? `JSON ${validJson ? 'válido' : 'inválido'} (${topLevelType || 'n/a'})` : (nosniff ? 'nosniff ativo' : 'nosniff ausente'),
      details: { is_json: isJson, valid_json: validJson, top_level: topLevelType, nosniff },
      findings
    };
  },

  'openapi-contract-check': (ctx) => {
    const ctLow = (ctx.contentType || '').toLowerCase();
    const isJson = ctLow.includes('application/json') || ctLow.includes('+json');
    if (!isJson || !ctx.bodyText) {
      return {
        status: 'info',
        summary: 'Resposta não é um documento JSON OpenAPI (use a aba OpenAPI/Schema na bancada QA para validar arquivos)',
        details: { is_openapi: false },
        findings: []
      };
    }
    try {
      const parsed = JSON.parse(ctx.bodyText);
      if (parsed && typeof parsed === 'object' && (parsed.openapi || parsed.swagger)) {
        const audit = auditOpenApiSpec(parsed);
        return {
          status: audit.findings.some(f => f.severity !== 'info') ? 'warn' : 'pass',
          summary: audit.summary,
          details: audit.metrics,
          findings: audit.findings
        };
      }
      return {
        status: 'pass',
        summary: 'Payload JSON comum (não é especificação OpenAPI/Swagger)',
        details: { is_openapi: false, keys: Object.keys(parsed || {}).slice(0, 12) },
        findings: []
      };
    } catch {
      return {
        status: 'info',
        summary: 'Corpo não analisável como contrato OpenAPI JSON',
        details: { is_openapi: false },
        findings: []
      };
    }
  },

  'cert-inspector': (ctx) => {
    if (ctx.url.protocol !== 'https:' || !ctx.tlsInfo) {
      return {
        status: 'info',
        summary: 'Sem sessão TLS (endpoint HTTP ou certificado indisponível)',
        details: { tls: false },
        findings: []
      };
    }
    const findings = [];
    const { protocol, cipher, subject, issuer, validTo, daysRemaining } = ctx.tlsInfo;
    if (protocol && /^(TLSv1|TLSv1\.1|SSLv)/i.test(protocol)) {
      findings.push({
        severity: 'high',
        item: `Protocolo TLS legado negociado (${protocol})`,
        recommendation: 'Desativar TLS 1.0/1.1 e exigir TLS 1.2 ou TLS 1.3.'
      });
    }
    if (typeof daysRemaining === 'number' && daysRemaining <= 30) {
      findings.push({
        severity: daysRemaining <= 7 ? 'high' : 'medium',
        item: `Certificado TLS próximo do vencimento (${daysRemaining} dias restantes)`,
        recommendation: 'Renovar o certificado TLS e automatizar rotação (ex.: ACME).'
      });
    }
    return {
      status: findings.length ? 'warn' : 'pass',
      summary: `${protocol || 'TLS'} · CN=${subject || 'n/a'} · expira em ${daysRemaining ?? '?'}d`,
      details: { protocol, cipher, subject, issuer, valid_to: validTo, days_remaining: daysRemaining },
      findings
    };
  },

  'tls-cipher-hardening': (ctx) => {
    if (ctx.url.protocol !== 'https:' || !ctx.tlsInfo) {
      return {
        status: 'info',
        summary: 'Alvo sem TLS (HTTP) — auditoria de cifras não aplicável',
        details: { tls: false },
        findings: []
      };
    }
    const findings = [];
    const { protocol, cipher, validFrom, validTo, sanCount } = ctx.tlsInfo;
    const isModernAead = Boolean(cipher && /(GCM|CHACHA20|POLY1305|TLS_AES_)/i.test(cipher));
    const isWeakCipher = Boolean(cipher && /(RC4|3DES|DES|NULL|EXPORT|MD5|_CBC_)/i.test(cipher));

    if (isWeakCipher) {
      findings.push({
        severity: 'medium',
        item: `Suíte criptográfica fraca ou CBC detectada (${cipher})`,
        recommendation: 'Priorizar cifras AEAD modernas (TLS_AES_256_GCM_SHA384, CHACHA20_POLY1305, ECDHE+AESGCM).'
      });
    }
    if (protocol === 'TLSv1.2') {
      findings.push({
        severity: 'info',
        item: 'Negociado TLSv1.2 (considere habilitar TLSv1.3)',
        recommendation: 'Habilitar TLS 1.3 no servidor/proxy reverso mantendo TLS 1.2 apenas com cifras AEAD.'
      });
    }
    if (validFrom && validTo) {
      const lifetimeDays = Math.round((Date.parse(validTo) - Date.parse(validFrom)) / (1000 * 60 * 60 * 24));
      if (Number.isFinite(lifetimeDays) && lifetimeDays > 398) {
        findings.push({
          severity: 'low',
          item: `Validade total do certificado (${lifetimeDays} dias) excede limite CA/B Forum (398 dias)`,
          recommendation: 'Emitir certificados com ciclo de vida <= 90–398 dias e renovação automatizada.'
        });
      }
    }
    return {
      status: findings.some(f => f.severity !== 'info') ? 'warn' : 'pass',
      summary: `${protocol || 'TLS'} · ${cipher || 'cifra n/a'} · AEAD=${isModernAead ? 'Sim' : 'Não'} · SANs=${sanCount ?? 0}`,
      details: { protocol, cipher, aead: isModernAead, san_count: sanCount ?? 0 },
      findings
    };
  },

  'form-hygiene': (ctx) => {
    const findings = [];
    const refPol = ctx.headers['referrer-policy'] || null;
    const permPol = ctx.headers['permissions-policy'] || null;
    if (!refPol) {
      findings.push({
        severity: 'info',
        item: 'Referrer-Policy ausente',
        recommendation: 'Definir Referrer-Policy: strict-origin-when-cross-origin ou no-referrer.'
      });
    }
    if (!permPol) {
      findings.push({
        severity: 'info',
        item: 'Permissions-Policy ausente',
        recommendation: 'Definir Permissions-Policy restringindo câmera, microfone e geolocalização não utilizados.'
      });
    }
    const forms = [...(ctx.bodyText || '').matchAll(/<form\b([^>]*)>/gi)];
    let insecureForms = 0;
    for (const m of forms) {
      const attrs = m[1];
      if (ctx.url.protocol === 'https:' && /\baction=["']http:\/\//i.test(attrs)) {
        insecureForms++;
      }
    }
    if (insecureForms > 0) {
      findings.push({
        severity: 'medium',
        item: `${insecureForms} formulário(s) enviando dados para action HTTP em página HTTPS`,
        recommendation: 'Alterar o atributo action de todos os formulários para HTTPS.'
      });
    }
    return {
      status: findings.some(f => f.severity !== 'info') ? 'warn' : 'pass',
      summary: `${forms.length} formulário(s) analisado(s) · Referrer=${refPol || 'ausente'}`,
      details: { forms_count: forms.length, insecure_forms: insecureForms, referrer_policy: refPol, permissions_policy: permPol },
      findings
    };
  },

  'dns-email-auth-check': (ctx) => {
    const dns = ctx.dnsPosture;
    if (!dns || dns.skipped) {
      return {
        status: 'info',
        summary: (dns && dns.reason) || 'Consulta DNS passiva não aplicável (alvo IP/local)',
        details: dns || { skipped: true },
        findings: []
      };
    }
    const findings = [];
    if (!dns.caa || dns.caa.length === 0) {
      findings.push({
        severity: 'info',
        item: `Registro DNS CAA ausente em ${dns.domain}`,
        recommendation: 'Publicar registro DNS CAA especificando quais Autoridades Certificadoras podem emitir certificados para o domínio.'
      });
    }
    if (!dns.spf) {
      findings.push({
        severity: 'low',
        item: `Registro SPF (v=spf1) ausente em ${dns.domain}`,
        recommendation: 'Publicar registro TXT SPF (ex.: v=spf1 -all se o domínio não envia e-mails).'
      });
    }
    if (!dns.dmarc) {
      findings.push({
        severity: 'low',
        item: `Registro DMARC (_dmarc.${dns.domain}) ausente`,
        recommendation: 'Publicar política DMARC (v=DMARC1; p=quarantine ou p=reject) contra spoofing de e-mail.'
      });
    } else if (/\bp=none\b/i.test(dns.dmarc)) {
      findings.push({
        severity: 'info',
        item: `Política DMARC em modo apenas monitoramento (p=none) em ${dns.domain}`,
        recommendation: 'Evoluir gradualmente a política DMARC para p=quarantine e p=reject.'
      });
    }
    return {
      status: findings.some(f => f.severity !== 'info') ? 'warn' : 'pass',
      summary: `CAA=${dns.caa.length ? 'OK' : 'ausente'} · SPF=${dns.spf ? 'OK' : 'ausente'} · DMARC=${dns.dmarc ? 'OK' : 'ausente'}`,
      details: dns,
      findings
    };
  },

  'host-inventory': (ctx) => ({
    status: 'pass',
    summary: `Host catalogado na sessão: ${ctx.url.host}`,
    details: { host: ctx.url.host, protocol: ctx.url.protocol },
    findings: []
  }),

  'async-webhook-monitor': (ctx) => {
    const allow = ctx.headers['allow'] || ctx.headers['access-control-allow-methods'] || null;
    return {
      status: 'pass',
      summary: `Diagnóstico de endpoint (${ctx.durationMs}ms${allow ? ` · Allow: ${allow}` : ''})`,
      details: { latency_ms: ctx.durationMs, allow_methods: allow, status_code: ctx.statusCode },
      findings: []
    };
  },

  'owasp-compliance': (ctx) => {
    const presentCount = [
      ctx.headers['strict-transport-security'],
      ctx.headers['content-security-policy'],
      ctx.headers['x-content-type-options'],
      ctx.headers['x-frame-options'],
      ctx.headers['referrer-policy'],
      ctx.headers['permissions-policy']
    ].filter(Boolean).length;
    return {
      status: presentCount >= 4 ? 'pass' : 'warn',
      summary: `${presentCount}/6 cabeçalhos OWASP base presentes`,
      details: { owasp_headers_present: presentCount, owasp_headers_total: 6 },
      findings: []
    };
  }
};

function computeOwaspScore(findings) {
  let score = 100;
  for (const f of findings) {
    if (f.severity === 'high') score -= 22;
    else if (f.severity === 'medium') score -= 12;
    else if (f.severity === 'low') score -= 6;
    else score -= 2;
  }
  score = Math.max(0, Math.min(100, score));
  let grade = 'F';
  if (score >= 90) grade = 'A';
  else if (score >= 80) grade = 'B';
  else if (score >= 65) grade = 'C';
  else if (score >= 50) grade = 'D';
  return { score, grade };
}

function generateHardeningSnippets(ctx, findings) {
  const recommendedHeaders = [];
  const h = ctx.headers || {};

  if (!h['strict-transport-security']) {
    recommendedHeaders.push(['Strict-Transport-Security', 'max-age=31536000; includeSubDomains']);
  }
  if (!h['content-security-policy']) {
    recommendedHeaders.push(['Content-Security-Policy', "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests"]);
  }
  if ((h['x-content-type-options'] || '').toLowerCase() !== 'nosniff') {
    recommendedHeaders.push(['X-Content-Type-Options', 'nosniff']);
  }
  if (!h['x-frame-options']) {
    recommendedHeaders.push(['X-Frame-Options', 'DENY']);
  }
  if (!h['referrer-policy']) {
    recommendedHeaders.push(['Referrer-Policy', 'strict-origin-when-cross-origin']);
  }
  if (!h['permissions-policy']) {
    recommendedHeaders.push(['Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()']);
  }
  if (!h['cross-origin-opener-policy']) {
    recommendedHeaders.push(['Cross-Origin-Opener-Policy', 'same-origin']);
  }
  if (!h['cross-origin-resource-policy']) {
    recommendedHeaders.push(['Cross-Origin-Resource-Policy', 'same-origin']);
  }

  const nginxLines = [
    '# Hardening defensivo sugerido (Nginx)',
    'server_tokens off;',
    ...recommendedHeaders.map(([k, v]) => `add_header ${k} "${v}" always;`)
  ];

  const apacheLines = [
    '# Hardening defensivo sugerido (Apache / mod_headers)',
    'ServerTokens Prod',
    'ServerSignature Off',
    ...recommendedHeaders.map(([k, v]) => `Header always set ${k} "${v}"`)
  ];

  const expressLines = [
    '// Hardening defensivo sugerido (Express.js)',
    "app.disable('x-powered-by');",
    'app.use((req, res, next) => {',
    ...recommendedHeaders.map(([k, v]) => `  res.setHeader('${k}', ${JSON.stringify(v)});`),
    '  next();',
    '});'
  ];

  return {
    missing_count: recommendedHeaders.length,
    findings_addressed: (findings || []).length,
    headers: Object.fromEntries(recommendedHeaders),
    nginx: nginxLines.join('\n'),
    apache: apacheLines.join('\n'),
    express: expressLines.join('\n')
  };
}

function autoSelectModulesForContext(ctx) {
  const picks = new Set(['request-inspector', 'header-extractor', 'http-history', 'owasp-compliance']);
  if (ctx.url.protocol === 'https:') {
    picks.add('hsts-tls-checker');
    picks.add('cert-inspector');
    picks.add('tls-cipher-hardening');
  } else {
    picks.add('hsts-tls-checker');
  }
  const ct = (ctx.contentType || '').toLowerCase();
  if (ct.includes('text/html')) {
    picks.add('csp-auditor');
    picks.add('clickjacking-guard');
    picks.add('static-script-reviewer');
    picks.add('form-hygiene');
    picks.add('html-link-hygiene');
    picks.add('cross-origin-isolation');
  }
  if (ct.includes('application/json') || ct.includes('+json')) {
    picks.add('json-schema-check');
    picks.add('openapi-contract-check');
    picks.add('cors-samesite-auditor');
    picks.add('rate-limit-hygiene');
  }
  if (ctx.rawHeaders['set-cookie']) {
    picks.add('cookie-session-auditor');
    picks.add('token-entropy');
  }
  if (ctx.headers['server'] || ctx.headers['x-powered-by']) {
    picks.add('runtime-header-review');
    picks.add('passive-leak-detector');
  }
  if (ctx.headers['cache-control'] || ctx.headers['via'] || ctx.headers['cf-ray']) {
    picks.add('cdn-cache-review');
    picks.add('ingress-hygiene');
  }
  if (ctx.headers['access-control-allow-origin']) {
    picks.add('cors-samesite-auditor');
  }
  if (ctx.dnsPosture && !ctx.dnsPosture.skipped) {
    picks.add('dns-email-auth-check');
  }
  return [...picks];
}

function runActiveModules(ctx, installedModules) {
  const activeList = installedModules.filter(m => m.active);
  const moduleResults = [];
  const allFindings = [];
  const seenFindingKeys = new Set();

  for (const mod of activeList) {
    const runner = MODULE_RUNNERS[mod.id];
    if (!runner) continue;
    const t0 = Date.now();
    try {
      const out = runner(ctx);
      const elapsed = Date.now() - t0;
      const modFindings = Array.isArray(out.findings) ? out.findings : [];
      for (const f of modFindings) {
        const key = `${f.severity}|${f.item}`;
        if (!seenFindingKeys.has(key)) {
          seenFindingKeys.add(key);
          allFindings.push({ ...f, module_id: mod.id, module_name: mod.name });
        }
      }
      moduleResults.push({
        module_id: mod.id,
        module_name: mod.name,
        category: mod.category,
        status: out.status || 'pass',
        summary: out.summary || '',
        details: out.details || {},
        findings_count: modFindings.length,
        duration_ms: elapsed
      });
    } catch (err) {
      moduleResults.push({
        module_id: mod.id,
        module_name: mod.name,
        category: mod.category,
        status: 'warn',
        summary: `Erro interno do módulo: ${err.message}`,
        details: {},
        findings_count: 0,
        duration_ms: Date.now() - t0
      });
    }
  }

  const owasp = computeOwaspScore(allFindings);
  const hardeningSnippets = generateHardeningSnippets(ctx, allFindings);
  return {
    executed_count: moduleResults.length,
    skipped_count: installedModules.length - activeList.length,
    module_results: moduleResults,
    findings: allFindings,
    owasp_score: owasp.score,
    owasp_grade: owasp.grade,
    hardening_snippets: hardeningSnippets
  };
}

module.exports = {
  MODULE_RUNNERS,
  runActiveModules,
  autoSelectModulesForContext,
  computeOwaspScore,
  shannonEntropy,
  analyzeCspHeader,
  generateHardeningSnippets,
  validateJsonAgainstSchema,
  auditOpenApiSpec
};
