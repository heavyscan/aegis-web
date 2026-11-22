'use strict';

/**
 * Aegis Web Console — Executive Report Generator (PDF 1.4, HTML, Markdown & Summary Analytics)
 * Zero external dependencies: native PDF 1.4 vector graphics with WinAnsi Portuguese typography.
 */

const { enrichFindingWithCompliance, buildComplianceMatrix } = require('./compliance_mapper');

const SEVERITY_RANK = { info: 1, low: 2, medium: 3, high: 4 };
const SEVERITY_LABEL = {
  high: 'ALTA',
  medium: 'MÉDIA',
  low: 'BAIXA',
  info: 'INFO'
};

function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatDateBr(isoStr) {
  const d = isoStr ? new Date(isoStr) : new Date();
  if (Number.isNaN(d.getTime())) return String(isoStr || '');
  const pad = n => String(n).padStart(2, '0');
  return `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function scoreToGrade(score) {
  if (score === null || score === undefined || Number.isNaN(Number(score))) return '—';
  const s = Number(score);
  if (s >= 90) return 'A';
  if (s >= 80) return 'B';
  if (s >= 65) return 'C';
  if (s >= 50) return 'D';
  return 'F';
}

function filterFindingsBySeverity(findings, minSeverity) {
  const minRank = SEVERITY_RANK[String(minSeverity || 'info').toLowerCase()] || 1;
  return (findings || [])
    .map(enrichFindingWithCompliance)
    .filter(f => (SEVERITY_RANK[String(f.severity || 'info').toLowerCase()] || 1) >= minRank)
    .sort((a, b) => (SEVERITY_RANK[String(b.severity || 'info').toLowerCase()] || 1) - (SEVERITY_RANK[String(a.severity || 'info').toLowerCase()] || 1));
}

function computeReportSummary(inspections, hosts, modulesList, minSeverity) {
  const list = Array.isArray(inspections) ? inspections : [];
  const counts = { high: 0, medium: 0, low: 0, info: 0, total: 0 };
  let scoreSum = 0;
  let minScore = null;
  let maxScore = null;

  for (const insp of list) {
    const s = Number(insp.owasp_score ?? 0);
    scoreSum += s;
    if (minScore === null || s < minScore) minScore = s;
    if (maxScore === null || s > maxScore) maxScore = s;
    const filt = filterFindingsBySeverity(insp.findings, minSeverity);
    for (const f of filt) {
      const sev = String(f.severity || 'info').toLowerCase();
      if (sev in counts) counts[sev]++;
      else counts.info++;
      counts.total++;
    }
  }

  const avgScore = list.length ? Math.round(scoreSum / list.length) : null;
  const activeCount = (modulesList || []).filter(m => m.active).length;

  return {
    inspections_count: list.length,
    hosts_count: Array.isArray(hosts) ? hosts.length : 0,
    average_owasp_score: avgScore,
    overall_grade: scoreToGrade(avgScore),
    min_owasp_score: minScore,
    max_owasp_score: maxScore,
    severity_counts: counts,
    modules_active: activeCount,
    modules_total: (modulesList || []).length
  };
}

// =============================================================================
// PDF 1.4 ENGINE (Vector graphics, WinAnsi accents, KPI cards, tables & footers)
// =============================================================================

const CP1252_EXTRA = {
  0x2013: 0x96, // en-dash
  0x2014: 0x97, // em-dash
  0x2018: 0x91, // left single quote
  0x2019: 0x92, // right single quote
  0x201C: 0x93, // left double quote
  0x201D: 0x94, // right double quote
  0x2022: 0x95, // bullet
  0x2026: 0x85  // ellipsis
};

function pdfEncodeWinAnsi(str) {
  const normalized = String(str ?? '')
    .replace(/\u2192/g, '->')
    .replace(/\u2265/g, '>=')
    .replace(/\u2264/g, '<=')
    .replace(/\u2011/g, '-')
    .replace(/[\r\t]/g, ' ');

  let out = '';
  for (let i = 0; i < normalized.length; i++) {
    const code = normalized.charCodeAt(i);
    if (code === 0x5C) {
      out += '\\\\';
    } else if (code === 0x28) {
      out += '\\(';
    } else if (code === 0x29) {
      out += '\\)';
    } else if (code >= 0x20 && code <= 0x7E) {
      out += normalized[i];
    } else if (code >= 0xA0 && code <= 0xFF) {
      out += '\\' + code.toString(8).padStart(3, '0');
    } else if (CP1252_EXTRA[code]) {
      out += '\\' + CP1252_EXTRA[code].toString(8).padStart(3, '0');
    } else {
      // Fallback: strip combining accents or replace with space
      const fallback = normalized[i].normalize('NFD').replace(/[\u0300-\u036f]/g, '');
      if (fallback.length === 1 && fallback.charCodeAt(0) >= 0x20 && fallback.charCodeAt(0) <= 0x7E) {
        const fc = fallback.charCodeAt(0);
        if (fc === 0x5C) out += '\\\\';
        else if (fc === 0x28) out += '\\(';
        else if (fc === 0x29) out += '\\)';
        else out += fallback;
      } else {
        out += ' ';
      }
    }
  }
  return out;
}

function wrapText(text, maxChars) {
  const limit = Math.max(8, Math.floor(maxChars));
  const rawParagraphs = String(text ?? '').split('\n');
  const allLines = [];

  for (const para of rawParagraphs) {
    const trimmed = para.trim();
    if (!trimmed) {
      allLines.push('');
      continue;
    }
    const words = trimmed.split(/\s+/);
    let cur = '';
    for (const word of words) {
      if (word.length > limit) {
        if (cur) {
          allLines.push(cur);
          cur = '';
        }
        for (let i = 0; i < word.length; i += limit) {
          const chunk = word.slice(i, i + limit);
          if (chunk.length === limit) allLines.push(chunk);
          else cur = chunk;
        }
      } else if (!cur) {
        cur = word;
      } else if (cur.length + 1 + word.length <= limit) {
        cur += ' ' + word;
      } else {
        allLines.push(cur);
        cur = word;
      }
    }
    if (cur) allLines.push(cur);
  }
  return allLines.length ? allLines : [''];
}

function wrapCodeLines(codeText, maxChars) {
  const limit = Math.max(20, Math.floor(maxChars));
  const rawLines = String(codeText ?? '').split('\n');
  const out = [];
  for (const line of rawLines) {
    if (line.length <= limit) {
      out.push(line);
      continue;
    }
    let rest = line;
    while (rest.length > limit) {
      let cut = rest.lastIndexOf(' ', limit);
      if (cut < Math.floor(limit * 0.45)) cut = limit;
      out.push(rest.slice(0, cut));
      rest = '  ' + rest.slice(cut).trimStart();
    }
    if (rest.trim().length > 0) out.push(rest);
  }
  return out;
}

const PDF_COLORS = {
  navy: [0.043, 0.075, 0.169],
  navyMid: [0.118, 0.161, 0.231],
  teal: [0.059, 0.463, 0.431],
  tealDark: [0.067, 0.369, 0.349],
  tealSoft: [0.910, 0.969, 0.961],
  text: [0.059, 0.090, 0.165],
  muted: [0.333, 0.392, 0.478],
  lightSlate: [0.796, 0.835, 0.882],
  border: [0.855, 0.882, 0.914],
  surface: [0.973, 0.980, 0.988],
  zebra: [0.945, 0.961, 0.976],
  codeBg: [0.941, 0.957, 0.976],
  white: [1, 1, 1],
  high: { bg: [0.996, 0.886, 0.886], fg: [0.600, 0.106, 0.106], bar: [0.863, 0.149, 0.149] },
  medium: { bg: [1.000, 0.929, 0.835], fg: [0.604, 0.204, 0.071], bar: [0.918, 0.345, 0.047] },
  low: { bg: [0.996, 0.953, 0.780], fg: [0.573, 0.251, 0.055], bar: [0.851, 0.467, 0.024] },
  info: { bg: [0.878, 0.949, 0.996], fg: [0.027, 0.349, 0.522], bar: [0.008, 0.518, 0.780] },
  pass: { bg: [0.863, 0.988, 0.906], fg: [0.086, 0.396, 0.204], bar: [0.086, 0.639, 0.290] },
  warn: { bg: [0.996, 0.953, 0.780], fg: [0.573, 0.251, 0.055], bar: [0.851, 0.467, 0.024] }
};

function fmtRgb(rgb) {
  return `${rgb[0].toFixed(3)} ${rgb[1].toFixed(3)} ${rgb[2].toFixed(3)}`;
}

function scoreColorStyle(score) {
  if (score === null || score === undefined) return PDF_COLORS.info;
  const s = Number(score);
  if (s >= 80) return PDF_COLORS.pass;
  if (s >= 60) return PDF_COLORS.low;
  return PDF_COLORS.high;
}

function buildValidPdfBuffer(opts, ctx) {
  const PAGE_W = 595;
  const PAGE_H = 842;
  const ML = 40;
  const MR = 40;
  const PW = PAGE_W - ML - MR; // 515pt
  const MIN_Y = 54;
  const CONT_TOP_Y = 786;

  const inspections = ctx.inspectionHistory || [];
  const hosts = ctx.hosts || [];
  const modulesList = ctx.modulesInstalled || [];
  const activeMods = modulesList.filter(m => m.active);
  const summary = computeReportSummary(inspections, hosts, modulesList, opts.minSeverity);
  const formattedDate = formatDateBr(opts.generatedAt);

  const pages = [];
  let ops = [];
  let y = PAGE_H;

  const rectFill = (x, bY, w, h, rgb) => {
    ops.push(`${fmtRgb(rgb)} rg ${x.toFixed(2)} ${bY.toFixed(2)} ${w.toFixed(2)} ${h.toFixed(2)} re f`);
  };
  const rectStroke = (x, bY, w, h, rgb, lw = 0.5) => {
    ops.push(`${lw.toFixed(2)} w ${fmtRgb(rgb)} RG ${x.toFixed(2)} ${bY.toFixed(2)} ${w.toFixed(2)} ${h.toFixed(2)} re S`);
  };
  const rectFillStroke = (x, bY, w, h, fillRgb, strokeRgb, lw = 0.5) => {
    ops.push(`${lw.toFixed(2)} w ${fmtRgb(fillRgb)} rg ${fmtRgb(strokeRgb)} RG ${x.toFixed(2)} ${bY.toFixed(2)} ${w.toFixed(2)} ${h.toFixed(2)} re B`);
  };
  const drawLine = (x1, y1, x2, y2, rgb, lw = 0.5) => {
    ops.push(`${lw.toFixed(2)} w ${fmtRgb(rgb)} RG ${x1.toFixed(2)} ${y1.toFixed(2)} m ${x2.toFixed(2)} ${y2.toFixed(2)} l S`);
  };
  const drawText = (x, tY, text, size = 9, font = '/F1', rgb = PDF_COLORS.text) => {
    ops.push(`BT ${fmtRgb(rgb)} rg ${font} ${size.toFixed(1)} Tf ${x.toFixed(2)} ${tY.toFixed(2)} Td (${pdfEncodeWinAnsi(text)}) Tj ET`);
  };
  const drawPill = (x, bY, w, h, text, style, size = 7) => {
    rectFill(x, bY, w, h, style.bg);
    rectStroke(x, bY, w, h, style.bar, 0.5);
    const estW = text.length * size * 0.58;
    const tx = x + Math.max(4, (w - estW) / 2);
    const ty = bY + (h - size * 0.72) / 2;
    drawText(tx, ty, text, size, '/F2', style.fg);
  };

  const startNewPage = () => {
    if (ops.length > 0) pages.push(ops);
    ops = [];
    // Subtle running header on pages 2+
    rectFill(0, PAGE_H - 36, PAGE_W, 36, PDF_COLORS.surface);
    drawLine(0, PAGE_H - 36, PAGE_W, PAGE_H - 36, PDF_COLORS.border, 0.6);
    rectFill(0, PAGE_H - 36, 4, 36, PDF_COLORS.teal);
    const shortTitle = opts.title.length > 62 ? `${opts.title.slice(0, 59)}...` : opts.title;
    drawText(ML, PAGE_H - 22, shortTitle, 8.5, '/F2', PDF_COLORS.navy);
    const rightMeta = `${opts.org} · ${opts.classification.toUpperCase()}`;
    const estMetaW = rightMeta.length * 7.5 * 0.54;
    drawText(Math.max(ML + 260, PAGE_W - MR - estMetaW), PAGE_H - 22, rightMeta, 7.5, '/F1', PDF_COLORS.muted);
    y = CONT_TOP_Y;
  };

  const ensureSpace = (neededH) => {
    if (y - neededH < MIN_Y) {
      startNewPage();
    }
  };

  const drawSectionHeading = (title, subtitle, minExtraH = 26) => {
    ensureSpace((subtitle ? 42 : 30) + minExtraH);
    y -= 6;
    rectFill(ML, y - 14, 4, 15, PDF_COLORS.teal);
    drawText(ML + 10, y - 11, title, 11.5, '/F2', PDF_COLORS.navy);
    if (subtitle) {
      const estW = subtitle.length * 7.5 * 0.52;
      drawText(Math.max(ML + 240, PAGE_W - MR - estW), y - 10, subtitle, 7.5, '/F1', PDF_COLORS.muted);
    }
    drawLine(ML, y - 18, ML + PW, y - 18, PDF_COLORS.border, 0.75);
    y -= 26;
  };

  // --- PAGE 1: COVER BANNER ---
  const bannerH = 122;
  const bannerBottom = PAGE_H - bannerH;
  rectFill(0, bannerBottom, PAGE_W, bannerH, PDF_COLORS.navy);
  rectFill(0, bannerBottom - 4, PAGE_W, 4, PDF_COLORS.teal);

  // Brand icon box
  rectFill(ML, PAGE_H - 44, 24, 24, PDF_COLORS.teal);
  drawText(ML + 4.5, PAGE_H - 35.5, 'AW', 9.5, '/F2', PDF_COLORS.white);
  drawText(ML + 32, PAGE_H - 30, (ctx.appName || 'Aegis Web Console').toUpperCase(), 9.5, '/F2', PDF_COLORS.white);
  drawText(ML + 32, PAGE_H - 41, 'DIAGNÓSTICO HTTP PASSIVO · HARDENING OWASP · WEB QA', 7.2, '/F1', PDF_COLORS.lightSlate);

  // Classification badge (top right)
  const classText = String(opts.classification || 'INTERNO').toUpperCase();
  const classW = Math.max(66, classText.length * 6.2 + 18);
  const classStyle = /restrit|confid/i.test(classText) ? PDF_COLORS.high : PDF_COLORS.info;
  drawPill(PAGE_W - MR - classW, PAGE_H - 40, classW, 18, classText, classStyle, 7.5);

  // Report title (wrapped max 2 lines)
  const titleLines = wrapText(opts.title, 48).slice(0, 2);
  let ty = PAGE_H - 68;
  for (const tl of titleLines) {
    drawText(ML, ty, tl, 15.5, '/F2', PDF_COLORS.white);
    ty -= 19;
  }

  // Metadata strip in banner footer
  const metaLine = `Organização: ${opts.org} · Gerado em: ${formattedDate} · Severidade >= ${opts.minSeverity.toUpperCase()} · Modo: ${ctx.currentMode || 'manual'}`;
  drawText(ML, bannerBottom + 10, metaLine.slice(0, 128), 7.5, '/F1', PDF_COLORS.lightSlate);

  y = bannerBottom - 18;

  // --- EXECUTIVE SUMMARY KPI CARDS (4 cards) ---
  const cardGap = 10;
  const cardW = (PW - cardGap * 3) / 4;
  const cardH = 62;
  const kpiTop = y;
  const kpiBottom = kpiTop - cardH;
  const gradeStyle = scoreColorStyle(summary.average_owasp_score);

  const kpiCards = [
    {
      label: 'NOTA MÉDIA OWASP',
      value: summary.average_owasp_score !== null ? `${summary.overall_grade} (${summary.average_owasp_score}/100)` : '—',
      sub: summary.inspections_count > 1 ? `Mín: ${summary.min_owasp_score} · Máx: ${summary.max_owasp_score}` : (summary.inspections_count === 1 ? 'Avaliação da sessão' : 'Sem inspeções'),
      accent: gradeStyle.bar,
      valColor: gradeStyle.fg
    },
    {
      label: 'ESCOPO AUDITADO',
      value: `${summary.hosts_count} Host(s)`,
      sub: `${summary.inspections_count} inspeção(ões) passiva(s)`,
      accent: PDF_COLORS.teal,
      valColor: PDF_COLORS.navy
    },
    {
      label: 'ACHADOS FILTRADOS',
      value: `${summary.severity_counts.total}`,
      sub: `${summary.severity_counts.high} alta · ${summary.severity_counts.medium} média`,
      accent: summary.severity_counts.high > 0 ? PDF_COLORS.high.bar : (summary.severity_counts.medium > 0 ? PDF_COLORS.medium.bar : PDF_COLORS.pass.bar),
      valColor: PDF_COLORS.navy
    },
    {
      label: 'MÓDULOS & IA LOCAL',
      value: `${summary.modules_active} / ${summary.modules_total}`,
      sub: ctx.aiConfig && ctx.aiConfig.ai_type === 'ollama' ? `IA: ${ctx.aiConfig.ai_model}` : 'IA Local: Desativada',
      accent: PDF_COLORS.navyMid,
      valColor: PDF_COLORS.navy
    }
  ];

  kpiCards.forEach((c, idx) => {
    const cx = ML + idx * (cardW + cardGap);
    rectFillStroke(cx, kpiBottom, cardW, cardH, PDF_COLORS.surface, PDF_COLORS.border, 0.6);
    rectFill(cx, kpiTop - 3, cardW, 3, c.accent);
    drawText(cx + 8, kpiTop - 16, c.label, 6.8, '/F2', PDF_COLORS.muted);
    drawText(cx + 8, kpiTop - 37, c.value.slice(0, 18), 13.5, '/F2', c.valColor);
    drawText(cx + 8, kpiBottom + 9, c.sub.slice(0, 26), 7.2, '/F1', PDF_COLORS.muted);
  });

  y = kpiBottom - 12;

  // --- SEVERITY DISTRIBUTION STRIP ---
  const sevBoxH = 26;
  const sevGap = 8;
  const sevBoxW = (PW - sevGap * 3) / 4;
  const sevBottom = y - sevBoxH;
  const sevDefs = [
    { key: 'high', title: 'ALTA (HIGH)', count: summary.severity_counts.high, style: PDF_COLORS.high },
    { key: 'medium', title: 'MÉDIA (MEDIUM)', count: summary.severity_counts.medium, style: PDF_COLORS.medium },
    { key: 'low', title: 'BAIXA (LOW)', count: summary.severity_counts.low, style: PDF_COLORS.low },
    { key: 'info', title: 'INFO', count: summary.severity_counts.info, style: PDF_COLORS.info }
  ];

  sevDefs.forEach((sd, idx) => {
    const sx = ML + idx * (sevBoxW + sevGap);
    rectFillStroke(sx, sevBottom, sevBoxW, sevBoxH, sd.style.bg, sd.style.bar, 0.5);
    rectFill(sx, sevBottom, 3.5, sevBoxH, sd.style.bar);
    drawText(sx + 9, sevBottom + 9.5, sd.title, 7.2, '/F2', sd.style.fg);
    const cntStr = String(sd.count);
    const cntW = cntStr.length * 6.5;
    drawText(sx + sevBoxW - 10 - cntW, sevBottom + 8.5, cntStr, 11, '/F2', sd.style.fg);
  });

  y = sevBottom - 14;

  // --- SECTION 1: HOST INVENTORY TABLE ---
  if (hosts.length > 0) {
    drawSectionHeading('1. Inventário de Hosts Auditados', `${hosts.length} host(s) único(s)`);

    const cols = [
      { label: 'Host', w: 145 },
      { label: 'Protocolo / TLS', w: 98 },
      { label: 'Postura DNS', w: 112 },
      { label: 'HTTP', w: 42 },
      { label: 'OWASP', w: 68 },
      { label: 'Achados', w: 50 }
    ];

    const drawInvHeader = () => {
      ensureSpace(34);
      const hH = 19;
      rectFill(ML, y - hH, PW, hH, PDF_COLORS.navy);
      let cx = ML;
      for (const col of cols) {
        drawText(cx + 5, y - 13, col.label, 7.5, '/F2', PDF_COLORS.white);
        cx += col.w;
      }
      y -= hH;
    };

    drawInvHeader();
    hosts.forEach((h, idx) => {
      const rH = 19;
      if (y - rH < MIN_Y) {
        startNewPage();
        drawInvHeader();
      }
      const bg = idx % 2 === 0 ? PDF_COLORS.white : PDF_COLORS.zebra;
      rectFillStroke(ML, y - rH, PW, rH, bg, PDF_COLORS.border, 0.4);
      const vals = [
        String(h.host || '').slice(0, 29),
        (h.tls_protocol ? `${h.protocol} (${h.tls_protocol})` : String(h.protocol || '')).slice(0, 20),
        String(h.dns_summary || '—').slice(0, 23),
        String(h.last_status ?? '—'),
        `${h.owasp_grade} (${h.owasp_score}/100)`,
        String(h.findings_count ?? 0)
      ];
      let cx = ML;
      vals.forEach((v, ci) => {
        const font = ci === 0 || ci === 4 ? '/F2' : '/F1';
        const color = ci === 4 ? scoreColorStyle(h.owasp_score).fg : PDF_COLORS.text;
        drawText(cx + 5, y - 13, v, 7.6, font, color);
        cx += cols[ci].w;
      });
      y -= rH;
    });
    y -= 10;
  }

  // --- SECTION 2: DETAILED INSPECTIONS ---
  const secNumInsp = hosts.length > 0 ? 2 : 1;
  drawSectionHeading(`${secNumInsp}. Detalhamento Técnico das Inspeções Passivas`, `${inspections.length} execução(ões)`);

  if (inspections.length === 0) {
    ensureSpace(34);
    rectFillStroke(ML, y - 28, PW, 28, PDF_COLORS.surface, PDF_COLORS.border, 0.5);
    drawText(ML + 10, y - 17, 'Nenhuma inspeção passiva foi executada nesta sessão até o momento.', 8.5, '/F1', PDF_COLORS.muted);
    y -= 36;
  } else {
    inspections.forEach((insp, iIdx) => {
      const filtFindings = filterFindingsBySeverity(insp.findings, opts.minSeverity);
      const iStyle = scoreColorStyle(insp.owasp_score);

      // Inspection Header Card
      ensureSpace(88);
      const hdrH = 54;
      const hdrBottom = y - hdrH;
      rectFillStroke(ML, hdrBottom, PW, hdrH, PDF_COLORS.surface, PDF_COLORS.border, 0.6);
      rectFill(ML, hdrBottom, 4.5, hdrH, iStyle.bar);

      const targetLine = `[${insp.method} ${insp.status_code}] ${insp.target}`;
      drawText(ML + 12, y - 16, targetLine.slice(0, 72), 9.5, '/F2', PDF_COLORS.navy);

      // OWASP grade pill on right
      const pillText = `OWASP ${insp.owasp_grade} · ${insp.owasp_score}/100`;
      const pillW = 88;
      drawPill(ML + PW - pillW - 10, y - 22, pillW, 16, pillText, iStyle, 7.5);

      // Score progress bar
      const barX = ML + 12;
      const barY = y - 31;
      const barW = PW - 24;
      const barH = 5;
      rectFill(barX, barY, barW, barH, PDF_COLORS.border);
      const fillW = Math.max(4, Math.min(barW, (barW * Number(insp.owasp_score || 0)) / 100));
      rectFill(barX, barY, fillW, barH, iStyle.bar);

      // Sub-metadata line
      const subLine = `Execução #${iIdx + 1} · Data: ${formatDateBr(insp.timestamp)} · Latência: ${insp.duration_ms}ms · Módulos executados: ${insp.executed_modules_count} (ignorados: ${insp.skipped_modules_count}) · Achados: ${filtFindings.length}`;
      drawText(ML + 12, hdrBottom + 8, subLine.slice(0, 108), 7.3, '/F1', PDF_COLORS.muted);
      y = hdrBottom - 8;

      // TLS, Redirect Chain & DNS summary strip (if available)
      const hasTls = Boolean(insp.tls_info);
      const hasDns = Boolean(insp.dns_posture && !insp.dns_posture.skipped);
      const hasRedir = Array.isArray(insp.redirect_chain) && insp.redirect_chain.length > 1;
      const hasDelta = Boolean(insp.delta);
      if (hasTls || hasDns || hasRedir || hasDelta) {
        const infoLines = [];
        if (hasRedir) {
          const trail = insp.redirect_chain.map(h => `${h.statusCode}`).join(' -> ');
          infoLines.push(`Redirecionamentos (${insp.redirect_chain.length - 1} salto(s)): ${trail} · Origem: ${insp.redirect_chain[0].url} -> Destino: ${insp.target}`);
        }
        if (hasDelta) {
          const sign = insp.delta.score_delta >= 0 ? '+' : '';
          infoLines.push(`Evolução vs inspeção anterior: ${sign}${insp.delta.score_delta} pts (anterior: ${insp.delta.previous_grade} ${insp.delta.previous_score}/100) · Resolvidos: ${insp.delta.resolved_count} · Novos: ${insp.delta.new_count}`);
        }
        if (hasTls) {
          infoLines.push(`TLS: ${insp.tls_info.protocol || 'n/a'} · Cifra: ${insp.tls_info.cipher || 'n/a'} · CN: ${insp.tls_info.subject || 'n/a'} · Emissor: ${insp.tls_info.issuer || 'n/a'} · Expira em: ${insp.tls_info.daysRemaining ?? '?'} dias`);
        }
        if (hasDns) {
          const adv = insp.dns_posture.advancedChecked
            ? ` · MX=${(insp.dns_posture.mx || []).length} · MTA-STS=${insp.dns_posture.mtaSts ? 'OK' : 'ausente'}`
            : '';
          infoLines.push(`Postura DNS (${insp.dns_posture.domain}): CAA=${insp.dns_posture.caa.length ? 'OK' : 'ausente'} · SPF=${insp.dns_posture.spf ? 'OK' : 'ausente'} · DMARC=${insp.dns_posture.dmarc ? 'OK' : 'ausente'}${adv}`);
        }
        const wrappedInfo = infoLines.flatMap(l => wrapText(l, 96));
        const boxH = wrappedInfo.length * 11 + 10;
        ensureSpace(boxH + 6);
        rectFillStroke(ML, y - boxH, PW, boxH, PDF_COLORS.white, PDF_COLORS.border, 0.5);
        rectFill(ML, y - boxH, 3, boxH, PDF_COLORS.teal);
        let iy = y - 12;
        for (const wl of wrappedInfo) {
          drawText(ML + 9, iy, wl, 7.6, '/F1', PDF_COLORS.text);
          iy -= 11;
        }
        y -= (boxH + 8);
      }

      // Findings Cards (sorted High -> Info)
      ensureSpace(26);
      drawText(ML, y - 10, `Achados & Recomendações Prioritárias (${filtFindings.length})`, 9, '/F2', PDF_COLORS.navy);
      y -= 16;

      if (filtFindings.length === 0) {
        ensureSpace(24);
        rectFillStroke(ML, y - 20, PW, 20, PDF_COLORS.pass.bg, PDF_COLORS.pass.bar, 0.4);
        drawText(ML + 8, y - 13, 'Nenhuma vulnerabilidade ou observação acima da severidade mínima selecionada.', 7.8, '/F1', PDF_COLORS.pass.fg);
        y -= 28;
      } else {
        for (const f of filtFindings) {
          const sevKey = String(f.severity || 'info').toLowerCase();
          const fStyle = PDF_COLORS[sevKey] || PDF_COLORS.info;
          const sevText = `${f.priority || 'P3'} · ${SEVERITY_LABEL[sevKey] || sevKey.toUpperCase()}`;
          const metaTag = [f.module_id, f.cwe, f.asvs ? `ASVS ${f.asvs}` : null].filter(Boolean).join(' · ');
          const titleWrapped = wrapText(`[${metaTag}] ${f.item}`, 76);
          const recWrapped = wrapText(`Recomendação (${f.effort || 'Hardening'}): ${f.recommendation}`, 92);
          const itemH = 8 + titleWrapped.length * 10.8 + recWrapped.length * 10 + 6;

          ensureSpace(itemH + 5);
          const fBottom = y - itemH;
          rectFillStroke(ML, fBottom, PW, itemH, PDF_COLORS.white, PDF_COLORS.border, 0.45);
          rectFill(ML, fBottom, 3.5, itemH, fStyle.bar);

          drawPill(ML + 8, y - 17, 52, 12, sevText, fStyle, 6.2);
          let fy = y - 14;
          titleWrapped.forEach((tl, ti) => {
            drawText(ti === 0 ? ML + 66 : ML + 10, fy, tl, 8.0, '/F2', PDF_COLORS.text);
            fy -= 10.8;
          });
          for (const rl of recWrapped) {
            drawText(ML + 10, fy, rl, 7.6, '/F1', PDF_COLORS.muted);
            fy -= 10;
          }
          y = fBottom - 4;
        }
        y -= 4;
      }

      // Module Execution Summary Table
      if (Array.isArray(insp.module_results) && insp.module_results.length > 0) {
        ensureSpace(46);
        drawText(ML, y - 10, `Resumo por Módulo Executado (${insp.module_results.length})`, 9, '/F2', PDF_COLORS.navy);
        y -= 16;

        const mCols = [
          { label: 'Módulo', w: 148 },
          { label: 'Status', w: 50 },
          { label: 'Resumo da Análise', w: 277 },
          { label: 'Ach.', w: 40 }
        ];

        const drawModTblHeader = () => {
          ensureSpace(32);
          rectFill(ML, y - 17, PW, 17, PDF_COLORS.navyMid);
          let cx = ML;
          for (const col of mCols) {
            drawText(cx + 5, y - 11.5, col.label, 7.3, '/F2', PDF_COLORS.white);
            cx += col.w;
          }
          y -= 17;
        };

        drawModTblHeader();
        insp.module_results.forEach((mr, mIdx) => {
          const nameLines = wrapText(mr.module_name || mr.module_id, 28).slice(0, 2);
          const sumLines = wrapText(mr.summary || '', 55).slice(0, 3);
          const maxL = Math.max(nameLines.length, sumLines.length);
          const rowH = Math.max(17, maxL * 9.8 + 7);

          if (y - rowH < MIN_Y) {
            startNewPage();
            drawModTblHeader();
          }
          const bg = mIdx % 2 === 0 ? PDF_COLORS.white : PDF_COLORS.zebra;
          rectFillStroke(ML, y - rowH, PW, rowH, bg, PDF_COLORS.border, 0.35);

          let ny = y - 11;
          for (const nl of nameLines) {
            drawText(ML + 5, ny, nl, 7.4, '/F2', PDF_COLORS.text);
            ny -= 9.8;
          }

          const stKey = String(mr.status || 'info').toLowerCase();
          const stStyle = PDF_COLORS[stKey] || PDF_COLORS.info;
          drawPill(ML + mCols[0].w + 4, y - 14.5, 40, 11.5, stKey.toUpperCase(), stStyle, 6.4);

          let sy = y - 11;
          for (const sl of sumLines) {
            drawText(ML + mCols[0].w + mCols[1].w + 5, sy, sl, 7.3, '/F1', PDF_COLORS.muted);
            sy -= 9.8;
          }

          drawText(ML + mCols[0].w + mCols[1].w + mCols[2].w + 14, y - 11, String(mr.findings_count ?? 0), 7.5, '/F2', PDF_COLORS.text);
          y -= rowH;
        });
        y -= 10;
      }

      // Hardening Snippets (Code blocks)
      const drawCodeBlock = (blockTitle, codeStr) => {
        const codeLines = wrapCodeLines(codeStr, 110);
        if (!codeLines.length) return;
        ensureSpace(46);
        drawText(ML, y - 10, blockTitle, 8.5, '/F2', PDF_COLORS.navy);
        y -= 15;

        let idx = 0;
        while (idx < codeLines.length) {
          const avail = Math.floor((y - MIN_Y - 12) / 9.4);
          if (avail < 3) {
            startNewPage();
            continue;
          }
          const slice = codeLines.slice(idx, idx + avail);
          const bH = slice.length * 9.4 + 10;
          rectFillStroke(ML, y - bH, PW, bH, PDF_COLORS.codeBg, PDF_COLORS.border, 0.5);
          rectFill(ML, y - bH, 3.5, bH, PDF_COLORS.teal);
          let cy = y - 11;
          for (const cl of slice) {
            drawText(ML + 9, cy, cl, 7.2, '/F3', PDF_COLORS.text);
            cy -= 9.4;
          }
          y -= (bH + 7);
          idx += slice.length;
        }
      };

      if (opts.includeSnippets && insp.hardening_snippets && insp.hardening_snippets.missing_count > 0) {
        drawCodeBlock(`Hardening Sugerido — Nginx (${insp.hardening_snippets.missing_count} cabeçalho(s))`, insp.hardening_snippets.nginx || '');
        drawCodeBlock('Hardening Sugerido — Express.js', insp.hardening_snippets.express || '');
      }

      if (opts.includeHeaders && insp.response_headers) {
        const hdrStr = Object.entries(insp.response_headers).map(([k, v]) => `${k}: ${v}`).join('\n');
        drawCodeBlock(`Cabeçalhos HTTP Recebidos (${Object.keys(insp.response_headers).length})`, hdrStr);
      }

      if (insp.ai_summary) {
        const aiLines = wrapText(insp.ai_summary, 94);
        ensureSpace(34);
        drawText(ML, y - 10, 'Resumo Defensivo — Assistente de IA Local', 8.5, '/F2', PDF_COLORS.tealDark);
        y -= 15;
        let idx = 0;
        while (idx < aiLines.length) {
          const avail = Math.floor((y - MIN_Y - 12) / 10.5);
          if (avail < 3) {
            startNewPage();
            continue;
          }
          const slice = aiLines.slice(idx, idx + avail);
          const bH = slice.length * 10.5 + 12;
          rectFillStroke(ML, y - bH, PW, bH, PDF_COLORS.tealSoft, PDF_COLORS.teal, 0.5);
          let ay = y - 12;
          for (const al of slice) {
            drawText(ML + 9, ay, al, 7.8, '/F1', PDF_COLORS.text);
            ay -= 10.5;
          }
          y -= (bH + 8);
          idx += slice.length;
        }
      }

      y -= 6;
    });
  }

  // --- SECTION: OWASP TOP 10:2021 COMPLIANCE MATRIX ---
  const allFilteredFindings = inspections.flatMap(i => filterFindingsBySeverity(i.findings, opts.minSeverity));
  const sessionMatrix = buildComplianceMatrix(allFilteredFindings);
  let nextSecNum = secNumInsp + 1;
  if (sessionMatrix.owasp_top10.length > 0) {
    drawSectionHeading(`${nextSecNum}. Matriz de Conformidade OWASP Top 10:2021 & CWE`, `P1:${sessionMatrix.priority_counts.P1} · P2:${sessionMatrix.priority_counts.P2} · P3:${sessionMatrix.priority_counts.P3}`, 56);
    nextSecNum++;

    const omCols = [
      { label: 'Categoria OWASP Top 10:2021', w: 225 },
      { label: 'CWEs Associados', w: 120 },
      { label: 'Alta', w: 42 },
      { label: 'Média', w: 42 },
      { label: 'Baixa', w: 42 },
      { label: 'Total', w: 44 }
    ];
    const drawOmHeader = () => {
      ensureSpace(40);
      rectFill(ML, y - 17, PW, 17, PDF_COLORS.navy);
      let cx = ML;
      for (const col of omCols) {
        drawText(cx + 5, y - 11.5, col.label, 7.3, '/F2', PDF_COLORS.white);
        cx += col.w;
      }
      y -= 17;
    };
    drawOmHeader();
    sessionMatrix.owasp_top10.forEach((row, idx) => {
      const rH = 19;
      if (y - rH < MIN_Y) {
        startNewPage();
        drawOmHeader();
      }
      const bg = idx % 2 === 0 ? PDF_COLORS.white : PDF_COLORS.zebra;
      rectFillStroke(ML, y - rH, PW, rH, bg, PDF_COLORS.border, 0.35);
      const vals = [
        String(row.category).slice(0, 44),
        row.cwes.slice(0, 3).join(', '),
        String(row.high),
        String(row.medium),
        String(row.low),
        String(row.total)
      ];
      let cx = ML;
      vals.forEach((v, ci) => {
        const font = ci === 0 || ci === 5 ? '/F2' : '/F1';
        const color = (ci === 2 && row.high > 0) ? PDF_COLORS.high.fg : ((ci === 3 && row.medium > 0) ? PDF_COLORS.medium.fg : PDF_COLORS.text);
        drawText(cx + 5, y - 12.5, v, 7.4, font, color);
        cx += omCols[ci].w;
      });
      y -= rH;
    });
    y -= 10;
  }

  // --- SECTION: ACTIVE DEFENSIVE MODULES CATALOG ---
  if (opts.includeModules) {
    const secNumMod = nextSecNum;
    drawSectionHeading(`${secNumMod}. Catálogo de Módulos Defensivos Ativos`, `${activeMods.length} de ${modulesList.length} ativos`, 56);

    if (activeMods.length === 0) {
      ensureSpace(26);
      drawText(ML, y - 12, 'Nenhum módulo defensivo estava ativo no momento da geração deste relatório.', 8.2, '/F1', PDF_COLORS.muted);
      y -= 24;
    } else {
      const cCols = [
        { label: 'Módulo / Identificador', w: 180 },
        { label: 'Categoria', w: 72 },
        { label: 'Escopo de Verificação', w: 263 }
      ];

      const drawCatHeader = () => {
        ensureSpace(46);
        rectFill(ML, y - 17, PW, 17, PDF_COLORS.navy);
        let cx = ML;
        for (const col of cCols) {
          drawText(cx + 5, y - 11.5, col.label, 7.4, '/F2', PDF_COLORS.white);
          cx += col.w;
        }
        y -= 17;
      };

      drawCatHeader();
      activeMods.forEach((mod, idx) => {
        const nameLines = wrapText(mod.name, 34).slice(0, 2);
        const descLines = wrapText(mod.description, 52).slice(0, 3);
        const leftH = nameLines.length * 9.5 + 14;
        const rightH = descLines.length * 9.6 + 8;
        const rowH = Math.max(24, leftH, rightH);
        if (y - rowH < MIN_Y) {
          startNewPage();
          drawCatHeader();
        }
        const bg = idx % 2 === 0 ? PDF_COLORS.white : PDF_COLORS.zebra;
        rectFillStroke(ML, y - rowH, PW, rowH, bg, PDF_COLORS.border, 0.35);

        let ny = y - 10.5;
        for (const nl of nameLines) {
          drawText(ML + 5, ny, nl, 7.4, '/F2', PDF_COLORS.text);
          ny -= 9.5;
        }
        drawText(ML + 5, ny - 0.5, String(mod.id).slice(0, 36), 6.7, '/F3', PDF_COLORS.muted);
        drawPill(ML + cCols[0].w + 6, y - 15.5, 58, 11.5, String(mod.category || 'general').toUpperCase(), PDF_COLORS.info, 6.2);

        let dy = y - 10.8;
        for (const dl of descLines) {
          drawText(ML + cCols[0].w + cCols[1].w + 5, dy, dl, 7.3, '/F1', PDF_COLORS.text);
          dy -= 9.6;
        }
        y -= rowH;
      });
    }
  }

  if (ops.length > 0 || pages.length === 0) pages.push(ops);

  // Stamp running footer with exact "Página X de Y" on every page
  const totalPages = pages.length;
  const pageStreams = pages.map((pageOps, pIdx) => {
    const footerOps = [];
    footerOps.push(`0.50 w ${fmtRgb(PDF_COLORS.border)} RG ${ML} 38 m ${ML + PW} 38 l S`);
    const leftFooter = `${ctx.appName || 'Aegis Web Console'} · ${opts.org} · Classificação: ${opts.classification}`;
    footerOps.push(`BT ${fmtRgb(PDF_COLORS.muted)} rg /F1 7.2 Tf ${ML} 25 Td (${pdfEncodeWinAnsi(leftFooter.slice(0, 88))}) Tj ET`);
    const rightFooter = `Página ${pIdx + 1} de ${totalPages}`;
    const rfW = rightFooter.length * 7.2 * 0.54;
    footerOps.push(`BT ${fmtRgb(PDF_COLORS.muted)} rg /F2 7.2 Tf ${(PAGE_W - MR - rfW).toFixed(2)} 25 Td (${pdfEncodeWinAnsi(rightFooter)}) Tj ET`);
    return [...pageOps, ...footerOps].join('\n');
  });

  // Assemble PDF 1.4 binary with WinAnsiEncoding standard fonts
  const objects = [];
  const addObj = (content) => {
    objects.push(content);
    return objects.length;
  };

  const fontRegularId = addObj('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>');
  const fontBoldId = addObj('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>');
  const fontMonoId = addObj('<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>');
  const pageIds = [];
  const pagesObjId = addObj('');

  for (const stream of pageStreams) {
    const streamBuf = Buffer.from(stream, 'ascii');
    const contentId = addObj(`<< /Length ${streamBuf.length} >>\nstream\n${stream}\nendstream`);
    const pageId = addObj(
      `<< /Type /Page /Parent ${pagesObjId} 0 R /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] ` +
      `/Resources << /Font << /F1 ${fontRegularId} 0 R /F2 ${fontBoldId} 0 R /F3 ${fontMonoId} 0 R >> >> ` +
      `/Contents ${contentId} 0 R >>`
    );
    pageIds.push(pageId);
  }

  objects[pagesObjId - 1] = `<< /Type /Pages /Kids [${pageIds.map(id => `${id} 0 R`).join(' ')}] /Count ${pageIds.length} >>`;
  const catalogId = addObj(`<< /Type /Catalog /Pages ${pagesObjId} 0 R >>`);
  const infoId = addObj(
    `<< /Title (${pdfEncodeWinAnsi(opts.title)}) ` +
    `/Author (${pdfEncodeWinAnsi(opts.org)}) ` +
    `/Subject (${pdfEncodeWinAnsi('Relatório de Auditoria Passiva OWASP')}) ` +
    `/Producer (${pdfEncodeWinAnsi(ctx.appName || 'Aegis Web Console')}) >>`
  );

  let pdf = '%PDF-1.4\n';
  const offsets = [0];
  for (let i = 0; i < objects.length; i++) {
    offsets.push(Buffer.byteLength(pdf, 'ascii'));
    pdf += `${i + 1} 0 obj\n${objects[i]}\nendobj\n`;
  }
  const xrefOffset = Buffer.byteLength(pdf, 'ascii');
  pdf += `xref\n0 ${objects.length + 1}\n`;
  pdf += '0000000000 65535 f \n';
  for (let i = 1; i <= objects.length; i++) {
    pdf += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root ${catalogId} 0 R /Info ${infoId} 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;
  return Buffer.from(pdf, 'ascii');
}

// =============================================================================
// EXECUTIVE HTML REPORT (Print-ready A4 + Responsive)
// =============================================================================

function buildHtmlReport(opts, ctx) {
  const inspections = ctx.inspectionHistory || [];
  const hosts = ctx.hosts || [];
  const modulesList = ctx.modulesInstalled || [];
  const activeMods = modulesList.filter(m => m.active);
  const summary = computeReportSummary(inspections, hosts, modulesList, opts.minSeverity);
  const formattedDate = formatDateBr(opts.generatedAt);

  const gradeBadgeCls = (score) => {
    if (score === null || score === undefined) return 'grade-info';
    if (score >= 80) return 'grade-pass';
    if (score >= 60) return 'grade-warn';
    return 'grade-fail';
  };

  const totalSev = Math.max(1, summary.severity_counts.total);
  const sevBarHtml = summary.severity_counts.total > 0
    ? `<div class="sev-bar" aria-label="Distribuição de severidade">
        ${summary.severity_counts.high ? `<div class="sev-seg seg-high" style="width:${(summary.severity_counts.high / totalSev * 100).toFixed(1)}%"></div>` : ''}
        ${summary.severity_counts.medium ? `<div class="sev-seg seg-medium" style="width:${(summary.severity_counts.medium / totalSev * 100).toFixed(1)}%"></div>` : ''}
        ${summary.severity_counts.low ? `<div class="sev-seg seg-low" style="width:${(summary.severity_counts.low / totalSev * 100).toFixed(1)}%"></div>` : ''}
        ${summary.severity_counts.info ? `<div class="sev-seg seg-info" style="width:${(summary.severity_counts.info / totalSev * 100).toFixed(1)}%"></div>` : ''}
      </div>`
    : '';

  const hostsHtml = hosts.length > 0
    ? `<section class="section">
        <h2 class="sec-title">1. Inventário de Hosts Auditados <span>${hosts.length} host(s)</span></h2>
        <div class="tbl-wrap">
          <table>
            <thead><tr><th>Host</th><th>Protocolo / TLS</th><th>Postura DNS</th><th>Último HTTP</th><th>Nota OWASP</th><th>Achados</th></tr></thead>
            <tbody>
              ${hosts.map(h => `<tr>
                <td><strong>${escapeHtml(h.host)}</strong></td>
                <td>${escapeHtml(h.tls_protocol ? `${h.protocol} (${h.tls_protocol})` : h.protocol)}</td>
                <td>${escapeHtml(h.dns_summary || '—')}</td>
                <td>${escapeHtml(h.last_status)}</td>
                <td><span class="pill ${gradeBadgeCls(h.owasp_score)}">${escapeHtml(h.owasp_grade)} (${escapeHtml(h.owasp_score)}/100)</span></td>
                <td>${escapeHtml(h.findings_count)}</td>
              </tr>`).join('')}
            </tbody>
          </table>
        </div>
      </section>`
    : '';

  const inspSecNum = hosts.length > 0 ? 2 : 1;
  const inspBlocks = inspections.map((insp, idx) => {
    const filt = filterFindingsBySeverity(insp.findings, opts.minSeverity);
    const barColor = insp.owasp_score >= 80 ? '#16a34a' : (insp.owasp_score >= 60 ? '#d97706' : '#dc2626');

    const tlsCard = insp.tls_info
      ? `<div class="meta-card">
          <div class="meta-title">Segurança de Transporte (TLS)</div>
          <div><strong>Protocolo:</strong> ${escapeHtml(insp.tls_info.protocol || 'n/a')} · <strong>Cifra:</strong> ${escapeHtml(insp.tls_info.cipher || 'n/a')}</div>
          <div><strong>CN:</strong> ${escapeHtml(insp.tls_info.subject || 'n/a')} · <strong>Emissor:</strong> ${escapeHtml(insp.tls_info.issuer || 'n/a')} · <strong>Expira em:</strong> ${escapeHtml(insp.tls_info.daysRemaining ?? '?')} dias</div>
        </div>`
      : '';

    const dnsCard = insp.dns_posture && !insp.dns_posture.skipped
      ? `<div class="meta-card">
          <div class="meta-title">Postura DNS Passiva (${escapeHtml(insp.dns_posture.domain)})</div>
          <div><strong>CAA:</strong> ${insp.dns_posture.caa.length ? 'Configurado' : 'Ausente'} · <strong>SPF:</strong> ${insp.dns_posture.spf ? 'Configurado' : 'Ausente'} · <strong>DMARC:</strong> ${insp.dns_posture.dmarc ? 'Configurado' : 'Ausente'}${insp.dns_posture.advancedChecked ? ` · <strong>MX:</strong> ${(insp.dns_posture.mx || []).length} · <strong>MTA-STS:</strong> ${insp.dns_posture.mtaSts ? 'OK' : 'Ausente'}` : ''}</div>
        </div>`
      : '';

    const redirCard = Array.isArray(insp.redirect_chain) && insp.redirect_chain.length > 1
      ? `<div class="meta-card">
          <div class="meta-title">Cadeia de Redirecionamentos (${insp.redirect_chain.length - 1} salto(s))</div>
          <div>${escapeHtml(insp.redirect_chain.map(h => `${h.statusCode} (${h.host})`).join(' -> '))}</div>
        </div>`
      : '';

    const deltaCard = insp.delta
      ? `<div class="meta-card">
          <div class="meta-title">Evolução vs Inspeção Anterior</div>
          <div><strong>Delta:</strong> ${insp.delta.score_delta >= 0 ? '+' : ''}${escapeHtml(insp.delta.score_delta)} pts (anterior: ${escapeHtml(insp.delta.previous_grade)} ${escapeHtml(insp.delta.previous_score)}/100) · <strong>Resolvidos:</strong> ${escapeHtml(insp.delta.resolved_count)} · <strong>Novos:</strong> ${escapeHtml(insp.delta.new_count)}</div>
        </div>`
      : '';

    const findingsHtml = filt.length
      ? `<div class="finding-grid">${filt.map(f => {
          const sev = String(f.severity || 'info').toLowerCase();
          return `<div class="finding-item sev-border-${escapeHtml(sev)}">
            <div class="finding-head">
              <span class="sev sev-${escapeHtml(sev)}">${escapeHtml(f.priority || 'P3')} · ${escapeHtml(SEVERITY_LABEL[sev] || sev.toUpperCase())}</span>
              <span class="mod-tag">${escapeHtml(f.module_id)}</span>
              ${f.cwe ? `<span class="mod-tag">${escapeHtml(f.cwe)}</span>` : ''}
              ${f.asvs ? `<span class="mod-tag">ASVS ${escapeHtml(f.asvs)}</span>` : ''}
              <strong>${escapeHtml(f.item)}</strong>
            </div>
            <div class="finding-rec"><strong>Recomendação (${escapeHtml(f.effort || 'Hardening')}):</strong> ${escapeHtml(f.recommendation)} <span class="muted">· ${escapeHtml(f.owasp_top10 || '')}</span></div>
          </div>`;
        }).join('')}</div>`
      : '<div class="empty-ok">Nenhuma observação acima da severidade mínima selecionada.</div>';

    const modRowsHtml = Array.isArray(insp.module_results) && insp.module_results.length > 0
      ? `<h4>Resumo por Módulo Executado (${insp.module_results.length})</h4>
        <div class="tbl-wrap">
          <table>
            <thead><tr><th>Módulo</th><th>Status</th><th>Resumo</th><th>Achados</th></tr></thead>
            <tbody>
              ${insp.module_results.map(m => `<tr>
                <td><strong>${escapeHtml(m.module_name)}</strong> <span class="muted">(${escapeHtml(m.module_id)})</span></td>
                <td><span class="pill st-${escapeHtml(m.status)}">${escapeHtml(String(m.status || 'info').toUpperCase())}</span></td>
                <td>${escapeHtml(m.summary)}</td>
                <td>${escapeHtml(m.findings_count)}</td>
              </tr>`).join('')}
            </tbody>
          </table>
        </div>`
      : '';

    const snippetsHtml = opts.includeSnippets && insp.hardening_snippets && insp.hardening_snippets.missing_count > 0
      ? `<h4>Snippets de Hardening Sugeridos (${insp.hardening_snippets.missing_count} cabeçalho(s))</h4>
        <div class="code-grid">
          <div><div class="code-label">Nginx</div><pre>${escapeHtml(insp.hardening_snippets.nginx)}</pre></div>
          <div><div class="code-label">Apache (mod_headers)</div><pre>${escapeHtml(insp.hardening_snippets.apache)}</pre></div>
          <div><div class="code-label">Express.js</div><pre>${escapeHtml(insp.hardening_snippets.express)}</pre></div>
          ${insp.hardening_snippets.caddy ? `<div><div class="code-label">Caddyfile</div><pre>${escapeHtml(insp.hardening_snippets.caddy)}</pre></div>` : ''}
          ${insp.hardening_snippets.cloudflare ? `<div><div class="code-label">Cloudflare Workers</div><pre>${escapeHtml(insp.hardening_snippets.cloudflare)}</pre></div>` : ''}
        </div>`
      : '';

    const headersHtml = opts.includeHeaders && insp.response_headers
      ? `<h4>Cabeçalhos HTTP Recebidos (${Object.keys(insp.response_headers).length})</h4>
        <pre>${escapeHtml(Object.entries(insp.response_headers).map(([k, v]) => `${k}: ${v}`).join('\n'))}</pre>`
      : '';

    const aiHtml = insp.ai_summary
      ? `<h4>Resumo Defensivo — Assistente IA</h4><div class="ai-box">${escapeHtml(insp.ai_summary)}</div>`
      : '';

    return `<article class="insp-card">
      <div class="insp-top">
        <div>
          <div class="insp-kicker">Inspeção #${idx + 1} · ${escapeHtml(formatDateBr(insp.timestamp))} · ${escapeHtml(insp.duration_ms)}ms · ${escapeHtml(insp.executed_modules_count)} módulos executados</div>
          <h3><span class="http-tag">${escapeHtml(insp.method)} ${escapeHtml(insp.status_code)}</span> ${escapeHtml(insp.target)}</h3>
        </div>
        <span class="pill pill-lg ${gradeBadgeCls(insp.owasp_score)}">OWASP ${escapeHtml(insp.owasp_grade)} · ${escapeHtml(insp.owasp_score)}/100</span>
      </div>
      <div class="score-track"><div class="score-fill" style="width:${Math.max(4, Math.min(100, Number(insp.owasp_score || 0)))}%;background:${barColor}"></div></div>
      ${(tlsCard || dnsCard || redirCard || deltaCard) ? `<div class="meta-grid">${tlsCard}${dnsCard}${redirCard}${deltaCard}</div>` : ''}
      <h4>Achados &amp; Recomendações (${filt.length})</h4>
      ${findingsHtml}
      ${modRowsHtml}
      ${snippetsHtml}
      ${headersHtml}
      ${aiHtml}
    </article>`;
  }).join('') || '<div class="empty-box">Nenhuma inspeção passiva foi executada nesta sessão.</div>';

  const modSecNum = inspSecNum + 1;
  const modsHtml = opts.includeModules
    ? `<section class="section">
        <h2 class="sec-title">${modSecNum}. Catálogo de Módulos Defensivos Ativos <span>${activeMods.length} / ${modulesList.length} ativos</span></h2>
        <div class="tbl-wrap">
          <table>
            <thead><tr><th>Módulo</th><th>ID</th><th>Categoria</th><th>Escopo</th></tr></thead>
            <tbody>
              ${activeMods.map(m => `<tr>
                <td><strong>${escapeHtml(m.name)}</strong></td>
                <td><code>${escapeHtml(m.id)}</code></td>
                <td><span class="pill grade-info">${escapeHtml(m.category)}</span></td>
                <td>${escapeHtml(m.description)}</td>
              </tr>`).join('') || '<tr><td colspan="4">Nenhum módulo ativo.</td></tr>'}
            </tbody>
          </table>
        </div>
      </section>`
    : '';

  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(opts.title)}</title>
  <style>
    @page { size: A4; margin: 14mm; }
    * { box-sizing: border-box; }
    body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; margin: 0; background: #f1f5f9; color: #0f172a; line-height: 1.5; }
    .page { max-width: 1040px; margin: 1.5rem auto; padding: 0 1rem 2rem; }
    .hero { background: linear-gradient(135deg, #0b132b 0%, #162447 100%); color: #fff; border-radius: 12px; padding: 1.6rem 1.8rem; border-bottom: 5px solid #0f766e; box-shadow: 0 6px 20px rgba(11,19,43,0.18); }
    .hero-top { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 0.9rem; }
    .brand { display: flex; align-items: center; gap: 10px; }
    .brand-icon { width: 34px; height: 34px; border-radius: 8px; background: #0f766e; color: #fff; font-weight: 800; display: flex; align-items: center; justify-content: center; font-size: 0.9rem; }
    .brand-sub { font-size: 0.72rem; letter-spacing: 0.06em; text-transform: uppercase; color: #94a3b8; }
    .hero h1 { margin: 0 0 0.65rem; font-size: 1.55rem; line-height: 1.25; }
    .hero-meta { display: flex; flex-wrap: wrap; gap: 10px 18px; font-size: 0.83rem; color: #cbd5e1; }
    .class-pill { padding: 0.25rem 0.75rem; border-radius: 999px; font-size: 0.74rem; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; background: rgba(56,189,248,0.16); color: #7dd3fc; border: 1px solid rgba(125,211,252,0.45); }
    .kpi-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin: 1.2rem 0 0.9rem; }
    .kpi { background: #fff; border: 1px solid #e2e8f0; border-top: 3px solid #0f766e; border-radius: 8px; padding: 0.9rem 1rem; box-shadow: 0 1px 3px rgba(15,23,42,0.06); }
    .kpi-label { font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; color: #64748b; }
    .kpi-val { font-size: 1.38rem; font-weight: 800; margin: 4px 0 2px; color: #0b132b; }
    .kpi-sub { font-size: 0.76rem; color: #64748b; }
    .sev-strip { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin-bottom: 0.7rem; }
    .sev-card { border-radius: 8px; padding: 0.55rem 0.85rem; display: flex; justify-content: space-between; align-items: center; font-size: 0.78rem; font-weight: 700; border-left: 4px solid; }
    .sev-card strong { font-size: 1.12rem; }
    .sc-high { background: #fee2e2; color: #991b1b; border-color: #dc2626; }
    .sc-medium { background: #ffedd5; color: #9a3412; border-color: #ea580c; }
    .sc-low { background: #fef3c7; color: #92400e; border-color: #d97706; }
    .sc-info { background: #e0f2fe; color: #075985; border-color: #0284c7; }
    .sev-bar { display: flex; height: 8px; border-radius: 999px; overflow: hidden; background: #e2e8f0; margin-bottom: 1.3rem; }
    .seg-high { background: #dc2626; } .seg-medium { background: #ea580c; } .seg-low { background: #d97706; } .seg-info { background: #0284c7; }
    .section { margin-top: 1.4rem; }
    .sec-title { display: flex; justify-content: space-between; align-items: baseline; gap: 10px; flex-wrap: wrap; font-size: 1.12rem; color: #0b132b; border-bottom: 2px solid #e2e8f0; border-left: 4px solid #0f766e; padding: 0.15rem 0 0.45rem 0.7rem; margin: 0 0 0.85rem; }
    .sec-title span { font-size: 0.78rem; font-weight: 600; color: #64748b; }
    .insp-card { background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 1.2rem 1.35rem; margin-bottom: 1.15rem; box-shadow: 0 1px 3px rgba(15,23,42,0.06); }
    .insp-top { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; flex-wrap: wrap; }
    .insp-kicker { font-size: 0.77rem; color: #64748b; margin-bottom: 3px; }
    .insp-card h3 { margin: 0; font-size: 1.05rem; color: #0b132b; overflow-wrap: anywhere; }
    .insp-card h4 { margin: 1rem 0 0.5rem; font-size: 0.92rem; color: #0b132b; }
    .http-tag { display: inline-block; background: #0b132b; color: #fff; padding: 0.1rem 0.48rem; border-radius: 4px; font-size: 0.76rem; margin-right: 6px; vertical-align: middle; }
    .score-track { height: 8px; background: #e2e8f0; border-radius: 999px; overflow: hidden; margin: 0.7rem 0 0.9rem; }
    .score-fill { height: 100%; border-radius: 999px; }
    .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 10px; margin-bottom: 0.9rem; }
    .meta-card { background: #f8fafc; border: 1px solid #e2e8f0; border-left: 3px solid #0f766e; border-radius: 6px; padding: 0.65rem 0.8rem; font-size: 0.81rem; }
    .meta-title { font-size: 0.73rem; font-weight: 700; text-transform: uppercase; color: #0f766e; margin-bottom: 4px; }
    .pill { display: inline-block; padding: 0.16rem 0.55rem; border-radius: 999px; font-size: 0.73rem; font-weight: 700; white-space: nowrap; }
    .pill-lg { padding: 0.28rem 0.75rem; font-size: 0.82rem; }
    .grade-pass, .st-pass { background: #dcfce7; color: #166534; }
    .grade-warn, .st-warn { background: #fef3c7; color: #92400e; }
    .grade-fail { background: #fee2e2; color: #991b1b; }
    .grade-info, .st-info { background: #e0f2fe; color: #075985; }
    .finding-grid { display: flex; flex-direction: column; gap: 8px; }
    .finding-item { background: #f8fafc; border: 1px solid #e2e8f0; border-left: 4px solid #0284c7; border-radius: 6px; padding: 0.65rem 0.85rem; break-inside: avoid; }
    .sev-border-high { border-left-color: #dc2626; } .sev-border-medium { border-left-color: #ea580c; } .sev-border-low { border-left-color: #d97706; } .sev-border-info { border-left-color: #0284c7; }
    .finding-head { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; font-size: 0.86rem; margin-bottom: 4px; }
    .finding-rec { font-size: 0.81rem; color: #334155; }
    .mod-tag { background: #e2e8f0; color: #334155; padding: 0.08rem 0.42rem; border-radius: 4px; font-family: monospace; font-size: 0.74rem; }
    .sev { display: inline-block; padding: 0.12rem 0.48rem; border-radius: 4px; font-size: 0.71rem; font-weight: 800; }
    .sev-high { background: #fee2e2; color: #991b1b; } .sev-medium { background: #ffedd5; color: #9a3412; } .sev-low { background: #fef3c7; color: #92400e; } .sev-info { background: #e0f2fe; color: #075985; }
    .tbl-wrap { width: 100%; overflow-x: auto; border-radius: 8px; border: 1px solid #e2e8f0; }
    table { width: 100%; border-collapse: collapse; font-size: 0.82rem; background: #fff; }
    th, td { padding: 0.5rem 0.65rem; border-bottom: 1px solid #e2e8f0; text-align: left; vertical-align: top; }
    thead th { background: #0b132b; color: #fff; font-weight: 600; white-space: nowrap; }
    tbody tr:nth-child(even) { background: #f8fafc; }
    .muted { color: #64748b; font-size: 0.76rem; }
    .code-grid { display: grid; grid-template-columns: 1fr; gap: 10px; }
    .code-label { font-size: 0.76rem; font-weight: 700; color: #0f766e; margin-bottom: 4px; text-transform: uppercase; }
    pre { background: #0b132b; color: #e2e8f0; padding: 0.8rem 0.95rem; border-radius: 6px; overflow-x: auto; font-size: 0.78rem; margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; }
    .ai-box { background: #f0fdfa; border: 1px solid #99f6e4; border-left: 4px solid #0f766e; border-radius: 6px; padding: 0.8rem 1rem; white-space: pre-wrap; font-size: 0.84rem; }
    .empty-ok { background: #dcfce7; color: #166534; padding: 0.65rem 0.9rem; border-radius: 6px; font-size: 0.84rem; font-weight: 600; }
    .empty-box { background: #fff; border: 1px dashed #cbd5e1; padding: 1.2rem; border-radius: 8px; color: #64748b; text-align: center; }
    footer { margin-top: 2rem; padding-top: 0.8rem; border-top: 1px solid #cbd5e1; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px; font-size: 0.78rem; color: #64748b; }
    @media (max-width: 720px) { .kpi-grid, .sev-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); } .hero { padding: 1.15rem; } .hero h1 { font-size: 1.22rem; } }
    @media print { body { background: #fff; -webkit-print-color-adjust: exact; print-color-adjust: exact; } .page { max-width: 100%; margin: 0; padding: 0; } .insp-card, .kpi { box-shadow: none; } }
  </style>
</head>
<body>
  <div class="page">
    <header class="hero">
      <div class="hero-top">
        <div class="brand">
          <div class="brand-icon">AW</div>
          <div>
            <strong>${escapeHtml(ctx.appName || 'Aegis Web Console')}</strong>
            <div class="brand-sub">Diagnóstico HTTP Passivo · Hardening OWASP · Web QA</div>
          </div>
        </div>
        <span class="class-pill">${escapeHtml(opts.classification)}</span>
      </div>
      <h1>${escapeHtml(opts.title)}</h1>
      <div class="hero-meta">
        <span><strong>Organização:</strong> ${escapeHtml(opts.org)}</span>
        <span><strong>Gerado em:</strong> ${escapeHtml(formattedDate)}</span>
        <span><strong>Severidade mínima:</strong> ${escapeHtml(opts.minSeverity.toUpperCase())}</span>
        <span><strong>Modo:</strong> ${escapeHtml(ctx.currentMode || 'manual')}</span>
      </div>
    </header>

    <section class="kpi-grid">
      <div class="kpi">
        <div class="kpi-label">Nota Média OWASP</div>
        <div class="kpi-val">${summary.average_owasp_score !== null ? `${escapeHtml(summary.overall_grade)} (${escapeHtml(summary.average_owasp_score)}/100)` : '—'}</div>
        <div class="kpi-sub">${summary.inspections_count > 1 ? `Mín ${summary.min_owasp_score} · Máx ${summary.max_owasp_score}` : 'Pontuação consolidada'}</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Escopo Auditado</div>
        <div class="kpi-val">${summary.hosts_count} Host(s)</div>
        <div class="kpi-sub">${summary.inspections_count} inspeção(ões) na sessão</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Achados Filtrados</div>
        <div class="kpi-val">${summary.severity_counts.total}</div>
        <div class="kpi-sub">${summary.severity_counts.high} alta · ${summary.severity_counts.medium} média</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Módulos Defensivos</div>
        <div class="kpi-val">${summary.modules_active} / ${summary.modules_total}</div>
        <div class="kpi-sub">${ctx.aiConfig && ctx.aiConfig.ai_type === 'ollama' ? `IA: ${escapeHtml(ctx.aiConfig.ai_model)}` : 'IA Local: Desativada'}</div>
      </div>
    </section>

    <section class="sev-strip">
      <div class="sev-card sc-high"><span>ALTA (HIGH)</span><strong>${summary.severity_counts.high}</strong></div>
      <div class="sev-card sc-medium"><span>MÉDIA (MEDIUM)</span><strong>${summary.severity_counts.medium}</strong></div>
      <div class="sev-card sc-low"><span>BAIXA (LOW)</span><strong>${summary.severity_counts.low}</strong></div>
      <div class="sev-card sc-info"><span>INFO</span><strong>${summary.severity_counts.info}</strong></div>
    </section>
    ${sevBarHtml}

    ${hostsHtml}

    <section class="section">
      <h2 class="sec-title">${inspSecNum}. Detalhamento Técnico das Inspeções Passivas <span>${inspections.length} execução(ões)</span></h2>
      ${inspBlocks}
    </section>

    ${modsHtml}

    <footer>
      <span>${escapeHtml(ctx.appName || 'Aegis Web Console')} · ${escapeHtml(opts.org)}</span>
      <span>Classificação: ${escapeHtml(opts.classification)} · Gerado em ${escapeHtml(formattedDate)}</span>
    </footer>
  </div>
</body>
</html>`;
}

// =============================================================================
// EXECUTIVE MARKDOWN REPORT
// =============================================================================

function buildMarkdownReport(opts, ctx) {
  const inspections = ctx.inspectionHistory || [];
  const hosts = ctx.hosts || [];
  const modulesList = ctx.modulesInstalled || [];
  const activeMods = modulesList.filter(m => m.active);
  const summary = computeReportSummary(inspections, hosts, modulesList, opts.minSeverity);
  const formattedDate = formatDateBr(opts.generatedAt);

  const lines = [
    `# ${opts.title}`,
    '',
    `> **Organização:** ${opts.org} | **Classificação:** \`${opts.classification.toUpperCase()}\` | **Gerado em:** ${formattedDate} | **Filtro:** \`>= ${opts.minSeverity.toUpperCase()}\``,
    '',
    '## Sumário Executivo',
    '',
    '| Indicador | Valor |',
    '| :--- | :--- |',
    `| **Plataforma / Modo** | ${ctx.appName || 'Aegis Web Console'} (\`${ctx.currentMode || 'manual'}\`) |`,
    `| **Nota Média OWASP** | ${summary.average_owasp_score !== null ? `**${summary.overall_grade} (${summary.average_owasp_score}/100)**` : '—'} |`,
    `| **Hosts / Inspeções** | ${summary.hosts_count} host(s) · ${summary.inspections_count} inspeção(ões) |`,
    `| **Módulos Ativos** | ${summary.modules_active} / ${summary.modules_total} |`,
    `| **Achados (Alta / Média / Baixa / Info)** | **${summary.severity_counts.high}** / **${summary.severity_counts.medium}** / **${summary.severity_counts.low}** / **${summary.severity_counts.info}** (Total: ${summary.severity_counts.total}) |`,
    ''
  ];

  if (hosts.length > 0) {
    lines.push('## Inventário de Hosts Auditados', '');
    lines.push('| Host | Protocolo / TLS | Postura DNS | HTTP | Nota OWASP | Achados |');
    lines.push('| :--- | :--- | :--- | :---: | :---: | :---: |');
    for (const h of hosts) {
      const proto = h.tls_protocol ? `${h.protocol} (${h.tls_protocol})` : h.protocol;
      lines.push(`| \`${h.host}\` | ${proto} | ${h.dns_summary || '—'} | ${h.last_status} | **${h.owasp_grade} (${h.owasp_score}/100)** | ${h.findings_count} |`);
    }
    lines.push('');
  }

  lines.push(`## Detalhamento das Inspeções Passivas (${inspections.length})`, '');
  if (inspections.length === 0) {
    lines.push('_Nenhuma inspeção executada nesta sessão._', '');
  } else {
    inspections.forEach((insp, idx) => {
      const filt = filterFindingsBySeverity(insp.findings, opts.minSeverity);
      lines.push(`### ${idx + 1}. [${insp.method} ${insp.status_code}] ${insp.target}`);
      lines.push(`- **Nota OWASP:** **${insp.owasp_grade} (${insp.owasp_score}/100)** | **Latência:** ${insp.duration_ms}ms | **Módulos:** ${insp.executed_modules_count} executados / ${insp.skipped_modules_count} ignorados`);
      if (insp.tls_info) {
        lines.push(`- **TLS:** ${insp.tls_info.protocol || 'n/a'} / ${insp.tls_info.cipher || 'n/a'} | **CN:** \`${insp.tls_info.subject || 'n/a'}\` | **Emissor:** ${insp.tls_info.issuer || 'n/a'} | **Expira em:** ${insp.tls_info.daysRemaining ?? '?'} dias`);
      }
      if (insp.dns_posture && !insp.dns_posture.skipped) {
        lines.push(`- **DNS (${insp.dns_posture.domain}):** CAA=${insp.dns_posture.caa.length ? 'OK' : 'ausente'} | SPF=${insp.dns_posture.spf ? 'OK' : 'ausente'} | DMARC=${insp.dns_posture.dmarc ? 'OK' : 'ausente'}`);
      }
      lines.push('');

      lines.push(`#### Achados & Recomendações (${filt.length})`, '');
      if (filt.length === 0) {
        lines.push('_Nenhuma observação acima da severidade mínima selecionada._', '');
      } else {
        for (const f of filt) {
          const sev = String(f.severity || 'info').toLowerCase();
          lines.push(`- **[${SEVERITY_LABEL[sev] || sev.toUpperCase()} · \`${f.module_id}\`]** ${f.item}`);
          lines.push(`  - _Recomendação:_ ${f.recommendation}`);
        }
        lines.push('');
      }

      if (Array.isArray(insp.module_results) && insp.module_results.length > 0) {
        lines.push(`#### Resumo por Módulo (${insp.module_results.length})`, '');
        lines.push('| Módulo | Status | Resumo | Achados |');
        lines.push('| :--- | :---: | :--- | :---: |');
        for (const mr of insp.module_results) {
          lines.push(`| ${mr.module_name} (\`${mr.module_id}\`) | \`${String(mr.status || 'info').toUpperCase()}\` | ${String(mr.summary || '').replace(/\|/g, '/')} | ${mr.findings_count} |`);
        }
        lines.push('');
      }

      if (opts.includeSnippets && insp.hardening_snippets && insp.hardening_snippets.missing_count > 0) {
        lines.push('#### Snippets de Hardening Sugeridos', '');
        lines.push('```nginx', insp.hardening_snippets.nginx, '```', '');
        lines.push('```apache', insp.hardening_snippets.apache, '```', '');
        lines.push('```javascript', insp.hardening_snippets.express, '```', '');
        if (insp.hardening_snippets.caddy) {
          lines.push('```caddyfile', insp.hardening_snippets.caddy, '```', '');
        }
      }

      if (opts.includeHeaders && insp.response_headers) {
        lines.push('#### Cabeçalhos HTTP Recebidos', '', '```http');
        for (const [k, v] of Object.entries(insp.response_headers)) lines.push(`${k}: ${v}`);
        lines.push('```', '');
      }

      if (insp.ai_summary) {
        lines.push('#### Resumo Defensivo (IA Local)', '', insp.ai_summary, '');
      }
    });
  }

  if (opts.includeModules) {
    lines.push(`## Catálogo de Módulos Defensivos Ativos (${activeMods.length}/${modulesList.length})`, '');
    lines.push('| Módulo | ID | Categoria | Escopo |');
    lines.push('| :--- | :--- | :---: | :--- |');
    for (const m of activeMods) {
      lines.push(`| **${m.name}** | \`${m.id}\` | \`${m.category}\` | ${m.description} |`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

// =============================================================================
// OASIS SARIF 2.1.0 REPORT (GitHub Code Scanning / Azure DevOps / CI-CD)
// =============================================================================

function buildSarifReport(opts, ctx) {
  const inspections = ctx.inspectionHistory || [];
  const rulesMap = new Map();
  const results = [];

  for (const insp of inspections) {
    const filt = filterFindingsBySeverity(insp.findings, opts.minSeverity);
    for (const f of filt) {
      const ruleId = `aegis/${f.module_id}/${f.cwe || 'CWE-693'}`;
      if (!rulesMap.has(ruleId)) {
        rulesMap.set(ruleId, {
          id: ruleId,
          name: f.module_name || f.module_id,
          shortDescription: { text: f.control || f.module_name || f.module_id },
          fullDescription: { text: `${f.owasp_top10 || 'OWASP'} (${f.asvs || 'ASVS'}) — ${f.recommendation}` },
          properties: {
            tags: ['security', 'owasp', 'passive-audit', f.cwe || 'CWE-693', f.owasp_top10 || 'OWASP']
          }
        });
      }
      const sev = String(f.severity || 'info').toLowerCase();
      const level = sev === 'high' ? 'error' : (sev === 'medium' ? 'warning' : 'note');
      results.push({
        ruleId,
        level,
        message: { text: `[${f.priority || 'P3'} · ${f.cwe || 'CWE'}] ${f.item} — Recomendação: ${f.recommendation}` },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: insp.target }
          }
        }],
        properties: {
          severity: sev,
          priority: f.priority,
          cwe: f.cwe,
          owasp_top10: f.owasp_top10,
          asvs: f.asvs,
          effort: f.effort,
          owasp_score: insp.owasp_score
        }
      });
    }
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: ctx.appName || 'Aegis Web Console',
          version: '3.0.0',
          informationUri: 'https://owasp.org/',
          rules: [...rulesMap.values()]
        }
      },
      results
    }]
  };
}

// =============================================================================
// RFC 4180 CSV EXPORT (UTF-8 BOM for Excel / LibreOffice / GRC)
// =============================================================================

function csvEscape(val) {
  const s = String(val ?? '');
  if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function buildCsvReport(opts, ctx) {
  const inspections = ctx.inspectionHistory || [];
  const header = ['Timestamp', 'Target', 'Method', 'HTTP_Status', 'OWASP_Grade', 'OWASP_Score', 'Severity', 'Priority', 'Module', 'CWE', 'OWASP_Top10', 'ASVS', 'Effort', 'Item', 'Recommendation'];
  const rows = [header.map(csvEscape).join(',')];

  for (const insp of inspections) {
    const filt = filterFindingsBySeverity(insp.findings, opts.minSeverity);
    if (filt.length === 0) {
      rows.push([
        insp.timestamp, insp.target, insp.method, insp.status_code, insp.owasp_grade, insp.owasp_score,
        'PASS', '-', '-', '-', '-', '-', '-', 'Nenhum achado acima do filtro de severidade', '-'
      ].map(csvEscape).join(','));
    } else {
      for (const f of filt) {
        rows.push([
          insp.timestamp, insp.target, insp.method, insp.status_code, insp.owasp_grade, insp.owasp_score,
          String(f.severity || 'info').toUpperCase(), f.priority || 'P3', f.module_id, f.cwe || '',
          f.owasp_top10 || '', f.asvs || '', f.effort || '', f.item, f.recommendation
        ].map(csvEscape).join(','));
      }
    }
  }
  return '\uFEFF' + rows.join('\r\n') + '\r\n';
}

module.exports = {
  filterFindingsBySeverity,
  computeReportSummary,
  buildValidPdfBuffer,
  buildHtmlReport,
  buildMarkdownReport,
  buildSarifReport,
  buildCsvReport,
  pdfEncodeWinAnsi
};
