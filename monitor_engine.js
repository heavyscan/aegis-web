'use strict';

/**
 * Aegis Web Console v3.0 — Continuous Passive Watchlist & Regression Monitor
 * Strictly passive scheduled auditing with trend history, score regression alerts,
 * TLS expiration alerts, and optional JSON webhook notification.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MAX_WATCHLIST = 25;
const MAX_TREND = 24;
const MAX_ALERTS = 80;

function createMonitorEngine(storePath, inspectFn) {
  let state = {
    targets: [],
    alerts: []
  };
  let timer = null;
  let sweeping = false;

  function load() {
    try {
      if (!fs.existsSync(storePath)) return;
      const parsed = JSON.parse(fs.readFileSync(storePath, 'utf8'));
      if (parsed && Array.isArray(parsed.targets)) state.targets = parsed.targets.slice(0, MAX_WATCHLIST);
      if (parsed && Array.isArray(parsed.alerts)) state.alerts = parsed.alerts.slice(0, MAX_ALERTS);
    } catch {
      state = { targets: [], alerts: [] };
    }
  }

  function save() {
    try {
      fs.mkdirSync(path.dirname(storePath), { recursive: true });
      const tmp = `${storePath}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(state, null, 2) + '\n', 'utf8');
      fs.renameSync(tmp, storePath);
    } catch {
      // ignore persistence failure
    }
  }

  async function notifyWebhook(webhookUrl, alertObj) {
    if (!webhookUrl) return;
    try {
      const u = new URL(webhookUrl);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
      await fetch(u.href, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'User-Agent': 'AegisWebConsole-Monitor/3.0' },
        body: JSON.stringify({
          source: 'Aegis Web Console',
          text: `[${alertObj.severity.toUpperCase()}] ${alertObj.target}: ${alertObj.message}`,
          alert: alertObj
        }),
        signal: AbortSignal.timeout(5000)
      });
    } catch {
      // webhook delivery is best-effort
    }
  }

  function pushAlert(targetItem, severity, message) {
    const alertObj = {
      id: `alt-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
      timestamp: new Date().toISOString(),
      target_id: targetItem.id,
      target: targetItem.url,
      label: targetItem.label,
      severity,
      message
    };
    state.alerts.unshift(alertObj);
    if (state.alerts.length > MAX_ALERTS) state.alerts = state.alerts.slice(0, MAX_ALERTS);
    if (targetItem.webhook_url) {
      notifyWebhook(targetItem.webhook_url, alertObj).catch(() => {});
    }
    return alertObj;
  }

  function list() {
    return {
      targets: state.targets,
      alerts: state.alerts,
      summary: {
        total_targets: state.targets.length,
        active_alerts: state.alerts.length,
        failing_targets: state.targets.filter(t => t.last_score !== null && t.last_score < t.min_score).length
      }
    };
  }

  function add({ url, label, interval_minutes, min_score, webhook_url }) {
    const cleanUrl = String(url || '').trim();
    const normalized = /^https?:\/\//i.test(cleanUrl) ? cleanUrl : `https://${cleanUrl}`;
    let parsed;
    try {
      parsed = new URL(normalized);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new Error('Invalid protocol');
    } catch {
      throw new Error('URL inválida para monitoramento (use http:// ou https://).');
    }

    if (state.targets.length >= MAX_WATCHLIST) {
      throw new Error(`Limite máximo de ${MAX_WATCHLIST} alvos na Watchlist atingido.`);
    }

    const existing = state.targets.find(t => t.url === parsed.href);
    if (existing) {
      throw new Error(`Alvo "${parsed.href}" já está cadastrado na Watchlist.`);
    }

    let cleanWebhook = '';
    if (webhook_url && String(webhook_url).trim()) {
      try {
        const wu = new URL(String(webhook_url).trim());
        if (wu.protocol !== 'http:' && wu.protocol !== 'https:') throw new Error('bad');
        cleanWebhook = wu.href;
      } catch {
        throw new Error('URL de Webhook inválida (use http:// ou https://).');
      }
    }

    const intervalMin = Math.max(5, Math.min(1440, Number(interval_minutes) || 60));
    const minScore = Math.max(0, Math.min(100, Number(min_score ?? 80)));

    const item = {
      id: `mon-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
      url: parsed.href,
      label: String(label || parsed.host).trim().slice(0, 64),
      interval_minutes: intervalMin,
      min_score: minScore,
      webhook_url: cleanWebhook,
      created_at: new Date().toISOString(),
      last_checked_at: null,
      next_run_at: new Date().toISOString(),
      last_status: null,
      last_score: null,
      last_grade: null,
      last_error: null,
      trend: []
    };

    state.targets.unshift(item);
    save();
    return item;
  }

  function remove(id) {
    const before = state.targets.length;
    state.targets = state.targets.filter(t => t.id !== id);
    if (state.targets.length === before) return false;
    save();
    return true;
  }

  function clearAlerts() {
    state.alerts = [];
    save();
  }

  async function checkTarget(targetItem) {
    const prevScore = targetItem.last_score;
    const now = Date.now();
    targetItem.last_checked_at = new Date(now).toISOString();
    targetItem.next_run_at = new Date(now + targetItem.interval_minutes * 60 * 1000).toISOString();

    try {
      const rec = await inspectFn({ target: targetItem.url, method: 'GET', mode: 'manual' });
      targetItem.last_status = rec.status_code;
      targetItem.last_score = rec.owasp_score;
      targetItem.last_grade = rec.owasp_grade;
      targetItem.last_error = null;

      const tlsDays = rec.tls_info && typeof rec.tls_info.daysRemaining === 'number' ? rec.tls_info.daysRemaining : null;
      targetItem.trend.push({
        timestamp: rec.timestamp,
        score: rec.owasp_score,
        grade: rec.owasp_grade,
        status_code: rec.status_code,
        findings_count: rec.findings_count,
        tls_days: tlsDays
      });
      if (targetItem.trend.length > MAX_TREND) {
        targetItem.trend = targetItem.trend.slice(-MAX_TREND);
      }

      if (rec.owasp_score < targetItem.min_score) {
        pushAlert(targetItem, 'high', `Nota OWASP ${rec.owasp_grade} (${rec.owasp_score}/100) abaixo do mínimo configurado (${targetItem.min_score}).`);
      }
      if (typeof prevScore === 'number' && rec.owasp_score < prevScore) {
        pushAlert(targetItem, 'medium', `Regressão de segurança: nota caiu de ${prevScore} para ${rec.owasp_score} (${rec.owasp_score - prevScore} pts).`);
      }
      if (tlsDays !== null && tlsDays <= 14) {
        pushAlert(targetItem, 'high', `Certificado TLS expira em ${tlsDays} dia(s)!`);
      }
      save();
      return { id: targetItem.id, url: targetItem.url, success: true, score: rec.owasp_score, grade: rec.owasp_grade, status_code: rec.status_code };
    } catch (err) {
      targetItem.last_error = err.message;
      pushAlert(targetItem, 'high', `Alvo inacessível durante monitoramento: ${err.message}`);
      save();
      return { id: targetItem.id, url: targetItem.url, success: false, error: err.message };
    }
  }

  async function runSweep(forceAll = false, singleId = null) {
    if (sweeping) return { skipped: true, reason: 'Varredura da Watchlist já em andamento.', results: [] };
    sweeping = true;
    const results = [];
    try {
      const now = Date.now();
      const candidates = singleId
        ? state.targets.filter(t => t.id === singleId)
        : state.targets.filter(t => forceAll || !t.next_run_at || Date.parse(t.next_run_at) <= now);

      for (const item of candidates) {
        results.push(await checkTarget(item));
      }
    } finally {
      sweeping = false;
    }
    return { skipped: false, checked: results.length, results };
  }

  function startScheduler() {
    if (timer) return;
    timer = setInterval(() => {
      if (state.targets.length > 0) {
        runSweep(false).catch(() => {});
      }
    }, 60 * 1000);
    if (typeof timer.unref === 'function') timer.unref();
  }

  function stopScheduler() {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
  }

  load();
  return { list, add, remove, clearAlerts, runSweep, startScheduler, stopScheduler };
}

module.exports = { createMonitorEngine };
