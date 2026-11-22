#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo "=== 1. Syntax checks (JS modules, CLI & inline HTML script) ==="
node --check webserver.js
node --check module_engine.js
node --check compliance_mapper.js
node --check monitor_engine.js
node --check report_generator.js
node --check aegis-cli.js
node -e '
const fs = require("fs");
const vm = require("vm");
const html = fs.readFileSync("index.html", "utf8");
const m = html.match(/<script>([\s\S]*?)<\/script>/);
if (!m) throw new Error("Inline <script> not found in index.html");
new vm.Script(m[1], { filename: "index.html:script" });
console.log("index.html inline script syntax OK");
'

echo "=== 2. Module catalog (42/42 defensive modules), compliance mapper & unit checks ==="
node -e '
const assert = require("assert");
const fs = require("fs");
const engine = require("./module_engine");
const mods = JSON.parse(fs.readFileSync("modules.json", "utf8")).installed;

assert.strictEqual(mods.length, 42, `Expected 42 defensive modules, got ${mods.length}`);
const runnerIds = Object.keys(engine.MODULE_RUNNERS);
assert.strictEqual(runnerIds.length, 42, `Expected 42 runners, got ${runnerIds.length}`);

for (const m of mods) {
  assert.ok(engine.MODULE_RUNNERS[m.id], `Missing runner for module: ${m.id}`);
  assert.notStrictEqual(m.category, "offensive", `Unexpected offensive module: ${m.id}`);
}

// v3.0 module unit tests
const tlsChain = engine.MODULE_RUNNERS["tls-chain-ocsp-auditor"]({
  url: new URL("https://example.com"),
  tlsInfo: { keyType: "RSA", keyBits: 1024, chainDepth: 1, selfSigned: true, wildcardSan: true, sanCount: 1 }
});
assert.strictEqual(tlsChain.findings.filter(f => f.severity === "high").length, 2, "Expected 2 high findings for 1024b RSA + self-signed");

const bimiRes = engine.MODULE_RUNNERS["dns-bimi-dangling-audit"]({
  url: new URL("https://example.com"),
  dnsPosture: { skipped: false, domain: "example.com", resilienceChecked: true, ns: ["ns1.example.com"], aaaa: [], cname: ["old.azurewebsites.net"], bimi: null, danglingCnameRisk: true }
});
assert.ok(bimiRes.findings.some(f => f.severity === "high"), "Dangling CNAME must flag high");

const gqlRes = engine.MODULE_RUNNERS["graphql-api-hygiene"]({
  url: new URL("https://api.example.com/graphql"),
  headers: {},
  contentType: "text/html",
  bodyText: "<title>GraphQL Playground</title><div id=swagger>SwaggerUIBundle</div>"
});
assert.ok(gqlRes.findings.some(f => f.severity === "medium"), "Exposed GraphQL Playground should flag medium");

const pwaRes = engine.MODULE_RUNNERS["pwa-manifest-serviceworker-audit"]({
  url: new URL("http://example.com"),
  bodyText: "<script>navigator.serviceWorker.register(\"/sw.js\")</script>"
});
assert.ok(pwaRes.findings.some(f => f.severity === "medium"), "SW over HTTP should flag medium");

const libRes = engine.MODULE_RUNNERS["supply-chain-tech-fingerprint"]({
  url: new URL("https://example.com"),
  bodyText: "<script src=\"/js/jquery-1.12.4.min.js\"></script><script src=\"/js/lodash-4.17.15.min.js\"></script>"
});
assert.strictEqual(libRes.findings.length, 2, "Expected 2 outdated frontend lib findings");

const privRes = engine.MODULE_RUNNERS["privacy-consent-tracker-audit"]({
  url: new URL("https://example.com"),
  contentType: "text/html",
  headers: {},
  rawHeaders: { "set-cookie": ["_ga=GA1.2.123456; Path=/"] },
  bodyText: "<script src=\"https://www.googletagmanager.com/gtm.js?id=GTM-123\"></script>"
});
assert.ok(privRes.findings.some(f => f.severity === "low"), "Pre-consent tracking cookie should flag low");

// Full 42-module execution + compliance matrix check
const allActive = mods.map(m => ({ ...m, active: true }));
const res = engine.runActiveModules({
  url: new URL("https://example.com/"),
  method: "GET",
  statusCode: 200,
  durationMs: 12,
  contentType: "text/html; charset=utf-8",
  headers: { "content-type": "text/html; charset=utf-8" },
  rawHeaders: {},
  bodyText: "<html><body><script src=\"/js/jquery-2.2.4.min.js\"></script></body></html>",
  redirectChain: [{ url: "https://example.com/", host: "example.com", protocol: "https:", statusCode: 200 }],
  wellKnown: { securityTxt: { skipped: false, found: false, statusCode: 404 }, robotsTxt: { skipped: false, found: false, statusCode: 404 } },
  tlsInfo: { protocol: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384", subject: "example.com", issuer: "CA", validFrom: "2026-01-01", validTo: "2026-12-01", daysRemaining: 90, sanCount: 1, keyType: "EC", keyBits: 256, chainDepth: 2, selfSigned: false, wildcardSan: false },
  dnsPosture: { skipped: false, domain: "example.com", caa: [], spf: null, dmarc: null, advancedChecked: true, mx: [], mtaSts: null, dkimSelectors: [], resilienceChecked: true, ns: ["ns1.a", "ns2.a"], aaaa: ["::1"], cname: [], bimi: null, danglingCnameRisk: false }
}, allActive);
assert.strictEqual(res.executed_count, 42, `Expected 42 executed modules, got ${res.executed_count}`);
assert.strictEqual(res.skipped_count, 0);
assert.ok(res.hardening_snippets.cloudflare, "Expected Cloudflare Workers snippet");
assert.ok(res.compliance_matrix && res.compliance_matrix.owasp_top10.length > 0, "Expected OWASP Top 10 compliance matrix");
assert.ok(res.findings.every(f => f.cwe && f.owasp_top10 && f.priority), "Every finding must include CWE, OWASP Top 10 & priority");
console.log(`Unit checks OK (42/42 runners + Compliance Matrix verified)`);
'

echo "=== 3. Live HTTP API, Watchlist, CI/CD Gate, Reports (6 formats) & CLI test ==="
TMP_DIR="$(mktemp -d)"
cp modules.json "$TMP_DIR/modules.json.bak"
cp ai_config.json "$TMP_DIR/ai_config.json.bak"
SERVER_PID=""
cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  cp "$TMP_DIR/modules.json.bak" modules.json
  cp "$TMP_DIR/ai_config.json.bak" ai_config.json
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

PORT=3099 \
AEGIS_SESSION_PATH="$TMP_DIR/session.json" \
AEGIS_SECRETS_PATH="$TMP_DIR/secrets.json" \
AEGIS_WATCHLIST_PATH="$TMP_DIR/watchlist.json" \
node webserver.js >/dev/null 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 30); do
  if curl -sf http://127.0.0.1:3099/api/status >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

node -e '
const assert = require("assert");
(async () => {
  const base = "http://127.0.0.1:3099";

  // 1. UI HTML
  const html = await (await fetch(base + "/")).text();
  assert.ok(html.includes("Módulos (42)"), "Missing Módulos (42)");
  assert.ok(html.includes("btn-theme-toggle"), "Missing dark/light theme toggle");
  assert.ok(html.includes("panel-cicd"), "Missing CI/CD Quality Gate workbench panel");
  assert.ok(html.includes("wl-targets-box"), "Missing Watchlist UI");

  // 2. Status v3.0
  const st = await (await fetch(base + "/api/status")).json();
  assert.strictEqual(st.version, "3.0.0");
  assert.strictEqual(st.modules_total, 42);

  // 3. Presets
  for (const [preset, expected] of [["all-on", 42], ["essential", 15], ["api-qa", 17], ["compliance-full", 36], ["all-off", 0], ["all-on", 42]]) {
    const bData = await (await fetch(base + "/api/modules/bulk", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ preset })
    })).json();
    assert.strictEqual(bData.active, expected, `Preset ${preset}: expected ${expected}, got ${bData.active}`);
  }

  // 4. CI/CD Quality Gate (pass with min_score=40, fail 422 with min_score=100)
  const gatePass = await fetch(base + "/api/ci/gate", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target: base + "/", min_score: 40, max_high: 5, preset: "essential" })
  });
  assert.strictEqual(gatePass.status, 200);
  assert.strictEqual((await gatePass.json()).passed, true);

  const gateFail = await fetch(base + "/api/ci/gate", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target: base + "/", min_score: 100, max_high: 0, preset: "all-on" })
  });
  assert.strictEqual(gateFail.status, 422);
  const gfData = await gateFail.json();
  assert.strictEqual(gfData.passed, false);
  assert.ok(gfData.violations.length > 0);

  // 5. Watchlist CRUD + immediate sweep
  const wlAdd = await fetch(base + "/api/watchlist", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: base + "/", label: "Local Self-Test", interval_minutes: 30, min_score: 95 })
  });
  assert.strictEqual(wlAdd.status, 201);
  const wlItem = (await wlAdd.json()).item;
  const wlRun = await (await fetch(base + "/api/watchlist/run", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id: wlItem.id })
  })).json();
  assert.strictEqual(wlRun.checked, 1);
  assert.ok(wlRun.watchlist.alerts.length >= 1, "Expected threshold alert when min_score=95");
  const wlDel = await fetch(`${base}/api/watchlist/${wlItem.id}`, { method: "DELETE" });
  assert.strictEqual(wlDel.status, 200);

  // 6. All 6 report formats (pdf, html, md, sarif, csv, json)
  for (const fmt of ["pdf", "html", "md", "sarif", "csv", "json"]) {
    const rRes = await fetch(`${base}/api/report?format=${fmt}&include_headers=true`);
    assert.strictEqual(rRes.status, 200, `Report ${fmt} failed`);
    const buf = Buffer.from(await rRes.arrayBuffer());
    assert.ok(buf.byteLength > 150, `Report ${fmt} unexpectedly small (${buf.byteLength}B)`);
    if (fmt === "pdf") {
      assert.ok(buf.toString("ascii", 0, 8).startsWith("%PDF-1.4"));
      assert.ok(buf.toString("ascii").includes("%%EOF"));
    } else if (fmt === "sarif") {
      const s = JSON.parse(buf.toString("utf8"));
      assert.strictEqual(s.version, "2.1.0");
      assert.ok(s.runs[0].results.length > 0);
    } else if (fmt === "csv") {
      const c = buf.toString("utf8");
      assert.ok(c.includes("OWASP_Top10") && c.includes("CWE"));
    }
  }

  console.log("Live v3.0 API, Watchlist, CI/CD Gate & 6 Report Formats OK");
})().catch(err => {
  console.error(err);
  process.exit(1);
});
'

echo "=== 4. Standalone Aegis CLI test (SARIF output + Quality Gate exit codes) ==="
node aegis-cli.js audit http://127.0.0.1:3099/ --min-score 40 --format sarif --out "$TMP_DIR/cli.sarif"
test -s "$TMP_DIR/cli.sarif"
node -e "const s=JSON.parse(require('fs').readFileSync('$TMP_DIR/cli.sarif','utf8')); if(s.version!=='2.1.0') process.exit(1); console.log('CLI SARIF 2.1.0 OK (results:', s.runs[0].results.length, ')');"

echo "All v3.0 checks passed!"
