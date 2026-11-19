#!/usr/bin/env node
/*
 * browser_capture.js — drive a real headless Chromium against ONE authorized URL
 * and record every request/response/WebSocket frame the page makes, with real
 * headers. This sees the requests a modern JS SPA actually issues — past the
 * client-id / Client-Version / anti-automation gating that a static curl can't
 * reproduce and that returns generic 4xx/410 walls.
 *
 * Scope enforcement and the mandatory per-program research header are handled by
 * the browser_capture.sh wrapper BEFORE this runs. This script trusts the URL it
 * is handed and simply injects whatever headers the wrapper resolved.
 *
 * Usage: browser_capture.js <url> <output-dir>
 * Env:
 *   BB_EXTRA_HEADERS     JSON object of headers to inject on every request
 *                        (e.g. '{"X-HackerOne-Research":"dev101x"}')
 *   BB_CAPTURE_MS        extra settle time after networkidle (default 6000)
 *   BB_NAV_TIMEOUT_MS    navigation timeout (default 30000)
 *   BB_CAPTURE_UNREDACTED set to "1" to keep auth/cookie headers unredacted
 */
"use strict";

const fs = require("fs");
const path = require("path");

const SENSITIVE_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "x-auth-token",
]);

const SENSITIVE_BODY_KEYS = new Set([
  "password",
  "passwd",
  "secret",
  "token",
  "access_token",
  "refresh_token",
  "api_key",
  "apikey",
  "client_secret",
  "authorization",
]);

function redactHeaders(headers, unredacted = false) {
  if (!headers || typeof headers !== "object") {
    return {};
  }
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    if (!unredacted && SENSITIVE_HEADERS.has(String(k).toLowerCase())) {
      out[k] = "[REDACTED]";
    } else {
      out[k] = v;
    }
  }
  return out;
}

function redactJsonValue(val) {
  if (Array.isArray(val)) {
    return val.map(redactJsonValue);
  }
  if (val && typeof val === "object") {
    const out = {};
    for (const [k, v] of Object.entries(val)) {
      if (SENSITIVE_BODY_KEYS.has(String(k).toLowerCase())) {
        out[k] = "[REDACTED]";
      } else {
        out[k] = redactJsonValue(v);
      }
    }
    return out;
  }
  return val;
}

function redactPostData(postData, unredacted = false) {
  if (!postData || typeof postData !== "string" || unredacted) {
    return postData;
  }
  const trimmed = postData.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      return JSON.stringify(redactJsonValue(JSON.parse(trimmed)));
    } catch (e) {
      /* fall through to key=value redaction */
    }
  }
  if (trimmed.includes("=") && !trimmed.includes("\n") && (trimmed.includes("&") || /^[A-Za-z0-9_.~%-]+=/.test(trimmed))) {
    try {
      const params = new URLSearchParams(trimmed);
      let touched = false;
      for (const [k] of params.entries()) {
        if (SENSITIVE_BODY_KEYS.has(k.toLowerCase())) {
          params.set(k, "[REDACTED]");
          touched = true;
        }
      }
      if (touched) {
        return params.toString();
      }
    } catch (e) {
      /* ignore */
    }
  }
  return postData.replace(
    /("(?:password|passwd|secret|token|access_token|refresh_token|api_key|apikey|client_secret|authorization)"\s*:\s*)"[^"]*"/gi,
    '$1"[REDACTED]"'
  );
}

async function main() {
  const url = process.argv[2];
  const outDir = process.argv[3];
  if (!url || !outDir) {
    console.error("Usage: browser_capture.js <url> <output-dir>");
    process.exit(2);
  }

  let chromium;
  try {
    ({ chromium } = require("playwright"));
  } catch (e) {
    console.error("playwright is not installed (npm install playwright). Skipping.");
    process.exit(3);
  }

  let extraHeaders = {};
  if (process.env.BB_EXTRA_HEADERS) {
    try {
      extraHeaders = JSON.parse(process.env.BB_EXTRA_HEADERS);
    } catch (e) {
      console.error("BB_EXTRA_HEADERS is not valid JSON; ignoring it.");
    }
  }
  const settleMs = parseInt(process.env.BB_CAPTURE_MS || "6000", 10);
  const navTimeout = parseInt(process.env.BB_NAV_TIMEOUT_MS || "30000", 10);
  const unredacted = process.env.BB_CAPTURE_UNREDACTED === "1";

  fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });

  const requests = [];
  const wsEvents = [];

  const browser = await chromium.launch({ headless: true });
  let navError = null;
  try {
    const context = await browser.newContext({
      // A real desktop UA so the SPA serves its normal code path, not a bot page.
      userAgent:
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
      ignoreHTTPSErrors: false,
    });
    if (Object.keys(extraHeaders).length) {
      await context.setExtraHTTPHeaders(extraHeaders);
    }

    const page = await context.newPage();

    page.on("request", (req) => {
      requests.push({
        phase: "request",
        method: req.method(),
        url: req.url(),
        resourceType: req.resourceType(),
        headers: redactHeaders(req.headers(), unredacted),
        postData: safePostData(req, unredacted),
        ts: Date.now(),
      });
    });

    page.on("response", async (res) => {
      let status = null;
      try {
        status = res.status();
      } catch (e) {
        /* response may be gone */
      }
      requests.push({
        phase: "response",
        url: res.url(),
        status,
        headers: redactHeaders(safeHeaders(res), unredacted),
        ts: Date.now(),
      });
    });

    page.on("websocket", (ws) => {
      const wsUrl = ws.url();
      wsEvents.push({ event: "open", url: wsUrl, ts: Date.now() });
      ws.on("framesent", (data) =>
        wsEvents.push({ event: "sent", url: wsUrl, payload: truncate(data.payload), ts: Date.now() })
      );
      ws.on("framereceived", (data) =>
        wsEvents.push({ event: "received", url: wsUrl, payload: truncate(data.payload), ts: Date.now() })
      );
      ws.on("close", () => wsEvents.push({ event: "close", url: wsUrl, ts: Date.now() }));
    });

    try {
      await page.goto(url, { waitUntil: "domcontentloaded", timeout: navTimeout });
      await page.waitForLoadState("networkidle", { timeout: navTimeout }).catch(() => {});
      await page.waitForTimeout(settleMs);
    } catch (e) {
      navError = String(e && e.message ? e.message : e);
    }
  } finally {
    await browser.close();
  }

  // Distinct host:path endpoints the page actually called (the useful recon artifact).
  const endpoints = {};
  for (const r of requests) {
    if (r.phase !== "request") continue;
    try {
      const u = new URL(r.url);
      const key = `${r.method} ${u.host}${u.pathname}`;
      if (!endpoints[key]) endpoints[key] = { count: 0, resourceType: r.resourceType, sampleUrl: r.url };
      endpoints[key].count++;
    } catch (e) {
      /* skip non-URL */
    }
  }

  const result = {
    target: url,
    capturedAt: new Date().toISOString(),
    navError,
    injectedHeaders: Object.keys(extraHeaders),
    requestCount: requests.filter((r) => r.phase === "request").length,
    websocketCount: wsEvents.filter((w) => w.event === "open").length,
    endpoints,
  };

  fs.writeFileSync(path.join(outDir, "browser_capture.json"), JSON.stringify(result, null, 2), { mode: 0o600 });
  fs.writeFileSync(
    path.join(outDir, "browser_capture_raw.json"),
    JSON.stringify({ requests, wsEvents }, null, 2),
    { mode: 0o600 }
  );

  // Flat endpoint list for grep-ability / downstream tooling.
  fs.writeFileSync(
    path.join(outDir, "browser_endpoints.txt"),
    Object.keys(endpoints).sort().join("\n") + "\n",
    { mode: 0o600 }
  );

  // Unique HTTP(S) URLs for upstream scope filtering into recon artifacts.
  const rawUrls = Array.from(
    new Set(
      requests
        .filter((r) => r.phase === "request" && typeof r.url === "string" && /^https?:\/\//i.test(r.url))
        .map((r) => r.url)
    )
  ).sort();
  fs.writeFileSync(
    path.join(outDir, "browser_urls_raw.txt"),
    rawUrls.length ? rawUrls.join("\n") + "\n" : "",
    { mode: 0o600 }
  );

  console.error(
    `captured ${result.requestCount} requests, ${Object.keys(endpoints).length} distinct endpoints, ${result.websocketCount} websocket(s)` +
      (navError ? ` (nav warning: ${navError})` : "")
  );
}

function safePostData(req, unredacted = false) {
  try {
    const d = req.postData();
    return d ? truncate(redactPostData(d, unredacted)) : null;
  } catch (e) {
    return null;
  }
}

function safeHeaders(res) {
  try {
    return res.headers();
  } catch (e) {
    return {};
  }
}

function truncate(s) {
  s = typeof s === "string" ? s : String(s);
  return s.length > 4096 ? s.slice(0, 4096) + "...[truncated]" : s;
}

if (require.main === module) {
  main().catch((e) => {
    console.error("browser_capture fatal:", e && e.message ? e.message : e);
    process.exit(1);
  });
}

module.exports = { redactHeaders, redactPostData, truncate };
