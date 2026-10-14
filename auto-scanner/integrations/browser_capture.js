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
 *   BB_EXTRA_HEADERS   JSON object of headers to inject on every request
 *                      (e.g. '{"X-HackerOne-Research":"dev101x"}')
 *   BB_CAPTURE_MS      extra settle time after networkidle (default 6000)
 *   BB_NAV_TIMEOUT_MS  navigation timeout (default 30000)
 */
"use strict";

const fs = require("fs");
const path = require("path");

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

  fs.mkdirSync(outDir, { recursive: true });

  const requests = [];
  const wsEvents = [];

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    // A real desktop UA so the SPA serves its normal code path, not a bot page.
    userAgent:
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
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
      headers: req.headers(),
      postData: safePostData(req),
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
      headers: safeHeaders(res),
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

  let navError = null;
  try {
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: navTimeout });
    await page.waitForLoadState("networkidle", { timeout: navTimeout }).catch(() => {});
    await page.waitForTimeout(settleMs);
  } catch (e) {
    navError = String(e && e.message ? e.message : e);
  }

  await browser.close();

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

  fs.writeFileSync(path.join(outDir, "browser_capture.json"), JSON.stringify(result, null, 2));
  fs.writeFileSync(path.join(outDir, "browser_capture_raw.json"), JSON.stringify({ requests, wsEvents }, null, 2));

  // Flat endpoint list for grep-ability / downstream tooling.
  fs.writeFileSync(
    path.join(outDir, "browser_endpoints.txt"),
    Object.keys(endpoints).sort().join("\n") + "\n"
  );

  console.error(
    `captured ${result.requestCount} requests, ${Object.keys(endpoints).length} distinct endpoints, ${result.websocketCount} websocket(s)` +
      (navError ? ` (nav warning: ${navError})` : "")
  );
}

function safePostData(req) {
  try {
    const d = req.postData();
    return d ? truncate(d) : null;
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

main().catch((e) => {
  console.error("browser_capture fatal:", e && e.message ? e.message : e);
  process.exit(1);
});
