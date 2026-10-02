// Takes the README screenshots (Phase 17) from a running stack with the demo loaded.
//
//   SX_EMAIL=... SX_PASSWORD=... node scripts/screenshots.mjs [http://127.0.0.1:8081] [docs/screenshots]
//
// Use a throwaway stack and account: the account's email appears in the screenshots. The
// password comes from the environment only, never from an argument (shell history).
// Drives a local Chrome or Edge in headless mode over the DevTools protocol (Node's built-in
// WebSocket), so nothing is downloaded. Set BROWSER to the browser's path if it is elsewhere.
//
// Before the pictures, it does what an analyst would on the web-01 incident (assign, note,
// triage) through the API, so the incident page shows a worked investigation.

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const BASE = process.argv[2] ?? "http://127.0.0.1:8081";
const OUT = process.argv[3] ?? "docs/screenshots";
const { SX_EMAIL: EMAIL, SX_PASSWORD: PASSWORD } = process.env;
if (!EMAIL || !PASSWORD) throw new Error("Set SX_EMAIL and SX_PASSWORD");

const BROWSERS = [
  process.env.BROWSER,
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
].filter(Boolean);
const PORT = 9333;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// ---------- the API, for ids and the analyst's actions ----------

async function api(path, token, body) {
  const response = await fetch(BASE + path, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return response.status === 204 ? null : response.json();
}

async function prepare() {
  const { access_token: token, user } = await api("/api/auth/login", null, {
    email: EMAIL,
    password: PASSWORD,
  });
  const incidents = (await api("/api/incidents?limit=50", token)).items;
  const web = incidents.find((i) => i.hosts.includes("web-01"));
  if (!web) throw new Error("Load the demo first (python -m app.cli demo-load)");
  const detail = await api(`/api/incidents/${web.id}`, token);
  if (!detail.assigned_to) {
    await api(`/api/incidents/${web.id}/assign`, token, { assignee_id: user.id });
    await api(`/api/incidents/${web.id}/notes`, token, {
      body:
        "Brute force from 203.0.113.45 succeeded against deploy, followed by a root shell and " +
        "a new sudo account (svc-backup2). Asked the web team to confirm nothing was deployed " +
        "at 10:30; disabling svc-backup2 pending their answer.",
    });
    const success = detail.alerts.find((link) => link.alert.rule_id === "AUTH-002");
    await api(`/api/incidents/${web.id}/evidence`, token, {
      alert_id: success.alert.id,
      comment: "The logon that worked: everything after it used this session.",
    });
    await api(`/api/incidents/${web.id}/transition`, token, { status: "TRIAGED" });
  }
  const alert = detail.alerts.find((link) => link.alert.rule_id === "AUTH-002") ?? detail.alerts[0];
  return { incident: web.id, alert: alert.alert.id };
}

// ---------- the browser ----------

async function browser() {
  const path = BROWSERS.find((candidate) => existsSync(candidate));
  if (!path) throw new Error("No Chrome or Edge found; set BROWSER");
  const profile = mkdtempSync(join(tmpdir(), "sx-shots-"));
  const child = spawn(
    path,
    [
      "--headless=new",
      `--remote-debugging-port=${PORT}`,
      `--user-data-dir=${profile}`,
      "--hide-scrollbars",
      "--force-device-scale-factor=1",
      "--no-first-run",
      "--force-dark-mode",
      "about:blank",
    ],
    { stdio: "ignore" },
  );
  let target;
  for (let tries = 0; !target && tries < 50; tries++) {
    await sleep(200);
    try {
      const list = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
      target = list.find((t) => t.type === "page");
    } catch {
      // not listening yet
    }
  }
  if (!target) throw new Error("The browser did not start");
  const socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.onopen = resolve;
    socket.onerror = reject;
  });
  let next = 0;
  const pending = new Map();
  socket.onmessage = (message) => {
    const data = JSON.parse(message.data);
    if (data.id && pending.has(data.id)) {
      const { resolve, reject } = pending.get(data.id);
      pending.delete(data.id);
      if (data.error) reject(new Error(data.error.message));
      else resolve(data.result);
    }
  };
  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const id = ++next;
      pending.set(id, { resolve, reject });
      socket.send(JSON.stringify({ id, method, params }));
    });
  const close = () => {
    socket.close();
    child.kill();
    setTimeout(() => rmSync(profile, { recursive: true, force: true }), 1000);
  };
  return { send, close };
}

async function main() {
  const ids = await prepare();
  const { send, close } = await browser();
  const evaluate = async (expression) =>
    (await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }))
      .result.value;
  const waitFor = async (expression, what) => {
    for (let tries = 0; tries < 100; tries++) {
      if (await evaluate(expression)) return;
      await sleep(150);
    }
    throw new Error(`Timed out waiting for ${what}`);
  };
  // Loaded when nothing says "Loading" any more and the main area has content.
  const settled = `(() => { const main = document.querySelector("main");
    return !!main && main.innerText.length > 40 && !/Loading/.test(main.innerText); })()`;

  const size = async (width, height, mobile = false) =>
    send("Emulation.setDeviceMetricsOverride", {
      width,
      height,
      deviceScaleFactor: 1,
      mobile,
    });
  await send("Page.enable");
  await send("Emulation.setEmulatedMedia", {
    features: [{ name: "prefers-color-scheme", value: "dark" }],
  });
  await size(1440, 900);

  await send("Page.navigate", { url: `${BASE}/login` });
  await waitFor(`!!document.querySelector('input[type=email]')`, "the sign-in form");
  await evaluate(`(() => {
    const set = (selector, value) => {
      const input = document.querySelector(selector);
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
      setter.call(input, value);
      input.dispatchEvent(new Event("input", { bubbles: true }));
    };
    set("input[type=email]", ${JSON.stringify(EMAIL)});
    set("input[type=password]", ${JSON.stringify(PASSWORD)});
    document.querySelector("button[type=submit]").click();
  })()`);
  await waitFor(`location.pathname !== "/login"`, "sign-in");

  mkdirSync(OUT, { recursive: true });
  // Hunt: everything the outside address of the web-01 attack did in the last 7 days.
  const hunt = {
    kind: "query",
    query: {
      time_range: { last: "7d" },
      filters: [{ field: "source_ip", op: "eq", value: "203.0.113.45" }],
    },
  };
  // Playground: an example run against AUTH-002, showing why it fires.
  const playground = `(async () => {
    const button = (text) => [...document.querySelectorAll("button")].find((b) => b.innerText.trim() === text);
    button("Failures, then a successful logon").click();
    await new Promise((resolve) => setTimeout(resolve, 300));
    document.querySelector("button[type=submit]").click();
  })()`;
  const shots = [
    ["dashboard", "/dashboard"],
    ["alerts", "/alerts"],
    ["alert-detail", `/alerts/${ids.alert}`],
    ["incidents", "/incidents"],
    ["incident-detail", `/incidents/${ids.incident}`],
    ["hunt", `/hunt?q=${encodeURIComponent(JSON.stringify(hunt))}`, null, "/203\.0\.113\.45/"],
    ["detections", "/detections"],
    ["coverage", "/coverage"],
    ["playground", "/playground?rule=AUTH-002", playground, "/[Tt]riggered|fired|detection/"],
    ["audit", "/audit"],
  ];
  for (const [name, path, act, shows] of shots) {
    await send("Page.navigate", { url: BASE + path });
    await sleep(400);
    await waitFor(settled, name);
    if (act) await evaluate(act);
    if (shows) await waitFor(`${shows}.test(document.querySelector("main").innerText)`, name);
    await sleep(1200); // charts, results and late requests
    const height = await evaluate(
      "Math.min(Math.max(document.documentElement.scrollHeight, 900), 1800)",
    );
    const { data } = await send("Page.captureScreenshot", {
      format: "png",
      captureBeyondViewport: true,
      clip: { x: 0, y: 0, width: 1440, height, scale: 1 },
    });
    writeFileSync(join(OUT, `${name}.png`), Buffer.from(data, "base64"));
    console.log(`${name}.png (${path.replace(/[0-9a-f-]{36}/, ":id")}, 1440x${height})`);
  }

  await size(390, 844, true);
  await send("Page.navigate", { url: `${BASE}/incidents/${ids.incident}` });
  await sleep(400);
  await waitFor(settled, "incident on a phone");
  await sleep(700);
  const { data } = await send("Page.captureScreenshot", { format: "png" });
  writeFileSync(join(OUT, "incident-phone.png"), Buffer.from(data, "base64"));
  console.log("incident-phone.png (390x844)");
  close();
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
