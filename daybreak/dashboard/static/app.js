// daybreak-wids dashboard. All data is inserted with textContent (SSIDs and
// alert texts may be attacker-controlled), never as HTML.
"use strict";

const SVG_NS = "http://www.w3.org/2000/svg";

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") node.className = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) {
    if (c === null || c === undefined) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

function svg(tag, attrs) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, v);
  return node;
}

function fmtTime(ts) {
  if (!ts) return "-";
  const d = new Date(ts * 1000);
  return d.toLocaleString(undefined, { hour12: false });
}

async function getJSON(path) {
  const r = await fetch(path, { cache: "no-store" });
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return r.json();
}

function replace(id, ...nodes) {
  const target = document.getElementById(id);
  target.replaceChildren(...nodes);
}

function renderStatus(s) {
  const threat = document.getElementById("threat");
  threat.dataset.level = s.threat_level;
  document.getElementById("threat-value").textContent = s.threat_level;

  const sensor = s.sensor || {};
  document.getElementById("sensor-model").textContent = sensor.model || sensor.driver || "sensor";
  document.getElementById("sensor-iface").textContent = sensor.interface || "-";
  const stateEl = document.getElementById("sensor-state");
  let state = "unknown";
  if (sensor.online === true || (sensor.online == null && sensor.present)) state = "online";
  if (sensor.online === false || sensor.present === false) state = "lost";
  stateEl.dataset.state = state;
  stateEl.textContent = state.toUpperCase();
  const kv = [];
  const add = (k, v) => { if (v !== undefined && v !== null) kv.push(el("dt", {}, k), el("dd", {}, v)); };
  add("driver", sensor.driver);
  add("usb", sensor.usb_id);
  add("mode", sensor.type);
  const mon = s.monitor;
  if (mon) {
    add("monitor", mon.alive ? "running" : (mon.state || "stopped"));
    add("backend", (mon.backend && mon.backend.name) || "-");
  }
  replace("sensor-kv", ...kv);

  const l5 = s.last5 || {};
  const connects = (l5.auth || 0) + (l5.assoc || 0) + (l5.reassoc || 0);
  replace("last5",
    el("dt", {}, "Deauth"), el("dd", {}, l5.deauth || 0),
    el("dt", {}, "Disassoc"), el("dd", {}, l5.disassoc || 0),
    el("dt", {}, "EAPOL"), el("dd", {}, l5.eapol || 0),
    el("dt", {}, "(Re)connect"), el("dd", {}, connects));
  let line = mon
    ? `monitor ${mon.alive ? "running" : (mon.state || "stopped")}, last event ${mon.last_event || "-"}`
    : "monitor never started";
  if (s.database === "unreadable") line += " - database not readable by the dashboard process";
  document.getElementById("monitor-line").textContent = line;
}

function securityPills(n) {
  const pills = [];
  if (n.mode) {
    const cls = n.mode === "WPA3-SAE" ? "ok" : (n.mode.startsWith("WPA2/WPA3") ? "warn" : "risk");
    pills.push(el("span", { class: `pill ${cls}` }, n.mode));
  } else {
    pills.push(el("span", { class: "pill" }, "not observed"));
  }
  if (n.pmf) {
    const cls = n.pmf === "required" ? "ok" : (n.pmf === "capable" ? "warn" : "risk");
    pills.push(el("span", { class: `pill ${cls}` }, `PMF ${n.pmf}`));
  }
  if (n.wps) pills.push(el("span", { class: "pill risk" }, "WPS on"));
  return pills;
}

function unknownCount(n) {
  return n.unknown_bssid_count ?? (n.unknown_bssids || []).length;
}

function renderNetworks(nets) {
  if (!nets.length) {
    replace("networks", el("div", { class: "muted" }, "No protected networks configured."));
    return;
  }
  replace("networks", ...nets.map((n) => el("div", { class: "net" },
    el("div", { class: "ssid" }, n.ssid),
    el("div", { class: "muted" }, `${n.network} - ${n.status}` +
      (unknownCount(n) ? ` - ${unknownCount(n)} unregistered BSSID(s)` : "")),
    el("div", {}, ...securityPills(n)))));

  replace("security", ...nets.map((n) => {
    const items = (n.items || []).map((i) => el("li", {}, el("span", { class: `lvl ${i.level}` }, i.level.toUpperCase()),
      i.title + (i.detail ? ` - ${i.detail}` : "")));
    const recs = (n.recommendations || []).map((r) => el("li", {}, r));
    return el("div", { class: "sec-net" },
      el("div", { class: "ssid" }, `${n.ssid} `, el("span", { class: "muted" }, `(${n.network})`)),
      el("div", {}, ...securityPills(n),
        el("span", { class: "pill" }, `transition: ${n.transition_mode ? "enabled" : "no"}`),
        el("span", { class: "pill" }, `PMF required: ${n.pmf_required ? "yes" : "no"}`)),
      items.length ? el("ul", {}, ...items) : null,
      recs.length ? el("div", { class: "muted" }, "Recommendation:") : null,
      recs.length ? el("ul", {}, ...recs) : null);
  }));
}

function renderAlerts(alerts, period) {
  document.getElementById("alerts-note").textContent = `(${period}, ${alerts.length})`;
  if (!alerts.length) {
    replace("alerts", el("tr", {}, el("td", { colspan: "6", class: "muted" }, "No alerts.")));
    return;
  }
  replace("alerts", ...alerts.slice(0, 50).map((a) => {
    const comps = ((a.reason && a.reason.components) || [])
      .map((c) => `${c.points >= 0 ? "+" : ""}${c.points} ${c.label}${c.detail ? ` (${c.detail})` : ""}`);
    return el("tr", {},
      el("td", {}, fmtTime(a.timestamp)),
      el("td", {}, el("span", { class: `sev ${a.severity}` }, a.severity)),
      el("td", { class: "score" }, a.score),
      el("td", {}, a.alert_type, a.suppressed_count ? el("div", { class: "muted" }, `+${a.suppressed_count} suppressed`) : null),
      el("td", { class: "mono" }, a.bssid || ""),
      el("td", {}, el("div", { class: "why" }, comps.join("\n"))));
  }));
}

function renderTimeline(t) {
  const root = document.getElementById("timeline");
  root.replaceChildren();
  const buckets = t.buckets || [];
  document.getElementById("timeline-note").textContent = t.anchor
    ? `(per minute, ${fmtTime(t.start)} - ${fmtTime(t.anchor)})` : "(no data)";
  if (!buckets.length) return;
  const W = 960, H = 180, padL = 30, padB = 18, padT = 8;
  const plotW = W - padL - 6, plotH = H - padB - padT;
  const keys = [["deauth", "deauth"], ["disassoc", "disassoc"], ["eapol", "eapol"]];
  const total = (b) => (b.deauth || 0) + (b.disassoc || 0) + (b.eapol || 0) +
    (b.auth || 0) + (b.assoc || 0) + (b.reassoc || 0);
  const max = Math.max(1, ...buckets.map(total));
  const bw = plotW / buckets.length;
  root.append(svg("line", { x1: padL, y1: H - padB, x2: W - 4, y2: H - padB, class: "axis" }));
  const label = svg("text", { x: 2, y: padT + 10 });
  label.textContent = String(max);
  root.append(label);
  buckets.forEach((b, i) => {
    let y = H - padB;
    const parts = keys.map(([k, cls]) => [b[k] || 0, cls]);
    parts.push([(b.auth || 0) + (b.assoc || 0) + (b.reassoc || 0), "connect"]);
    for (const [v, cls] of parts) {
      if (!v) continue;
      const h = (v / max) * plotH;
      y -= h;
      const rect = svg("rect", { x: padL + i * bw + 0.5, y, width: Math.max(1, bw - 1), height: h, class: cls });
      const title = svg("title", {});
      title.textContent = `${fmtTime(b.t)} ${cls}: ${v}`;
      rect.append(title);
      root.append(rect);
    }
  });
  for (const a of t.alerts || []) {
    if (["INFO", "LOW"].includes(a.severity)) continue;
    const x = padL + ((a.t - t.start) / 60) * bw;
    const c = svg("circle", { cx: x, cy: padT + 4, r: 4, class: "alert-mark" });
    const title = svg("title", {});
    title.textContent = `${fmtTime(a.t)} ${a.severity} ${a.type} (${a.score})`;
    c.append(title);
    root.append(c);
  }
  const tick = Math.max(1, Math.floor(buckets.length / 6));
  for (let i = 0; i < buckets.length; i += tick) {
    const txt = svg("text", { x: padL + i * bw, y: H - 4 });
    txt.textContent = new Date(buckets[i].t * 1000).toLocaleTimeString(undefined, { hour12: false, hour: "2-digit", minute: "2-digit" });
    root.append(txt);
  }
}

function renderBaseline(rows) {
  if (!rows.length) {
    replace("baseline", el("div", { class: "muted" }, "No baseline yet: run `daybreak-wids baseline create`."));
    return;
  }
  replace("baseline", ...rows.map((b) => {
    const r = b.rates || {};
    const fmt = (m) => (r[m] ? `median ${r[m].median}/min, max ${r[m].max}` : "-");
    return el("div", { class: "sec-net" },
      el("div", { class: "ssid" }, b.network),
      el("dl", { class: "kv" },
        el("dt", {}, "learned"), el("dd", {}, b.window ? `${fmtTime(b.window[0])} - ${fmtTime(b.window[1])}` : "-"),
        el("dt", {}, "disconnects"), el("dd", {}, fmt("disconnects")),
        el("dt", {}, "EAPOL"), el("dd", {}, fmt("eapol")),
        el("dt", {}, "connects"), el("dd", {}, fmt("connects")),
        el("dt", {}, "clients"), el("dd", {}, b.clients ? `${b.clients.min}-${b.clients.max}` : "-"),
        el("dt", {}, "security"), el("dd", {}, b.security ? `${b.security.mode}, PMF ${b.security.pmf}` : "-"),
        el("dt", {}, "BSSIDs"), el("dd", { class: "mono" }, (b.known_bssids || []).join(", ") || "-"),
        el("dt", {}, "channels"), el("dd", {}, (b.known_channels || []).join(", ") || "-")));
  }));
}

async function refreshAlertsAndTimeline() {
  const t = await getJSON("/api/timeline?minutes=60");
  renderTimeline(t);
  let alerts = await getJSON("/api/alerts?hours=24&limit=100");
  let period = "last 24 h";
  const recorded = t.anchor && t.anchor < Date.now() / 1000 - 120;
  if (!alerts.length && recorded) {
    // No live data: like the timeline, show the most recent recorded period (e.g. a replay).
    alerts = await getJSON(`/api/alerts?hours=24&limit=100&until=${encodeURIComponent(t.anchor)}`);
    period = `recorded data, 24 h up to ${fmtTime(t.anchor)}`;
  }
  renderAlerts(alerts, period);
}

async function refresh() {
  const jobs = [
    ["/api/status", renderStatus],
    ["/api/networks", renderNetworks],
    ["/api/baseline", renderBaseline],
  ];
  await Promise.all([
    ...jobs.map(async ([path, fn]) => {
      try { fn(await getJSON(path)); } catch (e) { console.warn(e); }
    }),
    refreshAlertsAndTimeline().catch((e) => console.warn(e)),
  ]);
}

// Poll every 5 s, but never start a refresh while the previous one is still running.
async function loop() {
  await refresh();
  setTimeout(loop, 5000);
}

loop();
