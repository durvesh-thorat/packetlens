"use strict";

const byId = id => document.getElementById(id);
const view = byId("view");

const state = {
  route: "",
  window: 300,
  selectedMetric: "packets",
  chartStyle: "area",
  showMarkers: true,
  showGrid: true,
  followLive: true,
  historicalUntil: null,
  timeBounds: { first_t: null, last_t: null, live_now: null, view_until: null, is_live: true },

  incidentFilters: { q: "", status: "", severity: "", kind: "", limit: 50, offset: 0 },
  incidentSort: { key: "last_ts", direction: "desc" },

  hostFilters: { q: "", sort: "bytes", limit: 50, offset: 0 },
  qualityFile: null,
  qualityFiles: [],
  selectedCmModel: null,

  utc: true,
  theme: "dark",
  lastHealth: null,
  lastHealthAt: 0,
  lastOverview: null,
  seenIncidents: new Set(),
  failures: 0,
  chartState: null,
  overviewMounted: false,
  popoverCleanup: null
};

// Safe DOM Creation Helpers (Text nodes and DOM APIs only)
function node(tag, className, value) {
  const elem = document.createElement(tag);
  if (className) elem.className = className;
  if (value !== undefined && value !== null) elem.textContent = String(value);
  return elem;
}

function svgNode(tag, attrs) {
  const elem = document.createElementNS("http://www.w3.org/2000/svg", tag);
  if (attrs) {
    for (const [key, val] of Object.entries(attrs)) {
      elem.setAttribute(key, String(val));
    }
  }
  return elem;
}

function setText(id, value) {
  const el = byId(id);
  if (el) el.textContent = value === undefined || value === null ? "" : String(value);
}

function number(value) {
  if (value === null || value === undefined) return "—";
  const num = Number(value);
  return Number.isFinite(num) ? num.toLocaleString("en-US") : "—";
}

function humanBytes(value) {
  if (value === null || value === undefined) return "—";
  const amount = Number(value);
  if (!Number.isFinite(amount)) return "—";
  if (amount === 0) return "0 B";
  if (amount >= 1e9) return `${(amount / 1e9).toFixed(2)} GB`;
  if (amount >= 1e6) return `${(amount / 1e6).toFixed(2)} MB`;
  if (amount >= 1e3) return `${(amount / 1e3).toFixed(1)} KB`;
  return `${number(Math.round(amount))} B`;
}

function humanRate(value, unit) {
  if (value === null || value === undefined) return "—";
  const amount = Number(value);
  if (!Number.isFinite(amount)) return unit ? `— ${unit}` : "—";
  if (amount === 0) return unit ? `0 ${unit}` : "0";
  const suffix = unit ? ` ${unit}` : "";
  if (amount >= 1e6) return `${(amount / 1e6).toFixed(2)}M${suffix}`;
  if (amount >= 1e3) return `${(amount / 1e3).toFixed(1)}k${suffix}`;
  return `${amount >= 10 ? Math.round(amount) : amount.toFixed(1)}${suffix}`;
}

function formatTime(seconds, includeSeconds = true) {
  if (seconds === null || seconds === undefined) return "—";
  const num = Number(seconds);
  if (!Number.isFinite(num) || num <= 0) return "—";
  const date = new Date(num * 1000);
  if (Number.isNaN(date.getTime())) return "—";
  if (state.utc) {
    const iso = date.toISOString().replace("T", " ");
    return includeSeconds ? `${iso.slice(0, 19)} UTC` : `${iso.slice(0, 16)} UTC`;
  }
  return date.toLocaleString("en-US");
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return state.utc
    ? `${date.toISOString().replace("T", " ").slice(0, 19)} UTC`
    : date.toLocaleString("en-US");
}

function link(label, href, className, onClick, title) {
  const a = node("a", className, label);
  a.href = href;
  if (title) a.title = title;
  if (onClick) {
    a.addEventListener("click", event => {
      event.preventDefault();
      onClick(event);
    });
  }
  return a;
}

function getCsrfToken() {
  const meta = document.querySelector('meta[name="packetlens-token"]');
  return meta ? meta.getAttribute("content") || "" : "";
}

function copyToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    return navigator.clipboard.writeText(text);
  }
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.append(ta);
  ta.select();
  try {
    document.execCommand("copy");
  } finally {
    ta.remove();
  }
  return Promise.resolve();
}

async function request(path, options) {
  const opts = options || {};
  opts.cache = "no-store";
  const response = await fetch(path, opts);
  let payload;
  try {
    payload = await response.json();
  } catch (error) {
    throw new Error(`Server returned invalid JSON (${response.status})`);
  }
  if (!response.ok) {
    throw new Error(payload.error || `Request failed (${response.status})`);
  }
  return payload;
}

function showState(parent, message, kind) {
  const status = node("p", kind === "error" ? "state-message error-message" : "state-message", message);
  status.setAttribute("role", kind === "error" ? "alert" : "status");
  parent.replaceChildren(status);
}

function frame(title, description, actions) {
  const heading = node("div", "page-heading");
  const text = node("div");
  text.append(node("h1", "page-title", title));
  const sub = node("p", "page-subtitle", description || "");
  sub.id = "page-subtitle";
  if (description) text.append(sub);
  else text.append(sub);
  heading.append(text);
  if (actions) {
    const act = node("div", "page-actions");
    act.append(actions);
    heading.append(act);
  }
  view.replaceChildren(heading);
  return heading;
}

function section(title, content, className, subtitle) {
  const part = node("section", `panel${className ? ` ${className}` : ""}`);
  const head = node("div", "panel-header");
  const titleElem = node("h2", "panel-title", title);
  head.append(titleElem);
  if (subtitle) head.append(node("span", "panel-subtitle", subtitle));
  part.append(head, content);
  return part;
}

function tableWrap(tableElem) {
  const wrap = node("div", "table-wrap");
  wrap.append(tableElem);
  return wrap;
}

function table(headers, rows, emptyMessage, className) {
  const tbl = node("table", `data-table${className ? ` ${className}` : ""}`);
  const thead = node("thead");
  const headRow = node("tr");
  for (const item of headers) {
    const th = node("th");
    if (item.cellClass) th.className = item.cellClass;
    if (item.sort && item.key) {
      const btn = node("button", "sort-button");
      btn.type = "button";
      btn.dataset.sort = item.key;
      const active = item.sort === "ascending" || item.sort === "descending";
      btn.dataset.active = active ? "true" : "false";
      const arrow = item.sort === "ascending" ? "▲" : (item.sort === "descending" ? "▼" : "↕");
      btn.append(node("span", "", item.label), node("span", "sort-arrow", arrow));
      th.append(btn);
    } else {
      th.textContent = item.label;
    }
    headRow.append(th);
  }
  thead.append(headRow);
  tbl.append(thead);

  const tbody = node("tbody");
  if (!rows || rows.length === 0) {
    const row = node("tr");
    const cell = node("td", "state-message", emptyMessage || "No data recorded.");
    cell.colSpan = Math.max(1, headers.length);
    row.append(cell);
    tbody.append(row);
  } else {
    for (const r of rows) {
      const row = node("tr");
      r.forEach((val, index) => {
        const cell = node("td");
        const headerConfig = headers[index] || {};
        if (headerConfig.cellClass) cell.className = headerConfig.cellClass;
        if (headerConfig.titleGetter && typeof val === "string") {
          cell.title = val;
        }
        if (val instanceof Node) {
          cell.append(val);
        } else {
          cell.textContent = val === null || val === undefined ? "—" : String(val);
        }
        row.append(cell);
      });
      tbody.append(row);
    }
  }
  tbl.append(tbody);
  return tbl;
}

function severityBadge(sev) {
  const s = String(sev || "low").toLowerCase();
  const badge = node("span", `badge badge-${s}`);
  let icon = "●";
  if (s === "critical") icon = "▲";
  else if (s === "high") icon = "◆";
  else if (s === "medium") icon = "■";
  badge.append(node("span", "badge-icon", icon), document.createTextNode(` ${s.toUpperCase()}`));
  return badge;
}

function statusBadge(status) {
  const s = String(status || "open").toLowerCase();
  return node("span", `badge badge-status-${s}`, s.toUpperCase());
}

function formField(label, input, id) {
  const container = node("div", "form-field");
  if (label) {
    const lbl = node("label", "field-label", label);
    if (id) lbl.htmlFor = id;
    container.append(lbl);
  }
  if (id) input.id = id;
  container.append(input);
  return container;
}

function selectOption(select, value, label) {
  const opt = node("option", "", label);
  opt.value = value;
  select.append(opt);
  return opt;
}

function pageControls(parent, total, limit, offset, onChange) {
  const pages = Math.max(1, Math.ceil(total / limit));
  const current = Math.floor(offset / limit) + 1;
  const bar = node("div", "pagination-bar");
  const start = total === 0 ? 0 : Math.min(total, offset + 1);
  const end = Math.min(total, offset + limit);
  const info = node("span", "pagination-info",
    `Showing ${number(start)}–${number(end)} of ${number(total)} (Page ${current} of ${pages})`);
  bar.append(info);

  const controls = node("div", "page-controls");
  const prev = node("button", "secondary-button", "Previous");
  prev.type = "button";
  prev.disabled = offset <= 0;
  prev.addEventListener("click", () => onChange(Math.max(0, offset - limit)));

  const next = node("button", "secondary-button", "Next");
  next.type = "button";
  next.disabled = offset + limit >= total;
  next.addEventListener("click", () => onChange(offset + limit));

  controls.append(prev, next);
  bar.append(controls);
  parent.append(bar);
  return bar;
}

// Unified Live vs. Stored Capture Resolution
function deriveTelemetryTotals(health) {
  const sessionPackets = Number(health && health.packets_total ? health.packets_total : 0);
  const sessionBytes = Number(health && health.bytes_total ? health.bytes_total : 0);
  const storedPackets = Number(health && health.stored_packets ? health.stored_packets : 0);
  const storedBytes = Number(health && health.stored_bytes ? health.stored_bytes : 0);
  const isStoredOnly = sessionPackets === 0 && storedPackets > 0;
  return {
    sessionPackets,
    sessionBytes,
    storedPackets,
    storedBytes,
    isStoredOnly,
    displayPackets: sessionPackets > 0 ? sessionPackets : storedPackets,
    displayBytes: sessionBytes > 0 ? sessionBytes : storedBytes
  };
}

function updateNavIncidentsBadge(openCount) {
  const badge = byId("nav-incidents-badge");
  if (!badge) return;
  const count = Number(openCount || 0);
  badge.hidden = !(count > 0);
  badge.textContent = String(count);
}

// Health & Lifecycle Management
function updateHealth(health) {
  setText("source-name", health.source || "Unknown source");
  setText("version", health.version ? `v${health.version}` : "v1.0.0");

  const totals = deriveTelemetryTotals(health);
  const clockTs = health.now > 0 ? health.now : (state.timeBounds && state.timeBounds.last_t ? state.timeBounds.last_t : 0);
  if (clockTs > 0) {
    setText("packet-clock", formatTime(clockTs));
  } else if (totals.isStoredOnly) {
    setText("packet-clock", "Stored DB");
    request("/api/overview?window=60").then(ov => {
      if (ov && ov.time_bounds) {
        state.timeBounds = ov.time_bounds;
        if (ov.time_bounds.last_t) setText("packet-clock", formatTime(ov.time_bounds.last_t));
      }
    }).catch(() => {});
  } else {
    setText("packet-clock", "Awaiting traffic");
  }

  const indicator = byId("health-indicator");
  const healthLabel = byId("health-label");
  const modePill = byId("telemetry-mode-pill");
  const railDot = byId("rail-status-dot");
  const railTag = byId("rail-status-tag");

  indicator.classList.remove("is-degraded", "is-unhealthy", "is-stale");
  if (railDot) railDot.classList.remove("is-degraded", "is-unhealthy");

  let statusText = "Healthy";
  if (health.service_status === "unhealthy" || health.source_status === "error") {
    indicator.classList.add("is-unhealthy");
    if (railDot) railDot.classList.add("is-unhealthy");
    statusText = "Unhealthy";
  } else if (totals.isStoredOnly && health.store_status === "ok") {
    statusText = "Ready";
  } else if (health.service_status === "degraded" || (health.source_stale && !totals.isStoredOnly)) {
    indicator.classList.add("is-degraded");
    if (railDot) railDot.classList.add("is-degraded");
    statusText = health.source_stale ? "Idle" : "Degraded";
  }
  healthLabel.textContent = statusText;
  if (railTag && health.policy) {
    railTag.textContent = `POLICY: ${String(health.policy).toUpperCase()}`;
  }

  // Telemetry mode indicator
  if (health.source_status === "error") {
    modePill.textContent = "Source Error";
    modePill.className = "telemetry-mode-pill is-error";
  } else if (totals.isStoredOnly) {
    modePill.textContent = "Stored DB";
    modePill.className = "telemetry-mode-pill is-historical";
  } else if (health.source_stale) {
    modePill.textContent = "Source Idle";
    modePill.className = "telemetry-mode-pill is-idle";
  } else if (totals.sessionPackets > 0) {
    modePill.textContent = "Live";
    modePill.className = "telemetry-mode-pill is-live";
  } else {
    modePill.textContent = "Standby";
    modePill.className = "telemetry-mode-pill";
  }

  // Storage pill
  const storagePill = byId("storage-pill");
  const storageText = byId("storage-status-text");
  if (storagePill && storageText && health.store_counters) {
    const sc = health.store_counters;
    if (sc.dropped > 0) {
      storageText.textContent = `${sc.dropped} Drops`;
      storagePill.style.color = "var(--danger)";
    } else if (sc.queued > 100) {
      storageText.textContent = `Queue ${sc.queued}`;
      storagePill.style.color = "var(--amber)";
    } else {
      storageText.textContent = "Active";
      storagePill.style.color = "inherit";
    }
  }

  if (typeof health.open_incidents === "number") {
    updateNavIncidentsBadge(health.open_incidents);
  }

  if (health.memory_rss_bytes) {
    setText("rail-rss-metric", `RSS ${humanBytes(health.memory_rss_bytes)}`);
  }
  if (health.version) {
    setText("rail-ver-metric", `v${health.version}`);
  }

  // Refresh banner (avoid false stale alarm when inspecting stored DB)
  const banner = byId("stale-banner");
  const bannerMsg = byId("stale-banner-msg");
  if (health.source_status === "error") {
    banner.hidden = false;
    banner.className = "stale-banner";
    bannerMsg.textContent = `Capture source failed: ${health.source_error || "unreadable or truncated stream"}.`;
  } else if (health.store_error) {
    banner.hidden = false;
    banner.className = "stale-banner";
    bannerMsg.textContent = `SQLite writer error: ${health.store_error}. Telemetry may be incomplete.`;
  } else if (health.store_counters && health.store_counters.dropped > 0) {
    banner.hidden = false;
    banner.className = "stale-banner warning";
    bannerMsg.textContent = `Warning: ${number(health.store_counters.dropped)} database writes dropped due to queue saturation.`;
  } else if (!totals.isStoredOnly && health.source_stale && totals.sessionPackets > 0) {
    banner.hidden = false;
    banner.className = "stale-banner warning";
    bannerMsg.textContent = `Capture stream ended or paused (idle ${health.source_age_s}s). Showing last recorded state.`;
  } else {
    banner.hidden = true;
  }

  state.lastHealth = health;
  state.lastHealthAt = Date.now();
  setText("footer-refresh-indicator", `Refreshed ${formatTime(Date.now() / 1000, true)}`);
}

async function pollHealth() {
  const health = await request("/api/health");
  updateHealth(health);
  return health;
}

async function pollAnnouncements() {
  try {
    const result = await request("/api/incidents?status=open&limit=5&offset=0");
    const items = result.items || [];
    const current = new Set(items.map(item => String(item.id)));
    if (state.seenIncidents.size) {
      const fresh = items.filter(item => !state.seenIncidents.has(String(item.id)));
      if (fresh.length) {
        const first = fresh[0];
        setText("incident-announcer", `Alert: New ${first.severity} ${first.kind} incident from ${first.src}`);
      }
    }
    state.seenIncidents = current;
    updateNavIncidentsBadge(result.total);
  } catch (e) {
    // Graceful degradation
  }
}

function toggleErrorBanner(error) {
  const banner = byId("stale-banner");
  banner.hidden = false;
  banner.className = "stale-banner";
  setText("stale-banner-msg", `Connection to PacketLens server lost (${error.message}). Retrying...`);
  const ind = byId("health-indicator");
  ind.classList.add("is-stale");
  setText("health-label", "Disconnected");
}

async function tick() {
  try {
    await pollHealth();
    await pollAnnouncements();
    state.failures = 0;
    const parts = routeParts();
    if (parts[0] === "overview" && state.followLive && !document.hidden) {
      await updateOverviewData();
    }
  } catch (error) {
    state.failures += 1;
    toggleErrorBanner(error);
  } finally {
    const delay = state.failures ? Math.min(30000, 1000 * (2 ** Math.min(state.failures, 5))) : 2500;
    window.setTimeout(tick, delay);
  }
}

// KPI Component (Flat engineering card)
function createKpi(label, value, unit, subtext, id) {
  const card = node("article", "kpi-card");
  if (id) card.id = id;
  const head = node("div", "kpi-head");
  head.append(node("span", "kpi-label", label));
  card.append(head);

  const valRow = node("div", "kpi-value-row");
  const valElem = node("strong", "kpi-value", value);
  valRow.append(valElem);
  if (unit) valRow.append(node("span", "kpi-unit", unit));
  card.append(valRow);

  const subElem = node("div", "kpi-subtext", subtext || "");
  card.append(subElem);
  return card;
}

// Persistent In-Place Canvas Timeline Chart
function createTimelineChart(container, initialBins, initialIncidents, initialOptions) {
  const viewport = node("div", "chart-viewport");
  const canvas = node("canvas", "chart-canvas");
  viewport.append(canvas);

  const tooltip = node("div", "chart-tooltip");
  tooltip.style.display = "none";
  viewport.append(tooltip);
  container.replaceChildren(viewport);

  let currentBins = initialBins || [];
  let currentIncidents = initialIncidents || [];
  let currentOptions = { ...initialOptions };
  let lastHoverMouseX = null;
  let animationFrameId = null;
  let canvasW = 0;
  let canvasH = 0;
  let canvasDpr = 0;

  function computeBounds() {
    const windowSeconds = currentOptions.windowSeconds || 300;
    const viewUntil = currentOptions.viewUntil ||
      (currentBins.length ? currentBins[currentBins.length - 1].t : Date.now() / 1000);
    return {
      timeStart: Math.max(0, viewUntil - windowSeconds),
      timeEnd: viewUntil
    };
  }

  function cssVar(name, fallback) {
    const val = getComputedStyle(document.body).getPropertyValue(name).trim();
    return val || fallback;
  }

  function draw() {
    const rect = viewport.getBoundingClientRect();
    const width = Math.max(260, rect.width || viewport.clientWidth || 760);
    const height = Math.max(200, rect.height || viewport.clientHeight || 280);
    const dpr = window.devicePixelRatio || 1;
    const targetW = Math.round(width * dpr);
    const targetH = Math.round(height * dpr);

    if (canvasW !== targetW || canvasH !== targetH || canvasDpr !== dpr) {
      canvas.width = targetW;
      canvas.height = targetH;
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      canvasW = targetW;
      canvasH = targetH;
      canvasDpr = dpr;
    }

    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);

    const metricKey = currentOptions.metric || "packets";
    const isDual = metricKey === "dual";
    const style = currentOptions.style || "area";
    const showMarkers = currentOptions.showMarkers !== false;
    const showGrid = currentOptions.showGrid !== false;
    const { timeStart, timeEnd } = computeBounds();

    const padLeft = width < 480 ? 48 : 62;
    const padRight = isDual ? (width < 480 ? 52 : 66) : 18;
    const padTop = 22;
    const padBottom = 30;
    const plotW = Math.max(10, width - padLeft - padRight);
    const plotH = Math.max(10, height - padTop - padBottom);

    const isLight = document.body.getAttribute("data-theme") === "light";
    const colGrid = isLight ? "rgba(15, 23, 42, 0.08)" : "rgba(148, 163, 184, 0.12)";
    const colText = cssVar("--text-muted", isLight ? "#475569" : "#94a3b8");
    const colCyan = cssVar("--cyan", isLight ? "#0284c7" : "#38bdf8");
    const colViolet = cssVar("--violet", isLight ? "#7c3aed" : "#a78bfa");
    const colAmber = cssVar("--amber", isLight ? "#d97706" : "#f59e0b");
    const colRed = cssVar("--danger", isLight ? "#dc2626" : "#ef4444");
    const colTeal = cssVar("--teal", isLight ? "#0d9488" : "#2dd4bf");

    if (!currentBins || currentBins.length === 0) {
      ctx.fillStyle = colText;
      ctx.font = "12px system-ui, sans-serif";
      ctx.textAlign = "center";
      ctx.fillText("No packet telemetry recorded in this interval.", width / 2, height / 2);
      return;
    }

    const primaryKey = isDual ? "packets" : metricKey;
    const primaryVals = currentBins.map(b => Number(b[primaryKey] || 0));
    const max1 = Math.ceil(Math.max(5, ...primaryVals) * 1.15);

    let max2 = 1;
    if (isDual) {
      const secondaryVals = currentBins.map(b => Number(b.bytes || 0));
      max2 = Math.ceil(Math.max(1024, ...secondaryVals) * 1.15);
    }

    ctx.font = "10.5px monospace";
    ctx.lineWidth = 1;
    const steps = 4;
    for (let i = 0; i <= steps; i++) {
      const ratio = i / steps;
      const y = padTop + plotH - ratio * plotH;

      if (showGrid) {
        ctx.strokeStyle = colGrid;
        ctx.beginPath();
        ctx.moveTo(padLeft, y);
        ctx.lineTo(width - padRight, y);
        ctx.stroke();
      }

      const val1 = ratio * max1;
      ctx.fillStyle = isDual ? colCyan : colText;
      ctx.textAlign = "right";
      const lbl1 = primaryKey === "bytes" ? humanBytes(val1) : humanRate(val1, "");
      ctx.fillText(lbl1, padLeft - 7, y + 3.5);

      if (isDual) {
        const val2 = ratio * max2;
        ctx.fillStyle = colViolet;
        ctx.textAlign = "left";
        ctx.fillText(humanBytes(val2), width - padRight + 7, y + 3.5);
      }
    }

    ctx.font = "10px system-ui, sans-serif";
    ctx.textAlign = "left";
    ctx.fillStyle = isDual ? colCyan : colText;
    const unitMap = { bytes: "Bytes / s", packets: "Packets / s", sources: "Unique Sources / s" };
    const unit1 = unitMap[primaryKey] || `${primaryKey.toUpperCase()} / s`;
    ctx.fillText(unit1, padLeft, padTop - 7);

    if (isDual) {
      ctx.textAlign = "right";
      ctx.fillStyle = colViolet;
      ctx.fillText("Bytes / s", width - padRight, padTop - 7);
    }

    const timeSpan = Math.max(1, timeEnd - timeStart);
    const getX = t => padLeft + Math.max(0, Math.min(1, (t - timeStart) / timeSpan)) * plotW;
    const getY = (val, max) => padTop + plotH - (Math.max(0, val) / max) * plotH;

    function drawSeries(key, maxVal, colorHex, isSecondary) {
      const validBins = currentBins.filter(b => b.t >= timeStart && b.t <= timeEnd);
      if (validBins.length === 0) return;
      ctx.save();

      if (style === "area" && !isSecondary) {
        const grad = ctx.createLinearGradient(0, padTop, 0, padTop + plotH);
        grad.addColorStop(0, isLight ? "rgba(2, 132, 199, 0.22)" : "rgba(56, 189, 248, 0.24)");
        grad.addColorStop(1, "rgba(56, 189, 248, 0.0)");

        ctx.beginPath();
        let gapOpen = false;
        for (let i = 0; i < validBins.length; i++) {
          const b = validBins[i];
          const x = getX(b.t);
          const y = getY(Number(b[key] || 0), maxVal);

          if (i > 0 && b.t - validBins[i - 1].t > 1.5) {
            ctx.lineTo(getX(validBins[i - 1].t), padTop + plotH);
            ctx.closePath();
            ctx.fillStyle = grad;
            ctx.fill();
            ctx.beginPath();
            gapOpen = false;
          }

          if (!gapOpen) {
            ctx.moveTo(x, padTop + plotH);
            ctx.lineTo(x, y);
            gapOpen = true;
          } else {
            if (style === "stepped") {
              const prevY = getY(Number(validBins[i - 1][key] || 0), maxVal);
              ctx.lineTo(x, prevY);
            }
            ctx.lineTo(x, y);
          }
        }
        if (gapOpen) {
          ctx.lineTo(getX(validBins[validBins.length - 1].t), padTop + plotH);
          ctx.closePath();
          ctx.fillStyle = grad;
          ctx.fill();
        }
      }

      ctx.beginPath();
      ctx.strokeStyle = colorHex;
      ctx.lineWidth = 1.8;
      let lineOpen = false;

      for (let i = 0; i < validBins.length; i++) {
        const b = validBins[i];
        const x = getX(b.t);
        const y = getY(Number(b[key] || 0), maxVal);

        if (i > 0 && b.t - validBins[i - 1].t > 1.5) {
          ctx.stroke();
          ctx.beginPath();
          lineOpen = false;
        }

        if (!lineOpen) {
          ctx.moveTo(x, y);
          lineOpen = true;
        } else {
          if (style === "stepped") {
            const prevY = getY(Number(validBins[i - 1][key] || 0), maxVal);
            ctx.lineTo(x, prevY);
          }
          ctx.lineTo(x, y);
        }
      }
      ctx.stroke();
      ctx.restore();
    }

    let pCol = colCyan;
    if (primaryKey === "bytes") pCol = colViolet;
    else if (primaryKey === "syn") pCol = colAmber;
    else if (primaryKey === "dns") pCol = colTeal;
    drawSeries(primaryKey, max1, pCol, false);

    if (isDual) {
      drawSeries("bytes", max2, colViolet, true);
    }

    ctx.fillStyle = colText;
    ctx.font = "10px monospace";
    ctx.textAlign = "left";
    ctx.fillText(formatTime(timeStart, true), padLeft, height - 9);
    if (width >= 480) {
      ctx.textAlign = "center";
      ctx.fillText(formatTime(timeStart + timeSpan / 2, true), padLeft + plotW / 2, height - 9);
    }
    ctx.textAlign = "right";
    ctx.fillText(formatTime(timeEnd, true), width - padRight, height - 9);

    if (showMarkers && currentIncidents && currentIncidents.length > 0) {
      for (const inc of currentIncidents) {
        const ts = Number(inc.last_ts);
        if (!Number.isFinite(ts) || ts < timeStart || ts > timeEnd) continue;
        const x = getX(ts);
        const sev = String(inc.severity || "low").toLowerCase();
        let markerCol = colCyan;
        if (sev === "critical") markerCol = colRed;
        else if (sev === "high") markerCol = colAmber;

        ctx.save();
        ctx.strokeStyle = markerCol;
        ctx.setLineDash([3, 3]);
        ctx.lineWidth = 1.2;
        ctx.beginPath();
        ctx.moveTo(x, padTop);
        ctx.lineTo(x, padTop + plotH);
        ctx.stroke();

        ctx.setLineDash([]);
        ctx.fillStyle = markerCol;
        ctx.beginPath();
        ctx.arc(x, padTop, 3.5, 0, Math.PI * 2);
        ctx.fill();
        ctx.restore();
      }
    }
  }

  function updateTooltipAt(mouseX) {
    if (mouseX === null || !currentBins || currentBins.length === 0) {
      tooltip.style.display = "none";
      return;
    }
    const rect = viewport.getBoundingClientRect();
    const width = rect.width;
    const isDual = (currentOptions.metric || "packets") === "dual";
    const padLeft = width < 480 ? 48 : 62;
    const padRight = isDual ? (width < 480 ? 52 : 66) : 18;
    const plotW = width - padLeft - padRight;

    if (plotW <= 0 || mouseX < padLeft || mouseX > width - padRight) {
      tooltip.style.display = "none";
      return;
    }

    const { timeStart, timeEnd } = computeBounds();
    const ratio = Math.max(0, Math.min(1, (mouseX - padLeft) / plotW));
    const hoverT = timeStart + ratio * (timeEnd - timeStart);

    let closestBin = null;
    let minDiff = 2.0;
    for (const b of currentBins) {
      const diff = Math.abs(b.t - hoverT);
      if (diff < minDiff) {
        minDiff = diff;
        closestBin = b;
      }
    }

    if (!closestBin) {
      tooltip.style.display = "none";
      return;
    }

    let nearIncident = null;
    if (currentIncidents) {
      for (const inc of currentIncidents) {
        if (Math.abs(Number(inc.last_ts) - closestBin.t) <= 2.5) {
          nearIncident = inc;
          break;
        }
      }
    }

    const content = node("div");
    content.append(node("div", "tooltip-time", formatTime(closestBin.t)));

    const makeRow = (lbl, val, col) => {
      const row = node("div", "tooltip-row");
      const leftPart = node("span", "");
      const dot = node("span", "tooltip-dot");
      dot.style.background = col;
      leftPart.append(dot, document.createTextNode(lbl));
      row.append(leftPart, node("span", "tooltip-val", val));
      return row;
    };

    content.append(makeRow("Packets", `${number(closestBin.packets)}/s`, "var(--cyan)"));
    content.append(makeRow("Bytes", `${humanBytes(closestBin.bytes)}/s`, "var(--violet)"));
    content.append(makeRow("SYN", `${number(closestBin.syn)}/s`, "var(--amber)"));
    content.append(makeRow("DNS", `${number(closestBin.dns)}/s`, "var(--teal)"));
    content.append(makeRow("Sources", number(closestBin.sources), "var(--accent-strong)"));

    if (nearIncident) {
      const incBox = node("div", "tooltip-incident");
      incBox.textContent = `${nearIncident.kind} (${String(nearIncident.severity || "").toUpperCase()})`;
      content.append(incBox);
    }

    tooltip.replaceChildren(content);
    tooltip.style.display = "block";

    const tipWidth = 190;
    let tipX = mouseX + 14;
    if (tipX + tipWidth > width) tipX = mouseX - tipWidth - 14;
    tooltip.style.left = `${Math.max(8, tipX)}px`;
    tooltip.style.top = "22px";
  }

  viewport.addEventListener("mousemove", event => {
    const rect = viewport.getBoundingClientRect();
    lastHoverMouseX = event.clientX - rect.left;
    updateTooltipAt(lastHoverMouseX);
  });

  viewport.addEventListener("mouseleave", () => {
    lastHoverMouseX = null;
    tooltip.style.display = "none";
  });

  let isDragging = false;
  let dragStartX = 0;

  const onMouseDown = event => {
    if (event.button !== 0) return;
    isDragging = true;
    dragStartX = event.clientX;
    canvas.style.cursor = "grabbing";
  };

  const onMouseUp = event => {
    if (!isDragging) return;
    isDragging = false;
    canvas.style.cursor = "crosshair";
    const deltaX = event.clientX - dragStartX;
    if (Math.abs(deltaX) > 20 && currentBins && currentBins.length > 0) {
      const bounds = state.timeBounds || {};
      const latestKnown = bounds.last_t || bounds.live_now ||
        (currentBins.length ? currentBins[currentBins.length - 1].t : Date.now() / 1000);
      const earliestKnown = bounds.first_t !== null ? bounds.first_t : 0;
      const curUntil = state.historicalUntil || latestKnown;
      const shiftSeconds = (deltaX / Math.max(1, viewport.clientWidth)) * state.window * 0.75;
      const newUntil = curUntil - shiftSeconds;

      if (newUntil >= latestKnown - 2) {
        state.followLive = true;
        state.historicalUntil = null;
      } else {
        state.followLive = false;
        state.historicalUntil = Math.max(earliestKnown + state.window * 0.5, newUntil);
      }
      syncOverviewToolbarControls();
      updateOverviewData();
    }
  };

  viewport.addEventListener("mousedown", onMouseDown);
  window.addEventListener("mouseup", onMouseUp);

  draw();
  const ro = new ResizeObserver(() => {
    if (animationFrameId) cancelAnimationFrame(animationFrameId);
    animationFrameId = requestAnimationFrame(draw);
  });
  ro.observe(viewport);

  return {
    mountedIn: container,
    update(bins, incidents, options) {
      currentBins = bins || [];
      currentIncidents = incidents || [];
      currentOptions = { ...currentOptions, ...(options || {}) };
      draw();
      if (lastHoverMouseX !== null) updateTooltipAt(lastHoverMouseX);
    },
    redraw(options) {
      currentOptions = { ...currentOptions, ...(options || {}) };
      draw();
      if (lastHoverMouseX !== null) updateTooltipAt(lastHoverMouseX);
    },
    destroy() {
      ro.disconnect();
      window.removeEventListener("mouseup", onMouseUp);
      if (animationFrameId) cancelAnimationFrame(animationFrameId);
    }
  };
}

// Donut Chart Component (Pure Safe SVG)
function renderProtocolDonut(container, protocols) {
  const wrap = node("div", "donut-wrap");
  const svgContainer = node("div", "donut-svg-container");
  const svg = svgNode("svg", { viewBox: "0 0 160 160", width: "160", height: "160" });
  svgContainer.append(svg);

  const centerLabel = node("div", "donut-center-label");
  const centerVal = node("div", "donut-center-value", "0");
  const centerSub = node("div", "donut-center-sub", "PACKETS");
  centerLabel.append(centerVal, centerSub);
  svgContainer.append(centerLabel);
  wrap.append(svgContainer);

  const legend = node("div", "donut-legend");
  wrap.append(legend);
  container.append(wrap);

  const colors = {
    TCP: "var(--cyan)",
    UDP: "var(--violet)",
    DNS: "var(--teal)",
    ICMP: "var(--amber)",
    ARP: "var(--danger)",
    Other: "var(--text-dim)"
  };

  const entries = Object.entries(protocols || {}).filter(([_, count]) => count > 0);
  const total = entries.reduce((acc, [_, count]) => acc + Number(count), 0);
  const totalText = number(total);
  centerVal.textContent = totalText;
  centerVal.classList.toggle("is-compact", totalText.length >= 9);

  if (total === 0) {
    centerVal.textContent = "0";
    legend.append(node("p", "state-message", "No classified packets recorded."));
    return;
  }

  let currentAngle = -Math.PI / 2;
  const radius = 67;
  const innerRadius = 48;
  const cx = 80;
  const cy = 80;

  for (const [name, count] of entries) {
    const fraction = count / total;
    const sliceAngle = fraction * Math.PI * 2;
    const endAngle = currentAngle + sliceAngle;

    const x1 = cx + radius * Math.cos(currentAngle);
    const y1 = cy + radius * Math.sin(currentAngle);
    const x2 = cx + radius * Math.cos(endAngle);
    const y2 = cy + radius * Math.sin(endAngle);

    const ix1 = cx + innerRadius * Math.cos(endAngle);
    const iy1 = cy + innerRadius * Math.sin(endAngle);
    const ix2 = cx + innerRadius * Math.cos(currentAngle);
    const iy2 = cy + innerRadius * Math.sin(currentAngle);

    const largeArc = sliceAngle > Math.PI ? 1 : 0;
    const d = entries.length === 1
      ? `M ${cx} ${cy - radius} A ${radius} ${radius} 0 1 1 ${cx - 0.01} ${cy - radius} L ${cx - 0.01} ${cy - innerRadius} A ${innerRadius} ${innerRadius} 0 1 0 ${cx} ${cy - innerRadius} Z`
      : `M ${x1} ${y1} A ${radius} ${radius} 0 ${largeArc} 1 ${x2} ${y2} L ${ix1} ${iy1} A ${innerRadius} ${innerRadius} 0 ${largeArc} 0 ${ix2} ${iy2} Z`;

    const sliceColor = colors[name] || colors.Other;
    const path = svgNode("path", {
      d,
      fill: sliceColor,
      stroke: "var(--surface)",
      "stroke-width": "1.5",
      cursor: "pointer"
    });

    const percentStr = `${(fraction * 100).toFixed(1)}%`;

    path.addEventListener("mouseenter", () => {
      path.setAttribute("opacity", "0.82");
      const valText = number(count);
      centerVal.textContent = valText;
      centerVal.classList.toggle("is-compact", valText.length >= 9);
      centerSub.textContent = `${name} (${percentStr})`;
    });

    path.addEventListener("mouseleave", () => {
      path.setAttribute("opacity", "1");
      centerVal.textContent = totalText;
      centerVal.classList.toggle("is-compact", totalText.length >= 9);
      centerSub.textContent = "PACKETS";
    });

    svg.append(path);
    currentAngle = endAngle;

    const item = node("div", "donut-legend-item");
    const labelPart = node("div");
    const swatch = node("span", "legend-swatch");
    swatch.style.background = sliceColor;
    labelPart.append(swatch, node("span", "legend-name", name));

    const valPart = node("span", "legend-values", `${number(count)} (${percentStr})`);
    item.append(labelPart, valPart);

    item.addEventListener("mouseenter", () => {
      path.dispatchEvent(new Event("mouseenter"));
    });
    item.addEventListener("mouseleave", () => {
      path.dispatchEvent(new Event("mouseleave"));
    });

    legend.append(item);
  }
}

// Top Source Talkers Horizontal Bar Chart
function renderTopTalkers(container, talkers, totalBytes) {
  const list = node("div", "hbar-list");
  if (!talkers || talkers.length === 0) {
    list.append(node("p", "state-message", "No source talker data recorded."));
    container.append(list);
    return;
  }

  const maxVal = Math.max(1, ...talkers.map(t => Number(t[1])));
  for (const [ip, bytes] of talkers) {
    const row = node("div", "hbar-row");
    const meta = node("div", "hbar-meta");
    const ipLink = link(ip, `#/hosts/${encodeURIComponent(ip)}`, "mono-link");
    const pct = totalBytes > 0 ? ` (${((bytes / totalBytes) * 100).toFixed(1)}%)` : "";
    meta.append(ipLink, node("span", "hbar-val", `${humanBytes(bytes)}${pct}`));

    const track = node("div", "hbar-track");
    const fill = node("div", "hbar-fill");
    fill.style.width = `${Math.min(100, Math.max(2, (bytes / maxVal) * 100))}%`;
    track.append(fill);

    row.append(meta, track);
    list.append(row);
  }
  container.append(list);
}

function syncOverviewToolbarControls() {
  for (const btn of document.querySelectorAll("[data-metric-key]")) {
    btn.classList.toggle("is-active", btn.dataset.metricKey === state.selectedMetric);
  }
  for (const btn of document.querySelectorAll("[data-chart-style]")) {
    btn.classList.toggle("is-active", btn.dataset.chartStyle === state.chartStyle);
  }
  const winSel = byId("overview-window-select");
  if (winSel) winSel.value = String(state.window);

  const liveBtn = byId("overview-live-btn");
  if (liveBtn) {
    liveBtn.classList.toggle("is-live", state.followLive);
    const lbl = liveBtn.querySelector(".live-btn-text");
    if (lbl) lbl.textContent = state.followLive ? "Live" : "History";
  }

  const markerCheck = byId("display-markers-check");
  if (markerCheck) markerCheck.checked = state.showMarkers;
  const gridCheck = byId("display-grid-check");
  if (gridCheck) gridCheck.checked = state.showGrid;
}

function updateOverviewSubtitle() {
  const sub = byId("page-subtitle");
  if (!sub) return;
  const h = state.lastHealth;
  const bounds = state.timeBounds || {};
  const parts = [];
  if (h && h.source) parts.push(`Source: ${h.source}`);
  if (bounds.first_t && bounds.last_t) {
    parts.push(`Span: ${formatTime(bounds.first_t, false)} – ${formatTime(bounds.last_t, false)}`);
  }
  if (h && h.policy) parts.push(`Policy: ${h.policy}`);
  sub.textContent = parts.length ? parts.join(" · ") : "Traffic telemetry, detections, and store status.";
}

// In-Place Dynamic Overview Data Refresh (Preserves chart DOM & tooltips)
async function updateOverviewData() {
  if (!state.overviewMounted) return;
  try {
    let url = `/api/overview?window=${state.window}`;
    if (!state.followLive && state.historicalUntil) {
      url += `&until=${state.historicalUntil}`;
    }
    const overview = await request(url);
    state.lastOverview = overview;
    if (overview.time_bounds) {
      state.timeBounds = overview.time_bounds;
    }

    updateOverviewSubtitle();

    const h = state.lastHealth || {};
    const totals = deriveTelemetryTotals(h);

    // Refresh packet clock if health.now was 0 on a stored DB
    if (!h.now && state.timeBounds && state.timeBounds.last_t) {
      setText("packet-clock", formatTime(state.timeBounds.last_t));
    }

    const ppsRate = h.packets_per_s !== undefined ? humanRate(h.packets_per_s, "pps") : "—";
    const bpsRate = h.bytes_per_s !== undefined ? humanRate(h.bytes_per_s, "B/s") : "—";

    const kpiPktsVal = byId("kpi-total-pkts-val");
    if (kpiPktsVal) kpiPktsVal.textContent = number(totals.displayPackets);
    const kpiPktsSub = byId("kpi-total-pkts-sub");
    if (kpiPktsSub) {
      kpiPktsSub.textContent = totals.isStoredOnly
        ? "Stored capture total (DB)"
        : `Rate: ${ppsRate}`;
    }

    const kpiBytesVal = byId("kpi-total-bytes-val");
    if (kpiBytesVal) kpiBytesVal.textContent = humanBytes(totals.displayBytes);
    const kpiBytesSub = byId("kpi-total-bytes-sub");
    if (kpiBytesSub) {
      kpiBytesSub.textContent = totals.isStoredOnly
        ? "Persisted volume (DB)"
        : `Throughput: ${bpsRate}`;
    }

    if (overview.open_incidents_by_severity) {
      const openBy = overview.open_incidents_by_severity;
      const totalOpen = (openBy.critical || 0) + (openBy.high || 0) + (openBy.medium || 0) + (openBy.low || 0);
      const incVal = byId("kpi-incidents-val");
      if (incVal) incVal.textContent = number(totalOpen);
      const incSub = byId("kpi-incidents-sub");
      if (incSub) {
        incSub.textContent = `Crit: ${openBy.critical || 0} · High: ${openBy.high || 0} · Med: ${openBy.medium || 0} · Low: ${openBy.low || 0}`;
      }
      updateNavIncidentsBadge(totalOpen);
    }

    const kpiAlertsVal = byId("kpi-alerts-val");
    if (kpiAlertsVal) kpiAlertsVal.textContent = number(overview.total_alerts || 0);

    // Update chart in place (never destroy canvas on 2.5s ticks)
    const chartMount = byId("overview-chart-mount");
    if (chartMount) {
      const chartOpts = {
        metric: state.selectedMetric,
        style: state.chartStyle,
        showMarkers: state.showMarkers,
        showGrid: state.showGrid,
        windowSeconds: state.window,
        viewUntil: overview.time_bounds ? overview.time_bounds.view_until : null
      };
      if (state.chartState && state.chartState.mountedIn === chartMount) {
        state.chartState.update(overview.bins || [], overview.recent_incidents || [], chartOpts);
      } else {
        if (state.chartState && state.chartState.destroy) state.chartState.destroy();
        state.chartState = createTimelineChart(chartMount, overview.bins || [], overview.recent_incidents || [], chartOpts);
      }
    }

    const rangeInfo = byId("timeline-range-label");
    if (rangeInfo) {
      if (overview.bins && overview.bins.length > 0) {
        const firstT = overview.bins[0].t;
        const lastT = overview.bins[overview.bins.length - 1].t;
        rangeInfo.textContent = `${formatTime(firstT)} to ${formatTime(lastT)} (${overview.bins.length} bins)`;
      } else {
        rangeInfo.textContent = "No packet telemetry bins in this window.";
      }
    }

    // Secondary Analytical Panels
    const protoMount = byId("proto-mount");
    if (protoMount) {
      protoMount.replaceChildren();
      renderProtocolDonut(protoMount, overview.protocol_mix);
    }

    const talkerMount = byId("talker-mount");
    if (talkerMount) {
      talkerMount.replaceChildren();
      renderTopTalkers(talkerMount, overview.top_talkers, totals.displayBytes);
    }

    const recentMount = byId("recent-incidents-mount");
    if (recentMount) {
      recentMount.replaceChildren();
      const recIncidents = overview.recent_incidents || [];
      if (recIncidents.length === 0) {
        recentMount.append(node("p", "state-message", "No detections recorded."));
      } else {
        const incTable = table([
          { label: "Severity", cellClass: "nowrap-cell" },
          { label: "Kind", cellClass: "nowrap-cell" },
          { label: "Source", cellClass: "nowrap-cell" },
          { label: "Summary" },
          { label: "Time", cellClass: "num-cell" },
          { label: "", cellClass: "nowrap-cell" }
        ], recIncidents.slice(0, 6).map(inc => [
          severityBadge(inc.severity),
          inc.kind,
          inc.src && inc.src !== "many" && inc.src !== "-"
            ? link(inc.src, `#/hosts/${encodeURIComponent(inc.src)}`, "mono-link")
            : inc.src,
          node("span", "summary-cell", inc.detail || "—"),
          formatTime(inc.last_ts),
          link("Inspect", `#/incidents/${encodeURIComponent(inc.id)}`, "inline-link-btn")
        ]), "No detections.");
        recentMount.append(tableWrap(incTable));
      }
    }

    const diagMount = byId("diag-mount");
    if (diagMount && state.lastHealth) {
      diagMount.replaceChildren();
      const sc = h.store_counters || {};
      const dList = node("div", "detail-facts-grid");
      const addFact = (lbl, val) => {
        const item = node("div", "fact-item");
        item.append(node("span", "fact-label", lbl), node("strong", "fact-val", val));
        dList.append(item);
      };
      addFact("Avg / Peak Latency", `${h.avg_processing_us || 0} / ${h.max_processing_us || 0} µs`);
      addFact("Memory RSS", h.memory_rss_bytes ? humanBytes(h.memory_rss_bytes) : "—");
      addFact("Malformed / OOO", `${number(h.malformed || 0)} / ${number(h.out_of_order || 0)}`);
      addFact("Writer Thread", sc.writer_alive ? "Active" : "Stopped");
      addFact("Queue / Drops", `${number(sc.queued || 0)}/${number(sc.queue_capacity || 10000)} · ${number(sc.dropped || 0)} drops`);
      addFact("Records Written", number(sc.written || 0));
      diagMount.append(dList);
    }
  } catch (err) {
    // Silent degradation on live poll tick
  }
}

function redrawChartInPlace() {
  if (!state.chartState) return;
  const bounds = state.lastOverview && state.lastOverview.time_bounds
    ? state.lastOverview.time_bounds.view_until
    : null;
  state.chartState.redraw({
    metric: state.selectedMetric,
    style: state.chartStyle,
    showMarkers: state.showMarkers,
    showGrid: state.showGrid,
    windowSeconds: state.window,
    viewUntil: bounds
  });
}

// Initial Full Render of Overview View
async function renderOverview() {
  state.overviewMounted = false;
  frame("Traffic Overview", "Loading capture metadata...");

  // Balanced 4-Card KPI Strip
  const kpiGrid = node("div", "kpi-grid");
  view.append(kpiGrid);

  const cardPkts = createKpi("Packets", "—", "", "Loading...", "kpi-total-pkts");
  cardPkts.querySelector(".kpi-value").id = "kpi-total-pkts-val";
  cardPkts.querySelector(".kpi-subtext").id = "kpi-total-pkts-sub";

  const cardBytes = createKpi("Bytes", "—", "", "Loading...", "kpi-total-bytes");
  cardBytes.querySelector(".kpi-value").id = "kpi-total-bytes-val";
  cardBytes.querySelector(".kpi-subtext").id = "kpi-total-bytes-sub";

  const cardIncidents = createKpi("Open Incidents", "—", "", "Loading...", "kpi-incidents");
  cardIncidents.querySelector(".kpi-value").id = "kpi-incidents-val";
  cardIncidents.querySelector(".kpi-subtext").id = "kpi-incidents-sub";

  const cardAlerts = createKpi("Recorded Alerts", "—", "", "Matched detection events", "kpi-alerts");
  cardAlerts.querySelector(".kpi-value").id = "kpi-alerts-val";

  kpiGrid.append(cardPkts, cardBytes, cardIncidents, cardAlerts);

  // Timeline Centerpiece Panel (1 Compact Toolbar Row)
  const timelinePanel = node("section", "panel timeline-panel");
  const toolbar = node("div", "timeline-toolbar");

  const metricsGroup = node("div", "segmented-control");
  const metrics = [
    { key: "packets", label: "Packets" },
    { key: "bytes", label: "Bytes" },
    { key: "syn", label: "SYN" },
    { key: "dns", label: "DNS" },
    { key: "sources", label: "Sources" },
    { key: "dual", label: "Dual" }
  ];

  for (const m of metrics) {
    const btn = node("button", `metric-pill-btn${state.selectedMetric === m.key ? " is-active" : ""}`, m.label);
    btn.type = "button";
    btn.dataset.metricKey = m.key;
    btn.addEventListener("click", () => {
      state.selectedMetric = m.key;
      syncOverviewToolbarControls();
      redrawChartInPlace();
    });
    metricsGroup.append(btn);
  }
  toolbar.append(metricsGroup);

  const controlsRight = node("div", "timeline-controls");

  const windowSelect = node("select", "field-select");
  windowSelect.id = "overview-window-select";
  windowSelect.setAttribute("aria-label", "Time window");
  selectOption(windowSelect, "60", "1m");
  selectOption(windowSelect, "300", "5m");
  selectOption(windowSelect, "900", "15m");
  selectOption(windowSelect, "3600", "1h");
  windowSelect.value = String(state.window);
  windowSelect.addEventListener("change", () => {
    state.window = Number(windowSelect.value);
    updateOverviewData();
  });
  controlsRight.append(windowSelect);

  const stepGroup = node("div", "timeline-nav-group");
  const prevBtn = node("button", "timeline-nav-btn", "◀");
  prevBtn.type = "button";
  prevBtn.setAttribute("aria-label", "Step backward in time");
  prevBtn.title = "Step backward";
  prevBtn.addEventListener("click", () => {
    state.followLive = false;
    const bounds = state.timeBounds || {};
    const cur = state.historicalUntil || bounds.last_t || bounds.live_now || Date.now() / 1000;
    const earliest = bounds.first_t !== null ? bounds.first_t : 0;
    state.historicalUntil = Math.max(earliest + state.window * 0.5, cur - state.window * 0.5);
    syncOverviewToolbarControls();
    updateOverviewData();
  });

  const nextBtn = node("button", "timeline-nav-btn", "▶");
  nextBtn.type = "button";
  nextBtn.setAttribute("aria-label", "Step forward in time");
  nextBtn.title = "Step forward";
  nextBtn.addEventListener("click", () => {
    if (!state.historicalUntil) return;
    const bounds = state.timeBounds || {};
    const liveNow = bounds.last_t || bounds.live_now || Date.now() / 1000;
    const nextUntil = state.historicalUntil + state.window * 0.5;
    if (nextUntil >= liveNow - 2) {
      state.followLive = true;
      state.historicalUntil = null;
    } else {
      state.historicalUntil = nextUntil;
    }
    syncOverviewToolbarControls();
    updateOverviewData();
  });
  stepGroup.append(prevBtn, nextBtn);
  controlsRight.append(stepGroup);

  const fitBtn = node("button", "timeline-nav-btn", "Fit");
  fitBtn.type = "button";
  fitBtn.title = "Fit timeline to recorded bounds";
  fitBtn.addEventListener("click", () => {
    const bounds = state.timeBounds || {};
    if (bounds.first_t && bounds.last_t) {
      const span = bounds.last_t - bounds.first_t;
      if (span <= 60) state.window = 60;
      else if (span <= 300) state.window = 300;
      else if (span <= 900) state.window = 900;
      else state.window = 3600;
      state.historicalUntil = bounds.last_t;
      state.followLive = false;
      syncOverviewToolbarControls();
      updateOverviewData();
    }
  });
  controlsRight.append(fitBtn);

  // Compact Display Popover
  const popWrap = node("div", "popover-wrap");
  const displayBtn = node("button", "timeline-nav-btn", "Display ▾");
  displayBtn.type = "button";
  displayBtn.setAttribute("aria-expanded", "false");
  displayBtn.setAttribute("aria-haspopup", "true");

  const popover = node("div", "display-popover");
  popover.hidden = true;

  const styleSec = node("div", "popover-section");
  styleSec.append(node("span", "popover-label", "Series Style"));
  const styleSeg = node("div", "segmented-control");
  for (const st of [{ id: "area", label: "Area" }, { id: "line", label: "Line" }, { id: "stepped", label: "Stepped" }]) {
    const sBtn = node("button", `metric-pill-btn${state.chartStyle === st.id ? " is-active" : ""}`, st.label);
    sBtn.type = "button";
    sBtn.dataset.chartStyle = st.id;
    sBtn.addEventListener("click", () => {
      state.chartStyle = st.id;
      syncOverviewToolbarControls();
      redrawChartInPlace();
    });
    styleSeg.append(sBtn);
  }
  styleSec.append(styleSeg);
  popover.append(styleSec);

  const optSec = node("div", "popover-section");
  optSec.append(node("span", "popover-label", "Chart Options"));

  const mkToggleRow = (label, id, checked, onToggle) => {
    const row = node("label", "popover-check-row");
    row.append(node("span", "", label));
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.id = id;
    cb.checked = checked;
    cb.addEventListener("change", () => onToggle(cb.checked));
    row.append(cb);
    return row;
  };

  optSec.append(
    mkToggleRow("Incident Markers", "display-markers-check", state.showMarkers, val => {
      state.showMarkers = val;
      redrawChartInPlace();
    }),
    mkToggleRow("Gridlines", "display-grid-check", state.showGrid, val => {
      state.showGrid = val;
      redrawChartInPlace();
    })
  );
  popover.append(optSec);

  const resetBtn = node("button", "secondary-button", "Reset to Live (5m)");
  resetBtn.type = "button";
  resetBtn.addEventListener("click", () => {
    state.window = 300;
    state.followLive = true;
    state.historicalUntil = null;
    popover.hidden = true;
    displayBtn.setAttribute("aria-expanded", "false");
    syncOverviewToolbarControls();
    updateOverviewData();
  });
  popover.append(resetBtn);

  displayBtn.addEventListener("click", event => {
    event.stopPropagation();
    const nextHidden = !popover.hidden;
    popover.hidden = nextHidden;
    displayBtn.setAttribute("aria-expanded", nextHidden ? "false" : "true");
  });

  const closeOnOutside = event => {
    if (!popWrap.contains(event.target) && !popover.hidden) {
      popover.hidden = true;
      displayBtn.setAttribute("aria-expanded", "false");
    }
  };
  const closeOnEsc = event => {
    if (event.key === "Escape" && !popover.hidden) {
      popover.hidden = true;
      displayBtn.setAttribute("aria-expanded", "false");
    }
  };
  document.addEventListener("click", closeOnOutside);
  document.addEventListener("keydown", closeOnEsc);
  state.popoverCleanup = () => {
    document.removeEventListener("click", closeOnOutside);
    document.removeEventListener("keydown", closeOnEsc);
  };

  popWrap.append(displayBtn, popover);
  controlsRight.append(popWrap);

  const liveBtn = node("button", `follow-live-btn${state.followLive ? " is-live" : ""}`);
  liveBtn.id = "overview-live-btn";
  liveBtn.type = "button";
  liveBtn.append(
    node("span", "follow-live-dot"),
    node("span", "live-btn-text", state.followLive ? "Live" : "History")
  );
  liveBtn.addEventListener("click", () => {
    state.followLive = !state.followLive;
    if (state.followLive) state.historicalUntil = null;
    syncOverviewToolbarControls();
    updateOverviewData();
  });
  controlsRight.append(liveBtn);

  toolbar.append(controlsRight);
  timelinePanel.append(toolbar);

  const chartContainer = node("div", "chart-mount");
  chartContainer.id = "overview-chart-mount";
  timelinePanel.append(chartContainer);

  const timelineFoot = node("div", "timeline-footer");
  const rangeInfo = node("span", "timeline-range-label", "Loading time-series...");
  rangeInfo.id = "timeline-range-label";
  timelineFoot.append(rangeInfo);
  timelinePanel.append(timelineFoot);
  view.append(timelinePanel);

  // Secondary 2x2 Analytical Grid
  const grid = node("div", "analytics-grid");

  const protoPanel = section("Protocol Distribution", node("div"), "", "Classified packet mix");
  const protoMount = protoPanel.lastChild;
  protoMount.id = "proto-mount";
  protoMount.append(node("p", "state-message", "Loading protocol breakdown..."));

  const talkerPanel = section("Top Source Talkers", node("div"), "", "Ranked by outbound bytes");
  const talkerMount = talkerPanel.lastChild;
  talkerMount.id = "talker-mount";
  talkerMount.append(node("p", "state-message", "Loading top talkers..."));

  const incidentFeedPanel = section("Recent Detections", node("div"), "", "Latest correlated incidents");
  const recentMount = incidentFeedPanel.lastChild;
  recentMount.id = "recent-incidents-mount";
  recentMount.append(node("p", "state-message", "Loading detections..."));

  const diagnosticsPanel = section("Storage & Diagnostics", node("div"), "", "Pipeline latency, RSS, and SQLite writer");
  const diagMount = diagnosticsPanel.lastChild;
  diagMount.id = "diag-mount";
  diagMount.append(node("p", "state-message", "Loading diagnostics..."));

  grid.append(protoPanel, talkerPanel, incidentFeedPanel, diagnosticsPanel);
  view.append(grid);

  state.overviewMounted = true;
  await updateOverviewData();
}

// Incidents Workflow & Detail Views
function sortable(key, current) {
  return current.key === key ? (current.direction === "asc" ? "ascending" : "descending") : "none";
}

function shortIdControl(fullId) {
  const wrap = node("span", "id-cell-wrap");
  const short = String(fullId || "").slice(0, 8);
  wrap.append(link(short, `#/incidents/${encodeURIComponent(fullId)}`, "identifier", null, String(fullId)));
  const copyBtn = node("button", "copy-mini-btn", "⎘");
  copyBtn.type = "button";
  copyBtn.title = `Copy ID ${fullId}`;
  copyBtn.setAttribute("aria-label", `Copy incident ID ${fullId}`);
  copyBtn.addEventListener("click", async event => {
    event.stopPropagation();
    await copyToClipboard(String(fullId));
    copyBtn.textContent = "✓";
    setTimeout(() => { copyBtn.textContent = "⎘"; }, 1400);
  });
  wrap.append(copyBtn);
  return wrap;
}

async function renderIncidents(parts) {
  state.overviewMounted = false;
  const detailId = parts.length > 1 ? parts[1] : "";
  frame("Incidents", "Search, filter, and triage correlated detection incidents.");

  const controls = node("form", "filter-bar");
  controls.addEventListener("submit", event => {
    event.preventDefault();
    state.incidentFilters.q = controls.elements.q.value.trim();
    state.incidentFilters.status = controls.elements.status.value;
    state.incidentFilters.severity = controls.elements.severity.value;
    state.incidentFilters.kind = controls.elements.kind.value.trim();
    state.incidentFilters.offset = 0;
    renderRoute(routeParts(), true);
  });

  const search = node("input", "field-input");
  search.name = "q";
  search.type = "search";
  search.value = state.incidentFilters.q;
  search.placeholder = "IP, kind, or summary...";
  search.setAttribute("aria-label", "Search incidents");

  const status = node("select", "field-select");
  status.name = "status";
  selectOption(status, "", "All statuses");
  for (const v of ["open", "acknowledged", "closed"]) selectOption(status, v, v.toUpperCase());
  status.value = state.incidentFilters.status;

  const severity = node("select", "field-select");
  severity.name = "severity";
  selectOption(severity, "", "All severities");
  for (const v of ["critical", "high", "medium", "low"]) selectOption(severity, v, v.toUpperCase());
  severity.value = state.incidentFilters.severity;

  const kind = node("input", "field-input");
  kind.name = "kind";
  kind.value = state.incidentFilters.kind;
  kind.placeholder = "Detector (e.g. port_scan)";

  const submit = node("button", "primary-button", "Filter");
  submit.type = "submit";

  const clearBtn = node("button", "secondary-button", "Reset");
  clearBtn.type = "button";
  clearBtn.addEventListener("click", () => {
    state.incidentFilters = { q: "", status: "", severity: "", kind: "", limit: 50, offset: 0 };
    state.incidentSort = { key: "last_ts", direction: "desc" };
    renderRoute(routeParts(), true);
  });

  controls.append(
    formField("Search", search, "incident-search"),
    formField("Status", status, "incident-status"),
    formField("Severity", severity, "incident-severity"),
    formField("Detector", kind, "incident-kind"),
    submit,
    clearBtn
  );
  view.append(controls);

  const layout = node("div", detailId ? "split-layout" : "");
  const listPanel = section("Incident Register", node("p", "state-message", "Loading incidents..."));
  layout.append(listPanel);
  view.append(layout);

  try {
    const filters = state.incidentFilters;
    const params = new URLSearchParams({
      limit: String(filters.limit),
      offset: String(filters.offset),
      sort: state.incidentSort.key,
      dir: state.incidentSort.direction
    });
    for (const k of ["q", "status", "severity", "kind"]) {
      if (filters[k]) params.set(k, filters[k]);
    }
    const response = await request(`/api/incidents?${params}`);
    const rows = response.items || [];

    const incidentTable = table([
      { label: "ID", cellClass: "nowrap-cell" },
      { label: "Kind", key: "kind", sort: sortable("kind", state.incidentSort), cellClass: "nowrap-cell" },
      { label: "Severity", key: "severity", sort: sortable("severity", state.incidentSort), cellClass: "nowrap-cell" },
      { label: "Status", key: "status", sort: sortable("status", state.incidentSort), cellClass: "nowrap-cell" },
      { label: "Source", key: "src", sort: sortable("src", state.incidentSort), cellClass: "nowrap-cell" },
      { label: "Summary" },
      { label: "Count", key: "count", sort: sortable("count", state.incidentSort), cellClass: "num-cell" },
      { label: "Last Seen", key: "last_ts", sort: sortable("last_ts", state.incidentSort), cellClass: "num-cell" }
    ], rows.map(item => [
      shortIdControl(item.id),
      item.kind,
      severityBadge(item.severity),
      statusBadge(item.status),
      item.src && item.src !== "many" && item.src !== "-"
        ? link(item.src, `#/hosts/${encodeURIComponent(item.src)}`, "mono-link")
        : item.src,
      node("span", "summary-cell", item.detail || "—"),
      number(item.count),
      detailId ? formatTime(item.last_ts, false).replace(" UTC", "") : formatTime(item.last_ts, true)
    ]), "No incidents match the selected filters.");

    for (const summarySpan of incidentTable.querySelectorAll(".summary-cell")) {
      summarySpan.title = summarySpan.textContent;
    }

    listPanel.replaceChildren();
    const lHead = node("div", "panel-header");
    lHead.append(
      node("h2", "panel-title", `Incident Register (${number(response.total)})`),
      node("span", "panel-subtitle", `Sorted by ${state.incidentSort.key} (${state.incidentSort.direction})`)
    );
    listPanel.append(lHead, tableWrap(incidentTable));

    pageControls(listPanel, response.total, filters.limit, filters.offset, off => {
      state.incidentFilters.offset = off;
      renderRoute(routeParts(), true);
    });

    for (const btn of incidentTable.querySelectorAll("[data-sort]")) {
      btn.addEventListener("click", () => {
        const k = btn.dataset.sort;
        if (state.incidentSort.key === k) {
          state.incidentSort.direction = state.incidentSort.direction === "asc" ? "desc" : "asc";
        } else {
          state.incidentSort = { key: k, direction: "desc" };
        }
        state.incidentFilters.offset = 0;
        renderRoute(routeParts(), true);
      });
    }

    if (detailId) {
      const panel = await renderIncidentDetail(detailId);
      layout.append(panel);
    }
  } catch (error) {
    showState(listPanel, `Could not load incidents: ${error.message}`, "error");
  }
}

function appendEvidenceGauge(container, labelLeft, labelRight, subline, observed, threshold, baseline) {
  const gauge = node("div", "evidence-gauge");
  const labels = node("div", "gauge-labels");
  labels.append(node("span", "", labelLeft), node("span", "", labelRight));
  gauge.append(labels);

  const obsNum = Number(observed || 0);
  const refNum = threshold !== undefined && threshold !== null ? Number(threshold) : Number(baseline || 0);
  const maxScale = Math.max(obsNum * 1.1, refNum * 1.5, 1);

  const track = node("div", "gauge-track");
  const fill = node("div", `gauge-observed-bar${obsNum >= refNum ? " is-alert" : ""}`);
  fill.style.width = `${Math.min(100, Math.max(3, (obsNum / maxScale) * 100))}%`;
  track.append(fill);

  if (baseline !== undefined && baseline !== null && Number.isFinite(Number(baseline))) {
    const bMark = node("div", "gauge-baseline-marker");
    bMark.style.left = `${Math.min(99, (Number(baseline) / maxScale) * 100)}%`;
    bMark.title = `Baseline: ${baseline}`;
    track.append(bMark);
  }
  if (threshold !== undefined && threshold !== null && Number.isFinite(Number(threshold))) {
    const tMark = node("div", "gauge-threshold-marker");
    tMark.style.left = `${Math.min(99, (Number(threshold) / maxScale) * 100)}%`;
    tMark.title = `Threshold: ${threshold}`;
    track.append(tMark);
  }

  gauge.append(track);
  if (subline) gauge.append(node("div", "gauge-sub", subline));
  container.append(gauge);
}

function renderEvidenceCard(panel, data) {
  if (!data || typeof data !== "object" || Object.keys(data).length === 0) return;

  const evidenceCard = node("div", "evidence-card");
  evidenceCard.append(node("div", "evidence-title", "Structured Detection Evidence"));
  let rendered = false;

  // Volumetric detector metrics array: [{metric, observed, baseline, z_score, threshold}]
  if (Array.isArray(data.metrics) && data.metrics.length > 0) {
    for (const m of data.metrics) {
      if (!m || typeof m !== "object") continue;
      const metricName = String(m.metric || "metric").toUpperCase();
      const obsVal = Number(m.observed || 0);
      const baseVal = Number(m.baseline || 0);
      const zVal = Number(m.z_score !== undefined ? m.z_score : 0);
      const zThr = Number(m.threshold !== undefined ? m.threshold : (data.z_threshold || 0));
      const fmtVal = v => (m.metric === "bytes" ? `${humanBytes(v)}/s` : `${number(Math.round(v))}/s`);
      appendEvidenceGauge(
        evidenceCard,
        `${metricName}: ${fmtVal(obsVal)}`,
        `Baseline: ${fmtVal(baseVal)}`,
        `z-score: ${zVal.toFixed(2)} (threshold z >= ${zThr.toFixed(1)}, window ${data.window_s || 1}s)`,
        obsVal,
        null,
        baseVal
      );
      rendered = true;
    }
  }

  // SYN flood / generic threshold gauge
  if (data.observed !== undefined && data.threshold !== undefined) {
    const extra = [];
    if (data.destination_port !== undefined) extra.push(`port ${data.destination_port}`);
    if (data.sources !== undefined) extra.push(`${number(data.sources)} source(s)`);
    if (data.window_s !== undefined) extra.push(`${data.window_s}s window`);
    appendEvidenceGauge(
      evidenceCard,
      `Observed: ${number(data.observed)}`,
      `Threshold: ${number(data.threshold)}`,
      extra.join(" · "),
      data.observed,
      data.threshold,
      null
    );
    rendered = true;
  }

  // Port scan gauge
  if (data.distinct_ports !== undefined && data.threshold !== undefined) {
    appendEvidenceGauge(
      evidenceCard,
      `Distinct Ports: ${number(data.distinct_ports)}`,
      `Threshold: ${number(data.threshold)}`,
      data.window_s !== undefined ? `Inspection window: ${data.window_s}s` : "",
      data.distinct_ports,
      data.threshold,
      null
    );
    rendered = true;
  }

  // Horizontal scan gauge
  if (data.distinct_hosts !== undefined && data.threshold !== undefined) {
    const parts = [];
    if (data.destination_port !== undefined) parts.push(`port ${data.destination_port}`);
    if (data.window_s !== undefined) parts.push(`${data.window_s}s window`);
    appendEvidenceGauge(
      evidenceCard,
      `Target Hosts: ${number(data.distinct_hosts)}`,
      `Threshold: ${number(data.threshold)}`,
      parts.join(" · "),
      data.distinct_hosts,
      data.threshold,
      null
    );
    rendered = true;
  }

  // DNS tunnel multi-signal gauges
  if (data.unique_subdomains !== undefined) {
    appendEvidenceGauge(
      evidenceCard,
      `Unique Subdomains: ${number(data.unique_subdomains)}`,
      `Min Required: ${number(data.min_unique)}`,
      `Domain: ${data.base_domain || "—"} · Window: ${data.window_s || 60}s`,
      data.unique_subdomains,
      data.min_unique,
      null
    );
    if (data.avg_length !== undefined && data.min_avg_length !== undefined) {
      appendEvidenceGauge(
        evidenceCard,
        `Avg Subdomain Length: ${Number(data.avg_length).toFixed(1)}`,
        `Min Required: ${number(data.min_avg_length)}`,
        "",
        data.avg_length,
        data.min_avg_length,
        null
      );
    }
    if (data.avg_entropy !== undefined && data.min_avg_entropy !== undefined) {
      appendEvidenceGauge(
        evidenceCard,
        `Avg Shannon Entropy: ${Number(data.avg_entropy).toFixed(2)}`,
        `Min Required: ${Number(data.min_avg_entropy).toFixed(2)}`,
        "",
        data.avg_entropy,
        data.min_avg_entropy,
        null
      );
    }
    rendered = true;
  }

  // ARP spoof MAC transition
  if (data.claimed_ip !== undefined) {
    const fGrid = node("div", "detail-facts-grid");
    const addE = (k, v) => {
      const it = node("div", "fact-item");
      it.append(node("span", "fact-label", k), node("span", "fact-val", v));
      fGrid.append(it);
    };
    addE("Claimed IP", data.claimed_ip);
    addE("Previous MAC", data.old_mac || "—");
    addE("New MAC", data.new_mac || "—");
    if (data.cooldown_s !== undefined) addE("Cooldown", `${data.cooldown_s}s`);
    evidenceCard.append(fGrid);
    rendered = true;
  }

  if (data.z !== undefined || data.zscore !== undefined) {
    const z = data.z !== undefined ? data.z : data.zscore;
    evidenceCard.append(node("div", "gauge-sub", `Statistical deviation: z = ${z}`));
    rendered = true;
  }

  // Generic fallback for any remaining structured data keys
  if (!rendered) {
    const fGrid = node("div", "detail-facts-grid");
    for (const [k, v] of Object.entries(data)) {
      const it = node("div", "fact-item");
      it.append(
        node("span", "fact-label", k),
        node("span", "fact-val", typeof v === "object" ? JSON.stringify(v) : String(v))
      );
      fGrid.append(it);
    }
    evidenceCard.append(fGrid);
    rendered = true;
  }

  if (rendered) panel.append(evidenceCard);
}

// Deep Incident Detail & Triage Workspace
async function renderIncidentDetail(id) {
  const panel = node("aside", "detail-panel");
  panel.setAttribute("aria-label", "Incident Investigation Detail");
  showState(panel, "Loading incident details...");

  try {
    const incident = await request(`/api/incidents/${encodeURIComponent(id)}`);
    panel.replaceChildren();

    const header = node("div", "detail-header");
    const titleBlock = node("div", "detail-title-block");
    titleBlock.append(node("span", "eyebrow", `INCIDENT ${incident.id}`));
    const titleRow = node("div", "capture-title-wrap");
    titleRow.append(
      node("h2", "detail-title", incident.kind),
      severityBadge(incident.severity),
      statusBadge(incident.status)
    );
    titleBlock.append(titleRow);

    const closeBtn = link("Close", "#/incidents", "close-panel-btn");
    header.append(titleBlock, closeBtn);
    panel.append(header);

    const actionRow = node("div", "page-actions");
    const copyBtn = node("button", "secondary-button", "Copy JSON");
    copyBtn.type = "button";
    copyBtn.addEventListener("click", async () => {
      await copyToClipboard(JSON.stringify(incident, null, 2));
      copyBtn.textContent = "Copied";
      setTimeout(() => { copyBtn.textContent = "Copy JSON"; }, 1800);
    });
    actionRow.append(copyBtn);
    panel.append(actionRow);

    const facts = node("div", "detail-facts-grid");
    const addFact = (label, val, isHostLink) => {
      const item = node("div", "fact-item");
      item.append(node("span", "fact-label", label));
      const valWrap = node("span", "fact-val");
      if (isHostLink && val && val !== "many" && val !== "-") {
        valWrap.append(link(val, `#/hosts/${encodeURIComponent(val)}`, "mono-link"));
      } else {
        valWrap.textContent = String(val || "—");
      }
      item.append(valWrap);
      facts.append(item);
    };

    addFact("Source", incident.src, true);

    const alerts = incident.alerts || [];
    const dstAddresses = Array.from(new Set(alerts.map(a => a.dst).filter(d => d && d !== "-")));
    const dstSummary = dstAddresses.length > 0
      ? dstAddresses.slice(0, 3).join(", ") + (dstAddresses.length > 3 ? ` (+${dstAddresses.length - 3})` : "")
      : "—";
    addFact("Destination", dstSummary, dstAddresses.length === 1);
    addFact("Occurrences", number(incident.count), false);
    addFact("First Seen", formatTime(incident.first_ts), false);
    addFact("Last Seen", formatTime(incident.last_ts), false);
    panel.append(facts);

    const relatedHosts = Array.from(new Set([incident.src, ...dstAddresses])).filter(h => h && h !== "many" && h !== "-");
    if (relatedHosts.length > 0) {
      const relSec = node("div", "panel");
      relSec.append(node("h3", "panel-title", "Related Hosts"));
      const rList = node("div", "pill-list");
      rList.style.marginTop = "8px";
      for (const h of relatedHosts) {
        rList.append(link(h, `#/hosts/${encodeURIComponent(h)}`, "inline-link-btn"));
      }
      relSec.append(rList);
      panel.append(relSec);
    }

    const explanationSec = node("div", "panel");
    explanationSec.append(node("h3", "panel-title", "Detection Summary"));
    const detSub = node("p", "panel-subtitle", incident.detail || "No summary recorded.");
    detSub.style.marginTop = "6px";
    explanationSec.append(detSub);

    if (incident.kind === "volumetric") {
      const caveat = node("div", "caveat-banner");
      caveat.style.marginTop = "10px";
      caveat.style.marginBottom = "0";
      caveat.append(node("span", "caveat-badge", "Experimental"));
      caveat.append(node("span", "caveat-text",
        "EWMA volumetric detection flags rapid traffic shifts and can trigger on legitimate bursts. Verify host flows before taking action."));
      explanationSec.append(caveat);
    }
    panel.append(explanationSec);

    if (alerts.length > 0) {
      renderEvidenceCard(panel, alerts[0].data);
    }

    // Chronological Alert Timeline
    const timelineSec = node("div", "panel");
    const tTitle = `Alert Events (${alerts.length}${incident.alerts_truncated ? ", truncated" : ""})`;
    const tlTitle = node("h3", "panel-title", tTitle);
    tlTitle.style.marginBottom = "10px";
    timelineSec.append(tlTitle);

    const vTimeline = node("div", "timeline-vertical");
    for (const a of alerts) {
      const eventItem = node("div", `timeline-event-item${a.severity === "critical" ? " critical" : ""}`);
      const eHead = node("div", "timeline-event-header");
      eHead.append(node("span", "timeline-event-time", formatTime(a.ts)), severityBadge(a.severity));
      const eDetail = node("div", "timeline-event-detail", a.detail);
      const eMeta = node("div", "alert-item-meta");
      eMeta.append(
        node("span", "", `Src: ${a.src || "—"}`),
        node("span", "", `Dst: ${a.dst || "—"}`),
        node("span", "", `Policy: ${a.policy_id || "default"}`)
      );
      eventItem.append(eHead, eDetail, eMeta);

      if (a.data && Object.keys(a.data).length > 0) {
        eventItem.append(node("pre", "alert-data-pre", JSON.stringify(a.data, null, 2)));
      }
      vTimeline.append(eventItem);
    }
    timelineSec.append(vTimeline);
    panel.append(timelineSec);

    // Operator Audit Log History
    const auditLogs = incident.audit_log || [];
    const auditSec = node("div", "panel");
    const auditTitle = `Operator Audit History${incident.audit_truncated ? " (truncated)" : ""}`;
    const aHead = node("h3", "panel-title", auditTitle);
    aHead.style.marginBottom = "10px";
    auditSec.append(aHead);

    if (auditLogs.length === 0) {
      auditSec.append(node("p", "state-message", "No status transitions recorded."));
    } else {
      const aTable = table([
        { label: "Action" },
        { label: "Timestamp", cellClass: "nowrap-cell" },
        { label: "Note" }
      ], auditLogs.map(l => [
        statusBadge(l.action),
        formatTime(l.ts),
        l.note || "—"
      ]), "No audit records.");
      auditSec.append(tableWrap(aTable));
    }
    panel.append(auditSec);

    // Status Transition Form
    if (incident.status !== "closed") {
      const actionForm = node("form", "panel");
      const formHead = node("h3", "panel-title", "Update Status");
      formHead.style.marginBottom = "10px";
      actionForm.append(formHead);

      const feedbackBox = node("div", "");
      feedbackBox.style.display = "none";
      actionForm.append(feedbackBox);

      const noteInput = node("textarea", "field-textarea");
      noteInput.rows = 2;
      noteInput.placeholder = "Enter triage justification note...";
      noteInput.setAttribute("aria-label", "Triage note");
      actionForm.append(formField("Triage Note", noteInput));

      const btnRow = node("div", "page-actions");
      btnRow.style.marginTop = "10px";
      const allActionButtons = [];

      if (incident.status === "open") {
        const ackBtn = node("button", "primary-button", "Acknowledge");
        ackBtn.type = "button";
        allActionButtons.push(ackBtn);
        ackBtn.addEventListener("click", async () => {
          await submitStatus(incident.id, "acknowledged", noteInput.value.trim(), allActionButtons, feedbackBox);
        });
        btnRow.append(ackBtn);
      }

      const closeActionBtn = node("button", "secondary-button", "Close Incident");
      closeActionBtn.type = "button";
      allActionButtons.push(closeActionBtn);
      closeActionBtn.addEventListener("click", async () => {
        await submitStatus(incident.id, "closed", noteInput.value.trim(), allActionButtons, feedbackBox);
      });
      btnRow.append(closeActionBtn);

      actionForm.append(btnRow);
      panel.append(actionForm);
    }
  } catch (error) {
    showState(panel, `Incident details unavailable: ${error.message}`, "error");
  }

  return panel;
}

async function submitStatus(id, newStatus, note, buttons, feedbackBox) {
  if (!note) {
    feedbackBox.className = "feedback-banner error";
    feedbackBox.textContent = "Enter a triage note explaining this status change.";
    feedbackBox.style.display = "block";
    return;
  }
  const token = getCsrfToken();
  if (!token) {
    feedbackBox.className = "feedback-banner error";
    feedbackBox.textContent = "Security token missing. Reload the page.";
    feedbackBox.style.display = "block";
    return;
  }

  for (const b of buttons) b.disabled = true;
  feedbackBox.className = "feedback-banner";
  feedbackBox.textContent = "Updating incident status...";
  feedbackBox.style.display = "block";

  try {
    await request(`/api/incidents/${encodeURIComponent(id)}/status`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-PacketLens-Token": token
      },
      body: JSON.stringify({ status: newStatus, note })
    });
    feedbackBox.className = "feedback-banner success";
    feedbackBox.textContent = "Status updated.";
    await Promise.allSettled([pollHealth(), pollAnnouncements()]);
    await renderRoute(routeParts(), false);
  } catch (error) {
    feedbackBox.className = "feedback-banner error";
    feedbackBox.textContent = `Failed to update incident: ${error.message}`;
    for (const b of buttons) b.disabled = false;
  }
}

// Host Inventory & Investigation Workspace
async function renderHosts(parts) {
  state.overviewMounted = false;
  const detailIp = parts.length > 1 ? parts[1] : "";
  frame("Hosts", "Per-host traffic counters, peer relationships, and destination ports.");

  const controls = node("form", "filter-bar");
  controls.addEventListener("submit", event => {
    event.preventDefault();
    state.hostFilters.q = controls.elements.q.value.trim();
    state.hostFilters.sort = controls.elements.sort.value;
    state.hostFilters.offset = 0;
    renderRoute(routeParts(), true);
  });

  const search = node("input", "field-input");
  search.name = "q";
  search.type = "search";
  search.value = state.hostFilters.q;
  search.placeholder = "Filter by IP address...";

  const sortSelect = node("select", "field-select");
  sortSelect.name = "sort";
  selectOption(sortSelect, "bytes", "Total Bytes");
  selectOption(sortSelect, "last_seen", "Last Seen");
  selectOption(sortSelect, "alerts", "Alert Count");
  selectOption(sortSelect, "ip", "IP Address");
  sortSelect.value = state.hostFilters.sort;

  const submit = node("button", "primary-button", "Filter");
  submit.type = "submit";

  controls.append(formField("Search IP", search, "host-search"), formField("Sort By", sortSelect, "host-sort"), submit);
  view.append(controls);

  const layout = node("div", detailIp ? "split-layout" : "");
  const listPanel = section("Host Profiles", node("p", "state-message", "Loading hosts..."));
  layout.append(listPanel);
  view.append(layout);

  try {
    const filters = state.hostFilters;
    const params = new URLSearchParams({
      sort: filters.sort,
      limit: String(filters.limit),
      offset: String(filters.offset)
    });
    if (filters.q) params.set("q", filters.q);

    const response = await request(`/api/hosts?${params}`);
    const rows = response.items || [];

    const hostCols = [
      { label: "IP Address", cellClass: "nowrap-cell" },
      { label: "Traffic In", cellClass: "num-cell" },
      { label: "Traffic Out", cellClass: "num-cell" },
      { label: "Total", cellClass: "num-cell" },
      { label: "Peers", cellClass: "num-cell" },
      { label: "Alerts", cellClass: "num-cell" },
    ];
    if (!detailIp) hostCols.push({ label: "First Seen", cellClass: "num-cell" });
    hostCols.push({ label: "Last Seen", cellClass: "num-cell" });

    const hostTable = table(hostCols, rows.map(h => {
      const cells = [
        link(h.ip, `#/hosts/${encodeURIComponent(h.ip)}`, "mono-link"),
        `${humanBytes(h.bytes_in)} · ${number(h.packets_in)}`,
        `${humanBytes(h.bytes_out)} · ${number(h.packets_out)}`,
        humanBytes((h.bytes_in || 0) + (h.bytes_out || 0)),
        `${number(h.peers ? h.peers.length : 0)}${h.peers_truncated ? "+" : ""}`,
        h.alert_count > 0 ? node("span", "alert-count-hot", number(h.alert_count)) : "0",
      ];
      if (!detailIp) cells.push(formatTime(h.first_seen));
      cells.push(formatTime(h.last_seen, !detailIp));
      return cells;
    }), "No host profiles found.");

    listPanel.replaceChildren();
    const lHead = node("div", "panel-header");
    lHead.append(
      node("h2", "panel-title", `Host Profiles (${number(response.total)})`),
      node("span", "panel-subtitle", "Sorted by " + filters.sort)
    );
    listPanel.append(lHead, tableWrap(hostTable));

    pageControls(listPanel, response.total, filters.limit, filters.offset, off => {
      state.hostFilters.offset = off;
      renderRoute(routeParts(), true);
    });

    if (detailIp) {
      const panel = await renderHostDetail(detailIp);
      layout.append(panel);
    }
  } catch (error) {
    showState(listPanel, `Could not load hosts: ${error.message}`, "error");
  }
}

// Deep Host Investigation Detail View
async function renderHostDetail(ip) {
  const panel = node("aside", "detail-panel");
  panel.setAttribute("aria-label", "Host Investigation Detail");
  showState(panel, "Loading host profile...");

  try {
    const host = await request(`/api/hosts/${encodeURIComponent(ip)}`);
    panel.replaceChildren();

    const header = node("div", "detail-header");
    const titleBlock = node("div", "detail-title-block");
    titleBlock.append(node("span", "eyebrow", "HOST PROFILE"));
    titleBlock.append(node("h2", "detail-title", host.ip));
    const closeBtn = link("Close", "#/hosts", "close-panel-btn");
    header.append(titleBlock, closeBtn);
    panel.append(header);

    // Directional Traffic Split
    const trafficSec = node("div", "panel");
    const tHead = node("h3", "panel-title", "Directional Traffic Split");
    tHead.style.marginBottom = "10px";
    trafficSec.append(tHead);

    const totBytes = (host.bytes_in || 0) + (host.bytes_out || 0);
    const inPct = totBytes > 0 ? ((host.bytes_in / totBytes) * 100).toFixed(1) : "50.0";
    const outPct = totBytes > 0 ? ((host.bytes_out / totBytes) * 100).toFixed(1) : "50.0";

    const gaugeWrap = node("div", "evidence-gauge");
    const gaugeLabels = node("div", "gauge-labels");
    gaugeLabels.append(
      node("span", "", `In: ${humanBytes(host.bytes_in)} (${inPct}%) · ${number(host.packets_in)} pkts`),
      node("span", "", `Out: ${humanBytes(host.bytes_out)} (${outPct}%) · ${number(host.packets_out)} pkts`)
    );
    gaugeWrap.append(gaugeLabels);

    const track = node("div", "gauge-track");
    const inFill = node("div", "gauge-observed-bar");
    inFill.style.width = `${inPct}%`;
    track.append(inFill);
    gaugeWrap.append(track);

    trafficSec.append(gaugeWrap);
    panel.append(trafficSec);

    // Host Protocol Breakdown
    const protoSec = node("div", "panel");
    protoSec.append(node("h3", "panel-title", "Protocol Mix"));
    renderProtocolDonut(protoSec, host.protocols);
    panel.append(protoSec);

    // Top Destination Ports
    const ports = host.top_ports || [];
    const portsSec = node("div", "panel");
    const pHead = node("h3", "panel-title", "Top Destination Ports");
    pHead.style.marginBottom = "10px";
    portsSec.append(pHead);

    if (ports.length === 0) {
      portsSec.append(node("p", "state-message", "No outbound TCP/UDP destination ports recorded."));
    } else {
      const portNames = { 80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 25: "SMTP", 123: "NTP", 445: "SMB", 3389: "RDP" };
      const maxP = Math.max(1, ...ports.map(p => Number(p[1])));
      const portList = node("div", "hbar-list");

      for (const [pNum, count] of ports) {
        const row = node("div", "hbar-row");
        const meta = node("div", "hbar-meta");
        const pLabel = `${pNum}${portNames[pNum] ? ` (${portNames[pNum]})` : ""}`;
        meta.append(node("span", "hbar-label", pLabel), node("span", "hbar-val", `${number(count)} pkts`));

        const pTrack = node("div", "hbar-track");
        const pFill = node("div", "hbar-fill");
        pFill.style.width = `${(count / maxP) * 100}%`;
        pTrack.append(pFill);
        row.append(meta, pTrack);
        portList.append(row);
      }
      portsSec.append(portList);
    }
    panel.append(portsSec);

    // Observed Peers
    const peers = host.peers || [];
    const peersSec = node("div", "panel");
    const peersHead = node("div", "panel-header");
    peersHead.append(node("h3", "panel-title", `Observed Peers (${number(peers.length)})`));
    peersSec.append(peersHead);

    if (host.peers_truncated) {
      const warn = node("div", "caveat-banner");
      warn.append(node("span", "caveat-badge", "Truncated"));
      warn.append(node("span", "caveat-text", "Peer tracking reached the 2,000-peer limit."));
      peersSec.append(warn);
    }

    if (peers.length === 0) {
      peersSec.append(node("p", "state-message", "No peer relationships recorded."));
    } else {
      const peerWrap = node("div", "pill-list");
      for (const pIp of peers.slice(0, 30)) {
        peerWrap.append(link(pIp, `#/hosts/${encodeURIComponent(pIp)}`, "inline-link-btn"));
      }
      if (peers.length > 30) {
        peerWrap.append(node("span", "kpi-unit", `+${number(peers.length - 30)} more`));
      }
      peersSec.append(peerWrap);
    }
    panel.append(peersSec);

    // Related Incidents
    const relIds = host.related_incident_ids || [];
    const relSec = node("div", "panel");
    const relTitle = node("h3", "panel-title", `Related Incidents (${number(relIds.length)})`);
    relTitle.style.marginBottom = "8px";
    relSec.append(relTitle);

    if (relIds.length === 0) {
      relSec.append(node("p", "state-message", "No correlated security incidents."));
    } else {
      const relList = node("div", "pill-list");
      for (const rId of relIds) {
        relList.append(link(String(rId).slice(0, 8), `#/incidents/${encodeURIComponent(rId)}`, "inline-link-btn", null, String(rId)));
      }
      relSec.append(relList);
    }
    panel.append(relSec);

    // First & Last Seen
    const factsSec = node("div", "panel");
    const fGrid = node("div", "detail-facts-grid");
    const addF = (lbl, val) => {
      const it = node("div", "fact-item");
      it.append(node("span", "fact-label", lbl), node("strong", "fact-val", val));
      fGrid.append(it);
    };
    addF("First Seen", formatTime(host.first_seen));
    addF("Last Seen", formatTime(host.last_seen));
    factsSec.append(fGrid);
    panel.append(factsSec);
  } catch (error) {
    showState(panel, `Could not load host detail: ${error.message}`, "error");
  }

  return panel;
}

// Detection Quality & Statistical Evaluation Workspace
async function renderQuality() {
  state.overviewMounted = false;
  frame("Detection Quality", "Synthetic regression, CIC-IDS2017 flow benchmarks, and replay validation.");

  let qualityItems = [];
  try {
    const listResp = await request("/api/quality");
    qualityItems = listResp.items || [];
    state.qualityFiles = qualityItems.map(i => i.name);
  } catch (e) {
    qualityItems = [];
  }

  if (qualityItems.length === 0) {
    const emptySec = node("div", "panel");
    emptySec.append(node("p", "state-message", "No evaluation or benchmark artifacts found in results/."));
    emptySec.append(node("p", "panel-subtitle", "Run 'python -m packetlens reproduce --write' to generate artifacts."));
    view.append(emptySec);
    return;
  }

  if (!state.qualityFile || !state.qualityFiles.includes(state.qualityFile)) {
    state.qualityFile = state.qualityFiles[0];
    state.selectedCmModel = null;
  }

  const tabsBar = node("div", "filter-bar");
  const friendlyNames = {
    "evaluation.json": "Synthetic Rule Evaluation",
    "flows_real.json": "Real Flow Volume (CIC-IDS2017)",
    "flowmodel_real.json": "Bot Classifier & Leakage",
    "flowmodel_audit.json": "Duplicate Leakage Audit",
    "flowmodel_ddos.json": "DDoS Flow Classifier",
    "flowmodel_portscan.json": "PortScan Flow Classifier",
    "benchmark.json": "Throughput Benchmark",
    "hf_pcap_validation.json": "Curated PCAPs (HF)"
  };

  for (const item of qualityItems) {
    const fName = item.name;
    const label = friendlyNames[fName] || fName;
    const btn = node("button", `metric-pill-btn${state.qualityFile === fName ? " is-active" : ""}`, label);
    btn.type = "button";
    btn.title = `Last modified: ${formatDate(item.modified)}`;
    btn.addEventListener("click", () => {
      state.qualityFile = fName;
      state.selectedCmModel = null;
      renderRoute(routeParts(), true);
    });
    tabsBar.append(btn);
  }
  view.append(tabsBar);

  const contentArea = node("div", "quality-content");
  view.append(contentArea);

  try {
    const data = await request(`/api/quality/${encodeURIComponent(state.qualityFile)}`);

    if (state.qualityFile === "evaluation.json") {
      renderSyntheticQuality(contentArea, data);
    } else if (state.qualityFile === "flows_real.json") {
      renderFlowsRealQuality(contentArea, data);
    } else if (state.qualityFile.startsWith("flowmodel_")) {
      renderFlowModelQuality(contentArea, data);
    } else if (state.qualityFile === "benchmark.json") {
      renderBenchmarkQuality(contentArea, data);
    } else if (state.qualityFile === "hf_pcap_validation.json") {
      renderHfPcapQuality(contentArea, data);
    } else {
      contentArea.append(node("pre", "alert-data-pre", JSON.stringify(data, null, 2)));
    }
  } catch (error) {
    showState(contentArea, `Could not load evaluation result (${state.qualityFile}): ${error.message}`, "error");
  }
}

function renderSyntheticQuality(container, data) {
  const caveat = node("div", "caveat-banner");
  caveat.append(node("span", "caveat-badge", "Methodological Boundary"));
  caveat.append(node("span", "caveat-text",
    "Synthetic traffic and attack labels are generated together; these results verify deterministic detector behavior and do NOT estimate field performance."));
  container.append(caveat);

  const grid = node("div", "kpi-grid");
  grid.append(createKpi("Benign Packets", number(data.packets_benign), "", `Duration: ${data.duration_s}s`));
  grid.append(createKpi("Attack Packets", number(data.packets_attack), "", "Synthetic injects"));
  grid.append(createKpi("Alert Precision", `${((data.alert_precision || 0) * 100).toFixed(1)}%`, "", `${number(data.alerts_in_attack_windows)} / ${number(data.alerts_total)} in attack windows`));
  grid.append(createKpi("False Alarms / Hr", String(data.false_positives_per_hour || 0), "", "Clean traffic baseline"));
  container.append(grid);

  const events = data.events || [];
  const evSec = section("Scripted Attack Detection Matrix", node("div"), "", "Detector delay from first attack packet");
  const evTable = table([
    { label: "Attack Event" },
    { label: "Detector" },
    { label: "Detected", cellClass: "nowrap-cell" },
    { label: "Detection Delay", cellClass: "num-cell" }
  ], events.map(e => [
    e.event,
    e.detector,
    e.detected ? node("span", "badge badge-status-closed", "YES") : node("span", "badge badge-critical", "MISSED"),
    e.delay_s !== null && e.delay_s !== undefined ? `${e.delay_s}s` : "—"
  ]), "No events recorded.");
  evSec.replaceChildren(evSec.firstChild, tableWrap(evTable));
  container.append(evSec);

  if (data.bin_level_volume_detectors) {
    const vd = data.bin_level_volume_detectors;
    const volSec = section("Bin-Level Volume Detectors", node("div"), "", "1-second EWMA Z-score vs Isolation Forest");
    const volRows = [];
    for (const [name, stats] of Object.entries(vd)) {
      if (!stats) {
        volRows.push([
          name,
          node("span", "panel-subtitle", "Unavailable (install scikit-learn)"),
          "—",
          "—",
          "—",
          "—",
          "—"
        ]);
        continue;
      }
      volRows.push([
        name,
        `${((stats.precision || 0) * 100).toFixed(1)}%`,
        `${((stats.recall || 0) * 100).toFixed(1)}%`,
        `${((stats.f1 || 0) * 100).toFixed(1)}%`,
        number(stats.tp),
        number(stats.fp),
        number(stats.fn)
      ]);
    }
    const volTable = table([
      { label: "Algorithm" },
      { label: "Precision", cellClass: "num-cell" },
      { label: "Recall", cellClass: "num-cell" },
      { label: "F1", cellClass: "num-cell" },
      { label: "TP", cellClass: "num-cell" },
      { label: "FP", cellClass: "num-cell" },
      { label: "FN", cellClass: "num-cell" }
    ], volRows);
    volSec.replaceChildren(volSec.firstChild, tableWrap(volTable));
    container.append(volSec);
  }

  if (data.false_positive_details && data.false_positive_details.length > 0) {
    const fpSec = section("Clean Baseline False Positives", node("div"), "", "Spurious detections on benign synthetic traffic");
    const fpWrap = fpSec.lastChild;
    for (const det of data.false_positive_details) {
      fpWrap.append(node("p", "kpi-subtext", det));
    }
    container.append(fpSec);
  }
}

function renderFlowsRealQuality(container, data) {
  const caveat = node("div", "caveat-banner");
  caveat.append(node("span", "caveat-badge", "Real Flow Dataset"));
  caveat.append(node("span", "caveat-text",
    "Evaluated on CIC-IDS2017 Friday flow tables. Volume aggregation discards per-flow TCP header state. Samples under 30 bins are excluded from bootstrap intervals."));
  container.append(caveat);

  if (data.bins) {
    const bGrid = node("div", "kpi-grid kpi-grid-3");
    bGrid.append(createKpi("Train Bins", number(data.bins.train), "", "Baseline training window"));
    bGrid.append(createKpi("Clean Holdout Bins", number(data.bins.clean_holdout), "", "Benign traffic evaluation"));
    bGrid.append(createKpi("Attack Set Bins", number(data.bins.attack_set), "", `${number(data.bins.attack_bins || 0)} attack bins`));
    container.append(bGrid);
  }

  const methods = data.methods || {};
  const mSec = section("Volume Anomaly Algorithms (CIC-IDS2017)", node("div"), "", "Point estimates and 95% bootstrap confidence intervals");
  const rows = [];
  for (const [name, stats] of Object.entries(methods)) {
    if (!stats) {
      rows.push([name, "Unavailable", "—", "—", "—", "—"]);
      continue;
    }
    const boot = stats.bootstrap || {};
    const precCi = boot.precision && boot.precision.ci95 ? ` [${boot.precision.ci95.join(" – ")}]` : "";
    const recCi = boot.recall && boot.recall.ci95 ? ` [${boot.recall.ci95.join(" – ")}]` : "";
    const f1Ci = boot.f1 && boot.f1.ci95 ? ` [${boot.f1.ci95.join(" – ")}]` : "";

    rows.push([
      name,
      `${((stats.precision || 0) * 100).toFixed(1)}%${precCi}`,
      `${((stats.recall || 0) * 100).toFixed(1)}%${recCi}`,
      `${((stats.f1 || 0) * 100).toFixed(1)}%${f1Ci}`,
      `${stats.false_alarms_per_hour_on_clean || 0} / hr`,
      stats.recall_by_attack ? Object.entries(stats.recall_by_attack).map(([k, v]) => `${k}: ${(v * 100).toFixed(0)}%`).join(", ") : "—"
    ]);
  }

  const mTable = table([
    { label: "Method" },
    { label: "Precision (95% CI)", cellClass: "num-cell" },
    { label: "Recall (95% CI)", cellClass: "num-cell" },
    { label: "F1 (95% CI)", cellClass: "num-cell" },
    { label: "False Alarms / Hr", cellClass: "num-cell" },
    { label: "Recall by Attack" }
  ], rows);
  mSec.replaceChildren(mSec.firstChild, tableWrap(mTable));
  container.append(mSec);
}

function renderFlowModelQuality(container, data) {
  const caveat = node("div", "caveat-banner");
  caveat.append(node("span", "caveat-badge", "Offline Research Audit"));
  caveat.append(node("span", "caveat-text",
    "Flow-level ML classifiers run offline in research/ and do not participate in the live packet pipeline. Exact feature duplicates between train and test splits inflate raw scores; inspect duplicate-free metrics."));
  container.append(caveat);

  if (data.counts) {
    const cGrid = node("div", "kpi-grid kpi-grid-2");
    if (data.counts.train) {
      const trainDesc = Object.entries(data.counts.train).map(([k, v]) => `${k}: ${number(v)}`).join(" · ");
      cGrid.append(createKpi("Training Split", number(Object.values(data.counts.train).reduce((a, b) => a + b, 0)), "", trainDesc));
    }
    if (data.counts.test) {
      const testDesc = Object.entries(data.counts.test).map(([k, v]) => `${k}: ${number(v)}`).join(" · ");
      cGrid.append(createKpi("Test Split", number(Object.values(data.counts.test).reduce((a, b) => a + b, 0)), "", testDesc));
    }
    container.append(cGrid);
  }

  if (data.duplicate_check && data.duplicate_check.per_class) {
    const dupSec = section("Exact Duplicate Feature Leakage Audit", node("div"), "", "Training feature vectors repeated verbatim in test set");
    const dupRows = [];
    for (const [cls, stats] of Object.entries(data.duplicate_check.per_class)) {
      dupRows.push([
        cls,
        number(stats.test_rows),
        number(stats.exact_duplicates),
        `${((stats.exact_duplicate_rate || 0) * 100).toFixed(2)}%`,
        number(stats.duplicate_free_rows)
      ]);
    }
    const dupTable = table([
      { label: "Class" },
      { label: "Test Rows", cellClass: "num-cell" },
      { label: "Exact Duplicates", cellClass: "num-cell" },
      { label: "Duplicate Rate", cellClass: "num-cell" },
      { label: "Duplicate-Free Rows", cellClass: "num-cell" }
    ], dupRows);
    const dupWrap = dupSec.lastChild;
    dupWrap.append(tableWrap(dupTable));

    if (data.duplicate_check.duplicate_free_test && data.duplicate_check.duplicate_free_test.metrics) {
      const dfm = data.duplicate_check.duplicate_free_test.metrics;
      const dfCard = node("div", "caveat-banner");
      dfCard.style.marginTop = "10px";
      dfCard.style.marginBottom = "0";
      dfCard.append(node("span", "caveat-badge", "Duplicate-Free Test"));
      dfCard.append(node("span", "caveat-text",
        `Precision: ${((dfm.precision || 0) * 100).toFixed(1)}%, Recall: ${((dfm.recall || 0) * 100).toFixed(1)}%, F1: ${((dfm.f1 || 0) * 100).toFixed(1)}% (TP: ${number(dfm.tp)}, FP: ${number(dfm.fp)}, FN: ${number(dfm.fn)}, TN: ${number(dfm.tn)}).`));
      dupWrap.append(dfCard);
    }
    container.append(dupSec);
  }

  if (data.results && data.results.length > 0) {
    const resSec = section("Offline Model Comparison", node("div"), "", "Test split evaluation");
    const resRows = data.results.map(r => {
      const m = r.metrics || {};
      return [
        r.model,
        `${((m.precision || 0) * 100).toFixed(2)}%`,
        `${((m.recall || 0) * 100).toFixed(2)}%`,
        `${((m.f1 || 0) * 100).toFixed(2)}%`,
        `${m.fp_per_1000_benign !== undefined ? m.fp_per_1000_benign : "—"} / 1k`,
        number(m.tp),
        number(m.fp),
        number(m.fn),
        number(m.tn)
      ];
    });
    const resTable = table([
      { label: "Classifier" },
      { label: "Precision", cellClass: "num-cell" },
      { label: "Recall", cellClass: "num-cell" },
      { label: "F1", cellClass: "num-cell" },
      { label: "FP / 1k Benign", cellClass: "num-cell" },
      { label: "TP", cellClass: "num-cell" },
      { label: "FP", cellClass: "num-cell" },
      { label: "FN", cellClass: "num-cell" },
      { label: "TN", cellClass: "num-cell" }
    ], resRows);
    const resWrap = resSec.lastChild;
    resWrap.append(tableWrap(resTable));

    // Select best model by highest F1 score by default
    const candidates = data.results.filter(r => r && r.metrics && r.metrics.tp !== undefined);
    if (candidates.length > 0) {
      let bestModel = candidates[0];
      for (const cand of candidates) {
        if (Number(cand.metrics.f1 || 0) > Number(bestModel.metrics.f1 || 0)) {
          bestModel = cand;
        }
      }
      const activeModel = candidates.find(c => c.model === state.selectedCmModel) || bestModel;

      const cmSec = node("div", "cm-container");
      const cmHead = node("div", "cm-header");
      cmHead.append(node("h3", "panel-title", `Confusion Matrix: ${activeModel.model} (F1 ${((activeModel.metrics.f1 || 0) * 100).toFixed(2)}%)`));

      if (candidates.length > 1) {
        const modelSel = node("div", "segmented-control");
        for (const cand of candidates) {
          const btn = node("button", `metric-pill-btn${cand.model === activeModel.model ? " is-active" : ""}`, cand.model);
          btn.type = "button";
          btn.addEventListener("click", () => {
            state.selectedCmModel = cand.model;
            renderRoute(routeParts(), false);
          });
          modelSel.append(btn);
        }
        cmHead.append(modelSel);
      }

      cmSec.append(cmHead);
      const cmGrid = node("div", "cm-grid");
      const makeCell = (title, val, cls) => {
        const c = node("div", `cm-cell ${cls}`);
        c.append(node("div", "cm-cell-title", title), node("div", "cm-cell-val", number(val)));
        return c;
      };
      cmGrid.append(
        makeCell("True Positive (TP)", activeModel.metrics.tp, "cm-cell-tp"),
        makeCell("False Positive (FP)", activeModel.metrics.fp, "cm-cell-fp"),
        makeCell("False Negative (FN)", activeModel.metrics.fn, "cm-cell-fn"),
        makeCell("True Negative (TN)", activeModel.metrics.tn, "cm-cell-tn")
      );
      cmSec.append(cmGrid);
      resWrap.append(cmSec);
    }

    container.append(resSec);
  }
}

function renderBenchmarkQuality(container, data) {
  const grid = node("div", "kpi-grid kpi-grid-3");
  grid.append(createKpi("Packets Processed", number(data.packets), "", "Benchmark sample"));
  grid.append(createKpi("Parse-Only Throughput", humanRate(data.parse_only_pps, "pps"), "", "Packet decoder speed"));
  grid.append(createKpi("Full Pipeline Throughput", humanRate(data.full_pipeline_pps, "pps"), "", "Decode + engine + detectors"));
  container.append(grid);

  if (data.meta) {
    const metaSec = section("Benchmark Provenance", node("div"), "", "Run environment metadata");
    const facts = node("div", "detail-facts-grid");
    const addFact = (k, v) => {
      const it = node("div", "fact-item");
      it.append(node("span", "fact-label", k), node("strong", "fact-val", v));
      facts.append(it);
    };
    addFact("Command", data.meta.command_line || "—");
    addFact("Timestamp", data.meta.utc_time || "—");
    if (data.meta.versions) {
      for (const [vk, vv] of Object.entries(data.meta.versions)) {
        addFact(`Version: ${vk}`, vv);
      }
    }
    metaSec.replaceChildren(metaSec.firstChild, facts);
    container.append(metaSec);
  }
}

function renderHfPcapQuality(container, data) {
  const caps = data.captures || [];
  const datasetSet = new Set(caps.map(c => c.dataset).filter(Boolean));
  datasetSet.add("maureille/agentic-pcap");
  datasetSet.add("mtasfi/ton-iot-with-pcap-payload");
  const cited = Array.from(datasetSet).join(" and ");

  const caveat = node("div", "caveat-banner");
  caveat.append(node("span", "caveat-badge", "Curated PCAPs"));
  caveat.append(node("span", "caveat-text",
    `Validation results replayed across curated captures from HuggingFace datasets ${cited}.`));
  container.append(caveat);

  const cSec = section("Capture Replay Results", node("div"), "", `${number(caps.length)} validated captures`);
  const rows = caps.map(c => [
    c.label,
    c.dataset || "—",
    c.kind,
    number(c.packets),
    humanBytes(c.bytes),
    humanRate(c.pps, "pps"),
    `${c.avg_processing_us} µs`,
    number(c.alerts_total)
  ]);
  const cTable = table([
    { label: "Scenario" },
    { label: "Dataset" },
    { label: "Kind" },
    { label: "Packets", cellClass: "num-cell" },
    { label: "Bytes", cellClass: "num-cell" },
    { label: "Throughput", cellClass: "num-cell" },
    { label: "Avg Latency", cellClass: "num-cell" },
    { label: "Alerts", cellClass: "num-cell" }
  ], rows);
  cSec.replaceChildren(cSec.firstChild, tableWrap(cTable));
  container.append(cSec);
}

// Policies View
async function renderPolicies() {
  state.overviewMounted = false;
  frame("Policies", "Active rule definitions, inspection thresholds, and address allowlists.");

  const container = node("div", "quality-content");
  view.append(container);

  try {
    const policy = await request("/api/policies");
    const rules = policy.policies || [];

    const metaSec = node("div", "panel");
    const mHead = node("div", "panel-header");
    mHead.style.marginBottom = "0";
    mHead.append(
      node("h2", "panel-title", `Active Policy: ${policy.name || "Default"}`),
      node("span", "panel-subtitle", `Incident grouping gap: ${policy.incident_gap_s || 300}s · ${rules.length} rules`)
    );
    metaSec.append(mHead);
    container.append(metaSec);

    const cardsGrid = node("div", "analytics-grid");
    for (const r of rules) {
      const card = node("article", "panel");
      const cHead = node("div", "panel-header");
      const titleWrap = node("div", "capture-title-wrap");
      titleWrap.append(node("h3", "panel-title", r.id || r.detector));
      titleWrap.append(node("span", `badge ${r.enabled !== false ? "badge-status-closed" : "badge-low"}`, r.enabled !== false ? "ENABLED" : "DISABLED"));
      if (r.severity) {
        titleWrap.append(severityBadge(r.severity));
      }
      if (r.experimental) {
        titleWrap.append(node("span", "badge badge-experimental", "EXPERIMENTAL"));
      }
      cHead.append(titleWrap, node("span", "stat-text", r.action ? r.action.toUpperCase() : "ALERT"));
      card.append(cHead);

      if (r.description) {
        const desc = node("p", "panel-subtitle", r.description);
        desc.style.marginBottom = "10px";
        card.append(desc);
      }

      const params = r.params || {};
      const facts = node("div", "detail-facts-grid");
      const addFact = (k, v) => {
        const it = node("div", "fact-item");
        it.append(node("span", "fact-label", k), node("span", "fact-val", v));
        facts.append(it);
      };

      addFact("Detector", r.detector);
      if (params.windows) addFact("Threshold Windows", params.windows.map(w => `${w[0]}s: ${w[1]} pkts`).join(" | "));
      if (params.threshold !== undefined) addFact("Threshold", `${params.threshold} pkts`);
      if (params.cooldown !== undefined) addFact("Cooldown", `${params.cooldown}s`);
      if (params.span !== undefined) addFact("Inspection Span", `${params.span}s`);
      if (params.min_unique !== undefined) addFact("Min Unique Queries", String(params.min_unique));
      if (params.min_avg_len !== undefined) addFact("Min Avg Length", `${params.min_avg_len} chars`);
      if (params.min_avg_entropy !== undefined) addFact("Min Avg Entropy", String(params.min_avg_entropy));
      if (params.window_s !== undefined) addFact("Scan Window", `${params.window_s}s`);
      if (params.min_hosts !== undefined) addFact("Min Target Hosts", String(params.min_hosts));
      if (params.ignore_ports && params.ignore_ports.length > 0) addFact("Ignored Ports", params.ignore_ports.join(", "));
      if (params.metrics && params.metrics.length > 0) addFact("Volumetric Metrics", params.metrics.join(", "));
      if (params.alpha !== undefined) addFact("EWMA Alpha", String(params.alpha));
      if (params.z !== undefined) addFact("Z-Score Threshold", `z >= ${params.z}`);
      if (params.warmup !== undefined) addFact("Warmup Bins", `${params.warmup}s`);
      if (params.rearm !== undefined) addFact("Rearm Bins", `${params.rearm}s`);

      card.append(facts);

      const allow = r.allowlist || {};
      const hasSrc = allow.src && allow.src.length > 0;
      const hasDst = allow.dst && allow.dst.length > 0;

      if (hasSrc || hasDst) {
        const alSec = node("div", "");
        alSec.style.marginTop = "10px";
        alSec.append(node("span", "eyebrow", "Allowlists"));
        const alList = node("div", "pill-list");
        alList.style.marginTop = "4px";
        if (hasSrc) {
          for (const s of allow.src) alList.append(node("span", "identifier", `Src: ${s}`));
        }
        if (hasDst) {
          for (const d of allow.dst) alList.append(node("span", "identifier", `Dst: ${d}`));
        }
        alSec.append(alList);
        card.append(alSec);
      }

      cardsGrid.append(card);
    }
    container.append(cardsGrid);
  } catch (error) {
    showState(container, `Could not load policies: ${error.message}`, "error");
  }
}

// Router & Initialization
function routeParts() {
  const hash = window.location.hash.replace(/^#\/?/, "");
  return hash ? hash.split("/") : ["overview"];
}

async function renderRoute(parts, focusMain = true) {
  if (state.popoverCleanup) {
    state.popoverCleanup();
    state.popoverCleanup = null;
  }
  if (state.chartState && state.chartState.destroy) {
    state.chartState.destroy();
    state.chartState = null;
  }

  const primary = parts[0] || "overview";
  for (const a of document.querySelectorAll(".nav a")) {
    const isAct = a.dataset.route === `/${primary}`;
    a.classList.toggle("is-active", isAct);
    if (isAct) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }

  if (primary === "overview") await renderOverview();
  else if (primary === "incidents") await renderIncidents(parts);
  else if (primary === "hosts") await renderHosts(parts);
  else if (primary === "quality") await renderQuality();
  else if (primary === "policies") await renderPolicies();
  else await renderOverview();

  if (focusMain && view) {
    window.scrollTo(0, 0);
    view.focus({ preventScroll: true });
  }
}

function initTheme() {
  const urlParams = new URLSearchParams(window.location.search);
  const qTheme = urlParams.get("theme");
  const saved = localStorage.getItem("packetlens-theme");
  const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  const initial = qTheme === "light" || qTheme === "dark" ? qTheme : (saved || (prefersDark ? "dark" : "light"));
  setTheme(initial);

  const toggle = byId("theme-toggle");
  if (toggle) {
    toggle.addEventListener("click", () => {
      setTheme(state.theme === "dark" ? "light" : "dark");
    });
  }
}

function setTheme(theme) {
  state.theme = theme;
  document.body.setAttribute("data-theme", theme);
  localStorage.setItem("packetlens-theme", theme);
  const btn = byId("theme-toggle");
  if (btn) {
    btn.textContent = theme === "dark" ? "Dark" : "Light";
    btn.setAttribute("aria-pressed", theme === "dark" ? "true" : "false");
  }
  if (state.overviewMounted) {
    redrawChartInPlace();
  }
}

function initTimeToggle() {
  const btn = byId("time-toggle");
  if (btn) {
    btn.addEventListener("click", () => {
      state.utc = !state.utc;
      btn.textContent = state.utc ? "UTC" : "Local";
      btn.setAttribute("aria-pressed", state.utc ? "true" : "false");
      renderRoute(routeParts(), false);
    });
  }
}

function initMobileMenu() {
  const btn = byId("mobile-menu-btn");
  const closeBtn = byId("rail-close-btn");
  const rail = byId("app-rail");
  const backdrop = byId("rail-backdrop");

  const setOpen = open => {
    if (rail) rail.classList.toggle("is-open", open);
    if (backdrop) backdrop.hidden = !open;
  };

  if (btn) btn.addEventListener("click", () => setOpen(true));
  if (closeBtn) closeBtn.addEventListener("click", () => setOpen(false));
  if (backdrop) backdrop.addEventListener("click", () => setOpen(false));
  for (const a of document.querySelectorAll(".nav a")) {
    a.addEventListener("click", () => setOpen(false));
  }
}

window.addEventListener("hashchange", () => {
  renderRoute(routeParts(), true);
});

window.addEventListener("DOMContentLoaded", async () => {
  initTheme();
  initTimeToggle();
  initMobileMenu();
  await Promise.allSettled([pollHealth(), pollAnnouncements()]);
  await renderRoute(routeParts(), false);
  tick();
});
