"use strict";

const byId = id => document.getElementById(id);
const view = byId("view");
const state = {
  route: "",
  window: 300,
  incidentFilters: {q: "", status: "", severity: "", kind: "", limit: 50, offset: 0},
  incidentSort: {key: "last_ts", direction: "desc"},
  hostFilters: {q: "", sort: "bytes", limit: 50, offset: 0},
  hostSort: {key: "bytes", direction: "desc"},
  utc: true,
  theme: "",
  lastHealth: null,
  lastHealthAt: 0,
  lastBytesPerSecond: 0,
  seenIncidents: new Set(),
  failures: 0,
  detail: null
};

function node(tag, className, value) {
  const item = document.createElement(tag);
  if (className) item.className = className;
  if (value !== undefined && value !== null) item.textContent = String(value);
  return item;
}

function setText(id, value) {
  byId(id).textContent = value === undefined || value === null ? "" : String(value);
}

function number(value) {
  return Number(value || 0).toLocaleString();
}

function humanBytes(value) {
  const amount = Number(value || 0);
  if (amount >= 1e9) return `${(amount / 1e9).toFixed(1)} GB`;
  if (amount >= 1e6) return `${(amount / 1e6).toFixed(1)} MB`;
  if (amount >= 1e3) return `${(amount / 1e3).toFixed(1)} KB`;
  return `${number(amount)} B`;
}

function formatTime(seconds) {
  if (seconds === null || seconds === undefined || !Number.isFinite(Number(seconds))) return "—";
  const date = new Date(Number(seconds) * 1000);
  return state.utc ? `${date.toISOString().replace("T", " ").slice(0, 19)} UTC` :
    date.toLocaleString();
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) :
    (state.utc ? `${date.toISOString().replace("T", " ").slice(0, 19)} UTC` : date.toLocaleString());
}

async function request(path, options) {
  const response = await fetch(path, options || {cache: "no-store"});
  let payload;
  try {
    payload = await response.json();
  } catch (error) {
    throw new Error(`Server returned invalid JSON (${response.status})`);
  }
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
  return payload;
}

function showState(parent, message, kind) {
  const status = node("p", kind === "error" ? "state-message error-message" : "state-message", message);
  status.setAttribute("role", kind === "error" ? "alert" : "status");
  parent.replaceChildren(status);
}

function frame(title, description) {
  const heading = node("div", "page-heading");
  const text = node("div");
  text.append(node("h1", "", title));
  if (description) text.append(node("p", "muted", description));
  heading.append(text);
  view.replaceChildren(heading);
  return heading;
}

function section(title, content, className) {
  const part = node("section", `panel${className ? ` ${className}` : ""}`);
  part.append(node("h2", "panel-title", title), content);
  return part;
}

function tableWrap(table) {
  const wrap = node("div", "table-wrap");
  wrap.append(table);
  return wrap;
}

function table(headers, rows, emptyMessage, className) {
  const result = node("table", `data-table${className ? ` ${className}` : ""}`);
  const thead = node("thead");
  const headerRow = node("tr");
  for (const header of headers) {
    const th = node("th");
    th.scope = "col";
    if (header.cellClass) th.classList.add(header.cellClass);
    th.textContent = header.label;
    if (header.key) {
      th.setAttribute("aria-sort", header.sort || "none");
      const button = node("button", "sort-button", header.label);
      button.type = "button";
      button.dataset.sort = header.key;
      th.replaceChildren(button);
    }
    headerRow.append(th);
  }
  thead.append(headerRow);
  result.append(thead);
  const body = node("tbody");
  if (!rows.length) {
    const row = node("tr");
    const cell = node("td", "empty-cell", emptyMessage);
    cell.colSpan = headers.length;
    row.append(cell);
    body.append(row);
  } else {
    for (const rowData of rows) {
      const row = node("tr");
      for (const [index, cellData] of rowData.entries()) {
        const cell = node("td");
        if (headers[index] && headers[index].cellClass) {
          cell.classList.add(headers[index].cellClass);
        }
        if (cellData instanceof Node) cell.append(cellData);
        else cell.textContent = cellData === undefined || cellData === null ? "—" : String(cellData);
        row.append(cell);
      }
      body.append(row);
    }
  }
  result.append(body);
  return result;
}

function link(text, href, className) {
  const item = node("a", className || "", text);
  item.href = href;
  return item;
}

function routeParts() {
  const raw = location.hash.startsWith("#") ? location.hash.slice(1) : "/overview";
  try {
    return raw.split("/").filter(Boolean).map(part => decodeURIComponent(part));
  } catch (error) {
    return ["invalid-route"];
  }
}

function routePath(parts) {
  return `/${parts.join("/")}`;
}

function updateNavigation(parts) {
  const selected = parts[0] || "overview";
  for (const anchor of document.querySelectorAll(".nav a")) {
    const active = anchor.dataset.route.slice(1) === selected;
    if (active) anchor.setAttribute("aria-current", "page");
    else anchor.removeAttribute("aria-current");
  }
}

function updateHealth(health) {
  setText("source-name", health.source || "Unknown source");
  setText("version", health.version || "");
  setText("packet-clock", formatTime(health.now));
  const label = byId("health-label");
  const indicator = byId("health-indicator");
  const banner = byId("stale-banner");
  const reasons = Array.isArray(health.degraded_reasons) ? health.degraded_reasons : [];
  const serviceStatus = health.service_status || (health.source_stale ? "degraded" : "healthy");
  const isUnhealthy = serviceStatus === "unhealthy";
  const isDegraded = serviceStatus === "degraded" || Boolean(health.source_stale);
  if (isUnhealthy || isDegraded) {
    const reasonText = reasons.length ? ` (${reasons.join(", ")})` : "";
    banner.textContent = isUnhealthy ?
      `Storage or capture error detected${reasonText}. Check logs and /api/health.` :
      `Monitoring degraded${reasonText}. Displayed values may be stale or incomplete.`;
    banner.hidden = false;
    indicator.classList.add("is-stale");
    label.textContent = isUnhealthy ? "Unhealthy" : "Degraded";
  } else {
    banner.hidden = true;
    banner.textContent = "Server unavailable. Displayed values may be stale.";
    indicator.classList.remove("is-stale");
    label.textContent = "Connected";
  }

  const currentTime = Date.now();
  if (state.lastHealth) {
    const elapsed = Math.max(0.001, (currentTime - state.lastHealthAt) / 1000);
    state.lastBytesPerSecond = Math.max(0, (health.bytes_total - state.lastHealth.bytes_total) / elapsed);
  }
  state.lastHealth = health;
  state.lastHealthAt = currentTime;
}

async function pollHealth() {
  const health = await request("/api/health");
  updateHealth(health);
  return health;
}

async function pollAnnouncements() {
  const result = await request("/api/incidents?limit=10&offset=0");
  const current = new Set(result.items.map(item => String(item.id)));
  if (state.seenIncidents.size) {
    const fresh = result.items.filter(item => !state.seenIncidents.has(String(item.id)));
    if (fresh.length) {
      const first = fresh[0];
      setText("incident-announcer", `New ${first.severity} incident: ${first.kind} from ${first.src}`);
    }
  }
  state.seenIncidents = current;
}

function toggleErrorBanner(error) {
  byId("stale-banner").hidden = false;
  byId("health-indicator").classList.add("is-stale");
  setText("health-label", "Unavailable");
  if (error) console.warn("PacketLens refresh failed:", error.message);
}

async function tick() {
  try {
    await pollHealth();
    await pollAnnouncements();
    state.failures = 0;
    const parts = routeParts();
    if (parts[0] === "overview" && !view.contains(document.activeElement)) {
      await renderRoute(parts, false);
    }
  } catch (error) {
    state.failures += 1;
    toggleErrorBanner(error);
    if (view.childElementCount === 0) showState(view, "Unable to load data. Retrying automatically.", "error");
  } finally {
    const delay = state.failures ? Math.min(30000, 1000 * (2 ** Math.min(state.failures, 5))) : 3000;
    window.setTimeout(tick, delay);
  }
}

function createKpi(label, value, note) {
  const card = node("article", "kpi-card");
  card.append(node("span", "kpi-label", label), node("strong", "kpi-value", value));
  if (note) card.append(node("span", "kpi-note", note));
  return card;
}

function drawChart(canvas, bins, incidents, key, unit) {
  const context = canvas.getContext("2d");
  const ratio = window.devicePixelRatio || 1;
  const width = Math.max(320, canvas.clientWidth);
  const height = Math.max(210, canvas.clientHeight);
  canvas.width = width * ratio;
  canvas.height = height * ratio;
  context.setTransform(ratio, 0, 0, ratio, 0, 0);
  context.clearRect(0, 0, width, height);
  const styles = getComputedStyle(document.documentElement);
  const ink = styles.getPropertyValue("--muted").trim();
  const grid = styles.getPropertyValue("--border").trim();
  const line = styles.getPropertyValue("--accent").trim();
  const warn = styles.getPropertyValue("--danger").trim();
  const left = 64;
  const right = 18;
  const top = 14;
  const bottom = 38;
  const plotWidth = width - left - right;
  const plotHeight = height - top - bottom;
  const values = bins.map(bin => Number(bin[key] || 0));
  const max = Math.max(1, ...values) * 1.1;
  context.font = "12px system-ui, sans-serif";
  context.fillStyle = ink;
  context.strokeStyle = grid;
  context.lineWidth = 1;
  context.textAlign = "right";
  for (let index = 0; index <= 4; index += 1) {
    const value = max * index / 4;
    const y = top + plotHeight - plotHeight * index / 4;
    context.beginPath();
    context.moveTo(left, y);
    context.lineTo(width - right, y);
    context.stroke();
    context.fillText(key === "bytes" ? humanBytes(value) : number(Math.round(value)), left - 8, y + 4);
  }
  context.save();
  context.translate(14, top + plotHeight / 2);
  context.rotate(-Math.PI / 2);
  context.textAlign = "center";
  context.fillText(unit, 0, 0);
  context.restore();
  if (bins.length > 1) {
    context.beginPath();
    bins.forEach((bin, index) => {
      const x = left + index * plotWidth / (bins.length - 1);
      const y = top + plotHeight - Number(bin[key] || 0) / max * plotHeight;
      if (index === 0) context.moveTo(x, y);
      else context.lineTo(x, y);
    });
    context.strokeStyle = line;
    context.lineWidth = 2;
    context.stroke();
    const first = Number(bins[0].t);
    const last = Number(bins[bins.length - 1].t);
    for (const incident of incidents) {
      const stamp = Number(incident.last_ts);
      if (!Number.isFinite(stamp) || stamp < first || stamp > last || last <= first) continue;
      const x = left + (stamp - first) / (last - first) * plotWidth;
      context.strokeStyle = warn;
      context.beginPath();
      context.moveTo(x, top);
      context.lineTo(x, top + plotHeight);
      context.stroke();
    }
    context.textAlign = "left";
    context.fillStyle = ink;
    context.fillText(formatTime(first), left, height - 8);
    context.textAlign = "right";
    context.fillText(formatTime(last), width - right, height - 8);
  } else {
    context.textAlign = "center";
    context.fillStyle = ink;
    context.fillText("Waiting for packet-time bins", width / 2, height / 2);
  }
}

function selectOption(select, value, label) {
  const option = node("option", "", label);
  option.value = value;
  select.append(option);
  return option;
}

async function renderOverview() {
  const heading = frame("Overview", "Live traffic, detection signals, and capture health.");
  const toolbar = node("div", "range-control");
  const rangeLabel = node("label", "", "Time range");
  rangeLabel.htmlFor = "overview-range";
  const range = node("select", "field");
  range.id = "overview-range";
  selectOption(range, "300", "5 minutes");
  selectOption(range, "900", "15 minutes");
  selectOption(range, "3600", "1 hour");
  range.value = String(state.window);
  toolbar.append(rangeLabel, range);
  heading.append(toolbar);

  const loading = node("div", "loading");
  loading.textContent = "Loading overview…";
  view.append(loading);
  try {
    const [health, overview] = await Promise.all([
      request("/api/health"),
      request(`/api/overview?window=${state.window}`)
    ]);
    loading.remove();
    const kpis = node("div", "kpi-grid");
    kpis.append(
      createKpi("Packets / second", Number(health.packets_per_s || 0).toFixed(1), "10-second rolling rate"),
      createKpi("Bytes / second", `${humanBytes(state.lastBytesPerSecond)}/s`, "Sampled by the console"),
      createKpi("Malformed packets", number(health.malformed)),
      createKpi("Dropped writes", number(health.store_counters.dropped)),
      createKpi("Critical open", number(overview.open_incidents_by_severity.critical)),
      createKpi("High open", number(overview.open_incidents_by_severity.high)),
      createKpi("Medium open", number(overview.open_incidents_by_severity.medium)),
      createKpi("Low open", number(overview.open_incidents_by_severity.low))
    );
    view.append(kpis);

    const chart = node("canvas", "traffic-chart");
    chart.setAttribute("role", "img");
    chart.setAttribute("aria-label", "Packet and byte rates over packet time, with incident markers");
    const chartPanel = section("Traffic volume", chart);
    view.append(chartPanel);
    drawChart(chart, overview.bins, overview.recent_incidents, "packets", "packets / second");
    const bytesChart = node("canvas", "traffic-chart short-chart");
    bytesChart.setAttribute("role", "img");
    bytesChart.setAttribute("aria-label", "Bytes per second over packet time, with incident markers");
    view.append(section("Bytes per second", bytesChart));
    drawChart(bytesChart, overview.bins, overview.recent_incidents, "bytes", "bytes / second");

    const columns = node("div", "content-grid");
    const protocolRows = Object.entries(overview.protocol_mix)
      .sort((left, right) => right[1] - left[1])
      .map(([name, count]) => [name, number(count)]);
    columns.append(section("Protocol mix", table(
      [{label: "Protocol"}, {label: "Packets"}], protocolRows, "No protocol traffic recorded."
    )));
    const talkerRows = overview.top_talkers.map(([address, bytes]) =>
      [link(address, `#/hosts/${encodeURIComponent(address)}`, "mono-link"), humanBytes(bytes)]);
    columns.append(section("Top talkers", table(
      [{label: "Address"}, {label: "Bytes"}], talkerRows, "No talkers recorded."
    )));
    view.append(columns);

    const incidentRows = overview.recent_incidents.map(item => [
      link(item.id, `#/incidents/${encodeURIComponent(item.id)}`, "identifier"),
      item.kind, item.severity, item.status,
      link(item.src, `#/hosts/${encodeURIComponent(item.src)}`, "mono-link"),
      formatTime(item.last_ts)
    ]);
    view.append(section("Recent incidents", table([
      {label: "ID"}, {label: "Kind"}, {label: "Severity"}, {label: "Status"},
      {label: "Source"}, {label: "Last seen"}
    ], incidentRows, "No incidents recorded.")));
    range.addEventListener("change", () => {
      state.window = Number(range.value);
      renderRoute(routeParts(), true);
    });
  } catch (error) {
    loading.remove();
    view.append(node("p", "state-message error-message", `Could not load overview: ${error.message}`));
  }
}

function formField(labelText, control, id) {
  const label = node("label", "field-label", labelText);
  label.htmlFor = id;
  control.id = id;
  control.classList.add("field");
  const wrapper = node("div", "field-group");
  wrapper.append(label, control);
  return wrapper;
}

function pageControls(container, total, limit, offset, onChange) {
  const controls = node("div", "pagination");
  const summary = node("span", "muted", `Showing ${total ? offset + 1 : 0}–${Math.min(offset + limit, total)} of ${number(total)}`);
  const previous = node("button", "secondary-button", "Previous");
  previous.type = "button";
  previous.disabled = offset <= 0;
  previous.addEventListener("click", () => onChange(Math.max(0, offset - limit)));
  const next = node("button", "secondary-button", "Next");
  next.type = "button";
  next.disabled = offset + limit >= total;
  next.addEventListener("click", () => onChange(offset + limit));
  controls.append(summary, previous, next);
  container.append(controls);
}

function sortable(key, current) {
  return current.key === key ? (current.direction === "asc" ? "ascending" : "descending") : "none";
}

function localSort(items, sort, value) {
  return [...items].sort((left, right) => {
    const a = value(left, sort.key);
    const b = value(right, sort.key);
    const cmp = typeof a === "number" && typeof b === "number" ? a - b :
      String(a).localeCompare(String(b), undefined, {numeric: true});
    return sort.direction === "asc" ? cmp : -cmp;
  });
}

async function renderIncidents(parts) {
  const detailId = parts.length > 1 ? parts[1] : "";
  frame("Incidents", "Search, filter, and triage grouped detection events.");
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
  const search = node("input");
  search.name = "q";
  search.type = "search";
  search.value = state.incidentFilters.q;
  search.placeholder = "Search incidents";
  search.setAttribute("aria-label", "Search incidents");
  const status = node("select");
  status.name = "status";
  selectOption(status, "", "All statuses");
  for (const value of ["open", "acknowledged", "closed"]) selectOption(status, value, value);
  status.value = state.incidentFilters.status;
  status.setAttribute("aria-label", "Filter by status");
  const severity = node("select");
  severity.name = "severity";
  selectOption(severity, "", "All severities");
  for (const value of ["critical", "high", "medium", "low"]) selectOption(severity, value, value);
  severity.value = state.incidentFilters.severity;
  severity.setAttribute("aria-label", "Filter by severity");
  const kind = node("input");
  kind.name = "kind";
  kind.value = state.incidentFilters.kind;
  kind.placeholder = "Detector kind";
  kind.setAttribute("aria-label", "Filter by detector kind");
  const submit = node("button", "primary-button", "Apply filters");
  submit.type = "submit";
  controls.append(formField("Search", search, "incident-search"),
    formField("Status", status, "incident-status"),
    formField("Severity", severity, "incident-severity"),
    formField("Kind", kind, "incident-kind"), submit);
  view.append(controls);
  const layout = node("div", detailId ? "detail-layout" : "");
  const listPanel = section("Incident register", node("p", "muted", "Loading incidents…"), "list-panel");
  layout.append(listPanel);
  view.append(layout);

  try {
    const filters = state.incidentFilters;
    const params = new URLSearchParams({limit: String(filters.limit), offset: String(filters.offset)});
    for (const key of ["q", "status", "severity", "kind"]) if (filters[key]) params.set(key, filters[key]);
    const response = await request(`/api/incidents?${params}`);
    let rows = response.items;
    rows = localSort(rows, state.incidentSort, (item, key) => item[key]);
    const incidentTable = table([
      {label: "ID", cellClass: "nowrap-cell"},
      {label: "Kind", key: "kind", sort: sortable("kind", state.incidentSort), cellClass: "nowrap-cell"},
      {label: "Severity", key: "severity", sort: sortable("severity", state.incidentSort), cellClass: "nowrap-cell"},
      {label: "Status", key: "status", sort: sortable("status", state.incidentSort), cellClass: "nowrap-cell"},
      {label: "Source", key: "src", sort: sortable("src", state.incidentSort), cellClass: "nowrap-cell"},
      {label: "Count", key: "count", sort: sortable("count", state.incidentSort), cellClass: "nowrap-cell"},
      {label: "Last seen", key: "last_ts", sort: sortable("last_ts", state.incidentSort), cellClass: "nowrap-cell"}
    ], rows.map(item => [
      link(item.id, `#/incidents/${encodeURIComponent(item.id)}`, "identifier"),
      item.kind, item.severity, item.status,
      link(item.src, `#/hosts/${encodeURIComponent(item.src)}`, "mono-link"),
      number(item.count), formatTime(item.last_ts)
    ]), "No incidents match the selected filters.", "responsive-identifiable");
    listPanel.replaceChildren(node("h2", "panel-title", "Incident register"), tableWrap(incidentTable));
    pageControls(listPanel, response.total, filters.limit, filters.offset, offset => {
      state.incidentFilters.offset = offset;
      renderRoute(routeParts(), true);
    });
    for (const button of incidentTable.querySelectorAll("[data-sort]")) {
      button.addEventListener("click", () => {
        const key = button.dataset.sort;
        if (state.incidentSort.key === key) {
          state.incidentSort.direction = state.incidentSort.direction === "asc" ? "desc" : "asc";
        } else {
          state.incidentSort = {key, direction: "asc"};
        }
        renderRoute(routeParts(), true);
      });
    }
    if (detailId) {
      const panel = await renderIncidentDetail(detailId);
      layout.append(panel);
    }
  } catch (error) {
    listPanel.replaceChildren(node("p", "state-message error-message", `Could not load incidents: ${error.message}`));
    if (detailId) layout.append(showIncidentError(error));
  }
}

function showIncidentError(error) {
  const panel = node("aside", "detail-panel");
  panel.setAttribute("aria-label", "Incident detail");
  panel.append(link("Close", "#/incidents", "close-panel"), node("h2", "", "Incident unavailable"),
    node("p", "state-message error-message", error.message));
  return panel;
}

function explanationRows(alert) {
  const data = alert.data || {};
  const rows = [];
  const metrics = Array.isArray(data.metrics) ? data.metrics : [data];
  for (const item of metrics) {
    const observed = item.observed === undefined ? item.value : item.observed;
    const threshold = item.threshold === undefined ? data.threshold : item.threshold;
    if (observed === undefined && threshold === undefined) continue;
    rows.push([item.metric || "Signal", observed === undefined ? "—" : String(observed),
      threshold === undefined ? "—" : String(threshold)]);
  }
  return rows;
}

async function renderIncidentDetail(id) {
  const panel = node("aside", "detail-panel");
  panel.setAttribute("aria-label", "Incident detail");
  showState(panel, "Loading incident…");
  try {
    const incident = await request(`/api/incidents/${encodeURIComponent(id)}`);
    state.detail = incident;
    const close = link("Close", "#/incidents", "close-panel");
    const content = node("div");
    content.append(close, node("p", "eyebrow", `INCIDENT ${incident.id}`));
    const title = node("h2", "", incident.kind);
    content.append(title, severityBadge(incident.severity), node("span", "status-badge", incident.status));
    const summary = node("p", "detail-summary", incident.detail);
    content.append(summary);
    const facts = node("dl", "detail-facts");
    for (const [label, value, address] of [
      ["Source", incident.src, true], ["First seen", formatTime(incident.first_ts), false],
      ["Last seen", formatTime(incident.last_ts), false], ["Occurrences", number(incident.count), false]
    ]) {
      facts.append(node("dt", "", label));
      const item = node("dd");
      if (address && value && value !== "many" && value !== "-") {
        item.append(link(value, `#/hosts/${encodeURIComponent(value)}`, "mono-link"));
      } else item.textContent = value;
      facts.append(item);
    }
    content.append(facts);
    const firstAlert = incident.alerts[0];
    const why = node("div", "subpanel");
    why.append(node("h3", "", "Why it fired"));
    if (firstAlert) {
      const evidence = explanationRows(firstAlert);
      if (evidence.length) why.append(table([
        {label: "Signal"}, {label: "Observed"}, {label: "Threshold"}
      ], evidence, "No threshold evidence was recorded."));
      else why.append(node("p", "muted", "The detector did not provide structured observed-value and threshold fields."));
      why.append(node("p", "muted", firstAlert.detail));
    } else why.append(node("p", "muted", "No alert detail is available."));
    content.append(why);

    const hosts = node("div", "linked-hosts");
    hosts.append(node("h3", "", "Linked hosts"));
    const addresses = new Set();
    for (const alert of incident.alerts) {
      if (alert.src && !["many", "-"].includes(alert.src)) addresses.add(alert.src);
      if (alert.dst && !["many", "-"].includes(alert.dst)) addresses.add(alert.dst);
    }
    if (addresses.size) {
      for (const address of addresses) hosts.append(link(address,
        `#/hosts/${encodeURIComponent(address)}`, "mono-link"));
    } else hosts.append(node("p", "muted", "No address links recorded."));
    content.append(hosts);

    const timelineRows = incident.alerts.map(alert => [
      formatTime(alert.ts), severityBadge(alert.severity), alert.kind,
      link(alert.src, `#/hosts/${encodeURIComponent(alert.src)}`, "mono-link"), alert.detail
    ]);
    const timeline = section("Alert timeline", tableWrap(table([
      {label: "Packet time", cellClass: "nowrap-cell"},
      {label: "Severity", cellClass: "nowrap-cell"},
      {label: "Kind", cellClass: "nowrap-cell"},
      {label: "Source", cellClass: "nowrap-cell"},
      {label: "Detail", cellClass: "wrap-cell"}
    ], timelineRows, "No alert timeline recorded.", "responsive-identifiable")));
    content.append(timeline);

    const action = node("form", "status-actions");
    action.append(node("h3", "", "Update status"));
    const note = node("textarea", "field");
    note.rows = 3;
    note.maxLength = 4000;
    note.setAttribute("aria-label", "Status note");
    action.append(formField("Note", note, "incident-note"));
    if (incident.status === "open") action.append(statusButton("Acknowledge", "acknowledged"));
    if (incident.status !== "closed") action.append(statusButton("Close incident", "closed"));
    action.addEventListener("submit", async event => {
      event.preventDefault();
      const button = event.submitter;
      if (!button || !button.dataset.nextStatus) return;
      try {
        await request(`/api/incidents/${encodeURIComponent(id)}/status`, {
          method: "POST",
          cache: "no-store",
          headers: {
            "Content-Type": "application/json",
            "X-PacketLens-Token": document.querySelector('meta[name="packetlens-token"]').content
          },
          body: JSON.stringify({status: button.dataset.nextStatus, note: note.value})
        });
        await renderRoute(routeParts(), true);
      } catch (error) {
        action.append(node("p", "error-message", `Status update failed: ${error.message}`));
      }
    });
    content.append(action);

    const copy = node("button", "secondary-button", "Copy as JSON");
    copy.type = "button";
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(JSON.stringify(incident, null, 2));
        copy.textContent = "Copied";
      } catch (error) {
        copy.textContent = `Copy unavailable: ${error.message}`;
      }
    });
    content.append(copy);
    panel.replaceChildren(content);
    return panel;
  } catch (error) {
    return showIncidentError(error);
  }
}

function severityBadge(severity) {
  const value = String(severity).toLowerCase();
  const classValue = ["critical", "high", "medium", "low"].includes(value) ? value : "unknown";
  return node("span", `severity-badge severity-${classValue}`, severity);
}

function statusButton(label, status) {
  const button = node("button", "secondary-button", label);
  button.type = "submit";
  button.dataset.nextStatus = status;
  return button;
}

async function renderHosts(parts) {
  const hostIp = parts.length > 1 ? parts[1] : "";
  frame("Hosts", "Observed endpoints, traffic direction, peers, and related detections.");
  const controls = node("form", "filter-bar");
  controls.addEventListener("submit", event => {
    event.preventDefault();
    state.hostFilters.q = controls.elements.q.value.trim();
    state.hostFilters.sort = controls.elements.sort.value;
    state.hostFilters.offset = 0;
    renderRoute(routeParts(), true);
  });
  const query = node("input");
  query.name = "q";
  query.type = "search";
  query.placeholder = "Filter addresses";
  query.value = state.hostFilters.q;
  query.setAttribute("aria-label", "Filter host addresses");
  const sort = node("select");
  sort.name = "sort";
  for (const [value, label] of [["bytes", "Traffic volume"], ["last_seen", "Last seen"],
    ["alerts", "Related alerts"], ["ip", "Address"]]) selectOption(sort, value, label);
  sort.value = state.hostFilters.sort;
  sort.setAttribute("aria-label", "Sort hosts");
  const submit = node("button", "primary-button", "Apply");
  submit.type = "submit";
  controls.append(formField("Search", query, "host-search"),
    formField("Sort", sort, "host-sort"), submit);
  view.append(controls);
  const layout = node("div", hostIp ? "detail-layout" : "");
  const listPanel = section("Host inventory", node("p", "muted", "Loading hosts…"), "list-panel");
  layout.append(listPanel);
  view.append(layout);
  try {
    const filters = state.hostFilters;
    const params = new URLSearchParams({limit: String(filters.limit), offset: String(filters.offset),
      sort: filters.sort});
    if (filters.q) params.set("q", filters.q);
    const response = await request(`/api/hosts?${params}`);
    const rows = localSort(response.items, state.hostSort,
      (item, key) => key === "bytes" ? item.bytes_in + item.bytes_out : item[key]);
    const hostTable = table([
      {label: "Address", key: "ip", sort: sortable("ip", state.hostSort), cellClass: "nowrap-cell"},
      {label: "Packets", key: "packets_in", sort: sortable("packets_in", state.hostSort), cellClass: "nowrap-cell"},
      {label: "Bytes", key: "bytes", sort: sortable("bytes", state.hostSort), cellClass: "nowrap-cell"},
      {label: "Peers", cellClass: "nowrap-cell"},
      {label: "Alerts", key: "alert_count", sort: sortable("alert_count", state.hostSort), cellClass: "nowrap-cell"},
      {label: "Last seen", key: "last_seen", sort: sortable("last_seen", state.hostSort), cellClass: "nowrap-cell"}
    ], rows.map(item => [
      link(item.ip, `#/hosts/${encodeURIComponent(item.ip)}`, "mono-link"),
      number(item.packets_in + item.packets_out), humanBytes(item.bytes_in + item.bytes_out),
      number(item.peers.length), number(item.alert_count), formatTime(item.last_seen)
    ]), "No host profiles match the selected filter.", "responsive-identifiable");
    listPanel.replaceChildren(node("h2", "panel-title", "Host inventory"), tableWrap(hostTable));
    pageControls(listPanel, response.total, filters.limit, filters.offset, offset => {
      state.hostFilters.offset = offset;
      renderRoute(routeParts(), true);
    });
    for (const button of hostTable.querySelectorAll("[data-sort]")) {
      button.addEventListener("click", () => {
        const key = button.dataset.sort;
        state.hostSort = state.hostSort.key === key ?
          {key, direction: state.hostSort.direction === "asc" ? "desc" : "asc"} :
          {key, direction: "asc"};
        renderRoute(routeParts(), true);
      });
    }
    if (hostIp) layout.append(await renderHostDetail(hostIp));
  } catch (error) {
    listPanel.replaceChildren(node("p", "state-message error-message", `Could not load hosts: ${error.message}`));
    if (hostIp) layout.append(showHostError(error));
  }
}

function showHostError(error) {
  const panel = node("aside", "detail-panel");
  panel.setAttribute("aria-label", "Host detail");
  panel.append(link("Close", "#/hosts", "close-panel"),
    node("h2", "", "Host unavailable"), node("p", "error-message", error.message));
  return panel;
}

async function renderHostDetail(ip) {
  const panel = node("aside", "detail-panel");
  panel.setAttribute("aria-label", "Host detail");
  showState(panel, "Loading host…");
  try {
    const host = await request(`/api/hosts/${encodeURIComponent(ip)}`);
    const content = node("div");
    content.append(link("Close", "#/hosts", "close-panel"),
      node("p", "eyebrow", "HOST PROFILE"), node("h2", "mono-heading", host.ip));
    content.append(node("p", "muted", `Observed ${formatTime(host.first_seen)} to ${formatTime(host.last_seen)}`));
    const traffic = node("div", "kpi-grid compact-kpis");
    traffic.append(createKpi("Packets in", number(host.packets_in)),
      createKpi("Packets out", number(host.packets_out)),
      createKpi("Bytes in", humanBytes(host.bytes_in)),
      createKpi("Bytes out", humanBytes(host.bytes_out)));
    content.append(traffic);
    content.append(section("Peers", listLinks(host.peers, "/hosts/"), ""));
    const ports = host.top_ports.map(([port, count]) => [String(port), number(count)]);
    content.append(section("Top destination ports", table([
      {label: "Port"}, {label: "Packets"}
    ], ports, "No destination ports recorded.")));
    const protocolNames = {"1": "ICMP", "6": "TCP", "17": "UDP", "58": "ICMPv6"};
    const protocols = Object.entries(host.protocols).map(([protocol, count]) =>
      [protocolNames[protocol] || protocol, number(count)]);
    content.append(section("Protocol mix", table([
      {label: "Protocol"}, {label: "Packets"}
    ], protocols, "No protocol details recorded.")));
    const incidents = host.related_incident_ids.map(id => [
      link(id, `#/incidents/${encodeURIComponent(id)}`, "identifier")
    ]);
    content.append(section("Related incidents", table([
      {label: "Incident"}
    ], incidents, "No related incidents recorded.")));
    panel.replaceChildren(content);
    return panel;
  } catch (error) {
    return showHostError(error);
  }
}

function listLinks(values, route) {
  const list = node("ul", "link-list");
  if (!values.length) {
    list.append(node("li", "muted", "No peers recorded."));
  } else {
    for (const value of values) {
      const item = node("li");
      item.append(link(value, `#${route}${encodeURIComponent(value)}`, "mono-link"));
      list.append(item);
    }
  }
  return list;
}

function reportValue(value) {
  if (value === undefined) return "—";
  if (value === null) return "null";
  return typeof value === "object" ? JSON.stringify(value) : String(value);
}

function reportTable(parent, title, labels, rows, emptyMessage) {
  parent.append(section(title, tableWrap(table(
    labels.map(label => ({label})), rows.map(row => row.map(reportValue)), emptyMessage
  ))));
}

function flattenReport(value, path, rows) {
  if (Array.isArray(value)) {
    if (!value.length) rows.push([path, "[]"]);
    value.forEach((item, index) => flattenReport(item, `${path}[${index}]`, rows));
  } else if (value && typeof value === "object") {
    const entries = Object.entries(value);
    if (!entries.length) rows.push([path, "{}"]);
    entries.forEach(([key, item]) =>
      flattenReport(item, path ? `${path}.${key}` : key, rows));
  } else {
    rows.push([path, reportValue(value)]);
  }
}

function renderReportMetadata(parent, report) {
  const rows = [];
  if (Object.prototype.hasOwnProperty.call(report, "seed")) {
    rows.push(["seed", reportValue(report.seed)]);
  }
  if (Object.prototype.hasOwnProperty.call(report, "train_frac")) {
    rows.push(["train_frac", reportValue(report.train_frac)]);
  }
  if (Object.prototype.hasOwnProperty.call(report, "library_versions")) {
    const versions = report.library_versions;
    if (versions && typeof versions === "object" && !Array.isArray(versions)) {
      for (const [library, version] of Object.entries(versions)) {
        rows.push([`library_versions.${library}`, reportValue(version)]);
      }
    } else rows.push(["library_versions", reportValue(versions)]);
  }
  if (rows.length) reportTable(parent, "Run metadata", ["Field", "Value"], rows);
}

function renderAudit(parent, audit) {
  const sections = [
    ["h1_bot_flows_per_30min", "H1 — Bot flows per 30 minutes"],
    ["h2_attacker_flows_after_window", "H2 — Attacker flows after the window"],
    ["h3_destination_pairs", "H3 — Destination-pair overlap"],
    ["h4_test_bot", "H4 — Test Bot results"]
  ];
  for (const [key, title] of sections) {
    if (!Object.prototype.hasOwnProperty.call(audit, key)) continue;
    const rows = [];
    flattenReport(audit[key], "", rows);
    reportTable(parent, title, ["Field", "Value"], rows, "No audit data recorded.");
  }
}

function renderEvaluationReport(parent, report) {
  const events = Array.isArray(report.events) ? report.events : [];
  reportTable(parent, "Event detection", ["Event", "Detector", "Detected", "Delay (s)"],
    events.map(item => [item.event, item.detector, item.detected, item.delay_s]),
    "No event results recorded.");
  const falsePositives = Object.entries(report.false_positives_on_clean_traffic || {})
    .map(([kind, count]) => [kind, count]);
  reportTable(parent, "Clean-traffic false positives", ["Detector", "Alerts"],
    falsePositives, "No clean-traffic false positives recorded.");

  const metrics = ["tp", "fp", "fn", "precision", "recall", "f1"];
  const detectors = Object.entries(report.bin_level_volume_detectors || {});
  reportTable(parent, "Bin-level volume detectors", ["Method", ...metrics],
    detectors.map(([method, result]) => [
      method, ...metrics.map(metric => result && result[metric])
    ]), "No volume-detector results recorded.");
}

function renderFlowsReport(parent, report) {
  const bins = Object.entries(report.bins || {}).map(([name, count]) => [name, count]);
  reportTable(parent, "Bins summary", ["Set", "Bins"], bins, "No bins summary recorded.");

  const methods = report.methods || {};
  const methodNames = Object.keys(methods);
  const metricNames = [];
  const attackNames = [];
  for (const method of methodNames) {
    for (const [name, value] of Object.entries(methods[method] || {})) {
      if (name === "recall_by_attack") {
        for (const attack of Object.keys(value || {})) {
          if (!attackNames.includes(attack)) attackNames.push(attack);
        }
      } else if (!metricNames.includes(name)) metricNames.push(name);
    }
  }
  reportTable(parent, "Per-method metrics", ["Method", ...metricNames],
    methodNames.map(method => [
      method, ...metricNames.map(metric => methods[method][metric])
    ]), "No method results recorded.");
  reportTable(parent, "Recall by attack", ["Attack", ...methodNames],
    attackNames.map(attack => [
      attack, ...methodNames.map(method => {
        const values = methods[method].recall_by_attack || {};
        return Object.prototype.hasOwnProperty.call(values, attack) ? values[attack] : "—";
      })
    ]), "No per-attack recall recorded.");

  if (report.granite && typeof report.granite === "object") {
    const graniteRows = Object.entries(report.granite)
      .map(([key, value]) => [key, reportValue(value)]);
    reportTable(parent, "Granite metadata", ["Field", "Value"], graniteRows);
  }
}

function renderFlowmodelReport(parent, report) {
  const counts = [];
  for (const [split, values] of Object.entries(report.counts || {})) {
    for (const [label, count] of Object.entries(values || {})) {
      counts.push([split, label, count]);
    }
  }
  reportTable(parent, "Counts", ["Split", "Label", "Flows"], counts, "No counts recorded.");

  const metricNames = [
    "precision", "recall", "f1", "average_precision", "tn", "fp", "fn", "tp",
    "fp_per_1000_benign"
  ];
  const results = Array.isArray(report.results) ? report.results : [];
  reportTable(parent, "Results", ["Model", ...metricNames],
    results.map(result => [
      result.model, ...metricNames.map(metric => result.metrics && result.metrics[metric])
    ]), "No model results recorded.");

  const importances = Array.isArray(report.top_10_feature_importances) ?
    report.top_10_feature_importances : [];
  reportTable(parent, "Top feature importances", ["Feature", "Importance"],
    importances.map(item => [item.feature, item.importance]),
    "No feature importances recorded.");
  if (report.audit && typeof report.audit === "object") renderAudit(parent, report.audit);
}

function renderQualityReport(parent, name, report) {
  if (!report || typeof report !== "object" || Array.isArray(report)) {
    const details = node("details", "raw-report");
    details.append(node("summary", "", "Raw JSON report"));
    details.append(node("pre", "raw-json", JSON.stringify(report, null, 2)));
    parent.append(section("Report data", details));
    return;
  }
  renderReportMetadata(parent, report);
  if (name === "evaluation.json") renderEvaluationReport(parent, report);
  else if (name === "flows_real.json") renderFlowsReport(parent, report);
  else if (/^flowmodel_.*\.json$/.test(name)) renderFlowmodelReport(parent, report);
  else if (name === "benchmark.json") {
    reportTable(parent, "Benchmark results", ["Measurement", "Value"],
      Object.entries(report).map(([key, value]) => [key, reportValue(value)]),
      "No benchmark values recorded.");
  } else {
    const details = node("details", "raw-report");
    details.append(node("summary", "", "Raw JSON report"));
    const pre = node("pre", "raw-json", JSON.stringify(report, null, 2));
    details.append(pre);
    parent.append(section("Report data", details));
  }
}

async function renderQuality(parts) {
  frame("Detection quality", "Reference result files; values are not recomputed by the console.");
  const caveat = node("aside", "caveat-banner");
  caveat.setAttribute("role", "note");
  caveat.append(node("strong", "", "Interpret with care. "),
    node("span", "", "Synthetic and real-data results differ and should not be compared as if they were produced under identical conditions."));
  view.append(caveat);
  const panel = section("Available result files", node("p", "loading", "Loading result files…"));
  view.append(panel);
  try {
    const response = await request("/api/quality");
    const items = Array.isArray(response.items) ? response.items : [];
    const selectedName = parts.length > 1 ? parts[1] : "";
    const rows = items.map(item => [
      link(item.name, `#/quality/${encodeURIComponent(item.name)}`,
        selectedName === item.name ? "identifier selected-result" : "identifier"),
      formatDate(item.modified)
    ]);
    panel.replaceChildren(node("h2", "panel-title", "Available result files"));
    if (items.length) {
      panel.append(tableWrap(table([{label: "File"}, {label: "Modified"}], rows,
        "No result JSON files found.")));
    } else {
      panel.append(node("p", "muted",
        "No result JSON files found. Generate a synthetic evaluation with `packetlens evaluate --save results/evaluation.json`. Real-data reports are produced by the `flows` command."));
    }
    if (selectedName) {
      const selected = items.find(item => item.name === selectedName);
      if (!selected) {
        view.append(section("Selected report", node(
          "p", "state-message error-message", "This result file is no longer available."
        )));
        return;
      }
      const reportPanel = section("Selected report", node("p", "loading", "Loading report…"));
      view.append(reportPanel);
      try {
        const report = await request(`/api/quality/${encodeURIComponent(selectedName)}`);
        reportPanel.replaceChildren(
          node("h2", "panel-title", selectedName),
          node("p", "muted", `Modified ${formatDate(selected.modified)}`)
        );
        renderQualityReport(reportPanel, selectedName, report);
      } catch (error) {
        reportPanel.replaceChildren(node("h2", "panel-title", selectedName),
          node("p", "state-message error-message", `Could not load report: ${error.message}`));
      }
    }
  } catch (error) {
    panel.replaceChildren(node("h2", "panel-title", "Available result files"),
      node("p", "state-message error-message", `Could not load result files: ${error.message}`));
  }
}

async function renderPolicies() {
  frame("Policies", "Read-only view of the configured detection rules.");
  const panel = section("Policy rules", node("p", "muted", "Loading policy…"));
  view.append(panel);
  try {
    const policy = await request("/api/policies");
    const description = node("p", "muted", `${policy.name} · incident grouping gap ${number(policy.incident_gap_s)} seconds`);
    const rows = policy.policies.map(rule => [
      node("code", "identifier", rule.id),
      rule.detector,
      rule.enabled ? "Enabled" : "Disabled",
      rule.severity || "Detector default",
      rule.action,
      node("code", "parameter-text", JSON.stringify(rule.params || {})),
      node("code", "parameter-text", JSON.stringify(rule.allowlist || {}))
    ]);
    panel.replaceChildren(node("h2", "panel-title", "Policy rules"), description,
      tableWrap(table([
        {label: "Rule", cellClass: "nowrap-cell"},
        {label: "Detector", cellClass: "nowrap-cell"},
        {label: "State", cellClass: "nowrap-cell"},
        {label: "Severity", cellClass: "nowrap-cell"},
        {label: "Action", cellClass: "nowrap-cell"},
        {label: "Thresholds / parameters", cellClass: "wrap-cell"},
        {label: "Allowlists", cellClass: "wrap-cell"}
      ], rows, "No policy rules configured.", "responsive-identifiable")));
  } catch (error) {
    panel.replaceChildren(node("h2", "panel-title", "Policy rules"),
      node("p", "state-message error-message", `Could not load policy: ${error.message}`));
  }
}

async function renderRoute(parts, focus) {
  if (!parts.length) parts = ["overview"];
  updateNavigation(parts);
  const path = routePath(parts);
  state.route = path;
  view.replaceChildren();
  view.setAttribute("aria-busy", "true");
  try {
    if (parts[0] === "overview") await renderOverview();
    else if (parts[0] === "incidents") await renderIncidents(parts);
    else if (parts[0] === "hosts") await renderHosts(parts);
    else if (parts[0] === "quality") await renderQuality(parts);
    else if (parts[0] === "policies" && parts.length === 1) await renderPolicies();
    else {
      frame("Not found", "The requested console view does not exist.");
      view.append(node("p", "state-message", "Choose a view from the navigation rail."));
    }
  } finally {
    view.setAttribute("aria-busy", "false");
    if (focus) view.focus();
  }
}

function applyTheme(theme) {
  state.theme = theme;
  if (theme) document.body.dataset.theme = theme;
  else delete document.body.dataset.theme;
  const button = byId("theme-toggle");
  button.textContent = theme === "dark" ? "Light theme" : "Dark theme";
  button.setAttribute("aria-pressed", String(theme === "dark"));
}

function initialize() {
  byId("theme-toggle").addEventListener("click", () => {
    const current = state.theme || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    const next = current === "dark" ? "light" : "dark";
    applyTheme(next);
    try {
      window.localStorage.setItem("packetlens-theme", next);
    } catch (error) {
      console.warn("Theme preference could not be saved.");
    }
  });
  byId("time-toggle").addEventListener("click", event => {
    state.utc = !state.utc;
    event.currentTarget.textContent = state.utc ? "UTC" : "Local";
    event.currentTarget.setAttribute("aria-pressed", String(state.utc));
    renderRoute(routeParts(), true);
  });
  window.addEventListener("hashchange", () => renderRoute(routeParts(), true));
  window.addEventListener("keydown", event => {
    if (event.key === "Escape" && routeParts().length > 1 &&
        ["incidents", "hosts"].includes(routeParts()[0])) {
      location.hash = `#/${routeParts()[0]}`;
    }
  });
  try {
    applyTheme(window.localStorage.getItem("packetlens-theme") || "");
  } catch (error) {
    applyTheme("");
  }
  renderRoute(routeParts(), true);
  tick();
}

initialize();
