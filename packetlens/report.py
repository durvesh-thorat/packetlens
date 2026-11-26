"""Self-contained, print-oriented HTML reports."""
import html
from datetime import datetime, timezone

from . import __version__
from .policy import effective_policy
from .store import MAX_PAGE_SIZE, Store


def _escape(value):
    return html.escape(str(value), quote=True)


def _time(value):
    if value is None:
        return "Not recorded"
    return datetime.fromtimestamp(float(value), timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _all_incidents(store):
    items, offset = [], 0
    while True:
        page = store.list_incidents(limit=MAX_PAGE_SIZE, offset=offset)
        items.extend(page["items"])
        offset += len(page["items"])
        if offset >= page["total"] or not page["items"]:
            return items


def _incident_block(store, incident):
    details = store.get_incident(incident["id"])
    if details is None:
        return ""
    rows = []
    for alert in details["alerts"]:
        data = alert.get("data") or {}
        observed = data.get("observed", data.get("value", "Not supplied"))
        threshold = data.get("threshold", "Not supplied")
        rows.append(
            "<tr>"
            f"<td>{_escape(_time(alert['ts']))}</td>"
            f"<td>{_escape(alert['severity'])}</td>"
            f"<td>{_escape(alert['kind'])}</td>"
            f"<td class=\"mono\">{_escape(alert['src'])}</td>"
            f"<td>{_escape(alert['detail'])}</td>"
            f"<td>{_escape(observed)}</td>"
            f"<td>{_escape(threshold)}</td>"
            f"<td><code>{_escape(alert.get('policy_id', ''))}</code></td>"
            "</tr>"
        )
    if details.get("alerts_truncated"):
        rows.append('<tr><td colspan="8">Timeline truncated by the store limit.</td></tr>')
    alert_rows = "".join(rows) or '<tr><td colspan="8">No alert timeline recorded.</td></tr>'
    incident_id = _escape(incident["id"])
    return (
        f'<section class="incident-detail" id="incident-{incident_id}">'
        f"<h3>Incident {incident_id}</h3>"
        '<dl class="facts">'
        f"<dt>Kind</dt><dd>{_escape(incident['kind'])}</dd>"
        f"<dt>Severity</dt><dd>{_escape(incident['severity'])}</dd>"
        f"<dt>Status</dt><dd>{_escape(incident['status'])}</dd>"
        f"<dt>Source</dt><dd class=\"mono\">{_escape(incident['src'])}</dd>"
        f"<dt>First / last seen</dt><dd>{_escape(_time(incident['first_ts']))} / "
        f"{_escape(_time(incident['last_ts']))}</dd>"
        f"<dt>Occurrences</dt><dd>{_escape(incident['count'])}</dd>"
        f"<dt>Summary</dt><dd>{_escape(incident['detail'])}</dd>"
        "</dl>"
        "<h4>Alert timeline</h4>"
        '<div class="table-wrap"><table><thead><tr><th>Packet time</th><th>Severity</th>'
        "<th>Kind</th><th>Source</th><th>Detail</th><th>Observed</th><th>Threshold</th>"
        f"<th>Policy</th></tr></thead><tbody>{alert_rows}</tbody></table></div>"
        "</section>"
    )


def render_report(store, title="PacketLens Technical Report", policy=None):
    incidents = _all_incidents(store)
    capture = store.capture_summary()
    hosts = store.list_hosts(sort="bytes", limit=10, offset=0)["items"]
    policy = policy or effective_policy()
    by_severity = {severity: 0 for severity in ("critical", "high", "medium", "low")}
    by_status = {status: 0 for status in ("open", "acknowledged", "closed")}
    for incident in incidents:
        by_severity[incident["severity"]] = by_severity.get(incident["severity"], 0) + 1
        by_status[incident["status"]] = by_status.get(incident["status"], 0) + 1

    incident_rows = []
    for incident in incidents:
        incident_id = _escape(incident["id"])
        incident_rows.append(
            "<tr>"
            f'<td><a href="#incident-{incident_id}"><code>{incident_id}</code></a></td>'
            f"<td>{_escape(incident['kind'])}</td>"
            f"<td>{_escape(incident['severity'])}</td>"
            f"<td>{_escape(incident['status'])}</td>"
            f"<td class=\"mono\">{_escape(incident['src'])}</td>"
            f"<td>{_escape(incident['count'])}</td>"
            f"<td>{_escape(_time(incident['first_ts']))}</td>"
            f"<td>{_escape(incident['detail'])}</td>"
            "</tr>"
        )
    if not incident_rows:
        incident_rows.append('<tr><td colspan="8">No incidents recorded.</td></tr>')

    host_rows = [
        "<tr>"
        f"<td class=\"mono\">{_escape(host['ip'])}</td>"
        f"<td>{_escape(host['packets_in'] + host['packets_out'])}</td>"
        f"<td>{_escape(host['bytes_in'] + host['bytes_out'])}</td>"
        f"<td>{_escape(host['alert_count'])}</td>"
        f"<td>{_escape(host['last_seen'])}</td>"
        "</tr>"
        for host in hosts
    ] or ['<tr><td colspan="5">No host profiles recorded.</td></tr>']

    policy_rows = []
    for rule in policy.policies:
        policy_rows.append(
            "<tr>"
            f"<td><code>{_escape(rule.get('id', ''))}</code></td>"
            f"<td>{_escape(rule.get('detector', ''))}</td>"
            f"<td>{_escape(rule.get('severity', 'default'))}</td>"
            f"<td>{_escape(rule.get('enabled', False))}</td>"
            f"<td>{_escape(rule.get('action', ''))}</td>"
            f"<td><code>{_escape(rule.get('params', {}))}</code></td>"
            f"<td><code>{_escape(rule.get('allowlist', {}))}</code></td>"
            "</tr>"
        )
    if not policy_rows:
        policy_rows.append('<tr><td colspan="7">No policy rules configured.</td></tr>')

    malformed = capture["malformed"]
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    title_text = _escape(title)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; script-src 'none'; base-uri 'none'; form-action 'none'">
<title>{title_text}</title>
<style>
@page{{margin:16mm}}*{{box-sizing:border-box}}body{{margin:0;color:#17212b;background:#fff;
font:11pt/1.45 Arial,Helvetica,sans-serif;font-variant-numeric:tabular-nums}}
main{{max-width:1200px;margin:auto;padding:28px}}h1{{font-size:24pt;margin:0 0 4px}}
h2{{font-size:15pt;border-bottom:1px solid #71808e;padding-bottom:5px;margin:26px 0 10px}}
h3{{font-size:12pt;margin:20px 0 8px}}h4{{margin:14px 0 6px}}.muted{{color:#536271}}
.facts{{display:grid;grid-template-columns:150px 1fr;gap:4px 12px}}.facts dt{{font-weight:bold}}
.facts dd{{margin:0;overflow-wrap:anywhere}}.summary{{display:flex;flex-wrap:wrap;gap:10px}}
.metric{{border:1px solid #aeb8c2;padding:10px 12px;min-width:130px}}.metric strong{{display:block;font-size:16pt}}
.table-wrap{{overflow-x:auto}}table{{border-collapse:collapse;width:100%;margin:8px 0 16px}}
th,td{{border:1px solid #bac3cb;padding:5px 7px;text-align:left;vertical-align:top;overflow-wrap:anywhere}}
th{{background:#edf1f4}}.mono,code{{font-family:Consolas,"Courier New",monospace;font-size:9.5pt}}
.incident-detail{{break-inside:avoid-page;border-top:1px solid #bac3cb;padding-top:8px}}
.foot{{border-top:1px solid #bac3cb;margin-top:30px;padding-top:8px}}
@media print{{main{{max-width:none;padding:0}}a{{color:inherit;text-decoration:none}}}}
</style></head><body><main>
<h1>{title_text}</h1><p class="muted">Generated at {_escape(generated_at)} · PacketLens {_escape(__version__)} ·
Policy: {_escape(policy.name)}</p>
<h2>Executive summary</h2>
<dl class="facts"><dt>Capture period</dt><dd>{_escape(_time(capture['first_ts']))} – {_escape(_time(capture['last_ts']))}</dd>
<dt>Capture runs</dt><dd>{_escape(capture['runs'])}</dd></dl>
<div class="summary">
<div class="metric"><span>Packets</span><strong>{_escape(f"{capture['packets']:,}")}</strong></div>
<div class="metric"><span>Bytes</span><strong>{_escape(f"{capture['bytes']:,}")}</strong></div>
<div class="metric"><span>Incidents</span><strong>{_escape(len(incidents))}</strong></div>
{''.join(f'<div class="metric"><span>{_escape(severity.title())} incidents</span><strong>{_escape(by_severity[severity])}</strong></div>' for severity in by_severity)}
</div>
<p>By status: {' · '.join(f'{_escape(status.title())}: {_escape(count)}' for status, count in by_status.items())}</p>
<h2>Incident register</h2><div class="table-wrap"><table><thead><tr><th>ID</th><th>Kind</th><th>Severity</th>
<th>Status</th><th>Source</th><th>Count</th><th>First seen (UTC)</th><th>Summary</th></tr></thead>
<tbody>{''.join(incident_rows)}</tbody></table></div>
<h2>Incident details</h2>{''.join(_incident_block(store, incident) for incident in incidents)}
<h2>Top hosts by recorded traffic</h2><div class="table-wrap"><table><thead><tr><th>Address</th>
<th>Packets</th><th>Bytes</th><th>Related alerts</th><th>Last seen (packet time)</th></tr></thead>
<tbody>{''.join(host_rows)}</tbody></table></div>
<h2>Policies in force: {_escape(policy.name)}</h2><div class="table-wrap"><table><thead><tr><th>ID</th>
<th>Detector</th><th>Severity</th><th>Enabled</th><th>Action</th><th>Thresholds / parameters</th>
<th>Allowlists</th></tr></thead><tbody>{''.join(policy_rows)}</tbody></table></div>
<h2>Data quality</h2><ul>
<li>Malformed packets: {_escape(malformed if malformed is not None else "not recorded for this database")}</li>
<li>Dropped store writes: {_escape(capture['dropped_writes'] if capture['dropped_writes'] is not None else "not recorded")}</li>
<li>Alert and host totals reflect records retained by the store; packet totals are accumulated from recorded capture runs.</li>
</ul>
<p class="foot muted">PacketLens {_escape(__version__)} · Generated at {_escape(generated_at)}</p>
</main></body></html>"""


def write_report(db_path, out_path, title="PacketLens Technical Report", policy_path=None):
    store = Store(db_path)
    try:
        policy = effective_policy(policy_path)
        document = render_report(store, title, policy)
        with open(out_path, "w", encoding="utf-8", newline="\n") as output:
            output.write(document)
        return document
    finally:
        store.close()
