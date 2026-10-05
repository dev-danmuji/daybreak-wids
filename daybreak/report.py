"""`daybreak-wids report`: summary of sensor state, alerts, events and AP security."""

from __future__ import annotations

import time
from collections import Counter
from typing import Any

from .alerts.formatting import printable
from .config import Config
from .detectors.security import audit_network, observations_from_rows
from .models import Severity, format_local
from .scoring import explain, threat_level
from .storage import Database


def build_report(config: Config, db: Database, *, since: float, until: float | None = None) -> dict[str, Any]:
    until = until or time.time()
    alerts = [a for a in db.list_alerts(since=since, limit=None) if a["timestamp"] < until]
    by_sev = Counter(a["severity"] for a in alerts)
    by_type = Counter(a["alert_type"] for a in alerts)
    important = [a for a in alerts if Severity.parse(a["severity"]) >= Severity.MEDIUM][:20]
    networks = []
    recommendations: list[str] = []
    for net in config.protected_networks:
        audit = audit_network(net, observations_from_rows(db.list_aps(ssid=net.ssid)))
        info = audit.to_dict()
        net_alerts = [a for a in alerts if a.get("reason", {}).get("network") == net.name]
        info["alerts"] = len(net_alerts)
        info["max_severity"] = max((a["severity"] for a in net_alerts),
                                   key=lambda s: Severity.parse(s), default=None)
        networks.append(info)
        for r in audit.recommendations:
            if r not in recommendations:
                recommendations.append(r)
    baselines = [{"network": b["network"], "created": b["created_at"], "window_start": b["window_start"],
                  "window_end": b["window_end"]} for b in db.active_baselines()]
    return {
        "generated": time.time(),
        "period": {"since": since, "until": until},
        "threat_level": threat_level(alerts),
        "sensor": {"interface": config.sensor.interface, "status": db.latest_sensor_status(limit=5)},
        "alerts": {"total": len(alerts), "by_severity": dict(by_sev), "by_type": dict(by_type.most_common()),
                   "acknowledged": sum(1 for a in alerts if a["acknowledged"]),
                   "important": [{
                       "id": a["id"], "timestamp": a["timestamp"], "severity": a["severity"],
                       "type": a["alert_type"], "score": a["score"], "bssid": a["bssid"],
                       "summary": a["summary"], "suppressed": a["suppressed_count"],
                       "components": a.get("reason", {}).get("components", []),
                   } for a in important]},
        "events": db.event_counts(since=since, until=until),
        "networks": networks,
        "baselines": baselines,
        "recommendations": recommendations,
    }


def render_report(rep: dict[str, Any]) -> str:
    p = rep["period"]
    lines = [
        "DAYBREAK WIDS REPORT",
        f"Period      : {format_local(p['since'])} - {format_local(p['until'])}",
        f"Threat level: {rep['threat_level']}",
        "",
        "Sensor",
        f"  Interface : {rep['sensor']['interface']}",
    ]
    for st in rep["sensor"]["status"][:5]:
        lines.append(f"  {format_local(st['timestamp'])}  {st['status']:<20} {st.get('backend') or ''}")
    a = rep["alerts"]
    sev = ", ".join(f"{s} {a['by_severity'].get(s, 0)}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
    lines += ["", f"Alerts ({a['total']}): {sev}"]
    for t, n in list(a["by_type"].items())[:12]:
        lines.append(f"  {n:>5}  {t}")
    if a["important"]:
        lines += ["", "Notable alerts (MEDIUM and above)"]
        for item in a["important"]:
            lines.append(f"  #{item['id']} {format_local(item['timestamp'])} {item['severity']} {item['type']}"
                         f" {item['bssid'] or ''}".rstrip())
            for line in explain(item["score"], item["components"]):
                lines.append(f"      {line}")
            if item["suppressed"]:
                lines.append(f"      (+{item['suppressed']} similar suppressed by cooldown)")
    ev = rep["events"]
    if ev:
        lines += ["", "Events: " + ", ".join(f"{k} {v}" for k, v in sorted(ev.items()))]
    lines += ["", "Protected networks"]
    for n in rep["networks"]:
        mode = n["mode"] or "not observed"
        lines.append(f"  {n['network']:<12} {n['ssid']:<24} {n['status']:<12} {mode:<22} PMF {n['pmf'] or '-'}"
                     f"  alerts {n['alerts']}")
        if n["unknown_bssids"]:
            label = "candidates" if n["status"] == "unconfigured" else "unregistered BSSIDs"
            lines.append(f"      {label}: {', '.join(n['unknown_bssids'])}")
    lines += ["", "Baselines"]
    if rep["baselines"]:
        for b in rep["baselines"]:
            lines.append(f"  {b['network']:<12} learned {format_local(b['window_start'])} - "
                         f"{format_local(b['window_end'])}")
    else:
        lines.append("  none (run `daybreak-wids baseline create`)")
    if rep["recommendations"]:
        lines += ["", "Recommendations"]
        lines += [f"  - {r}" for r in rep["recommendations"]]
    return "\n".join(printable(line) for line in lines)
