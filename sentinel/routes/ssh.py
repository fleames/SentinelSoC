# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/routes/ssh.py -- SSH attack dashboard page and data endpoint.
"""
from datetime import datetime, timezone

from flask import Blueprint, jsonify, render_template

from sentinel import config, state

bp = Blueprint("ssh", __name__)


@bp.route("/ssh")
def ssh_dashboard():
    return render_template("ssh_dashboard.html")


@bp.route("/api/ssh/data")
def api_ssh_data():
    with state.lock:
        total = state.ssh_total
        unique_ips = len(state.ssh_ips)
        unique_users = len(state.ssh_usernames)
        timeline = list(state.ssh_timeline)

        # Top 50 attacking IPs enriched with geo + top username
        top_ips_raw = state.ssh_ips.most_common(50)
        top_ips = []
        for ip, hits in top_ips_raw:
            g = state.ip_geo.get(ip, {})
            if not isinstance(g, dict):
                g = {}
            user_counts = state.ssh_ip_users.get(ip, {})
            top_user = max(user_counts, key=user_counts.get) if user_counts else ""
            top_user_hits = user_counts[top_user] if top_user else 0
            top_ips.append({
                "ip": ip,
                "hits": hits,
                "score": state.ip_scores.get(ip, 0),
                "country": g.get("country", "?"),
                "asn": (g.get("asn") or "")[:100],
                "tags": sorted(state.ip_tags.get(ip, ())),
                "top_user": top_user,
                "top_user_hits": top_user_hits,
                "unique_users": len(user_counts),
            })

        # Top 100 tried usernames
        top_users = [
            {"user": u, "attempts": n}
            for u, n in state.ssh_usernames.most_common(100)
        ]

        # Top countries + ASNs
        top_countries = state.ssh_countries.most_common(15)
        top_asns = [
            {"asn": a, "hits": n}
            for a, n in state.ssh_asns.most_common(10)
        ]

        # Alert feed + history
        alerts = list(state.ssh_recent_alerts)[:50]
        history = list(state.ssh_history_events)[:100]

    return jsonify({
        "total": total,
        "unique_ips": unique_ips,
        "unique_users": unique_users,
        "timeline": timeline,
        "top_ips": top_ips,
        "top_users": top_users,
        "top_countries": [[c, n] for c, n in top_countries],
        "top_asns": top_asns,
        "alerts": alerts,
        "history": history,
        "server_time": datetime.now(timezone.utc).isoformat(),
    })
