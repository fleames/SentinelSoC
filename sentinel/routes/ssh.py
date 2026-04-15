# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/routes/ssh.py -- SSH attack dashboard page and data endpoint.
"""
from datetime import datetime, timezone

from flask import Blueprint, jsonify, render_template, request

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

        # Auth method totals
        auth_totals = dict(state.ssh_auth_method_totals)

        # Top SSH public key fingerprints (LogLevel VERBOSE)
        top_key_fps = []
        for fp, attempts in state.ssh_key_fps.most_common(20):
            ip_count = len(state.ssh_key_fp_ips.get(fp, set()))
            top_key_fps.append({
                "fp": fp,
                "attempts": attempts,
                "ip_count": ip_count,
            })

        # Credential campaigns — clusters of IPs sharing the same wordlist fingerprint
        campaigns = []
        for fp, ips in state.ssh_wordlist_campaigns.items():
            if len(ips) < 2:
                continue
            ip_list = sorted(ips, key=lambda x: -state.ssh_ips.get(x, 0))
            total_hits = sum(state.ssh_ips.get(ip, 0) for ip in ip_list)
            campaigns.append({
                "fp": fp,
                "fp_short": fp[:8],
                "ip_count": len(ip_list),
                "total_hits": total_hits,
                "top_ips": ip_list[:5],
            })
        campaigns.sort(key=lambda c: (-c["ip_count"], -c["total_hits"]))

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
        "auth_totals": auth_totals,
        "campaigns": campaigns,
        "top_key_fps": top_key_fps,
        "server_time": datetime.now(timezone.utc).isoformat(),
    })


@bp.route("/api/ssh/ip")
def api_ssh_ip():
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "ip required"}), 400
    with state.lock:
        hits = state.ssh_ips.get(ip, 0)
        score = state.ip_scores.get(ip, 0)
        g = state.ip_geo.get(ip, {})
        if not isinstance(g, dict):
            g = {}
        user_counts = dict(state.ssh_ip_users.get(ip, {}))
        tags = sorted(state.ip_tags.get(ip, ()))
        b = dict(state.ip_behavior.get(ip, {}))
        days_seen = sorted(state.ip_days_seen.get(ip, set()))
        auth_methods = dict(state.ssh_ip_auth_methods.get(ip, {}))
        wordlist_fp = state.ssh_ip_wordlist_fp.get(ip, "")
        campaign_size = len(state.ssh_wordlist_campaigns.get(wordlist_fp, set())) if wordlist_fp else 0
        key_fps = sorted(state.ssh_ip_key_fps.get(ip, set()))

    users_sorted = sorted(user_counts.items(), key=lambda x: -x[1])
    return jsonify({
        "ip": ip,
        "hits": hits,
        "score": score,
        "country": g.get("country", "?"),
        "asn": (g.get("asn") or "")[:120],
        "tags": tags,
        "users": [{"user": u, "attempts": n} for u, n in users_sorted],
        "unique_users": len(users_sorted),
        "auth_methods": auth_methods,
        "wordlist_fp": wordlist_fp,
        "campaign_size": campaign_size,
        "key_fps": [
            {"fp": fp, "shared_ips": len(state.ssh_key_fp_ips.get(fp, set()))}
            for fp in key_fps
        ],
        "behavior": {
            "first_seen": b.get("first_seen"),
            "last_seen": b.get("last_seen"),
            "req_count": b.get("req_count", 0),
        },
        "days_seen": days_seen,
    })
