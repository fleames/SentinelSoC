# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/routes/main.py -- /health and /data endpoints.
"""
import time
from collections import Counter
from datetime import datetime, timezone

from flask import Blueprint, Response, jsonify

from sentinel import config, state
from sentinel.botnet import _campaign_for_api
from sentinel.helpers import threat_level_label

bp = Blueprint("main", __name__)


@bp.route("/health")
def health():
    return Response("ok\n", 200, {"Content-Type": "text/plain; charset=utf-8"})


@bp.route("/data")
def data():
    with state.lock:
        rps_now = state.counters["rps"]
        peak_now = state.counters["peak_rps"]
        total_now = state.counters["total"]
        client_err_now = state.counters["client_err"]
        server_err_now = state.counters["server_err"]
        uniq = len(state.ips)
        te = client_err_now + server_err_now
        err_rate = round(100.0 * te / total_now, 2) if total_now else 0.0
        top_ip_n = state.ips.most_common(1)
        top_share = round(100.0 * top_ip_n[0][1] / total_now, 1) if total_now and top_ip_n else 0.0
        attack_rps = state.attack_timeline[-1] if state.attack_timeline else 0
        level, level_color = threat_level_label(attack_rps, err_rate, top_share)

        top_threats = sorted(state.ip_scores.items(), key=lambda x: -x[1])[:20]
        threats_enriched = []
        for tip, sc in top_threats:
            if sc <= 0:
                continue
            g = state.ip_geo.get(tip, {})
            if not isinstance(g, dict):
                g = {}
            top_path = state.ip_paths[tip].most_common(1)
            p = top_path[0][0] if top_path else ""
            threats_enriched.append(
                {
                    "ip": tip,
                    "score": sc,
                    "hits": state.ips[tip],
                    "country": g.get("country", "?"),
                    "asn": (g.get("asn") or "")[:100],
                    "top_path": p[:120],
                    "tags": sorted(state.ip_tags.get(tip, ())),
                }
            )

        alerts_list = list(state.recent_alerts)[:50]

        stream_started_at = state.counters["stream_started_at"]
        uptime_s = int(time.time() - stream_started_at) if stream_started_at else None
        bytes_served_now = int(state.counters["bytes_served"])
        muted_total = int(sum(state.muted_hits.values()))
        sources_snapshot = dict(state.sources)
        banned_sorted = sorted(state.banned_ips)
        muted_dict = {k: int(state.muted_hits[k]) for k in banned_sorted}
        ip_tags_payload = {k: sorted(v) for k, v in state.ip_tags.items() if v}
        ips_top = state.ips.most_common(15)
        domains_top = state.domains.most_common(10)
        referers_top = state.referers.most_common(10)
        paths_top = state.paths.most_common(10)
        status_snapshot = {str(k): int(v) for k, v in state.status_codes.items()}
        asn_top = state.asn_counts.most_common(10)
        countries_top = state.countries.most_common(12)
        scores_snapshot = dict(state.ip_scores)
        geo_snapshot = {}
        for k, v in state.ip_geo.items():
            if isinstance(v, dict):
                geo_snapshot[k] = {
                    "country": str(v.get("country", "??") or "??"),
                    "asn": str(v.get("asn", "Unknown") or "Unknown"),
                }
            else:
                geo_snapshot[k] = {"country": "??", "asn": "Unknown"}
        rps_timeline_snapshot = list(state.rps_timeline)
        attack_timeline_snapshot = list(state.attack_timeline)
        stream_parse_debug_snapshot = dict(state.stream_parse_debug)
        fp_total = int(sum(state.fp_counts.values()))
        fp_unique = int(len(state.fp_counts))
        ua_cluster_max = int(max((len(v) for v in state.ua_to_ips.values()), default=0))
        ip_behavior_count = int(len(state.ip_behavior))
        behavior_signal_snapshot = {k: int(v) for k, v in state.behavior_signal_counts.items()}
        history_bucket_count = int(len(state.history_buckets))
        history_latest = int(max(state.history_buckets.keys()) if state.history_buckets else 0)

    # Snapshot botnet campaigns under their own lock (after releasing main lock)
    with state.botnet_lock:
        campaigns_snapshot = [
            _campaign_for_api(c)
            for c in sorted(
                state.botnet_campaigns.values(),
                key=lambda c: -int((c if isinstance(c, dict) else {}).get("confidence", 0) or 0),
            )
        ]

    return jsonify(
        {
            "rps": rps_now,
            "peak": peak_now,
            "total": total_now,
            "unique_ips": uniq,
            "client_errors": client_err_now,
            "server_errors": server_err_now,
            "error_rate_pct": err_rate,
            "threat_level": level,
            "threat_color": level_color,
            "attack_rps_last_tick": attack_rps,
            "stream_uptime_s": uptime_s,
            "ips": ips_top,
            "domains": domains_top,
            "referers": referers_top,
            "paths": paths_top,
            "status": status_snapshot,
            "asn": asn_top,
            "countries": countries_top,
            "scores": scores_snapshot,
            "geo": geo_snapshot,
            "top_threats": threats_enriched,
            "alerts": alerts_list,
            "botnet_campaigns": campaigns_snapshot,
            "rps_timeline": rps_timeline_snapshot,
            "attack_timeline": attack_timeline_snapshot,
            "server_time": datetime.now(timezone.utc).isoformat(),
            "banned_ips": banned_sorted,
            "muted_hits": muted_dict,
            "muted_total": muted_total,
            "bytes_served": bytes_served_now,
            "iptables_enabled": config.IPTABLES_ENABLED,
            "iptables_chain": config.IPTABLES_CHAIN,
            "auth_enabled": config.AUTH_ENABLED,
            "audit_log": bool(config.AUDIT_LOG_PATH),
            "audit_path": config.AUDIT_LOG_PATH,
            "state_dir": config.STATE_DIR,
            "ban_list_path": config.BAN_LIST_PATH,
            "parsed_state_path": config.PARSED_STATE_PATH,
            "log_path": config._effective_log_path(),
            "log_paths": config._effective_log_paths(),
            "log_from_start": config._effective_log_from_start(),
            "ingest_enabled": True,
            "sources": sources_snapshot,
            "stream_parse_debug": stream_parse_debug_snapshot,
            "ip_tags": ip_tags_payload,
            "fingerprint_stats": {
                "unique": fp_unique,
                "total_hits": fp_total,
                "largest_ua_cluster_ips": ua_cluster_max,
            },
            "behavior_stats": {
                "tracked_ips": ip_behavior_count,
                "signals": behavior_signal_snapshot,
            },
            "history_stats": {
                "retention_days": config.HISTORY_RETENTION_DAYS,
                "bucket_count": history_bucket_count,
                "latest_bucket_ts": history_latest,
            },
        }
    )


@bp.route("/api/reset", methods=["POST"])
def api_reset():
    from sentinel.workers import reset_dashboard_state
    from sentinel.persistence import _save_parsed_state, _save_behavior_state, _save_history_buckets
    from sentinel.auth import _audit_write, _audit_actor
    reset_dashboard_state()
    _save_parsed_state()
    _save_behavior_state()
    _save_history_buckets()
    _audit_write("reset", _audit_actor(), {})
    return jsonify({"ok": True})
