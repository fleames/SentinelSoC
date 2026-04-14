# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/events.py -- _process_log_event: ingest one access-log dict into state.
"""
import sys
import time
from datetime import datetime, timezone

from sentinel import config, state
from sentinel.geo import get_geo, enqueue_geo
from sentinel.helpers import (
    _behavior_bonus,
    _bucket_path,
    _client_ip_from_access,
    _fp_key,
    _ip_subnet,
    _is_static_asset,
    _normalize_caddy_headers,
    _normalize_client_ip,
    _normalize_uri_campaign,
    _update_history_bucket,
    extract_request_host,
    _header_first,
)
from sentinel.parsing import _parse_caddy_access_line
from sentinel.rules import _apply_rules
from sentinel.ua import _ua_tags
from sentinel.persistence import _append_history_event
from sentinel.enrichment import enqueue_reputation


def _process_log_event(data, source=""):
    """Process one Caddy access-log dict. Returns 'ok', 'noreq', or 'banned'."""

    req, status = _parse_caddy_access_line(data)
    if not req:
        return "noreq"

    h_root = _normalize_caddy_headers(data.get("headers"))
    h_req = _normalize_caddy_headers(req.get("headers"))
    headers = {**h_root, **h_req}
    ip_raw = _client_ip_from_access(data, req, headers)
    nip = _normalize_client_ip(ip_raw) if ip_raw else None
    mute_key = nip if nip is not None else (ip_raw.strip() if isinstance(ip_raw, str) else str(ip_raw))
    with state.lock:
        ip_banned = mute_key in state.banned_ips
        if ip_banned:
            state.muted_hits[mute_key] += 1
    if ip_banned:
        return "banned"

    ip = nip if nip is not None else ip_raw

    host = extract_request_host(req, headers)
    ref = _header_first(headers, "Referer", "referer") or "-"
    uri = req.get("uri", "/")
    path_bucket = _bucket_path(uri)
    ua = _header_first(headers, "User-Agent", "user-agent") or ""
    accept_v = _header_first(headers, "Accept", "accept")
    accept_enc_v = _header_first(headers, "Accept-Encoding", "accept-encoding")
    accept_lang_v = _header_first(headers, "Accept-Language", "accept-language")
    cf_ray_v = _header_first(headers, "CF-Ray", "cf-ray", "Cf-Ray")
    cf_ja3_v = _header_first(
        headers,
        "CF-HTTP-Fingerprint", "cf-http-fingerprint",
        "X-JA3-Fingerprint", "x-ja3-fingerprint",
    )
    tls_info = data.get("tls") if isinstance(data.get("tls"), dict) else {}
    tls_cipher_v = str(tls_info.get("cipher_suite", "") or "")
    tls_version_v = str(tls_info.get("version", "") or "")
    # Prefer Cloudflare JA3, fall back to cipher+version composite fingerprint.
    if cf_ja3_v and cf_ja3_v.strip():
        tls_fp_value = cf_ja3_v.strip()[:64]
    elif tls_cipher_v:
        tls_fp_value = "tls:{0}:{1}".format(tls_version_v, tls_cipher_v)
    else:
        tls_fp_value = ""
    ua_norm = (ua or "-").strip().lower()[:160]

    geo = get_geo(ip)
    asn = geo["asn"]
    country = geo.get("country", "??")

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    ts_epoch = time.time()
    fp = _fp_key(
        ip, ua, accept_v,
        accept_enc=accept_enc_v, accept_lang=accept_lang_v,
        tls_cipher=tls_cipher_v, cf_ja3=cf_ja3_v,
    )
    s, matched_rules = _apply_rules({
        "uri": uri,
        "ua": ua,
        "path": path_bucket,
        "status": status,
        "asn": asn,
        "cf_ray": bool(cf_ray_v),
    })

    with state.lock:
        state.counters["total"] += 1
        state.counters["current_second"] += 1
        try:
            state.counters["bytes_served"] += int(data.get("size") or 0)
        except (TypeError, ValueError):
            pass

        state.ips[ip] += 1
        state.domains[host] += 1
        state.referers[ref] += 1
        state.paths[uri] += 1
        state.status_codes[status] += 1

        if 400 <= status < 500:
            state.counters["client_err"] += 1
        elif status >= 500:
            state.counters["server_err"] += 1

        resolved = state.geo_cache.get(ip)
        if resolved is not None:
            asn_u = resolved["asn"]
            country_u = resolved.get("country", "??")
        else:
            asn_u = asn
            country_u = country

        if asn_u == config.PLACEHOLDER_ASN:
            state.pending_geo_hits[ip] += 1
        else:
            state.asn_counts[asn_u] += 1
            state.asn_ips[asn_u].add(ip)
        if country_u and country_u != config.PLACEHOLDER_CC:
            state.countries[country_u] += 1

        state.ip_geo[ip] = resolved if resolved is not None else geo
        state.ip_paths[ip][uri] += 1
        for tg in _ua_tags(ua):
            state.ip_tags[ip].add(tg)

        state.fp_counts[fp] += 1
        state.fp_last_seen[fp] = ts_epoch
        state.ua_to_ips[ua_norm].add(ip)
        state.ip_to_uas[ip].add(ua_norm)

        # TLS / JA3 fingerprint correlation
        if tls_fp_value:
            state.tls_fp_to_ips[tls_fp_value].add(ip)
            state.ip_tls_fp[ip] = tls_fp_value
            if len(state.tls_fp_to_ips[tls_fp_value]) >= config.TLS_FP_SHARED_THRESHOLD:
                state.behavior_signal_counts["shared_tls_fp"] += 1
                state.ip_tags[ip].add("shared_tls_fp")
                s += 4

        # UA impersonation burst: same UA across many IPs within a short window
        if ua_norm and ua_norm != "-":
            wb = state.ua_burst_window.get(ua_norm)
            if wb is None or (ts_epoch - wb["ts_start"]) > config.UA_BURST_WINDOW_S:
                state.ua_burst_window[ua_norm] = {"ts_start": ts_epoch, "ips": {ip}}
            else:
                wb["ips"].add(ip)
                if len(wb["ips"]) >= config.UA_BURST_THRESHOLD:
                    state.behavior_signal_counts["ua_burst"] += 1
                    state.ip_tags[ip].add("ua_burst")
                    s += 8

        b = state.ip_behavior[ip]
        if not b["first_seen"]:
            b["first_seen"] = ts_epoch
        b["last_seen"] = ts_epoch
        b["req_count"] += 1
        if not _is_static_asset(path_bucket) and (len(b["unique_paths"]) < 300 or path_bucket in b["unique_paths"]):
            b["unique_paths"].add(path_bucket)
        if 400 <= status < 500:
            b["status_4xx"] += 1
        elif status >= 500:
            b["status_5xx"] += 1
        if path_bucket in ("/login", "/signin"):
            b["login_hits"] += 1
        if path_bucket in ("/wp-login", "/wp-login.php"):
            b["wp_login_hits"] += 1
        if path_bucket.startswith("/admin"):
            b["admin_hits"] += 1
        if b["last_ua"] and b["last_ua"] != ua_norm:
            b["ua_switches"] += 1
        b["last_ua"] = ua_norm

        state.ip_recent_paths[ip].append(path_bucket)
        b_bonus = _behavior_bonus(ip, ua_norm, path_bucket)
        if b_bonus:
            s += b_bonus

        # Persistence detection: flag IPs seen across multiple calendar days.
        day_str = datetime.fromtimestamp(ts_epoch, tz=timezone.utc).strftime("%Y-%m-%d")
        state.ip_days_seen[ip].add(day_str)
        if len(state.ip_days_seen[ip]) >= config.PERSISTENT_THREAT_DAYS:
            state.ip_tags[ip].add("persistent")
            if s > 0:
                s += 3

        state.ip_scores[ip] += s

        # Auto-enqueue for background reputation enrichment once score is notable
        if state.ip_scores[ip] >= config.REPUTATION_ENRICH_THRESHOLD:
            enqueue_reputation(ip)

        if s > 0:
            state.counters["attack_counter"] += 1
            state.suspicious_hit_buffer.append({
                "ts": time.time(),
                "ip": ip,
                "uri": _normalize_uri_campaign(uri),
                "asn": asn_u,
                "country": country_u,
                "subnet": _ip_subnet(ip),
                "ua": ua_norm,
                "fp": fp,
                "seq": ">".join(list(state.ip_recent_paths[ip])[-3:]),
            })

        if s >= config.SCORE_ALERT_THRESHOLD:
            state.recent_alerts.appendleft(
                {
                    "ts": ts,
                    "ip": ip,
                    "uri": uri[:200],
                    "score": s,
                    "status": status,
                    "country": country_u,
                    "asn": asn_u[:120],
                    "ua": (ua or "-")[:80],
                    "tags": _ua_tags(ua),
                    "rules": matched_rules,
                }
            )
        _update_history_bucket(ts_epoch, ip, path_bucket, status, s)
        if source:
            state.sources[source] += 1

    if country_u == config.PLACEHOLDER_CC or asn_u == config.PLACEHOLDER_ASN:
        enqueue_geo(ip)

    _append_history_event(
        {
            "ts": ts,
            "ts_epoch": ts_epoch,
            "ip": ip,
            "host": host,
            "ua": ua[:200],
            "accept": (accept_v or "")[:120],
            "fingerprint": fp,
            "uri": uri[:220],
            "path": path_bucket,
            "status": int(status),
            "score": int(s),
            "country": country_u,
            "asn": asn_u[:120],
            "tags": _ua_tags(ua),
        }
    )

    return "ok"
