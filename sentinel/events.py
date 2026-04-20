# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/events.py -- _process_log_event: ingest one access-log dict into state.
"""
import hashlib
import ipaddress
import math
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
    _is_whitelisted_path,
    _normalize_caddy_headers,
    _normalize_client_ip,
    _normalize_uri_campaign,
    _update_history_bucket,
    _update_ssh_history_bucket,
    _is_protected_ip,
    extract_request_host,
    _header_first,
)
from sentinel.parsing import _parse_caddy_access_line
from sentinel.rules import _apply_rules
from sentinel.ua import _ua_tags
from sentinel.persistence import _append_history_event, _append_ssh_history_event
from sentinel.enrichment import enqueue_reputation


def _ssh_port_entropy(ports):
    """Shannon entropy in bits of the source-port histogram for one IP.
    Returns 0.0 when fewer than 10 samples are available."""
    if len(ports) < 10:
        return 0.0
    from collections import Counter as _Counter
    counts = _Counter(ports)
    total = sum(counts.values())
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


def _update_ssh_wordlist_fp(ip):
    """Recompute the wordlist fingerprint for an SSH attacker IP.
    Must be called inside state.lock. Minimum 3 unique usernames required."""
    user_counts = state.ssh_ip_users.get(ip)
    if not user_counts or len(user_counts) < 3:
        return
    fp = hashlib.sha256(",".join(sorted(user_counts.keys())).encode()).hexdigest()[:16]
    old_fp = state.ssh_ip_wordlist_fp.get(ip)
    if old_fp == fp:
        return
    if old_fp:
        state.ssh_wordlist_campaigns[old_fp].discard(ip)
        if not state.ssh_wordlist_campaigns[old_fp]:
            del state.ssh_wordlist_campaigns[old_fp]
    state.ssh_ip_wordlist_fp[ip] = fp
    state.ssh_wordlist_campaigns[fp].add(ip)


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
        if not ip_banned and nip is not None:
            try:
                ip_addr = ipaddress.ip_address(nip)
                ip_banned = any(ip_addr in net for net in state.banned_ip_networks)
            except ValueError:
                ip_banned = False
        ip_whitelisted = mute_key in state.whitelisted_ips
        if ip_banned:
            state.muted_hits[mute_key] += 1
    if ip_whitelisted:
        return "ok"
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
    # Belt-and-suspenders: static assets must never carry a non-zero score
    # even if a rule slipped through (e.g. origin_bypass on direct-CDN hits).
    if s and _is_static_asset(path_bucket):
        s = 0
        matched_rules = []

    # Analyst-managed path whitelist: zero score, skip path/history tracking.
    _path_whitelisted = _is_whitelisted_path(path_bucket)
    if _path_whitelisted:
        s = 0
        matched_rules = []

    is_ssh = (source == "ssh")
    ssh_auth_method  = (_header_first(headers, "X-SSH-Auth-Method", "x-ssh-auth-method") or "") if is_ssh else ""
    ssh_key_fp       = (_header_first(headers, "X-SSH-Key-Fp",  "x-ssh-key-fp")  or "") if is_ssh else ""
    ssh_kex_fp       = (_header_first(headers, "X-SSH-Kex-Fp",  "x-ssh-kex-fp")  or "") if is_ssh else ""
    ssh_src_port_raw = (_header_first(headers, "X-SSH-Src-Port", "x-ssh-src-port") or "") if is_ssh else ""
    ssh_pw_event     = (_header_first(headers, "X-SSH-PW-Event", "x-ssh-pw-event") or "") if is_ssh else ""
    ssh_password     = (_header_first(headers, "X-SSH-Password", "x-ssh-password") or "") if is_ssh else ""
    ssh_auto_ban_ip = None
    ssh_auto_ban_reason = ""

    with state.lock:
        # Password-only event from the PAM log: store user+password combo.
        # All other SSH counters (ssh_total, ssh_ips, usernames, etc.) are driven
        # by the regular auth.log/journal events to avoid double-counting.
        if is_ssh and ssh_pw_event:
            if ip:
                ssh_user_pw = ua[len("SSH-client/"):].strip() if ua.startswith("SSH-client/") else ""
                combo_key = f"{ssh_user_pw}||{ssh_password}"
                state.ssh_combos[combo_key] += 1
                state.ssh_ip_combos[ip][combo_key] += 1
            return "ok"

        if is_ssh:
            state.ssh_total += 1
            state.ssh_ips[ip] += 1
            ssh_ip_tries = state.ssh_ips[ip]
            state.counters["ssh_current_second"] = state.counters.get("ssh_current_second", 0) + 1
            if (
                config.SSH_AUTO_BAN_TRIES > 0
                and config.SSH_AUTO_BAN_TTL_S > 0
                and ssh_ip_tries >= config.SSH_AUTO_BAN_TRIES
                and ip not in state.banned_ips
                and not _is_protected_ip(ip)
            ):
                ssh_auto_ban_ip = ip
                ssh_auto_ban_reason = f"ssh_fail_{ssh_ip_tries}x"
            # Extract username from synthetic UA: SSH-client/<username>
            ssh_user = ua[len("SSH-client/"):].strip() if ua.startswith("SSH-client/") else ""
            if ssh_user:
                state.ssh_usernames[ssh_user] += 1
                state.ssh_ip_users[ip][ssh_user] += 1
            # Auth method tracking
            if ssh_auth_method:
                state.ssh_ip_auth_methods[ip][ssh_auth_method] += 1
                state.ssh_auth_method_totals[ssh_auth_method] += 1
            # Wordlist fingerprint — recompute when a new username is added
            if ssh_user:
                _update_ssh_wordlist_fp(ip)
            # SSH public key fingerprint (LogLevel VERBOSE only)
            if ssh_key_fp:
                state.ssh_key_fps[ssh_key_fp] += 1
                state.ssh_ip_key_fps[ip].add(ssh_key_fp)
                state.ssh_key_fp_ips[ssh_key_fp].add(ip)
                if len(state.ssh_key_fp_ips[ssh_key_fp]) >= 2:
                    state.ip_tags[ip].add("shared_ssh_key")
            # SSH KEX / cipher-suite fingerprint (LogLevel VERBOSE kex: lines)
            if ssh_kex_fp:
                state.ssh_kex_fps[ssh_kex_fp] += 1
                state.ssh_ip_kex_fp[ip] = ssh_kex_fp
                state.ssh_kex_fp_ips[ssh_kex_fp].add(ip)
                if len(state.ssh_kex_fp_ips[ssh_kex_fp]) >= config.SSH_KEX_SHARED_THRESHOLD:
                    state.ip_tags[ip].add("shared_ssh_kex")
            # Source port entropy — track port history and tag sequential/fixed-port botnets
            if ssh_src_port_raw:
                try:
                    state.ssh_ip_src_ports[ip].append(int(ssh_src_port_raw))
                    ports = state.ssh_ip_src_ports[ip]
                    if len(ports) >= 10 and len(ports) % 10 == 0:
                        ent = _ssh_port_entropy(ports)
                        state.ssh_ip_port_entropy[ip] = round(ent, 2)
                        if ent < config.SSH_PORT_ENTROPY_LOW:
                            state.ip_tags[ip].add("low_port_entropy")
                except (ValueError, TypeError):
                    pass
        else:
            state.counters["total"] += 1
            state.counters["current_second"] += 1
            try:
                state.counters["bytes_served"] += int(data.get("size") or 0)
            except (TypeError, ValueError):
                pass

            state.ips[ip] += 1
            state.domains[host] += 1
            state.referers[ref] += 1
            if not _is_static_asset(path_bucket) and not _path_whitelisted:
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
            if not is_ssh:
                state.asn_counts[asn_u] += 1
                state.asn_ips[asn_u].add(ip)
            else:
                state.ssh_asns[asn_u] += 1
        if country_u and country_u != config.PLACEHOLDER_CC:
            if not is_ssh:
                state.countries[country_u] += 1
            else:
                state.ssh_countries[country_u] += 1

        state.ip_geo[ip] = resolved if resolved is not None else geo
        if not _is_static_asset(path_bucket) and not _path_whitelisted:
            state.ip_paths[ip][uri] += 1
        state.ip_hosts[ip].add(host)
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
        # Only count login/admin pressure on auth failures — normal page visits
        # (including RSC prefetches returning 200) should not inflate the score.
        if status in (401, 403):
            if path_bucket in ("/login", "/signin", "/ssh"):
                b["login_hits"] += 1
            if path_bucket in ("/wp-login", "/wp-login.php"):
                b["wp_login_hits"] += 1
            if path_bucket.startswith("/admin"):
                b["admin_hits"] += 1
        if b["last_ua"] and b["last_ua"] != ua_norm:
            b["ua_switches"] += 1
        b["last_ua"] = ua_norm
        if ref == "-":
            b["no_ref_hits"] = b.get("no_ref_hits", 0) + 1

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

        alert_row = {
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
        if s >= config.SCORE_ALERT_THRESHOLD:
            if is_ssh:
                state.ssh_recent_alerts.appendleft(alert_row)
            else:
                state.recent_alerts.appendleft(alert_row)

        if is_ssh:
            _update_ssh_history_bucket(ts_epoch)
        else:
            _update_history_bucket(ts_epoch, ip, path_bucket, status, s)
        if source:
            state.sources[source] += 1

    if ssh_auto_ban_ip:
        from sentinel.auth import _auto_ban
        _auto_ban(ssh_auto_ban_ip, ssh_auto_ban_reason, ttl_s=config.SSH_AUTO_BAN_TTL_S)

    if country_u == config.PLACEHOLDER_CC or asn_u == config.PLACEHOLDER_ASN:
        enqueue_geo(ip)

    event_row = {
        "ts": ts,
        "ts_epoch": ts_epoch,
        "ip": ip,
        "host": host,
        "ref": ref if ref != "-" else "",
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
    if is_ssh:
        # SSH events: in-memory ring + disk file
        with state.lock:
            state.ssh_history_events.appendleft(event_row)
        _append_ssh_history_event(event_row)
    elif not _path_whitelisted and (s > 0 or not _is_static_asset(path_bucket)):
        # Skip logging zero-score static assets and whitelisted paths to history.
        _append_history_event(event_row)

    return "ok"
