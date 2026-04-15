# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/workers.py -- Background worker threads: reset loop, stream, state flush.
"""
import os
import sys
import time

from sentinel import config, state
from sentinel.events import _process_log_event
from sentinel.helpers import _prune_runtime_state
from sentinel.parsing import iter_caddy_log_objects
from sentinel.persistence import (
    _prune_history_event_files,
    _save_behavior_state,
    _save_history_buckets,
    _save_parsed_state,
)


def reset():
    ticks = 0
    while True:
        time.sleep(1)
        with state.lock:
            state.counters["rps"] = state.counters["current_second"]
            state.counters["peak_rps"] = max(state.counters["peak_rps"], state.counters["rps"])

            state.rps_timeline.append(state.counters["rps"])
            state.attack_timeline.append(state.counters["attack_counter"])
            state.ssh_timeline.append(state.counters.get("ssh_current_second", 0))

            if len(state.rps_timeline) > 60:
                state.rps_timeline.pop(0)
            if len(state.attack_timeline) > 60:
                state.attack_timeline.pop(0)
            if len(state.ssh_timeline) > 180:
                state.ssh_timeline.pop(0)

            state.counters["current_second"] = 0
            state.counters["attack_counter"] = 0
            state.counters["ssh_current_second"] = 0
            ticks += 1
            if ticks % 30 == 0:
                _prune_runtime_state()
        if ticks % 60 == 0:
            _prune_history_event_files()


def reset_dashboard_state():
    """Clear all counters, timelines, geo cache, and alerts. Log reader thread keeps running."""
    with state.geo_lock:
        state.geo_queue.clear()
    with state.lock:
        state.ips.clear()
        state.domains.clear()
        state.referers.clear()
        state.paths.clear()
        state.status_codes.clear()
        state.asn_counts.clear()
        state.countries.clear()
        state.ip_scores.clear()
        state.ip_geo.clear()
        state.ip_paths.clear()
        state.ip_tags.clear()
        state.asn_ips.clear()
        state.geo_cache.clear()
        state.recent_alerts.clear()
        state.pending_geo_hits.clear()
        state.counters["rps"] = 0
        state.counters["total"] = 0
        state.counters["current_second"] = 0
        state.counters["peak_rps"] = 0
        state.counters["attack_counter"] = 0
        state.counters["client_err"] = 0
        state.counters["server_err"] = 0
        state.counters["bytes_served"] = 0
        state.rps_timeline.clear()
        state.attack_timeline.clear()
        state.counters["stream_started_at"] = time.time()
        state.muted_hits.clear()
        state.stream_parse_debug["text_lines"] = 0
        state.stream_parse_debug["json_roots"] = 0
        state.stream_parse_debug["dicts_yielded"] = 0
        state.stream_parse_debug["buffer_overflows"] = 0
        state.suspicious_hit_buffer.clear()
        state.fp_counts.clear()
        state.fp_last_seen.clear()
        state.ua_to_ips.clear()
        state.ip_to_uas.clear()
        state.ip_behavior.clear()
        state.ip_recent_paths.clear()
        state.ip_days_seen.clear()
        state.auth_fail_counts.clear()
        state.sources.clear()
        state.behavior_signal_counts.clear()
        state.history_buckets.clear()
    with state.botnet_lock:
        state.botnet_campaigns.clear()
    with state.lock:
        state.tls_fp_to_ips.clear()
        state.ip_tls_fp.clear()
        state.ua_burst_window.clear()
        state.ip_hosts.clear()
        state.ssh_ips.clear()
        state.ssh_total = 0
        state.ssh_usernames.clear()
        state.ssh_ip_users.clear()
        state.ssh_countries.clear()
        state.ssh_asns.clear()
        state.ssh_timeline.clear()
        state.ssh_recent_alerts.clear()
        state.ssh_history_events.clear()
        state.counters["ssh_current_second"] = 0
    with state.reputation_lock:
        state.reputation_queue.clear()
        state.reputation_seen.clear()


def stream(path=None, from_start=None, source_label=None):
    log_path = path or config._effective_log_path()
    from_start_flag = from_start if from_start is not None else config._effective_log_from_start()
    if source_label is None:
        source_label = log_path

    if state.counters["stream_started_at"] is None:
        state.counters["stream_started_at"] = time.time()
    print(
        f"[sentinel] log tail path={log_path!r} LOG_FROM_START={from_start_flag} source={source_label!r}",
        file=sys.stderr,
        flush=True,
    )
    objects_seen = 0
    no_request = 0
    ingested = 0
    diag_issued = False
    try:
        for data in iter_caddy_log_objects(log_path, from_start=from_start_flag):
            if not isinstance(data, dict):
                continue
            objects_seen += 1

            result = _process_log_event(data, source=source_label)
            if result == "noreq":
                no_request += 1
                if no_request <= 2:
                    print(
                        f"[sentinel] skip non-access JSON object; sample keys={list(data.keys())[:25]}",
                        file=sys.stderr,
                        flush=True,
                    )
                continue
            if result != "ok":
                continue

            ingested += 1
            if from_start_flag and ingested > 0 and ingested % 25000 == 0:
                print(
                    f"[sentinel] replay progress: {ingested} lines ingested from {log_path!r}",
                    file=sys.stderr,
                    flush=True,
                )

            if not diag_issued and objects_seen >= 200 and ingested == 0:
                diag_issued = True
                try:
                    st = os.stat(log_path)
                    sz = st.st_size
                except OSError:
                    sz = -1
                print(
                    f"[sentinel] ingest stalled: parsed {objects_seen} JSON objects, 0 access records; "
                    f"no_request={no_request} file_bytes={sz} "
                    f"(check LOG_PATH and that objects look like Caddy access logs)",
                    file=sys.stderr,
                    flush=True,
                )
    except Exception:
        import traceback
        traceback.print_exc()


def _state_flush_worker():
    while True:
        time.sleep(20)
        try:
            _save_parsed_state()
            _save_behavior_state()
            _save_history_buckets()
            _prune_history_event_files()
        except Exception:
            pass
