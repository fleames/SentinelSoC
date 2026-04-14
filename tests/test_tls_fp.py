# ASCII-only source: valid UTF-8 on all platforms.
"""
tests/test_tls_fp.py -- Unit tests for TLS/JA3 fingerprint correlation.

Run with:
    python -m pytest tests/test_tls_fp.py -v
    # or without pytest:
    python tests/test_tls_fp.py

Tests cover:
 - CF-HTTP-Fingerprint header is preferred as the fingerprint value
 - tls.cipher_suite + tls.version is used as the fallback composite key
 - IPs below TLS_FP_SHARED_THRESHOLD do not receive shared_tls_fp tag
 - The IP that pushes the count to threshold gets the tag + score bonus
 - IPs added after threshold is already met continue to get tagged
 - behavior_signal_counts["shared_tls_fp"] increments correctly
 - Long fingerprints are truncated to 64 characters
 - Events with no TLS info produce no fp entry in state
 - IPs with different fingerprints are never cross-contaminated
"""

import sys
import os
import unittest
from collections import defaultdict

# Ensure the repo root is importable regardless of how the test is invoked.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel import config, state
from sentinel.events import _process_log_event


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset():
    """Reset every piece of shared state touched by TLS-FP tests."""
    with state.lock:
        state.ips.clear()
        state.ip_scores.clear()
        state.ip_tags.clear()
        state.ip_geo.clear()
        state.ip_paths.clear()
        state.ip_behavior.clear()
        state.ip_days_seen.clear()
        state.ip_to_uas.clear()
        state.ua_to_ips.clear()
        state.ua_burst_window.clear()
        state.domains.clear()
        state.paths.clear()
        state.referers.clear()
        state.status_codes.clear()
        state.fp_counts.clear()
        state.fp_last_seen.clear()
        state.tls_fp_to_ips.clear()
        state.ip_tls_fp.clear()
        state.behavior_signal_counts.clear()
        state.asn_counts.clear()
        state.asn_ips.clear()
        state.countries.clear()
        state.attack_timeline.clear()
        state.rps_timeline.clear()
        state.recent_alerts.clear()
        state.suspicious_hit_buffer.clear()
        for k in list(state.counters):
            if k != "stream_started_at":
                state.counters[k] = 0


def _event(ip, ja3=None, cipher=None, tls_version=None, status=200,
           ua="Mozilla/5.0 TestAgent/1.0"):
    """
    Build a minimal Caddy-style access log dict that _process_log_event accepts.

    Two ways to supply a TLS fingerprint:
      ja3=<string>        -> goes into request.headers["CF-HTTP-Fingerprint"]
      cipher=<suite>,     -> goes into the top-level "tls" dict;
      tls_version=<ver>      Sentinel composes "tls:{version}:{cipher}" from this.
    """
    evt = {
        "level": "info",
        "ts": "2026-01-01T00:00:00.000Z",
        "logger": "http.log.access.test",
        "msg": "handled request",
        "remote_ip": ip,
        "request": {
            "method": "GET",
            "host": "example.test",
            "uri": "/",
            "proto": "HTTP/2.0",
            "headers": {
                "User-Agent": [ua],
                "Accept": ["text/html"],
            },
        },
        "status": status,
        "size": 512,
        "duration": 0.005,
        "bytes_read": 128,
    }
    if ja3:
        evt["request"]["headers"]["CF-HTTP-Fingerprint"] = [ja3]
    if cipher or tls_version:
        evt["tls"] = {
            "cipher_suite": cipher or "",
            "version": tls_version or "",
        }
    return evt


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestTLSFingerprintStorage(unittest.TestCase):
    """Basic storage: fingerprint values are recorded correctly in state."""

    def setUp(self):
        _reset()
        config.TLS_FP_SHARED_THRESHOLD = 5  # default

    def tearDown(self):
        _reset()
        config.TLS_FP_SHARED_THRESHOLD = 5

    def test_ja3_header_stored_in_ip_tls_fp(self):
        """CF-HTTP-Fingerprint is stored verbatim as state.ip_tls_fp[ip]."""
        _process_log_event(_event("1.0.0.1", ja3="deadbeef12345678"))
        with state.lock:
            self.assertEqual(state.ip_tls_fp.get("1.0.0.1"), "deadbeef12345678")

    def test_ja3_header_stored_in_tls_fp_to_ips(self):
        """The IP is added to state.tls_fp_to_ips[fingerprint]."""
        _process_log_event(_event("1.0.0.2", ja3="deadbeef12345678"))
        with state.lock:
            self.assertIn("1.0.0.2", state.tls_fp_to_ips.get("deadbeef12345678", set()))

    def test_tls_dict_fallback_composite_key(self):
        """When no JA3 header, state uses 'tls:{version}:{cipher}' composite key."""
        _process_log_event(_event("1.0.0.3",
                                  cipher="TLS_AES_256_GCM_SHA384",
                                  tls_version="tls1.3"))
        with state.lock:
            stored = state.ip_tls_fp.get("1.0.0.3")
        self.assertEqual(stored, "tls:tls1.3:TLS_AES_256_GCM_SHA384")

    def test_ja3_takes_priority_over_tls_dict(self):
        """When both JA3 header and tls dict are present, JA3 wins."""
        _process_log_event(_event("1.0.0.4",
                                  ja3="ja3wins",
                                  cipher="TLS_CHACHA20_POLY1305_SHA256",
                                  tls_version="tls1.3"))
        with state.lock:
            stored = state.ip_tls_fp.get("1.0.0.4")
        self.assertEqual(stored, "ja3wins")

    def test_no_tls_info_no_entry(self):
        """Events with no JA3 header and no tls dict leave no fp entry."""
        _process_log_event(_event("1.0.0.5"))
        with state.lock:
            self.assertNotIn("1.0.0.5", state.ip_tls_fp)

    def test_fingerprint_truncated_to_64_chars(self):
        """JA3 values longer than 64 characters are stored truncated."""
        long_fp = "a" * 100
        _process_log_event(_event("1.0.0.6", ja3=long_fp))
        with state.lock:
            stored = state.ip_tls_fp.get("1.0.0.6", "")
        self.assertEqual(len(stored), 64)
        self.assertEqual(stored, "a" * 64)


class TestTLSFingerprintSharedDetection(unittest.TestCase):
    """Threshold detection: tag and score bonus fire at the right moment."""

    THRESHOLD = 3  # small value so tests run with few events

    def setUp(self):
        _reset()
        config.TLS_FP_SHARED_THRESHOLD = self.THRESHOLD

    def tearDown(self):
        _reset()
        config.TLS_FP_SHARED_THRESHOLD = 5

    def _send_n_ips(self, fp, n, ip_prefix="10.0.0."):
        ips = [f"{ip_prefix}{i+1}" for i in range(n)]
        for ip in ips:
            _process_log_event(_event(ip, ja3=fp))
        return ips

    # -- Below threshold --

    def test_below_threshold_no_tag(self):
        """IPs N-1 below threshold must not receive shared_tls_fp tag."""
        ips = self._send_n_ips("fp-below", self.THRESHOLD - 1)
        with state.lock:
            for ip in ips:
                self.assertNotIn(
                    "shared_tls_fp",
                    state.ip_tags.get(ip, set()),
                    msg=f"{ip} tagged prematurely (threshold not yet reached)",
                )

    def test_below_threshold_no_signal_count(self):
        """Signal counter must remain 0 while below threshold."""
        self._send_n_ips("fp-no-signal", self.THRESHOLD - 1)
        with state.lock:
            count = state.behavior_signal_counts.get("shared_tls_fp", 0)
        self.assertEqual(count, 0)

    # -- At threshold --

    def test_nth_ip_receives_tag(self):
        """The IP that pushes unique-ip count to threshold gets shared_tls_fp."""
        ips = self._send_n_ips("fp-exact", self.THRESHOLD)
        last_ip = ips[-1]
        with state.lock:
            tags = state.ip_tags.get(last_ip, set())
        self.assertIn("shared_tls_fp", tags,
                      msg=f"{last_ip} should be tagged when threshold is reached")

    def test_nth_ip_score_bonus(self):
        """The triggering IP should have at least +4 score from the TLS FP bonus."""
        ips = self._send_n_ips("fp-score", self.THRESHOLD)
        last_ip = ips[-1]
        with state.lock:
            score = state.ip_scores.get(last_ip, 0)
        self.assertGreaterEqual(score, 4,
                                msg=f"Expected score >= 4 (TLS bonus), got {score}")

    def test_signal_counter_increments_at_threshold(self):
        """behavior_signal_counts['shared_tls_fp'] increments when threshold is hit."""
        self._send_n_ips("fp-counter", self.THRESHOLD)
        with state.lock:
            count = state.behavior_signal_counts.get("shared_tls_fp", 0)
        self.assertGreater(count, 0)

    # -- Beyond threshold --

    def test_extra_ips_also_tagged(self):
        """IPs joining an already-over-threshold fingerprint also get tagged."""
        ips = self._send_n_ips("fp-extra", self.THRESHOLD + 3, ip_prefix="10.1.0.")
        # all IPs from index THRESHOLD-1 onward should be tagged
        with state.lock:
            for ip in ips[self.THRESHOLD - 1:]:
                self.assertIn("shared_tls_fp", state.ip_tags.get(ip, set()),
                              msg=f"{ip} should be tagged (over threshold)")

    # -- Isolation between fingerprints --

    def test_different_fps_do_not_cross_contaminate(self):
        """Each fingerprint is tracked independently; unique FPs never trigger sharing."""
        for i in range(self.THRESHOLD * 2):
            _process_log_event(_event(f"10.2.0.{i+1}", ja3=f"unique-fp-{i}"))
        with state.lock:
            for i in range(self.THRESHOLD * 2):
                self.assertNotIn("shared_tls_fp",
                                 state.ip_tags.get(f"10.2.0.{i+1}", set()),
                                 msg="Unique FPs must not trigger shared_tls_fp")

    def test_two_separate_shared_clusters(self):
        """Two separate fingerprints each hitting threshold are tracked independently."""
        ips_a = self._send_n_ips("cluster-A", self.THRESHOLD, ip_prefix="10.3.0.")
        ips_b = self._send_n_ips("cluster-B", self.THRESHOLD, ip_prefix="10.4.0.")
        with state.lock:
            self.assertIn("shared_tls_fp", state.ip_tags.get(ips_a[-1], set()),
                          msg="Cluster A's last IP should be tagged")
            self.assertIn("shared_tls_fp", state.ip_tags.get(ips_b[-1], set()),
                          msg="Cluster B's last IP should be tagged")
            # Verify the two fp sets are separate
            self.assertNotIn("10.3.0.1", state.tls_fp_to_ips.get("cluster-B", set()))
            self.assertNotIn("10.4.0.1", state.tls_fp_to_ips.get("cluster-A", set()))

    # -- Composite (tls dict) path --

    def test_shared_detection_via_tls_dict(self):
        """Shared detection works via the tls.cipher+version fallback path too."""
        cipher = "TLS_AES_128_GCM_SHA256"
        ver = "tls1.3"
        expected_fp = f"tls:{ver}:{cipher}"
        ips = [f"10.5.0.{i+1}" for i in range(self.THRESHOLD)]
        for ip in ips:
            _process_log_event(_event(ip, cipher=cipher, tls_version=ver))
        last_ip = ips[-1]
        with state.lock:
            stored_fp = state.ip_tls_fp.get(last_ip)
            tags = state.ip_tags.get(last_ip, set())
        self.assertEqual(stored_fp, expected_fp)
        self.assertIn("shared_tls_fp", tags,
                      msg="shared_tls_fp tag should fire via tls-dict fallback path")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
