# ASCII-only source: valid UTF-8 on all platforms.
"""
tests/test_ban_network.py -- Unit tests for CIDR network ban support.

Run with:
    python -m pytest tests/test_ban_network.py -v
    # or without pytest:
    python tests/test_ban_network.py
"""

import os
import sys
import unittest
import ipaddress

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel import state
from sentinel.events import _process_log_event
from sentinel.helpers import _normalize_client_ip_or_network


def _reset():
    with state.lock:
        state.banned_ips.clear()
        state.banned_ip_networks.clear()
        state.muted_hits.clear()
        state.ban_notes.clear()


def _event(ip):
    return {
        "level": "info",
        "ts": "2026-01-01T00:00:00.000Z",
        "logger": "http.log.access.test",
        "msg": "handled request",
        "remote_ip": ip,
        "request": {
            "method": "GET",
            "host": "example.test",
            "uri": "/",
            "proto": "HTTP/1.1",
            "headers": {
                "User-Agent": ["Mozilla/5.0 TestAgent/1.0"],
                "Accept": ["text/html"],
            },
        },
        "status": 200,
        "size": 256,
        "duration": 0.001,
        "bytes_read": 128,
    }


class TestCIDRBan(unittest.TestCase):
    def setUp(self):
        _reset()

    def tearDown(self):
        _reset()

    def test_normalize_client_ip_or_network_accepts_cidr(self):
        self.assertEqual(_normalize_client_ip_or_network("203.0.113.0/24"), "203.0.113.0/24")
        self.assertEqual(_normalize_client_ip_or_network("  2001:db8::/32 "), "2001:db8::/32")
        self.assertEqual(_normalize_client_ip_or_network("1.2.3.4"), "1.2.3.4")
        self.assertIsNone(_normalize_client_ip_or_network("not-an-ip"))

    def test_event_banned_by_cidr_network(self):
        with state.lock:
            state.banned_ips.add("203.0.113.0/24")
            state.banned_ip_networks.add(ipaddress.ip_network("203.0.113.0/24"))
        result = _process_log_event(_event("203.0.113.5"))
        self.assertEqual(result, "banned")
        with state.lock:
            self.assertEqual(state.muted_hits.get("203.0.113.5"), 1)


if __name__ == "__main__":
    unittest.main()
