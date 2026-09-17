#!/usr/bin/env python3
"""Offline checks for local COM allowlist and login-attempt order."""

import os
import tempfile
import unittest
from pathlib import Path

_tmp = Path(tempfile.mkdtemp(prefix="netdiag-test-"))
os.environ["NETDIAG_SETTINGS"] = str(_tmp / "settings.json")
os.environ["NETDIAG_SECRETS"] = str(_tmp / "secrets.bin")

import netdiag as nd  # noqa: E402


class LocalComTests(unittest.TestCase):
    def test_accepts_local_com(self):
        self.assertTrue(nd.is_local_com_port("COM3"))
        self.assertTrue(nd.is_local_com_port("com12"))
        self.assertTrue(nd.is_local_com_port("\\\\.\\COM12"))

    def test_rejects_remote(self):
        self.assertFalse(nd.is_local_com_port("socket://10.0.0.1:23"))
        self.assertFalse(nd.is_local_com_port("rfc2217://host:1234"))
        self.assertFalse(nd.is_local_com_port(""))
        self.assertFalse(nd.is_local_com_port("COM"))


class LoginAttemptsTests(unittest.TestCase):
    def setUp(self):
        nd.CUSTOMERS.clear()
        nd.CUSTOMERS.append(nd._make_customer("Site", "admin", "fleet"))
        nd.CUSTOMERS[0]["host_secrets"] = [
            {"hostname": "sw1", "username": "u1", "password": "p1"},
            {"hostname": "sw2", "username": "u2", "password": "p2"},
        ]
        nd.ACTIVE_CUSTOMER = "Site"
        nd.LOGIN_MODE = "auto"
        nd.LAST_SUCCESS_USERNAME = ""
        nd.LAST_SUCCESS_PASSWORD = ""
        nd.LAST_SUCCESS_CUSTOMER = ""
        nd._sync_active_aliases()

    def _pairs(self, attempts):
        return [(user, password) for _reason, user, password in attempts]

    def test_auto_without_hint_does_not_spray_hosts(self):
        pairs = self._pairs(nd.list_login_attempts(mode="auto"))
        self.assertEqual(pairs, [("admin", "fleet")])

    def test_auto_with_hint_uses_that_host_then_default(self):
        pairs = self._pairs(nd.list_login_attempts(hostname_hint="sw1", mode="auto"))
        self.assertEqual(pairs, [("u1", "p1"), ("admin", "fleet")])

    def test_manual_hint_does_not_try_other_hosts(self):
        pairs = self._pairs(nd.list_login_attempts(hostname_hint="sw2", mode="manual"))
        self.assertEqual(pairs, [("u2", "p2"), ("admin", "fleet")])

    def test_skip_tries_nothing(self):
        self.assertEqual(nd.list_login_attempts(mode="skip"), [])


if __name__ == "__main__":
    unittest.main()
