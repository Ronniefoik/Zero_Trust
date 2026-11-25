"""Focused security checks for the local API authorization primitives."""

import tempfile
import unittest
from pathlib import Path

from local_api import (
    AuditLog,
    AuthenticationError,
    LoginMonitor,
    ROLE_SCOPES,
    address_is_allowed,
    hash_password,
    issue_token,
    verify_password,
    verify_token,
)


class PasswordTests(unittest.TestCase):
    def test_scrypt_password_hash_verifies_without_storing_password(self):
        salt, digest = hash_password("przykladowe-bezpieczne-haslo")
        self.assertTrue(verify_password("przykladowe-bezpieczne-haslo", salt, digest))
        self.assertFalse(verify_password("inne-haslo", salt, digest))
        self.assertNotIn("przykladowe-bezpieczne-haslo", digest)


class SessionTests(unittest.TestCase):
    def test_short_lived_session_round_trip(self):
        token = issue_token("ala.audyt", "audytor", b"x" * 48, now=1000)
        payload = verify_token(token, b"x" * 48, set(), now=1001)
        self.assertEqual(payload["sub"], "ala.audyt")
        self.assertEqual(payload["role"], "audytor")
        self.assertEqual(payload["exp"], 1000 + 600)

    def test_tampered_expired_and_revoked_sessions_are_rejected(self):
        secret = b"x" * 48
        token = issue_token("ala.audyt", "audytor", secret, now=1000)
        with self.assertRaises(AuthenticationError):
            header_text, payload_text, signature_text = token.split(".")
            tampered_payload = ("A" if payload_text[0] != "A" else "B") + payload_text[1:]
            verify_token(f"{header_text}.{tampered_payload}.{signature_text}", secret, set(), now=1001)
        with self.assertRaises(AuthenticationError):
            verify_token(token, secret, set(), now=1600)
        payload = verify_token(token, secret, set(), now=1001)
        with self.assertRaises(AuthenticationError):
            verify_token(token, secret, {payload["jti"]}, now=1001)


class AuthorizationTests(unittest.TestCase):
    def test_auditor_has_read_only_scope_and_operator_can_ack(self):
        self.assertIn("telemetry:read", ROLE_SCOPES["audytor"])
        self.assertNotIn("alerts:ack", ROLE_SCOPES["audytor"])
        self.assertIn("alerts:ack", ROLE_SCOPES["operator"])

    def test_network_policy_allows_only_configured_segment(self):
        import ipaddress

        networks = (ipaddress.ip_network("127.0.0.1/32"), ipaddress.ip_network("10.42.0.0/24"))
        self.assertTrue(address_is_allowed("127.0.0.1", networks))
        self.assertTrue(address_is_allowed("10.42.0.9", networks))
        self.assertFalse(address_is_allowed("10.43.0.9", networks))
        self.assertFalse(address_is_allowed("not-an-ip", networks))


class DetectionTests(unittest.TestCase):
    def test_correlated_failures_emit_a_structured_alert(self):
        import json

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "audit.jsonl"
            audit = AuditLog(path)
            try:
                monitor = LoginMonitor()
                monitor.failed("127.0.0.1", audit, now=10)
                monitor.failed("127.0.0.1", audit, now=20)
                monitor.failed("127.0.0.1", audit, now=30)
                records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
                alerts = [record for record in records if record["event"] == "login_anomaly"]
                self.assertEqual(len(alerts), 1)
                self.assertEqual(alerts[0]["failed_attempts"], 3)
                self.assertEqual(alerts[0]["detector"], "correlated_failure_threshold")
                self.assertFalse(monitor.is_blocked("127.0.0.1", now=40))
                monitor.failed("127.0.0.1", audit, now=40)
                monitor.failed("127.0.0.1", audit, now=50)
                self.assertTrue(monitor.is_blocked("127.0.0.1", now=51))
            finally:
                audit.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
