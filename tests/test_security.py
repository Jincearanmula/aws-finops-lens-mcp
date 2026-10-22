"""Offline tests for security.py. No AWS calls, no MCP SDK needed."""

import asyncio
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from security import (  # noqa: E402
    BearerTokenMiddleware, redact_text, require_loopback, sanitize,
    sanitize_cloudtrail_result, sanitize_log_result,
)

FAKE_KEY_ID = "AKIA" + "ABCDEFGHIJKLMNOP"
FAKE_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
TOKEN = "t" * 40


class RedactTextTests(unittest.TestCase):
    def test_masks_aws_keys(self):
        out = redact_text(f"id={FAKE_KEY_ID} secret {FAKE_SECRET}")
        self.assertNotIn(FAKE_KEY_ID, out)
        self.assertNotIn(FAKE_SECRET, out)

    def test_masks_key_value_secrets(self):
        out = redact_text('password=hunter2 api_key: "abc123" token=xyz')
        for secret in ("hunter2", "abc123", "xyz"):
            self.assertNotIn(secret, out)

    def test_masks_bearer_jwt_email_ip_and_connection_strings(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl"
        out = redact_text(f"Authorization: Bearer abcdefgh12345 {jwt} bob@example.com "
                          "from 10.1.2.3 postgres://admin:s3cret@db:5432/app")
        for value in ("abcdefgh12345", jwt, "bob@example.com", "10.1.2.3", "s3cret"):
            self.assertNotIn(value, out)

    def test_masks_private_key(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
        self.assertNotIn("MIIabc", redact_text(pem))

    def test_keeps_ordinary_text_and_versions(self):
        text = "GET /health 200 in 12ms using lib 1.2.3"
        self.assertEqual(redact_text(text), text)

    def test_truncates_long_text(self):
        out = redact_text("x " * 5000)
        self.assertIn("[truncated", out)
        self.assertLess(len(out), 2100)


class SanitizeTests(unittest.TestCase):
    def test_masks_sensitive_keys_but_keeps_pagination(self):
        out = sanitize({"sessionToken": "abc", "next_token": "page2", "nextToken": "p3"})
        self.assertEqual(out["sessionToken"], "[REDACTED]")
        self.assertEqual(out["next_token"], "page2")
        self.assertEqual(out["nextToken"], "p3")

    def test_parses_and_sanitizes_embedded_json(self):
        event = {"responseElements": {"credentials": {"accessKeyId": FAKE_KEY_ID}},
                 "requestParameters": {"instanceType": "m5.large", "password": "pw"},
                 "sourceIPAddress": "203.0.113.9"}
        result = {"events": [{"EventName": "RunInstances", "CloudTrailEvent": json.dumps(event)}]}
        out = sanitize_cloudtrail_result(result)
        ct = out["events"][0]["CloudTrailEvent"]
        self.assertNotIn("responseElements", ct)
        self.assertEqual(ct["requestParameters"]["instanceType"], "m5.large")
        self.assertEqual(ct["requestParameters"]["password"], "[REDACTED]")
        self.assertEqual(ct["sourceIPAddress"], "[REDACTED_IP]")
        self.assertIn("_security_notice", out)
        self.assertNotIn(FAKE_KEY_ID, json.dumps(out))

    def test_log_result_masks_messages(self):
        out = sanitize_log_result({"events": [{"message": f"key {FAKE_KEY_ID} user a@b.io"}]})
        msg = out["events"][0]["message"]
        self.assertNotIn(FAKE_KEY_ID, msg)
        self.assertNotIn("a@b.io", msg)


class AuthTests(unittest.TestCase):
    def _call(self, headers):
        sent = []

        async def app(scope, receive, send):
            sent.append({"status": 200})

        async def send(message):
            if message["type"] == "http.response.start":
                sent.append({"status": message["status"]})

        mw = BearerTokenMiddleware(app, TOKEN)
        asyncio.run(mw({"type": "http", "headers": headers}, None, send))
        return sent[0]["status"]

    def test_rejects_missing_or_wrong_token(self):
        self.assertEqual(self._call([]), 401)
        self.assertEqual(self._call([(b"authorization", b"Bearer wrong")]), 401)

    def test_accepts_correct_token(self):
        self.assertEqual(self._call([(b"authorization", f"Bearer {TOKEN}".encode())]), 200)

    def test_rejects_short_token(self):
        with self.assertRaises(ValueError):
            BearerTokenMiddleware(None, "short")

    def test_require_loopback(self):
        self.assertEqual(require_loopback("127.0.0.1"), "127.0.0.1")
        with self.assertRaises(SystemExit):
            require_loopback("0.0.0.0")


if __name__ == "__main__":
    unittest.main()
