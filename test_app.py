import hashlib
import hmac
import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import app as poc
from password_hash import encode_password_hash


class ConnectCloudPocTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ,
            {
                "EDITOR_USERNAME": "poc-editor",
                "EDITOR_PASSWORD_HASH": encode_password_hash("a-long-test-password"),
                "DEMO_HMAC_SECRET": "server-only-poc-secret",
                "COOKIE_SECURE": "false",
            },
            clear=False,
        )
        self.env.start()
        poc.sessions.clear()
        poc.login_attempts.clear()
        self.client = TestClient(poc.app)
        self.origin = {"Origin": "http://testserver"}

    def tearDown(self):
        self.client.close()
        self.env.stop()
        poc.sessions.clear()
        poc.login_attempts.clear()

    def login(self):
        return self.client.post(
            "/api/login",
            headers=self.origin,
            json={"username": "poc-editor", "password": "a-long-test-password"},
        )

    def test_static_page_and_public_api_are_available_without_login(self):
        page = self.client.get("/")
        public = self.client.get("/api/public")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Static page and protected API", page.text)
        self.assertEqual(public.status_code, 200)
        self.assertEqual(public.json()["role"], "reader")

    def test_api_secret_is_used_server_side_and_not_returned(self):
        denied = self.client.post(
            "/api/sign",
            headers={**self.origin, "X-CSRF-Token": "missing"},
            json={"message": "proof"},
        )
        self.assertEqual(denied.status_code, 401)

        signed_in = self.login()
        self.assertEqual(signed_in.status_code, 200)
        csrf = signed_in.json()["csrf_token"]
        signed = self.client.post(
            "/api/sign",
            headers={**self.origin, "X-CSRF-Token": csrf},
            json={"message": "proof"},
        )
        expected = hmac.new(
            b"server-only-poc-secret", b"proof", hashlib.sha256
        ).hexdigest()
        self.assertEqual(signed.status_code, 200)
        self.assertEqual(signed.json()["signature"], expected)
        self.assertFalse(signed.json()["secret_returned_to_browser"])
        self.assertNotIn("server-only-poc-secret", signed.text)

    def test_login_checks_hash_and_rejects_cross_origin(self):
        wrong = self.client.post(
            "/api/login",
            headers=self.origin,
            json={"username": "poc-editor", "password": "incorrect-password"},
        )
        cross_origin = self.client.post(
            "/api/login",
            headers={"Origin": "https://attacker.example"},
            json={"username": "poc-editor", "password": "a-long-test-password"},
        )
        self.assertEqual(wrong.status_code, 401)
        self.assertEqual(cross_origin.status_code, 403)
        self.assertTrue(self.login().json()["authenticated"])

    def test_session_expires_after_ten_minutes_without_activity(self):
        self.assertEqual(self.login().status_code, 200)
        current_time = poc.time.time()
        with patch("app.time.time", return_value=current_time + poc.SESSION_TTL_SECONDS + 1):
            expired = self.client.get("/api/session")
        self.assertFalse(expired.json()["authenticated"])

    def test_activity_slides_session_and_refreshes_cookie(self):
        self.assertEqual(self.login().status_code, 200)
        current_time = poc.time.time()
        with patch("app.time.time", return_value=current_time + 9 * 60):
            refreshed = self.client.get("/api/public")
        self.assertIn("Max-Age=600", refreshed.headers["set-cookie"])
        with patch("app.time.time", return_value=current_time + 9 * 60 + 1):
            still_signed_in = self.client.get("/api/session")
        self.assertTrue(still_signed_in.json()["authenticated"])

    def test_write_requires_csrf_token(self):
        self.assertEqual(self.login().status_code, 200)
        rejected = self.client.post(
            "/api/sign",
            headers=self.origin,
            json={"message": "proof"},
        )
        self.assertEqual(rejected.status_code, 403)


if __name__ == "__main__":
    unittest.main()
