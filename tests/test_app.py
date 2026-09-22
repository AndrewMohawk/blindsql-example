import os
import time
import unittest


os.environ.setdefault("ADMIN_PASSWORD", "test-admin-password")  # gitleaks:allow
os.environ.setdefault("CHALLENGE_FLAG", "flag{test-only}")
os.environ.setdefault("SESSION_SECRET", "test-session-secret-not-for-production")

from app import app  # noqa: E402


CONTROL = "admin' AND (CASE WHEN 1=0 THEN sleep_ms(100) ELSE 0 END)=1 -- "
DELAYED = "admin' AND (CASE WHEN 1=1 THEN sleep_ms(100) ELSE 0 END)=1 -- "


class BlindSQLAuthenticationTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)

    @staticmethod
    def post(username, password="wrong"):
        with app.test_client() as client:
            started = time.monotonic()
            response = client.post(
                "/", data={"username": username, "password": password}
            )
            return response, time.monotonic() - started

    def test_control_and_delayed_fail_identically_with_timing_signal(self):
        control, control_elapsed = self.post(CONTROL)
        delayed, delayed_elapsed = self.post(DELAYED)

        self.assertEqual(control.status_code, 401)
        self.assertEqual(delayed.status_code, 401)
        self.assertEqual(control.data, delayed.data)
        self.assertEqual(len(control.data), len(delayed.data))
        for response in (control, delayed):
            self.assertNotIn("Location", response.headers)
            self.assertNotIn("Set-Cookie", response.headers)
            self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertGreater(delayed_elapsed - control_elapsed, 0.075)
        self.assertLess(delayed_elapsed - control_elapsed, 0.175)

    def test_comment_injection_cannot_authenticate(self):
        response, _ = self.post("admin' -- ")
        self.assertEqual(response.status_code, 401)
        self.assertNotIn("Location", response.headers)
        self.assertNotIn("Set-Cookie", response.headers)

    def test_correct_admin_login_still_succeeds(self):
        response, _ = self.post("admin", os.environ["ADMIN_PASSWORD"])
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["Location"], "/")
        self.assertIn("session=", response.headers["Set-Cookie"])

    def test_sql_errors_match_invalid_credentials(self):
        invalid, _ = self.post("nobody")
        syntax_error, _ = self.post("'")
        negative_sleep, _ = self.post("admin' AND sleep_ms(-1)=0 -- ")
        self.assertEqual(invalid.status_code, 401)
        self.assertEqual(invalid.data, syntax_error.data)
        self.assertEqual(invalid.data, negative_sleep.data)


if __name__ == "__main__":
    unittest.main()
