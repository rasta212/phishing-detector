import unittest

from phishing_detector import analyze, check_url


class TestAnalyze(unittest.TestCase):

    def test_normal_message_has_no_risk(self):
        result = analyze("Hi, are we still meeting for lunch on Friday?")
        self.assertEqual(result["risk"], "None detected")
        self.assertEqual(result["score"], 0)

    def test_urgent_password_request_is_flagged(self):
        result = analyze(
            "URGENT: your account will be suspended. "
            "Send us your password within 24 hours."
        )
        self.assertIn(result["risk"], {"Medium", "High"})
        self.assertIn("Asks for sensitive information", result["reasons"])
        self.assertIn("Creates urgency or threatens account closure", result["reasons"])

    def test_generic_greeting_adds_to_score(self):
        result = analyze("Dear customer, please review your statement.")
        self.assertIn("Uses a generic greeting instead of your name", result["reasons"])

    def test_suspicious_link_is_flagged(self):
        result = analyze("Log in here: http://192.168.10.5/login")
        self.assertIn("Link points to a raw IP address", result["reasons"])

    def test_trailing_punctuation_is_removed_from_links(self):
        result = analyze("Visit https://bit.ly/x.")
        self.assertIn("https://bit.ly/x", result["urls"])


class TestCheckUrl(unittest.TestCase):

    def test_normal_https_link_is_clean(self):
        self.assertEqual(check_url("https://github.com/"), [])

    def test_www_without_scheme_is_clean(self):
        self.assertEqual(check_url("www.github.com"), [])

    def test_http_link_is_flagged(self):
        self.assertIn("Link uses unencrypted HTTP", check_url("http://example.com"))

    def test_at_sign_trick_is_flagged(self):
        reasons = check_url("https://paypal.com@evil.example/login")
        self.assertTrue(any("@" in r for r in reasons))

    def test_raw_ip_address_is_flagged(self):
        self.assertIn("Link points to a raw IP address", check_url("http://192.168.10.5/login"))

    def test_shortener_is_flagged(self):
        self.assertIn(
            "Link uses a URL shortener that hides the destination",
            check_url("https://bit.ly/abc123"),
        )


if __name__ == "__main__":
    unittest.main()
