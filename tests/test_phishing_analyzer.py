import unittest

from phishing_analyzer import analyze_email_locally


PHISHING_EMAIL = """Return-Path: <bounce@security-microsoft-login.example>
Authentication-Results: mx.company.example; spf=fail smtp.mailfrom=security-microsoft-login.example; dkim=fail; dmarc=fail
From: "Microsoft 365 Support" <security@security-microsoft-login.example>
Reply-To: support-reset@outlook-support.example
To: employee@company.example
Subject: Urgent: Password expires in 24 hours
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<a href="http://198.51.100.55:8080/login">https://login.microsoftonline.com/</a>
Verify your account immediately.
"""

BENIGN_EMAIL = """Return-Path: <newsletter@example.com>
Authentication-Results: mx.company.example; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com
From: Example Newsletter <newsletter@example.com>
Reply-To: newsletter@example.com
To: employee@company.example
Subject: Monthly security newsletter
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Read the newsletter at https://example.com/security-news.
"""


class PhishingAnalyzerTests(unittest.TestCase):
    def test_detects_phishing_email_indicators(self):
        result = analyze_email_locally(PHISHING_EMAIL)
        finding_names = {item["name"] for item in result["findings"]}

        self.assertIn("SPF failed", finding_names)
        self.assertIn("DKIM failed", finding_names)
        self.assertIn("DMARC failed", finding_names)
        self.assertIn("From and Reply-To domain mismatch", finding_names)
        self.assertIn("URL uses IP address instead of domain", finding_names)
        self.assertIn("Non-standard URL port", finding_names)
        self.assertIn("Displayed link text does not match destination", finding_names)
        self.assertIn("198.51.100.55:8080", result["iocs"]["port"])
        self.assertGreaterEqual(result["risk_score"], 80)
        self.assertTrue(result["network_precheck"]["suspicious"])
        self.assertEqual(result["network_precheck"]["verdict"], "suspicious")

    def test_network_precheck_can_be_clean_while_email_still_analyzes(self):
        result = analyze_email_locally(BENIGN_EMAIL)

        self.assertFalse(result["network_precheck"]["suspicious"])
        self.assertEqual(result["network_precheck"]["verdict"], "no_obvious_network_suspicion")
        self.assertIn("https://example.com/security-news", result["iocs"]["url"])


if __name__ == "__main__":
    unittest.main()
