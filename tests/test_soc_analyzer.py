import unittest

from soc_analyzer import analyze_locally, redact_secrets


class SocAnalyzerTests(unittest.TestCase):
    def test_detects_bruteforce_and_successful_login(self):
        text = "\n".join(
            [
                "Jun 05 09:14:22 sshd[1]: Failed password for root from 203.0.113.42 port 51122 ssh2",
                "Jun 05 09:16:33 sshd[2]: Accepted password for deploy from 203.0.113.42 port 51200 ssh2",
            ]
        )

        result = analyze_locally(text)
        finding_names = {item["name"] for item in result["findings"]}

        self.assertIn("SSH brute-force pattern", finding_names)
        self.assertIn("Successful authentication", finding_names)
        self.assertIn("203.0.113.42", result["iocs"]["ipv4"])
        self.assertGreaterEqual(result["risk_score"], 30)

    def test_redacts_common_api_key_patterns(self):
        text = "token=" + "gsk_" + "abcdefghijklmnopqrstuvwxyz1234567890"

        self.assertNotIn("gsk_", redact_secrets(text))
        self.assertIn("[REDACTED_SECRET]", redact_secrets(text))

    def test_does_not_redact_sudo_working_directory(self):
        text = "sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root"

        self.assertIn("PWD=/home/deploy", redact_secrets(text))


if __name__ == "__main__":
    unittest.main()
