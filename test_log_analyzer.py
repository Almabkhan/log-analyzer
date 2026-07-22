"""
Unit tests for log_analyzer.py
Run with: python -m pytest test_log_analyzer.py -v
"""

import unittest
from log_analyzer import (
    parse_ssh_log,
    detect_brute_force,
    parse_access_log,
    detect_web_anomalies,
)


SSH_SAMPLE = [
    "Jan 15 02:15:33 host sshd[1045]: Failed password for root from 1.2.3.4 port 33218 ssh2\n",
    "Jan 15 02:15:35 host sshd[1046]: Failed password for root from 1.2.3.4 port 33220 ssh2\n",
    "Jan 15 02:15:38 host sshd[1047]: Failed password for admin from 1.2.3.4 port 33222 ssh2\n",
    "Jan 15 02:15:41 host sshd[1048]: Failed password for root from 1.2.3.4 port 33224 ssh2\n",
    "Jan 15 02:15:44 host sshd[1049]: Failed password for root from 1.2.3.4 port 33226 ssh2\n",
    "Jan 15 02:15:47 host sshd[1050]: Accepted password for root from 1.2.3.4 port 33228 ssh2\n",
    "Jan 15 03:00:00 host sshd[1080]: Accepted publickey for deploy from 10.0.0.5 port 51022 ssh2\n",
]


class TestSSHParsing(unittest.TestCase):
    def test_parses_failed_attempts(self):
        parsed = parse_ssh_log(SSH_SAMPLE)
        self.assertEqual(len(parsed["failed"]), 5)

    def test_parses_accepted_logins(self):
        parsed = parse_ssh_log(SSH_SAMPLE)
        self.assertEqual(len(parsed["accepted"]), 2)

    def test_extracts_correct_ip(self):
        parsed = parse_ssh_log(SSH_SAMPLE)
        self.assertEqual(parsed["failed"][0]["ip"], "1.2.3.4")

    def test_ignores_unrelated_lines(self):
        parsed = parse_ssh_log(["Jan 15 02:00:00 host kernel: some unrelated message\n"])
        self.assertEqual(len(parsed["failed"]), 0)
        self.assertEqual(len(parsed["accepted"]), 0)


class TestBruteForceDetection(unittest.TestCase):
    def test_detects_brute_force_over_threshold(self):
        parsed = parse_ssh_log(SSH_SAMPLE)
        alerts = detect_brute_force(parsed, threshold=4)
        brute_force_alerts = [a for a in alerts if a["type"] == "brute_force"]
        self.assertEqual(len(brute_force_alerts), 1)
        self.assertEqual(brute_force_alerts[0]["ip"], "1.2.3.4")

    def test_no_alert_under_threshold(self):
        parsed = parse_ssh_log(SSH_SAMPLE)
        alerts = detect_brute_force(parsed, threshold=100)
        brute_force_alerts = [a for a in alerts if a["type"] == "brute_force"]
        self.assertEqual(len(brute_force_alerts), 0)

    def test_detects_compromised_credential_pattern(self):
        parsed = parse_ssh_log(SSH_SAMPLE)
        alerts = detect_brute_force(parsed, threshold=4)
        compromised = [a for a in alerts if a["type"] == "possible_compromised_credential"]
        self.assertEqual(len(compromised), 1)
        self.assertEqual(compromised[0]["ip"], "1.2.3.4")

    def test_legitimate_traffic_produces_no_alerts(self):
        clean_log = ["Jan 15 03:00:00 host sshd[1080]: Accepted publickey for deploy from 10.0.0.5 port 51022 ssh2\n"]
        parsed = parse_ssh_log(clean_log)
        alerts = detect_brute_force(parsed, threshold=5)
        self.assertEqual(len(alerts), 0)


WEB_SAMPLE = [
    '1.2.3.4 - - [15/Jan/2026:09:20:01 +0000] "POST /login HTTP/1.1" 401 210\n',
    '1.2.3.4 - - [15/Jan/2026:09:20:03 +0000] "POST /login HTTP/1.1" 401 210\n',
    '1.2.3.4 - - [15/Jan/2026:09:20:05 +0000] "POST /login HTTP/1.1" 401 210\n',
    '1.2.3.4 - - [15/Jan/2026:09:20:07 +0000] "POST /login HTTP/1.1" 401 210\n',
    '1.2.3.4 - - [15/Jan/2026:09:20:11 +0000] "POST /login HTTP/1.1" 200 1024\n',
    '5.6.7.8 - - [15/Jan/2026:09:14:20 +0000] "GET /wp-login.php HTTP/1.1" 404 512\n',
    '5.6.7.8 - - [15/Jan/2026:09:14:21 +0000] "GET /admin.php HTTP/1.1" 404 512\n',
    '5.6.7.8 - - [15/Jan/2026:09:14:22 +0000] "GET /phpmyadmin HTTP/1.1" 404 512\n',
    '5.6.7.8 - - [15/Jan/2026:09:14:23 +0000] "GET /.env HTTP/1.1" 404 512\n',
    '9.9.9.9 - - [15/Jan/2026:12:44:10 +0000] "GET /product?id=1%20UNION%20SELECT%20u,p%20FROM%20users-- HTTP/1.1" 500 892\n',
    '10.0.0.1 - - [15/Jan/2026:14:30:00 +0000] "GET /dashboard HTTP/1.1" 200 5321\n',
]


class TestWebLogParsing(unittest.TestCase):
    def test_parses_all_valid_lines(self):
        events = parse_access_log(WEB_SAMPLE)
        self.assertEqual(len(events), len(WEB_SAMPLE))

    def test_extracts_fields_correctly(self):
        events = parse_access_log(WEB_SAMPLE)
        self.assertEqual(events[0]["ip"], "1.2.3.4")
        self.assertEqual(events[0]["status"], "401")
        self.assertEqual(events[0]["path"], "/login")


class TestWebAnomalyDetection(unittest.TestCase):
    def test_detects_brute_force_web_login(self):
        events = parse_access_log(WEB_SAMPLE)
        alerts = detect_web_anomalies(events, scan_threshold=4)
        bf = [a for a in alerts if a["type"] == "brute_force_web_login"]
        self.assertEqual(len(bf), 1)
        self.assertEqual(bf[0]["ip"], "1.2.3.4")

    def test_detects_compromised_credential_after_brute_force(self):
        events = parse_access_log(WEB_SAMPLE)
        alerts = detect_web_anomalies(events, scan_threshold=4)
        compromised = [a for a in alerts if a["type"] == "possible_compromised_credential"]
        self.assertEqual(len(compromised), 1)

    def test_detects_directory_scanning(self):
        events = parse_access_log(WEB_SAMPLE)
        alerts = detect_web_anomalies(events, scan_threshold=4)
        scanning = [a for a in alerts if a["type"] == "directory_scanning"]
        self.assertEqual(len(scanning), 1)
        self.assertEqual(scanning[0]["ip"], "5.6.7.8")

    def test_detects_sql_injection_in_encoded_url(self):
        events = parse_access_log(WEB_SAMPLE)
        alerts = detect_web_anomalies(events, scan_threshold=4)
        sqli = [a for a in alerts if a["type"] == "possible_sql_injection"]
        self.assertEqual(len(sqli), 1)
        self.assertEqual(sqli[0]["ip"], "9.9.9.9")

    def test_normal_traffic_produces_no_alerts(self):
        clean = ['10.0.0.1 - - [15/Jan/2026:14:30:00 +0000] "GET /dashboard HTTP/1.1" 200 5321\n']
        events = parse_access_log(clean)
        alerts = detect_web_anomalies(events, scan_threshold=4)
        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()
