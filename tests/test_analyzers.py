"""Known-case smoke tests for URL, PCAP, log, file, and email analyzers."""
import socket
import struct
import unittest

from services.extended_features import analyze_email
from services.file_analyzer import analyze_file
from services.log_analyzer import analyze_logs
from services.pcap_analyzer import analyze_pcap
from services.url_detector import analyze_url
from services.behavior import detect_flow_outliers
from services.domain_intel import lookup_domain, lookup_file_hash


def one_tcp_packet_pcap():
    # Synthetic Ethernet/IPv4/TCP frame between documentation-only addresses.
    eth = bytes.fromhex("0200000000020200000000010800")
    source, destination = socket.inet_aton("192.0.2.10"), socket.inet_aton("198.51.100.20")
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, source, destination)
    tcp = struct.pack("!HHLLBBHHH", 51514, 443, 1, 0, 0x50, 0x02, 65535, 0, 0)
    packet = eth + ip + tcp
    return (struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            + struct.pack("<IIII", 1_700_000_000, 0, len(packet), len(packet)) + packet)


class AnalyzerKnownCaseTests(unittest.TestCase):
    def test_url_benign_and_suspicious_inputs(self):
        benign = analyze_url("https://example.org/")
        suspicious = analyze_url("http://192.0.2.10/login/verify/account")
        self.assertIn("risk_score", benign)
        self.assertIsInstance(benign["indicators"], list)
        self.assertTrue(any("IP address" in item or "Not using HTTPS" in item
                            for item in suspicious["indicators"]))
        self.assertGreater(suspicious["rule_score"], 0)

    def test_logs_cover_benign_and_known_signatures(self):
        benign = analyze_logs("Oct 01 10:00:00 host service: operation completed successfully")
        suspicious = analyze_logs("Oct 01 10:00:00 host sshd: Failed login from 203.0.113.10\n" * 6)
        self.assertEqual(benign["event_count"], 0)
        self.assertGreater(suspicious["event_count"], 0)
        self.assertTrue(suspicious["brute_force_source_ips"])

    def test_valid_and_malformed_pcap(self):
        valid = analyze_pcap(one_tcp_packet_pcap())
        malformed = analyze_pcap(b"not a packet capture")
        self.assertEqual(valid["packet_count"], 1)
        self.assertEqual(valid["top_ports"], {443: 1})
        self.assertNotIn("error", valid)
        self.assertIn("error", malformed)

    def test_file_static_checks_and_benign_case(self):
        benign = analyze_file("notes.txt", b"Meeting notes: project review at 10 AM.")
        suspicious = analyze_file("script.txt", b"powershell -EncodedCommand AAAA")
        self.assertEqual(benign["risk_score"], 0)
        self.assertEqual(len(benign["sha256"]), 64)
        self.assertTrue(suspicious["indicators"])

    def test_email_benign_and_suspicious_cases(self):
        benign = (b"From: colleague@example.org\r\nSubject: Meeting\r\n"
                  b"Authentication-Results: spf=pass; dkim=pass; dmarc=pass\r\n"
                  b"Content-Type: text/plain; charset=utf-8\r\n\r\nSee you at the meeting.\r\n")
        suspicious = (b"From: notice@example.org\r\nReply-To: collect@other.example\r\n"
                      b"Subject: Verify your account immediately\r\n"
                      b"Authentication-Results: spf=fail; dkim=fail\r\n"
                      b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
                      b"Verify your password immediately at http://example.invalid/login\r\n")
        safe_result = analyze_email(benign)
        suspicious_result = analyze_email(suspicious)
        self.assertEqual(safe_result["risk_score"], 0)
        self.assertGreater(suspicious_result["risk_score"], safe_result["risk_score"])
        self.assertTrue(suspicious_result["indicators"])

    def test_reputation_and_flow_analyzer_safe_edges(self):
        self.assertIn("error", lookup_domain("not a domain"))
        self.assertIn("error", lookup_file_hash("not-a-hash"))
        flow_result = detect_flow_outliers({"top_connections": [], "top_connections_by_bytes": []})
        self.assertFalse(flow_result["available"])


if __name__ == "__main__":
    unittest.main()
