import json
import tempfile
import unittest
from pathlib import Path

from sdn_acl.policy import AccessPolicy, PolicyError
from sdn_acl.runtime import verify_dump_contains_rules


BASE_CONFIG = {
    "switch": "s1",
    "hosts": [
        {"name": "h1", "ip": "10.0.0.1/24", "mac": "00:00:00:00:00:01", "port": 1},
        {"name": "h2", "ip": "10.0.0.2/24", "mac": "00:00:00:00:00:02", "port": 2},
        {"name": "h3", "ip": "10.0.0.3/24", "mac": "00:00:00:00:00:03", "port": 3},
    ],
    "whitelist": [["h1", "h2"], ["h2", "h1"]],
}


class PolicyTests(unittest.TestCase):
    def write_config(self, payload):
        directory = tempfile.TemporaryDirectory()
        path = Path(directory.name) / "policy.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        self.addCleanup(directory.cleanup)
        return path

    def test_policy_matrix_matches_whitelist(self):
        policy = AccessPolicy.from_file(self.write_config(BASE_CONFIG))
        matrix = policy.matrix()
        self.assertTrue(matrix["h1"]["h2"])
        self.assertTrue(matrix["h2"]["h1"])
        self.assertFalse(matrix["h1"]["h3"])
        self.assertFalse(matrix["h3"]["h1"])

    def test_missing_reverse_rules_detected(self):
        payload = dict(BASE_CONFIG)
        payload["whitelist"] = [["h1", "h2"]]
        policy = AccessPolicy.from_file(self.write_config(payload))
        self.assertEqual(policy.missing_reverse_rules(), [("h1", "h2")])

    def test_duplicate_port_rejected(self):
        payload = dict(BASE_CONFIG)
        payload["hosts"] = [dict(item) for item in BASE_CONFIG["hosts"]]
        payload["hosts"][1]["port"] = 1
        with self.assertRaises(PolicyError):
            AccessPolicy.from_file(self.write_config(payload))

    def test_unknown_host_rejected(self):
        payload = dict(BASE_CONFIG)
        payload["whitelist"] = [["h1", "h9"]]
        with self.assertRaises(PolicyError):
            AccessPolicy.from_file(self.write_config(payload))

    def test_flow_generation_creates_default_drop_and_allow_rules(self):
        policy = AccessPolicy.from_file(self.write_config(BASE_CONFIG))
        rules = policy.build_flow_rules()
        self.assertEqual(rules[0].as_ovs_rule(), "priority=0,actions=drop")
        self.assertEqual(len(rules), 5)

    def test_ping_expectation_requires_bidirectional_policy(self):
        payload = dict(BASE_CONFIG)
        payload["whitelist"] = [["h1", "h2"]]
        policy = AccessPolicy.from_file(self.write_config(payload))
        expected = dict(((src, dst), allowed) for src, dst, allowed in policy.expected_connectivity())
        self.assertFalse(expected[("h1", "h2")])

    def test_flow_dump_verification_reports_missing_entries(self):
        missing = verify_dump_contains_rules(
            "cookie=0x0, duration=1.0s, dl_src=00:00:00:00:00:01,dl_dst=00:00:00:00:00:02 actions=output:2",
            [
                "dl_src=00:00:00:00:00:01,dl_dst=00:00:00:00:00:02",
                "dl_src=00:00:00:00:00:02,dl_dst=00:00:00:00:00:01",
            ],
        )
        self.assertEqual(missing, ["dl_src=00:00:00:00:00:02,dl_dst=00:00:00:00:00:01"])


if __name__ == "__main__":
    unittest.main()
