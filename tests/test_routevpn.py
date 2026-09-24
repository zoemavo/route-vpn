import base64
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import routevpn


class ConfigTests(unittest.TestCase):
    def test_config_routes_subscription_and_ports(self):
        state = {
            "secret": "test-secret", "active": "sample",
            "subscriptions": {"sample": {"type": "file", "source": "local"}},
            "routes": [routevpn.rule("suffix", "example.org", "direct"),
                       routevpn.rule("cidr", "203.0.113.9/24", "block")],
            "uplink": "wlan0", "ports": [{"name": "web", "listen": "127.0.0.1", "port": 8080,
                       "target": "example.org:443", "network": ["tcp"]}],
        }
        config = yaml.safe_load(routevpn.render(state))
        self.assertEqual(config["rules"], ["DOMAIN-SUFFIX,example.org,DIRECT", "IP-CIDR,203.0.113.0/24,REJECT", "MATCH,VPN"])
        self.assertEqual(config["listeners"][0]["proxy"], "VPN")
        self.assertEqual(config["proxy-groups"][1]["use"], ["sample"])
        self.assertFalse(config["profile"]["store-selected"])
        self.assertTrue(config["tun"]["strict-route"])
        self.assertEqual(config["interface-name"], "wlan0")

    def test_generated_config_accepted_by_mihomo(self):
        binary = Path(__file__).resolve().parents[1] / "mihomo"
        if not binary.exists():
            self.skipTest("mihomo binary not installed")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            provider = root / "providers" / "sample.yaml"
            provider.parent.mkdir()
            state = {"secret": "test-secret", "active": "sample",
                     "subscriptions": {"sample": {"type": "file", "source": str(provider)}},
                     "routes": [routevpn.rule("src-cidr", "10.77.0.50/32", "vpn"),
                                routevpn.rule("dst-port", "25", "block")],
                     "ports": [{"name": "web", "listen": "127.0.0.1", "port": 18081,
                                              "target": "example.org:443", "network": ["tcp"]}]}
            uri = "ss://YWVzLTI1Ni1nY206bWV0YUAxMjcuMC4wLjE6NDQz#home\n"
            formats = [
                "proxies:\n  - name: test\n    type: ss\n    server: 192.0.2.1\n    port: 443\n    cipher: aes-128-gcm\n    password: example\n",
                uri,
                base64.b64encode(uri.encode()).decode(),
            ]
            for content in formats:
                with self.subTest(content=content[:12]):
                    self.assertGreater(routevpn.validate_provider_content(content.encode())[0], 0)
                    provider.write_text(content)
                    config = root / "config.yaml"
                    config.write_text(routevpn.render(state))
                    result = subprocess.run([str(binary), "-t", "-d", str(root), "-f", str(config)],
                                            capture_output=True, text=True, timeout=20)
                    self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            with self.assertRaises(routevpn.Error):
                routevpn.validate_provider_content(b"not a subscription")

    def test_rejects_bad_target_and_route(self):
        with self.assertRaises(routevpn.Error):
            routevpn.host_port("example.org:0")
        with self.assertRaises(routevpn.Error):
            routevpn.rule("suffix", "bad,rule", "direct")
        with self.assertRaises(routevpn.Error):
            routevpn.rule("cidr", "2001:db8::/32", "vpn")


if __name__ == "__main__":
    unittest.main()
