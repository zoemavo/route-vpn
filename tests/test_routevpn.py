import base64
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import routevpn


class ConfigTests(unittest.TestCase):
    def test_bbp_bypass_precedes_user_rules_and_excludes_edge_from_tun(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"bbp.toml"
            path.write_text('[runtime]\nquic="203.0.113.4:443"\nh2="203.0.113.4:8443"\nserver_name="edge.example"\nsocks="127.0.0.1:17891"\n[secrets]\ncontrol_token="'+'a'*64+'"\n')
            state={"secret":"test","active":"bbp","subscriptions":{"bbp":{"type":"bbp","source":str(path),"socks":"127.0.0.1:17891"}},"routes":[routevpn.rule("process","bbpd","vpn")],"ports":[]}
            config=yaml.safe_load(routevpn.render(state))
            self.assertEqual(config["rules"][0],"PROCESS-NAME,bbpd,DIRECT")
            self.assertLess(config["rules"].index("IP-CIDR,203.0.113.4/32,DIRECT,no-resolve"),config["rules"].index("PROCESS-NAME,bbpd,VPN"))
            self.assertEqual(config["tun"]["route-exclude-address"],["203.0.113.4/32"])
            self.assertNotIn("DIRECT",config["proxy-groups"][1]["proxies"])

    def test_stop_process_has_bounded_kill_backstop(self):
        process=mock.Mock()
        process.poll.return_value=None
        process.wait.side_effect=[subprocess.TimeoutExpired("child",8),subprocess.TimeoutExpired("child",3),0]
        routevpn.stop_process(process)
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        self.assertEqual([call.kwargs["timeout"] for call in process.wait.call_args_list],[8,3,3])

    def test_old_state_and_isolated_ports_remain_compatible(self):
        self.assertEqual(routevpn.local_ports({}),{"mixed":17890,"controller":19090,"dns":15353})
        with self.assertRaises(routevpn.Error):
            routevpn.local_ports({"local_ports":{"mixed":19090}})

    def test_local_ports_command_sets_isolated_mihomo_ports(self):
        with tempfile.TemporaryDirectory() as directory:
            routevpn.main(["--state-dir", directory, "local-ports", "--mixed", "17893",
                           "--controller", "19091", "--dns", "15354"])
            state = routevpn.load(Path(directory))
            self.assertEqual(routevpn.local_ports(state),
                             {"mixed": 17893, "controller": 19091, "dns": 15354})

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

    def test_bbpd_renders_as_local_socks_proxy(self):
        state = {
            "secret": "test-secret", "active": "private-bbp",
            "subscriptions": {"private-bbp": {
                "type": "bbp", "source": "/tmp/bbp.toml",
                "binary": "bbpd", "socks": "127.0.0.1:1080",
            }},
            "routes": [], "ports": [],
        }
        config = yaml.safe_load(routevpn.render(state, tun=False))
        self.assertNotIn("proxy-providers", config)
        self.assertEqual(config["proxies"], [{
            "name": "BBP/private-bbp", "type": "socks5",
            "server": "127.0.0.1", "port": 1080, "udp": True,
        }])
        self.assertEqual(config["proxy-groups"][0]["proxies"], ["BBP/private-bbp"])
        binary = Path(__file__).resolve().parents[1] / "mihomo"
        if binary.exists():
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "config.yaml"
                path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False))
                result = subprocess.run([str(binary), "-t", "-d", directory, "-f", str(path)],
                                        capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_bbp_socks_endpoint_must_be_loopback(self):
        with self.assertRaises(routevpn.Error):
            routevpn.loopback_endpoint("192.0.2.10:1080")


if __name__ == "__main__":
    unittest.main()
