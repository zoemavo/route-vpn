"""Opt-in real process test. No subscription, mock BBP, or host TUN mutation.

BBP_BIN_DIR=/absolute/target/release python3 -m unittest discover -s tests -v
"""
import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import routevpn

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body=b"real RVPN -> mihomo -> SOCKS -> BBP -> edge TCP egress"
        self.send_response(200)
        self.send_header("Content-Length",str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self,*_):
        pass

class LiveTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("BBP_BIN_DIR"),"set BBP_BIN_DIR for native process integration")
    def test_rvpn_supervises_real_bbp_and_mihomo_and_reaps_on_sigterm(self):
        if os.geteuid()==0:
            self.skipTest("live daemons intentionally reject root")
        binary=Path(os.environ["BBP_BIN_DIR"]).resolve()
        self.assertTrue(routevpn.find_mihomo(),"mihomo required")
        with tempfile.TemporaryDirectory(prefix="rvpn-bbp-live-") as directory:
            root=Path(directory)
            server=http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler)
            thread=threading.Thread(target=server.serve_forever,daemon=True)
            thread.start()
            process=None
            leases=[]
            try:
                cli=[sys.executable,str(Path(routevpn.__file__).resolve()),"--state-dir",str(root)]
                result=subprocess.run(cli+["bbp","local","test","--bin-dir",str(binary)],capture_output=True,text=True,timeout=15)
                self.assertEqual(result.returncode,0,result.stderr)
                state=routevpn.load(root)
                selected=state["subscriptions"]["test"]
                # Every listener uses an isolated ephemeral port. Keep leases
                # until configs exist, then close before child startup.
                def port(udp=False):
                    lease=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
                    lease.bind(("127.0.0.1",0));leases.append(lease)
                    return lease.getsockname()[1]
                mapping={17891:port(),17892:port(),18443:port(True),18444:port()}
                for name in ("source","edge_config"):
                    path=Path(selected[name])
                    content=path.read_text()
                    for old,new in mapping.items():
                        content=content.replace(f"127.0.0.1:{old}",f"127.0.0.1:{new}")
                    path.write_text(content)
                selected["socks"]="127.0.0.1:"+str(mapping[17891])
                state["local_ports"]={"mixed":port(),"controller":port(),"dns":port()}
                state["probe_url"]=f"http://localhost:{server.server_port}/ready"
                routevpn.save(root,state)
                for lease in leases:lease.close()
                leases.clear()
                process=subprocess.Popen(cli+["run","--proxy-only"],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,start_new_session=True)
                deadline=time.monotonic()+20
                profile=routevpn.bbp_config(selected)
                while time.monotonic()<deadline:
                    if process.poll() is not None:
                        self.fail("RVPN startup failed: "+process.stdout.read())
                    try:
                        status=routevpn.bbp_status(selected)
                        if status["connected"] and len(status["paths"])==2:
                            with socket.create_connection(("127.0.0.1",state["local_ports"]["mixed"]),timeout=1):
                                break
                    except (routevpn.Error,OSError):
                        pass
                    time.sleep(0.1)
                else:self.fail("RVPN real startup deadline")
                # Absolute-form HTTP proxy request, avoiding NO_PROXY shortcuts.
                proxy=http.client.HTTPConnection("127.0.0.1",state["local_ports"]["mixed"],timeout=10)
                proxy.request("GET",f"http://localhost:{server.server_port}/data")
                response=proxy.getresponse()
                if response.status!=200:
                    body=response.read()
                    process.send_signal(signal.SIGTERM)
                    output=process.communicate(timeout=20)[0]
                    self.fail(f"HTTP {response.status}: {body!r}\n{output}")
                self.assertIn(b"real RVPN -> mihomo -> SOCKS -> BBP",response.read())
                proxy.close()
                process.send_signal(signal.SIGTERM)
                output=process.communicate(timeout=20)[0]
                self.assertEqual(process.returncode,0,output)
                for endpoint in (selected["socks"],profile["control"],"127.0.0.1:"+str(state["local_ports"]["controller"])):
                    parsed=routevpn.loopback_endpoint(endpoint)
                    with self.assertRaises(OSError):socket.create_connection(parsed,timeout=0.2)
                self.assertFalse((root/"running.json").exists())
                # Crash only children of this test-owned supervisor. No host
                # service PID or running subscription is searched or killed.
                for crashed in ("bbpd","mihomo"):
                    process=subprocess.Popen(cli+["run","--proxy-only"],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,start_new_session=True)
                    deadline=time.monotonic()+20
                    while time.monotonic()<deadline:
                        if process.poll() is not None:
                            self.fail("restart failed: "+process.stdout.read())
                        if (root/"running.json").exists():
                            break
                        time.sleep(0.1)
                    else:self.fail("restart deadline")
                    time.sleep(0.5)
                    children=Path(f"/proc/{process.pid}/task/{process.pid}/children").read_text().split()
                    target=next((int(pid) for pid in children if Path(f"/proc/{pid}/comm").read_text().strip()==crashed),None)
                    self.assertIsNotNone(target,"expected owned child "+crashed)
                    os.kill(target,signal.SIGKILL)
                    output=process.communicate(timeout=20)[0]
                    self.assertNotEqual(process.returncode,0,output)
                    self.assertFalse((root/"running.json").exists())
                    for pid in children:
                        self.assertFalse(Path(f"/proc/{pid}").exists(),"orphan test child "+pid)
                # Wrong pinned peer identity must fail before mihomo startup.
                bad_key=root/"wrong-peer.pub";bad_key.write_bytes(bytes(32))
                config=Path(selected["source"])
                config.write_text(config.read_text().replace(str(root/"bbp"/"test"/"edge.pub"),str(bad_key)))
                process=subprocess.Popen(cli+["run","--proxy-only"],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,start_new_session=True)
                output=process.communicate(timeout=20)[0]
                self.assertNotEqual(process.returncode,0,output)
                self.assertFalse((root/"running.json").exists())
            finally:
                if process and process.poll() is None:
                    os.killpg(process.pid,signal.SIGKILL)
                    process.communicate(timeout=5)
                if process and process.stdout:
                    process.stdout.close()
                for lease in leases:lease.close()
                server.shutdown();server.server_close();thread.join(timeout=2)
