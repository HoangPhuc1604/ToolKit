"""Định tuyến ẩn danh qua Tor / SOCKS5 / HTTP proxy."""
import os
import subprocess
import shutil
import time
from core.logger import get_logger

LOG = get_logger("ceh.proxy")

PROXYCHAINS_CONF = "/tmp/ceh_proxychains.conf"


class ProxyRouter:
    """Quản lý định tuyến qua proxy."""

    def __init__(self, mode="tor", proxy_url=None):
        self.mode = mode
        self.proxy_url = proxy_url
        self.available = {
            "tor": shutil.which("tor") is not None,
            "proxychains": shutil.which("proxychains4") is not None
                           or shutil.which("proxychains") is not None,
        }

    # ---------- Tor ----------
    def start_tor(self):
        if not self.available["tor"]:
            return {"error": "tor chưa cài (apt install tor)"}
        LOG.info("[proxy] Khởi động Tor...")
        try:
            subprocess.Popen(["tor"], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            # Chờ Tor khởi động
            for _ in range(15):
                time.sleep(1)
                if self._check_port("127.0.0.1", 9050):
                    LOG.info("[proxy] Tor đã sẵn sàng (SOCKS5 9050)")
                    return {"status": "ready", "socks5": "127.0.0.1:9050"}
            return {"error": "Tor không khởi động kịp"}
        except Exception as e:
            return {"error": str(e)}

    def _check_port(self, host, port, timeout=1.0):
        import socket
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.close()
            return True
        except Exception:
            return False

    # ---------- Proxychains ----------
    def write_proxychains_conf(self):
        """Tạo config proxychains tạm thời."""
        if self.mode == "tor":
            proxy_line = "socks5 127.0.0.1 9050"
        else:
            proxy_line = self.proxy_url or "socks5 127.0.0.1 1080"

        conf = f"""strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
{proxy_line}
"""
        with open(PROXYCHAINS_CONF, "w") as f:
            f.write(conf)
        return PROXYCHAINS_CONF

    def wrap_command(self, cmd: list) -> list:
        """Bọc lệnh để chạy qua proxychains."""
        pc = (shutil.which("proxychains4") or shutil.which("proxychains"))
        if not pc:
            LOG.warning("[proxy] proxychains chưa cài, chạy lệnh trực tiếp")
            return cmd
        self.write_proxychains_conf()
        return [pc, "-f", PROXYCHAINS_CONF] + cmd

    def nmap_proxy_args(self) -> list:
        """Args proxy cho Nmap (không cần proxychains)."""
        if self.mode == "tor":
            return ["--proxies", "socks4://127.0.0.1:9050"]
        if self.proxy_url:
            return ["--proxies", self.proxy_url]
        return []