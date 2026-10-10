"""Module 03 - Scanning Networks (Nmap wrapper nâng cao)"""
import re
from core.base_module import BaseModule

class Module(BaseModule):
    name = "m03_scanning"
    module_id = "03"
    description = "Network Scanning (Nmap, ping sweep, UDP, vuln scripts)"

    def __init__(self, target, config=None):
        super().__init__(target, config)
        self.evasion_level = None
        self.proxy_router = None

    def set_evasion(self, level):
        self.evasion_level = level

    def set_proxy(self, router):
        self.proxy_router = router

    def run(self):
        self.logger.info(f"[M03] Bắt đầu Scanning: {self.target}")
        if not self._tool_available("nmap"):
            return {"error": "Nmap chưa cài đặt"}

        cfg = self.config
        scan_type = cfg.get("scan_type", "service")
        timing = cfg.get("timing", "T4")

        # Bước 1: Host discovery
        self.results["host_discovery"] = self._host_discovery()
        
        # Bước 2: Port scan theo cấu hình
        self.results["port_scan"] = self._scan(scan_type, timing, cfg)
        
        # Bước 3: Nếu là service scan, tách port open ra cho module sau
        self.results["open_ports"] = self._parse_open_ports(
            self.results["port_scan"].get("output", ""))

        # ============ MỚI: ghi vào Shared State để chain ============
        from core.state import STATE
        port_nums = [p["port"] for p in self.results["open_ports"]]
        STATE.set("target", self.target)
        STATE.set_open_ports(port_nums, self.results["open_ports"])
        # ============================================================

        self.logger.info(f"[M03] Phát hiện {len(port_nums)} cổng mở.")
        return self.results

    def _host_discovery(self):
        self.logger.info("[M03] Host discovery (ping sweep)...")
        out = self._run_cmd(["nmap", "-sn", "-T4", self.target], timeout=60)
        return {"output": out}

    def _scan(self, scan_type, timing, cfg):
        ports = cfg.get("ports", "1-1000")
        base = ["nmap", "-Pn", f"-{timing}"]

        if scan_type == "basic":
            cmd = base + ["-F", self.target]
        elif scan_type == "service":
            cmd = base + ["-sV", "-sC", "-p", ports, self.target]
        elif scan_type == "full":
            cmd = base + ["-sV", "-sC", "-O", "-p-", self.target]
        elif scan_type == "udp":
            cmd = base + ["-sU", "--top-ports", "50", self.target]
        elif scan_type == "vuln":
            cmd = base + ["-sV", "--script", "vuln", "-p", ports, self.target]
        else:
            cmd = base + ["-sV", self.target]

        # Áp dụng cấu hình Evasion/Proxy nếu có
        if self.evasion_level:
            from core.evasion import evasion_nmap_command
            cmd = evasion_nmap_command(cmd, self.evasion_level, self.proxy_router)
            self.logger.info(f"[M03] Evasion: {self.evasion_level}")

        self.logger.info(f"[M03] Chạy: {' '.join(cmd)}")
        out = self._run_cmd(cmd, timeout=self.config.get("timeout", 300) or 300)
        
        return {
            "command": " ".join(cmd),
            "output": out
        }

    def _parse_open_ports(self, nmap_out):
        """Trích xuất port/protocol/service từ output nmap -sV."""
        ports = []
        pattern = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$", re.MULTILINE)
        for m in pattern.finditer(nmap_out):
            ports.append({
                "port": int(m.group(1)),
                "proto": m.group(2),
                "service": m.group(3),
                "version": m.group(4).strip(),
            })
        return ports