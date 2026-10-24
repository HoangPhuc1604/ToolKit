"""OT/ICS scan - Modbus, DNP3, S7, BACnet qua Nmap NSE."""
import subprocess
import re
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.ot")

# Protocol → port + NSE script
ICS_PROTOCOLS = {
    "modbus":   {"port": 502,   "scripts": ["modicon-info"]},
    "dnp3":     {"port": 20000, "scripts": ["dnp3-info", "dnp3-enumerate"]},
    "s7":       {"port": 102,   "scripts": ["s7-info", "s7-enumerate"]},
    "bacnet":   {"port": 47808, "scripts": ["bacnet-info"]},
    "enip":     {"port": 44818, "scripts": ["enip-info"]},
    "iec61850": {"port": 102,   "scripts": ["iec61850-mms"]},
}


class ICSDetector:
    def __init__(self):
        self.available = subprocess.run(
            ["which", "nmap"], capture_output=True).returncode == 0

    def scan(self, target, protocols=None, safe=True):
        """Quét ICS protocols; safe=True chỉ đọc thông tin, không ghi."""
        if not self.available:
            return {"error": "nmap chưa cài"}

        protocols = protocols or list(ICS_PROTOCOLS.keys())
        results = {}

        for proto in protocols:
            info = ICS_PROTOCOLS.get(proto)
            if not info:
                continue
            cmd = ["nmap", "-sV", "-Pn", "-p", str(info["port"])]
            for script in info["scripts"]:
                cmd += ["--script", script]
            cmd.append(target)

            LOG.info(f"[ot] {proto} scan: {' '.join(cmd)}")
            try:
                r = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=120)
                results[proto] = {
                    "port": info["port"],
                    "output": r.stdout[-3000:],
                    "open": "open" in r.stdout,
                    "findings": self._parse_ics_output(r.stdout, proto),
                }
            except subprocess.TimeoutExpired:
                results[proto] = {"error": "Timeout"}

        return results

    def _parse_ics_output(self, output, proto):
        """Trích xuất thông tin thiết bị từ NSE output."""
        findings = []
        # Modbus: device identification
        if proto == "modbus":
            for m in re.finditer(r"(\w+):\s*([^\n]+)", output):
                if m.group(1).lower() in ("vendor", "product", "version",
                                           "model", "device"):
                    findings.append({m.group(1): m.group(2).strip()})
        # S7: module info
        if proto == "s7":
            for m in re.finditer(r"Module:\s*([^\n]+)", output):
                findings.append({"module": m.group(1).strip()})
        return findings[:20]


class Module(BaseModule):
    name = "ot_ics"
    module_id = "OT"
    description = "OT/ICS scan (Modbus, DNP3, S7, BACnet)"

    def run(self):
        self.logger.info("[OT] ICS scan")
        self.logger.warning("[OT] Chỉ scan trên hệ thống được phép!")
        cfg = self.config
        detector = ICSDetector()
        return detector.scan(
            self.target,
            protocols=cfg.get("protocols"),
            safe=cfg.get("safe", True))