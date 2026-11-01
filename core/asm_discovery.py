# core/asm_discovery.py
import subprocess
import shutil
import json
import os
from pathlib import Path
from datetime import datetime
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.asm")

class ASMScanner:
    """Quản lý khám phá bề mặt tấn công."""
    def __init__(self, scope_domains: list):
        self.scope_domains = set(scope_domains)
        self.state_file = Path("/tmp/asm_state.json")
        self.state = self._load_state()

    def _load_state(self):
        if self.state_file.exists():
            return json.loads(self.state_file.read_text())
        return {"findings": {}}

    def _save_state(self):
        self.state_file.write_text(json.dumps(self.state, indent=2))

    def run_subfinder(self, domain):
        """Chạy subfinder để tìm subdomain."""
        if not shutil.which("subfinder"):
            return {"error": "subfinder chưa cài"}
        cmd = ["subfinder", "-d", domain, "-silent"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        subs = [line.strip() for line in r.stdout.splitlines() if line.strip()]
        return {"subdomains": subs}

    def run_httpx(self, subdomains):
        """Chạy httpx để kiểm tra dịch vụ web đang hoạt động."""
        if not shutil.which("httpx"):
            return {"error": "httpx chưa cài"}
        if not subdomains:
            return {"live_hosts": []}
        input_data = "\n".join(subdomains)
        cmd = ["httpx", "-silent", "-json", "-title", "-tech-detect"]
        r = subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=600)
        live_hosts = [json.loads(line) for line in r.stdout.splitlines() if line.strip()]
        return {"live_hosts": live_hosts}

    def run_nuclei(self, hosts):
        """Chạy nuclei để quét lỗ hổng."""
        if not shutil.which("nuclei"):
            return {"error": "nuclei chưa cài"}
        if not hosts:
            return {"findings": []}
        input_data = "\n".join(hosts)
        cmd = ["nuclei", "-json", "-silent", "-severity", "critical,high,medium"]
        r = subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=1200)
        findings = [json.loads(line) for line in r.stdout.splitlines() if line.strip()]
        return {"findings": findings}

    def upsert_findings(self, findings: list, source: str):
        """Cập nhật findings vào state, chỉ báo cáo cái mới."""
        new_findings = []
        for f in findings:
            # Tạo fingerprint đơn giản
            fp = f"{source}:{f.get('template-id', f.get('url', ''))}"
            if fp not in self.state["findings"]:
                f["first_seen"] = datetime.utcnow().isoformat()
                f["source"] = source
                self.state["findings"][fp] = f
                new_findings.append(f)
        self._save_state()
        return new_findings

class Module(BaseModule):
    name = "asm_discovery"
    module_id = "ASM"
    description = "Quản lý Bề mặt Tấn công (liên tục, scope-aware)"

    def run(self):
        self.logger.info("[ASM] Bắt đầu quét ASM")
        cfg = self.config
        domains = cfg.get("scope_domains", [])
        if not domains:
            return {"error": "Cần 'scope_domains' trong config"}

        scanner = ASMScanner(domains)
        all_new_findings = []

        for domain in domains:
            self.logger.info(f"[ASM] Đang quét domain: {domain}")
            subs_result = scanner.run_subfinder(domain)
            subs = subs_result.get("subdomains", [])
            if subs:
                httpx_result = scanner.run_httpx(subs)
                live_hosts = [h.get("url") for h in httpx_result.get("live_hosts", []) if h.get("url")]
                if live_hosts:
                    nuclei_result = scanner.run_nuclei(live_hosts)
                    new_f = scanner.upsert_findings(nuclei_result.get("findings", []), "nuclei")
                    all_new_findings.extend(new_f)

        self.results["new_findings"] = all_new_findings
        self.results["total_findings"] = len(scanner.state["findings"])
        return self.results