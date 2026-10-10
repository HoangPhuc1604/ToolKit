"""Container & K8s scan - Trivy, kube-bench, kube-hunter."""
import json
import os
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.container")


class ContainerScanner:
    """Wrapper cho các công cụ container/K8s."""

    def trivy_image(self, image):
        """Quét lỗ hổng image Docker."""
        cmd = ["trivy", "image", "--format", "json",
               "--severity", "CRITICAL,HIGH,MEDIUM", image]
        out = self._run(cmd, timeout=300)
        try:
            data = json.loads(out)
            vulns = []
            for result in data.get("Results", []):
                for v in result.get("Vulnerabilities", []):
                    vulns.append({
                        "cve": v.get("VulnerabilityID"),
                        "package": v.get("PkgName"),
                        "installed": v.get("InstalledVersion"),
                        "fixed": v.get("FixedVersion"),
                        "severity": v.get("Severity"),
                        "title": v.get("Title", "")[:200],
                    })
            return {"count": len(vulns), "vulnerabilities": vulns[:100]}
        except json.JSONDecodeError:
            return {"error": "Không parse được Trivy output", "raw": out[:500]}

    def trivy_k8s(self):
        """Quét misconfiguration trong cluster K8s hiện tại."""
        cmd = ["trivy", "k8s", "--format", "json",
               "--severity", "CRITICAL,HIGH"]
        out = self._run(cmd, timeout=300)
        try:
            return json.loads(out)
        except Exception:
            return {"raw": out[:500]}

    def kube_bench(self):
        """CIS Kubernetes Benchmark."""
        cmd = ["kube-bench", "--json"]
        out = self._run(cmd, timeout=300)
        try:
            data = json.loads(out)
            fails = []
            for test in data.get("Tests", []):
                for result in test.get("results", []):
                    if result.get("status") == "FAIL":
                        fails.append({
                            "test": result.get("test_number"),
                            "desc": result.get("test_desc", "")[:200],
                            "remediation": result.get("remediation", "")[:200],
                        })
            return {"failed_checks": len(fails), "details": fails[:50]}
        except Exception:
            return {"raw": out[:1000]}

    def kube_hunter(self, remote=None, cidr=None):
        """Quét attack surface (kube-hunter)."""
        cmd = ["kube-hunter", "--report", "json"]
        if remote:
            cmd += ["--remote", remote]
        if cidr:
            cmd += ["--cidr", cidr]
        out = self._run(cmd, timeout=600)
        try:
            data = json.loads(out)
            vulns = []
            for v in data.get("vulnerabilities", []):
                vulns.append({
                    "vid": v.get("vid"),
                    "severity": v.get("severity"),
                    "category": v.get("category"),
                    "description": v.get("description", "")[:200],
                })
            return {"count": len(vulns), "vulnerabilities": vulns}
        except Exception:
            return {"raw": out[:1000]}

    def _run(self, cmd, timeout=300):
        import subprocess
        if not self._available(cmd[0]):
            return f"[!] {cmd[0]} chưa cài"
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout)
            return r.stdout + (("\n" + r.stderr) if r.stderr else "")
        except Exception as e:
            return f"[!] {e}"

    def _available(self, tool):
        import shutil
        return shutil.which(tool) is not None


class Module(BaseModule):
    name = "container_scan"
    module_id = "K8S"
    description = "Container & K8s audit (Trivy, kube-bench, kube-hunter)"

    def run(self):
        self.logger.info("[K8S] Container/K8s scan")
        cfg = self.config
        sc = ContainerScanner()
        results = {}

        if cfg.get("image"):
            results["trivy_image"] = sc.trivy_image(cfg["image"])

        if cfg.get("k8s_cluster", False):
            results["trivy_k8s"] = sc.trivy_k8s()
            results["kube_bench"] = sc.kube_bench()

        if cfg.get("kube_hunter", False):
            results["kube_hunter"] = sc.kube_hunter(
                remote=cfg.get("k8s_api"),
                cidr=cfg.get("cidr"),
            )
        return results