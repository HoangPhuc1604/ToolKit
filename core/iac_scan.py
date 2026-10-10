"""IaC scan - Checkov + tfsec cho Terraform/CloudFormation/K8s/Helm."""
import json
import os
from pathlib import Path
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.iac")


class IaCScanner:
    def checkov(self, path, framework=None, soft_fail=True):
        """Chạy Checkov, trả về JSON."""
        cmd = ["checkov", "-d", path, "-o", "json", "--quiet"]
        if framework:
            cmd += ["--framework", framework]
        if soft_fail:
            cmd.append("--soft-fail")

        out = self._run(cmd, timeout=600)
        try:
            data = json.loads(out) if out.strip().startswith(("{", "[")) else None
            if not data:
                # Checkov có thể xuất multi-line JSON
                for line in out.splitlines():
                    line = line.strip()
                    if line.startswith("{"):
                        data = json.loads(line)
                        break
            return self._parse_checkov(data) if data else {"raw": out[:1000]}
        except Exception as e:
            return {"error": str(e), "raw": out[:500]}

    def _parse_checkov(self, data):
        """Chuẩn hóa Checkov output (có thể là dict hoặc list)."""
        if isinstance(data, list):
            data = data[0] if data else {}
        summary = data.get("summary", {})
        failed = []
        for check_type, checks in data.get("results", {}).items():
            for c in checks.get("failed_checks", []):
                failed.append({
                    "check_id": c.get("check_id"),
                    "check_name": c.get("check_name"),
                    "file": c.get("file_path"),
                    "line": c.get("file_line_range"),
                    "severity": c.get("severity") or "unknown",
                    "guideline": c.get("guideline", ""),
                })
        return {
            "passed": summary.get("passed"),
            "failed": summary.get("failed"),
            "skipped": summary.get("skipped"),
            "parsing_errors": summary.get("parsing_errors"),
            "failed_checks": failed[:80],
        }

    def tfsec(self, path):
        """Chạy tfsec, trả về JSON."""
        cmd = ["tfsec", path, "--format", "json", "--soft-fail"]
        out = self._run(cmd, timeout=300)
        try:
            data = json.loads(out)
            results = []
            for r in data.get("results", []):
                results.append({
                    "rule_id": r.get("rule_id"),
                    "description": r.get("description", "")[:200],
                    "severity": r.get("severity"),
                    "location": r.get("location", {}),
                    "resolution": r.get("resolution", "")[:200],
                })
            return {
                "critical": len([r for r in results if r.get("severity") == "CRITICAL"]),
                "high": len([r for r in results if r.get("severity") == "HIGH"]),
                "results": results[:50],
            }
        except Exception:
            return {"raw": out[:500]}

    def _run(self, cmd, timeout=300):
        import subprocess, shutil
        if not shutil.which(cmd[0]):
            return f"[!] {cmd[0]} chưa cài"
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout)
            return r.stdout
        except Exception as e:
            return f"[!] {e}"


class Module(BaseModule):
    name = "iac_scan"
    module_id = "IAC"
    description = "Infrastructure as Code security scan (Checkov, tfsec)"

    def run(self):
        path = self.config.get("path")
        if not path or not Path(path).exists():
            return {"error": "Cần config path trỏ đến thư mục IaC"}

        self.logger.info(f"[IAC] Scan: {path}")
        sc = IaCScanner()
        results = {}

        if self.config.get("checkov", True):
            results["checkov"] = sc.checkov(
                path,
                framework=self.config.get("framework"),
                soft_fail=self.config.get("soft_fail", True),
            )
        if self.config.get("tfsec", True):
            results["tfsec"] = sc.tfsec(path)
        return results