"""Module 16 - Cloud Computing (prowler, scoutsuite, cloudfox)."""
import os
import json
from core.base_module import BaseModule


class Module(BaseModule):
    name = "m16_cloud"
    module_id = "16"
    description = "Cloud Security (AWS/Azure/GCP audit qua prowler, scoutsuite)"

    def run(self):
        self.logger.info("[M16] Cloud Security Audit")
        cfg = self.config

        provider = cfg.get("provider", "aws")
        profile = cfg.get("profile")
        regions = cfg.get("regions", "us-east-1")

        if cfg.get("prowler", True):
            self.results["prowler"] = self._prowler(provider, profile, regions)
        if cfg.get("scoutsuite", False):
            self.results["scoutsuite"] = self._scoutsuite(provider, profile)
        if cfg.get("cloudfox", False):
            self.results["cloudfox"] = self._cloudfox(provider, profile)
        return self.results

    def _prowler(self, provider, profile, regions):
        self.logger.info("[M16] Chạy prowler...")
        if not self._tool_available("prowler"):
            return self._missing_tool("prowler")

        out_dir = f"/tmp/ceh_prowler_{os.getpid()}"
        cmd = ["prowler", provider,
               "-M", "json-ocsf", "-o", out_dir,
               "-r", regions]
        if profile:
            cmd += ["-p", profile]

        out = self._run_cmd(cmd, timeout=900)

        # Đọc summary JSON nếu có
        findings = self._read_prowler_findings(out_dir)
        return {
            "output": out[:1500],
            "findings_summary": findings,
            "report_dir": out_dir,
        }

    def _read_prowler_findings(self, out_dir):
        """Tổng hợp số lượng FAIL/PASS theo severity."""
        if not os.path.isdir(out_dir):
            return {}
        summary = {}
        for root, _, files in os.walk(out_dir):
            for f in files:
                if not f.endswith(".ocsf.json"):
                    continue
                try:
                    with open(os.path.join(root, f)) as fh:
                        for line in fh:
                            try:
                                obj = json.loads(line)
                            except Exception:
                                continue
                            sev = obj.get("severity", "unknown")
                            status = obj.get("status_code", "UNKNOWN")
                            key = f"{sev}_{status}"
                            summary[key] = summary.get(key, 0) + 1
                except Exception:
                    continue
        return summary

    def _scoutsuite(self, provider, profile):
        if not self._tool_available("scout"):
            return self._missing_tool("scout")
        out_dir = f"/tmp/ceh_scout_{os.getpid()}"
        cmd = ["scout", provider, "--report-dir", out_dir, "--no-browser"]
        if profile:
            cmd += ["--profile", profile]
        return {"output": self._run_cmd(cmd, timeout=900)[:1500],
                "report_dir": out_dir}

    def _cloudfox(self, provider, profile):
        if not self._tool_available("cloudfox"):
            return self._missing_tool("cloudfox")
        cmd = ["cloudfox", provider, "all-checks"]
        if profile:
            cmd += ["--profile", profile]
        return {"output": self._run_cmd(cmd, timeout=600)[:3000]}