# core/cspm.py
import subprocess
import shutil
import json
import os
from pathlib import Path
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.cspm")


class ProwlerRunner:
    """Chạy Prowler CSPM scan."""
    def __init__(self):
        self.available = shutil.which("prowler") is not None

    def scan(self, provider="aws", profile=None, region=None,
             checks=None, output_dir="/tmp/prowler") -> dict:
        if not self.available:
            return {"error": "prowler chưa cài (pip install prowler)"}
        cmd = ["prowler", provider, "-M", "json-ocsf", "-o", output_dir]
        if profile:
            cmd += ["-p", profile]
        if region:
            cmd += ["-r", region]
        if checks:
            cmd += ["-c", checks]
        LOG.info(f"[CSPM] Prowler: {' '.join(cmd[:4])}...")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            findings = self._read_findings(output_dir)
            return {"output": r.stdout[-1000:], "findings": findings}
        except subprocess.TimeoutExpired:
            return {"error": "Timeout"}

    def _read_findings(self, output_dir):
        findings = []
        if not os.path.isdir(output_dir):
            return findings
        for root, _, files in os.walk(output_dir):
            for f in files:
                if not f.endswith(".ocsf.json"):
                    continue
                try:
                    for line in Path(os.path.join(root, f)).read_text().splitlines():
                        obj = json.loads(line)
                        findings.append({
                            "check": obj.get("finding_info", {}).get("title"),
                            "severity": obj.get("severity"),
                            "status": obj.get("status_code"),
                            "resource": obj.get("resource", {}).get("uid"),
                            "region": obj.get("cloud", {}).get("region"),
                        })
                except Exception:
                    continue
        return findings


class ScoutSuiteRunner:
    """Chạy ScoutSuite multi-cloud audit."""
    def __init__(self):
        self.available = shutil.which("scout") is not None

    def scan(self, provider="aws", profile=None,
             report_dir="/tmp/scoutsuite") -> dict:
        if not self.available:
            return {"error": "scoutsuite chưa cài (pip install scoutsuite)"}
        cmd = ["scout", provider, "--report-dir", report_dir, "--no-browser"]
        if profile:
            cmd += ["--profile", profile]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            # Parse findings từ report
            report_file = Path(report_dir) / f"{provider}-report.json"
            findings = []
            if report_file.exists():
                data = json.loads(report_file.read_text())
                for svc, svc_data in data.get("services", {}).items():
                    for check, check_data in svc_data.get("findings", {}).items():
                        if check_data.get("flagged_items", 0) > 0:
                            findings.append({
                                "service": svc, "check": check,
                                "flagged": check_data["flagged_items"],
                                "description": check_data.get("description", "")[:200],
                            })
            return {"output": r.stdout[-500:], "findings": findings}
        except Exception as e:
            return {"error": str(e)}


class IAMPrivEscAnalyzer:
    """Phân tích đường leo thang đặc quyền từ IAM policy."""
    def analyze_policy(self, policy_json: dict) -> dict:
        """Phát hiện các hành động có thể leo thang."""
        privesc_actions = [
            "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
            "iam:PassRole", "iam:CreateAccessKey", "iam:CreateLoginProfile",
            "iam:UpdateLoginProfile", "iam:AttachUserPolicy",
            "iam:AttachGroupPolicy", "iam:AttachRolePolicy",
            "iam:PutUserPolicy", "iam:PutGroupPolicy", "iam:PutRolePolicy",
            "iam:AddUserToGroup", "iam:UpdateAssumeRolePolicy",
            "sts:AssumeRole", "lambda:CreateFunction",
            "lambda:InvokeFunction", "lambda:UpdateFunctionCode",
            "ec2:RunInstances", "glue:CreateDevEndpoint",
            "cloudformation:CreateStack", "datapipeline:CreatePipeline",
        ]
        found = []
        statements = policy_json.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                if action == "*" or action in privesc_actions:
                    found.append({
                        "action": action,
                        "resource": stmt.get("Resource", "*"),
                        "risk": "critical" if action == "*" else "high",
                    })
        return {"privilege_escalation_paths": found,
                "count": len(found)}


class Module(BaseModule):
    name = "cspm"
    module_id = "CSPM"
    description = "Cloud Security Posture Management (Prowler + ScoutSuite)"

    def run(self):
        self.logger.info("[CSPM] Cloud Security Posture Management")
        cfg = self.config
        results = {}

        if cfg.get("prowler", {}).get("enabled", True):
            p = ProwlerRunner()
            results["prowler"] = p.scan(
                provider=cfg["prowler"].get("provider", "aws"),
                profile=cfg["prowler"].get("profile"),
                region=cfg["prowler"].get("region"),
                checks=cfg["prowler"].get("checks"))

        if cfg.get("scoutsuite", {}).get("enabled", True):
            s = ScoutSuiteRunner()
            results["scoutsuite"] = s.scan(
                provider=cfg["scoutsuite"].get("provider", "aws"),
                profile=cfg["scoutsuite"].get("profile"))

        # IAM privesc analysis nếu có policy JSON
        if cfg.get("iam_policy_file"):
            analyzer = IAMPrivEscAnalyzer()
            policy = json.loads(Path(cfg["iam_policy_file"]).read_text())
            results["iam_privesc"] = analyzer.analyze_policy(policy)

        return results