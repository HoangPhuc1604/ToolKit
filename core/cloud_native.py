"""Cloud-native security - Falco runtime + Cloud Custodian policy."""
import subprocess
import shutil
import yaml
import json
import os
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.cloudnat")


class FalcoManager:
    """Quản lý Falco rules và alerts."""

    def __init__(self):
        self.available = shutil.which("falco") is not None

    def validate_rules(self, rules_file):
        if not self.available:
            return {"error": "falco chưa cài"}
        try:
            r = subprocess.run(["falco", "-V", "-r", rules_file],
                               capture_output=True, text=True, timeout=30)
            return {"valid": r.returncode == 0,
                    "output": (r.stdout + r.stderr)[:1000]}
        except Exception as e:
            return {"error": str(e)}

    def generate_k8s_rule(self, name, condition, output, priority="WARNING",
                          tags=None):
        """Sinh Falco rule cho K8s."""
        rule = {
            "rule": name,
            "desc": f"Custom rule for {name}",
            "condition": condition,
            "output": output,
            "priority": priority,
            "tags": tags or ["k8s", "custom"],
        }
        return yaml.dump({"customRules": {"- rule": name, "desc": rule["desc"],
                                           "condition": rule["condition"],
                                           "output": rule["output"],
                                           "priority": rule["priority"],
                                           "tags": rule["tags"]}},
                          default_flow_style=False)

    def deploy_helm(self, release="falco", namespace="falco",
                    values=None):
        """Sinh lệnh helm deploy Falco."""
        base = f"helm upgrade --install {release} falco/falco " \
               f"-n {namespace} --create-namespace " \
               f"--set driver.kind=modern_ebpf"
        if values:
            base += f" -f {values}"
        return {"command": base,
                "note": "Chạy lệnh này trên K8s cluster"}


class CloudCustodianRunner:
    """Chạy Cloud Custodian policies."""

    def __init__(self):
        self.available = shutil.which("custodian") is not None

    def validate_policy(self, policy_file):
        if not self.available:
            return {"error": "custodian chưa cài (pip install c7n)"}
        try:
            r = subprocess.run(["custodian", "validate", policy_file],
                               capture_output=True, text=True, timeout=30)
            return {"valid": r.returncode == 0,
                    "output": (r.stdout + r.stderr)[:1000]}
        except Exception as e:
            return {"error": str(e)}

    def run_policy(self, policy_file, dry_run=True, region=None):
        """Chạy policy ở chế độ dry-run hoặc thực thi."""
        if not self.available:
            return {"error": "custodian chưa cài"}
        cmd = ["custodian", "run", "-s", "/tmp/c7n-output"]
        if dry_run:
            cmd.append("--dryrun")
        if region:
            cmd += ["-r", region]
        cmd.append(policy_file)

        LOG.info(f"[cloudnat] custodian run: {' '.join(cmd)}")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            return {
                "stdout": r.stdout[-3000:],
                "stderr": r.stderr[-1000:],
                "success": r.returncode == 0,
            }
        except subprocess.TimeoutExpired:
            return {"error": "Timeout"}

    def generate_policy(self, name, resource, filters, actions):
        """Sinh policy YAML."""
        policy = {
            "policies": [{
                "name": name,
                "resource": resource,
                "filters": filters,
                "actions": actions,
            }]
        }
        return yaml.dump(policy, default_flow_style=False, sort_keys=False)


class Module(BaseModule):
    name = "cloud_native"
    module_id = "CLD"
    description = "Cloud-native security (Falco runtime + Cloud Custodian)"

    def run(self):
        self.logger.info("[CLD] Cloud-native security")
        cfg = self.config
        results = {}

        if cfg.get("falco"):
            fm = FalcoManager()
            f_cfg = cfg["falco"]
            if f_cfg.get("rules_file"):
                results["falco_validate"] = fm.validate_rules(
                    f_cfg["rules_file"])
            if f_cfg.get("helm_deploy"):
                results["falco_deploy"] = fm.deploy_helm(
                    f_cfg.get("release", "falco"),
                    f_cfg.get("namespace", "falco"),
                    f_cfg.get("values"))
            if f_cfg.get("custom_rule"):
                results["falco_rule"] = fm.generate_k8s_rule(
                    **f_cfg["custom_rule"])

        if cfg.get("custodian"):
            cc = CloudCustodianRunner()
            c_cfg = cfg["custodian"]
            if c_cfg.get("policy_file"):
                results["policy_validate"] = cc.validate_policy(
                    c_cfg["policy_file"])
                results["policy_run"] = cc.run_policy(
                    c_cfg["policy_file"],
                    dry_run=c_cfg.get("dry_run", True),
                    region=c_cfg.get("region"))

        return results