"""Blockchain audit - Slither + Mythril cho smart contracts."""
import subprocess
import shutil
import json
import os
from pathlib import Path
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.chain")


class SlitherRunner:
    """Chạy Slither static analysis."""

    def __init__(self):
        self.available = shutil.which("slither") is not None

    def analyze(self, contract_path, detectors=None):
        """Chạy Slither với JSON output."""
        if not self.available:
            return {"error": "slither chưa cài (pip install slither-analyzer)"}

        cmd = ["slither", contract_path, "--json", "-"]
        if detectors:
            cmd += ["--detect", ",".join(detectors)]

        LOG.info(f"[chain] Slither: {contract_path}")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            try:
                data = json.loads(r.stdout)
            except json.JSONDecodeError:
                return {"raw": r.stdout[:2000],
                        "stderr": r.stderr[:1000]}

            findings = []
            for f in data.get("results", {}).get("detectors", []):
                findings.append({
                    "check": f.get("check"),
                    "impact": f.get("impact"),
                    "confidence": f.get("confidence"),
                    "description": f.get("description", "")[:300],
                    "elements": [
                        {"type": e.get("type"),
                         "name": e.get("name"),
                         "line": e.get("source_mapping", {}).get("lines", [])}
                        for e in f.get("elements", [])[:3]
                    ],
                })
            return {
                "success": data.get("success"),
                "findings_count": len(findings),
                "findings": findings,
            }
        except subprocess.TimeoutExpired:
            return {"error": "Slither timeout"}

    def list_detectors(self):
        if not self.available:
            return []
        try:
            r = subprocess.run(["slither", "--list-detectors"],
                               capture_output=True, text=True, timeout=30)
            return [l.strip() for l in r.stdout.splitlines()
                    if "|" in l]
        except Exception:
            return []


class MythrilRunner:
    """Chạy Mythril symbolic execution."""

    def __init__(self):
        self.available = shutil.which("myth") is not None

    def analyze(self, contract_path, timeout=300):
        if not self.available:
            return {"error": "mythril chưa cài (pip install mythril)"}
        cmd = ["myth", "analyze", contract_path, "-o", "json",
               "--execution-timeout", str(timeout)]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout + 60)
            try:
                data = json.loads(r.stdout)
                issues = []
                for issue in data.get("issues", []):
                    issues.append({
                        "title": issue.get("title"),
                        "severity": issue.get("severity"),
                        "swc_id": issue.get("swc-id"),
                        "description": issue.get("description", "")[:300],
                        "contract": issue.get("contract"),
                        "function": issue.get("function"),
                    })
                return {"issues_count": len(issues), "issues": issues}
            except json.JSONDecodeError:
                return {"raw": r.stdout[:2000]}
        except subprocess.TimeoutExpired:
            return {"error": "Mythril timeout"}


class Module(BaseModule):
    name = "blockchain_audit"
    module_id = "CHAIN"
    description = "Smart contract audit (Slither + Mythril)"

    def run(self):
        self.logger.info("[CHAIN] Smart contract audit")
        cfg = self.config
        contract = cfg.get("contract_path")
        if not contract or not Path(contract).exists():
            return {"error": "Cần contract_path trỏ đến file .sol"}

        results = {}
        if cfg.get("slither", True):
            results["slither"] = SlitherRunner().analyze(
                contract, cfg.get("detectors"))
        if cfg.get("mythril", False):
            results["mythril"] = MythrilRunner().analyze(contract)
        return results