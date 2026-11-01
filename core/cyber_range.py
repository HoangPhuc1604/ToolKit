# core/cyber_range.py
import subprocess
import shutil
import yaml
import json
from pathlib import Path
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.range")


class CyRISManager:
    """Quản lý CyRIS cyber range."""
    def __init__(self):
        self.available = shutil.which("cyris") is not None

    def generate_description(self, name: str, hosts: list,
                              network: str = "10.10.0.0/24") -> str:
        """Sinh CyRIS YAML description."""
        desc = {
            "name": name,
            "type": "cyber-range",
            "network": network,
            "hosts": [],
        }
        for h in hosts:
            host = {
                "name": h["name"],
                "os": h.get("os", "ubuntu"),
                "ip": h.get("ip"),
                "services": h.get("services", []),
                "vulnerabilities": h.get("vulnerabilities", []),
            }
            desc["hosts"].append(host)
        return yaml.dump(desc, default_flow_style=False)

    def create_range(self, desc_yaml: str, range_id: str = None) -> dict:
        if not self.available:
            return {"error": "CyRIS chưa cài",
                    "description": desc_yaml[:500]}
        p = Path(f"/tmp/cyris_{range_id or 'range'}.yaml")
        p.write_text(desc_yaml)
        try:
            r = subprocess.run(
                ["cyris", "create", "-f", str(p)],
                capture_output=True, text=True, timeout=1800)
            return {"created": r.returncode == 0,
                    "output": (r.stdout + r.stderr)[:1000]}
        except Exception as e:
            return {"error": str(e)}


class ShifterManager:
    """Quản lý Shifter cyber range."""
    def __init__(self):
        self.available = shutil.which("shifter") is not None

    def generate_cyberscript(self, name: str, scenario: str,
                              hosts: list) -> str:
        """Sinh CyberScript cho Shifter."""
        script = f"""# CyberScript: {name}
scenario "{scenario}"
"""
        for h in hosts:
            script += f"""
host "{h['name']}" {{
    image: "{h.get('image', 'ubuntu:22.04')}"
    ip: "{h.get('ip')}"
    resources: {{ cpu: 2, memory: 4Gi }}
    vulnerabilities: {json.dumps(h.get('vulnerabilities', []))}
}}
"""
        return script


class AttackRangeManager:
    """Quản lý Attack Range (Splunk)."""
    def __init__(self):
        self.available = shutil.which("attack_range") is not None

    def generate_config(self, name: str, provider: str = "aws",
                         victims: list = None) -> dict:
        """Sinh config cho Attack Range."""
        return {
            "attack_range_name": name,
            "cloud_provider": provider,
            "victims": victims or [
                {"name": "victim-01", "os": "windows_server_2019",
                 "ip": "10.0.1.10"},
            ],
            "attackers": [
                {"name": "kali", "os": "kali_linux", "ip": "10.0.1.20"},
            ],
            "windows_servers": [],
            "splunk_server": {"ip": "10.0.1.5"},
        }

    def build(self, config: dict) -> dict:
        if not self.available:
            return {"error": "attack_range chưa cài",
                    "config": config}
        p = Path("/tmp/attack_range_config.json")
        p.write_text(json.dumps(config, indent=2))
        try:
            r = subprocess.run(
                ["attack_range", "build", "-c", str(p)],
                capture_output=True, text=True, timeout=3600)
            return {"built": r.returncode == 0,
                    "output": (r.stdout + r.stderr)[:1000]}
        except Exception as e:
            return {"error": str(e)}


class Module(BaseModule):
    name = "cyber_range"
    module_id = "RANGE"
    description = "Cyber Range Automation (CyRIS + Shifter + Attack Range)"

    def run(self):
        self.logger.info("[RANGE] Cyber Range Automation")
        cfg = self.config
        results = {}

        # CyRIS
        if cfg.get("cyris"):
            cm = CyRISManager()
            desc = cm.generate_description(
                cfg["cyris"].get("name", f"range-{self.target}"),
                cfg["cyris"].get("hosts", [
                    {"name": "victim", "ip": "10.10.0.10",
                     "services": ["ssh", "http"],
                     "vulnerabilities": ["CVE-2021-44228"]},
                    {"name": "attacker", "ip": "10.10.0.20",
                     "os": "kali", "services": []},
                ]))
            results["cyris_description"] = desc
            if cfg["cyris"].get("create"):
                results["cyris_create"] = cm.create_range(desc)

        # Shifter
        if cfg.get("shifter"):
            sm = ShifterManager()
            results["shifter_script"] = sm.generate_cyberscript(
                cfg["shifter"].get("name", "ceh-range"),
                cfg["shifter"].get("scenario", "purple-team"),
                cfg["shifter"].get("hosts", []))

        # Attack Range
        if cfg.get("attack_range"):
            arm = AttackRangeManager()
            config = arm.generate_config(
                cfg["attack_range"].get("name", "ceh-attack-range"),
                cfg["attack_range"].get("provider", "aws"),
                cfg["attack_range"].get("victims"))
            results["attack_range_config"] = config
            if cfg["attack_range"].get("build"):
                results["attack_range_build"] = arm.build(config)

        return results