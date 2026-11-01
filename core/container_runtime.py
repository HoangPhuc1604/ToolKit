# core/container_runtime.py
import subprocess
import shutil
import yaml
import json
from pathlib import Path
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.runtime")


class FalcoManager:
    """Quản lý Falco rules và events."""
    def __init__(self):
        self.available = shutil.which("falco") is not None

    def generate_rule(self, name: str, condition: str,
                      output: str, priority: str = "WARNING",
                      tags: list = None) -> str:
        """Sinh custom Falco rule YAML."""
        rule = {
            "customRules": {
                "rule": name,
                "desc": f"Custom detection rule: {name}",
                "condition": condition,
                "output": output,
                "priority": priority,
                "tags": tags or ["container", "custom"],
            }
        }
        return yaml.dump(rule, default_flow_style=False)

    def validate(self, rule_yaml: str) -> dict:
        if not self.available:
            return {"error": "falco chưa cài"}
        p = Path("/tmp/falco_rule.yaml")
        p.write_text(rule_yaml)
        try:
            r = subprocess.run(["falco", "-V", "-r", str(p)],
                               capture_output=True, text=True, timeout=30)
            return {"valid": r.returncode == 0,
                    "output": (r.stdout + r.stderr)[:500]}
        except Exception as e:
            return {"error": str(e)}


class TetragonManager:
    """Quản lý Tetragon TracingPolicy."""
    def __init__(self):
        self.available = shutil.which("kubectl") is not None

    def generate_policy(self, name: str, kprobe: str,
                         action: str = "Post",
                         args: list = None) -> str:
        """Sinh Tetragon TracingPolicy YAML.

        Actions: Post (observe) | Sigkill (enforce) | Override | NotifyEnforcer
        """
        policy = {
            "apiVersion": "cilium.io/v1alpha1",
            "kind": "TracingPolicy",
            "metadata": {"name": name},
            "spec": {
                "kprobes": [{
                    "call": kprobe,
                    "syscall": False,
                    "args": args or [{"index": 0, "type": "int"}],
                    "selectors": [{"matchActions": [{"action": action}]}],
                }],
            },
        }
        return yaml.dump(policy, default_flow_style=False)

    def apply(self, policy_yaml: str) -> dict:
        if not self.available:
            return {"error": "kubectl chưa cài"}
        p = Path("/tmp/tetragon_policy.yaml")
        p.write_text(policy_yaml)
        try:
            r = subprocess.run(["kubectl", "apply", "-f", str(p)],
                               capture_output=True, text=True, timeout=30)
            return {"applied": r.returncode == 0,
                    "output": (r.stdout + r.stderr)[:500]}
        except Exception as e:
            return {"error": str(e)}

    def get_events(self, limit: int = 100) -> list:
        """Lấy Tetragon events."""
        if not self.available:
            return []
        try:
            r = subprocess.run(
                ["kubectl", "logs", "-n", "kube-system",
                 "-l", "app.kubernetes.io/name=tetragon",
                 "--tail", str(limit)],
                capture_output=True, text=True, timeout=30)
            events = []
            for line in r.stdout.splitlines():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return events
        except Exception:
            return []


class Module(BaseModule):
    name = "container_runtime"
    module_id = "CRT"
    description = "Container runtime security (Falco + Tetragon)"

    def run(self):
        self.logger.info("[CRT] Container runtime security")
        cfg = self.config
        results = {}

        # Falco rules
        if cfg.get("falco"):
            fm = FalcoManager()
            for rule_cfg in cfg["falco"].get("rules", []):
                rule_yaml = fm.generate_rule(
                    rule_cfg["name"], rule_cfg["condition"],
                    rule_cfg["output"],
                    rule_cfg.get("priority", "WARNING"),
                    rule_cfg.get("tags"))
                results[f"falco_{rule_cfg['name']}"] = {
                    "yaml": rule_yaml,
                    "validation": fm.validate(rule_yaml),
                }

        # Tetragon policies
        if cfg.get("tetragon"):
            tm = TetragonManager()
            presets = {
                "kill_shell": {
                    "kprobe": "sys_execve",
                    "action": "Sigkill",
                    "args": [{"index": 0, "type": "string"}],
                },
                "block_ptrace": {
                    "kprobe": "sys_ptrace",
                    "action": "Sigkill",
                    "args": [{"index": 0, "type": "int"}],
                },
                "monitor_capset": {
                    "kprobe": "cap_capset",
                    "action": "Post",
                    "args": [],
                },
            }
            for preset_name in cfg["tetragon"].get("presets", []):
                preset = presets.get(preset_name)
                if not preset:
                    continue
                policy_yaml = tm.generate_policy(
                    f"ceh-{preset_name}", preset["kprobe"],
                    preset["action"], preset["args"])
                results[f"tetragon_{preset_name}"] = {"yaml": policy_yaml}
                if cfg["tetragon"].get("auto_apply"):
                    results[f"tetragon_{preset_name}"]["apply"] = \
                        tm.apply(policy_yaml)

            if cfg["tetragon"].get("get_events"):
                results["tetragon_events"] = tm.get_events()[:20]

        return results