"""Runtime enforcement - Tetragon + KubeArmor policies."""
import subprocess
import shutil
import yaml
from pathlib import Path
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.rtenforce")


class TetragonManager:
    """Quản lý Tetragon TracingPolicies."""

    def __init__(self):
        self.available = shutil.which("tetragon") is not None or \
                         shutil.which("kubectl") is not None

    def generate_tracing_policy(self, name: str, condition: str,
                                 action: str = "Post",
                                 severity: str = "warning") -> str:
        """Sinh TracingPolicy YAML.

        Actions: Post (observe) | Sigkill (kill) | Override | NotifyEnforcer
        """
        policy = {
            "apiVersion": "cilium.io/v1alpha1",
            "kind": "TracingPolicy",
            "metadata": {"name": name},
            "spec": {
                "kprobes": [{
                    "call": condition,
                    "syscall": False,
                    "args": [{"index": 0, "type": "int"}],
                    "selectors": [{
                        "matchActions": [{"action": action}],
                    }],
                }],
            },
        }
        return yaml.dump(policy, default_flow_style=False)

    def apply_policy(self, policy_yaml: str) -> dict:
        """Apply qua kubectl."""
        if not shutil.which("kubectl"):
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

    def get_events(self, namespace="default", limit=100) -> list:
        """Lấy events từ Tetragon (qua kubectl logs)."""
        if not shutil.which("kubectl"):
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
                    import json
                    events.append(json.loads(line))
                except Exception:
                    continue
            return events
        except Exception:
            return []


class KubeArmorManager:
    """Quản lý KubeArmor policies."""

    def __init__(self):
        self.available = shutil.which("karmor") is not None

    def generate_policy(self, name: str, selector_labels: dict,
                         process_action="Allow",
                         file_action="Allow",
                         network_action="Allow",
                         allowed_processes=None,
                         allowed_paths=None) -> str:
        """Sinh KubeArmorPolicy YAML."""
        policy = {
            "apiVersion": "security.kubearmor.com/v1",
            "kind": "KubeArmorPolicy",
            "metadata": {"name": name, "namespace": "default"},
            "spec": {
                "selector": {"matchLabels": selector_labels},
                "process": {
                    "matchPaths": [
                        {"path": p, "action": process_action}
                        for p in (allowed_processes or ["/bin/bash"])
                    ],
                    "action": process_action,
                },
                "file": {
                    "matchPaths": [
                        {"path": p, "action": file_action}
                        for p in (allowed_paths or ["/etc/shadow"])
                    ],
                    "action": file_action,
                },
                "action": "Block" if process_action == "Block" else "Allow",
            },
        }
        return yaml.dump(policy, default_flow_style=False)

    def apply(self, policy_yaml: str) -> dict:
        if not shutil.which("kubectl"):
            return {"error": "kubectl chưa cài"}
        p = Path("/tmp/kubearmor_policy.yaml")
        p.write_text(policy_yaml)
        try:
            r = subprocess.run(["kubectl", "apply", "-f", str(p)],
                               capture_output=True, text=True, timeout=30)
            return {"applied": r.returncode == 0,
                    "output": (r.stdout + r.stderr)[:500]}
        except Exception as e:
            return {"error": str(e)}

    def logs(self, namespace="default", limit=100) -> list:
        if not self.available:
            return []
        try:
            r = subprocess.run(
                ["karmor", "logs", "-n", namespace, "--json"],
                capture_output=True, text=True, timeout=30)
            import json
            return [json.loads(l) for l in r.stdout.splitlines()
                    if l.strip()]
        except Exception:
            return []


class Module(BaseModule):
    name = "runtime_enforce"
    module_id = "RTE"
    description = "Runtime enforcement (Tetragon + KubeArmor)"

    def run(self):
        self.logger.info("[RTE] Runtime enforcement")
        cfg = self.config
        results = {}

        if cfg.get("tetragon"):
            tm = TetragonManager()
            t_cfg = cfg["tetragon"]

            # Preset policies phổ biến
            presets = {
                "kill_shell_spawn": {
                    "condition": "sys_execve",
                    "action": "Sigkill",
                    "note": "Kill mọi execve của /bin/sh trong container",
                },
                "monitor_privileged": {
                    "condition": "security_bprm_check",
                    "action": "Post",
                    "note": "Log privilege escalation attempts",
                },
                "block_ptrace": {
                    "condition": "sys_ptrace",
                    "action": "Sigkill",
                    "note": "Block ptrace (chống debugging/injection)",
                },
            }

            for preset_name in t_cfg.get("presets", []):
                preset = presets.get(preset_name)
                if not preset:
                    continue
                policy_yaml = tm.generate_tracing_policy(
                    name=f"ceh-{preset_name}",
                    condition=preset["condition"],
                    action=preset["action"])
                results[f"tetragon_{preset_name}"] = {
                    "yaml": policy_yaml,
                    "note": preset["note"],
                }
                if t_cfg.get("auto_apply"):
                    results[f"tetragon_{preset_name}"]["apply"] = \
                        tm.apply_policy(policy_yaml)

            if t_cfg.get("get_events"):
                results["tetragon_events"] = tm.get_events(
                    t_cfg.get("namespace", "default"))[:20]

        if cfg.get("kubearmor"):
            km = KubeArmorManager()
            k_cfg = cfg["kubearmor"]
            policy_yaml = km.generate_policy(
                name=k_cfg.get("name", "ceh-restrict"),
                selector_labels=k_cfg.get("selector", {"app": "web"}),
                process_action=k_cfg.get("process_action", "Block"),
                file_action=k_cfg.get("file_action", "Block"),
                allowed_processes=k_cfg.get("allowed_processes"),
                allowed_paths=k_cfg.get("allowed_paths"))
            results["kubearmor_policy"] = policy_yaml
            if k_cfg.get("auto_apply"):
                results["kubearmor_apply"] = km.apply(policy_yaml)

        return results