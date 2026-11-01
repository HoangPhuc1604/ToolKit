# core/deception_scale.py
import os
import json
import subprocess
import shutil
from pathlib import Path
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.decscale")


class BeelzebubManager:
    """Quản lý Beelzebub deception runtime."""
    def __init__(self, config_dir=None):
        self.config_dir = config_dir or "/etc/beelzebub"
        self.available = shutil.which("beelzebub") is not None

    def generate_config(self, services: list, llm_provider: str = "openai") -> str:
        """Sinh config YAML cho Beelzebub."""
        config = {
            "core": {
                "log_path": "/var/log/beelzebub.json",
                "llm_provider": llm_provider,
                "llm_model": "gpt-4o-mini",
            },
            "services": [],
        }
        for svc in services:
            service = {
                "name": svc.get("name", "ssh-decoy"),
                "protocol": svc.get("protocol", "ssh"),
                "port": svc.get("port", 22),
                "description": svc.get("description", "Ubuntu 22.04 SSH server"),
                "prompt": svc.get("prompt", "You are a Ubuntu Linux server. "
                                              "Respond to attacker commands with realistic "
                                              "but non-compromisable output."),
            }
            config["services"].append(service)
        return json.dumps(config, indent=2)

    def deploy(self, config_json: str) -> dict:
        """Deploy Beelzebub với config."""
        if not self.available:
            return {"error": "beelzebub chưa cài",
                    "config_would_be": config_json[:500]}
        config_path = Path("/tmp/beelzebub_config.json")
        config_path.write_text(config_json)
        try:
            r = subprocess.run(
                ["beelzebub", "--config", str(config_path)],
                capture_output=True, text=True, timeout=30)
            return {"deployed": r.returncode == 0,
                    "output": (r.stdout + r.stderr)[:500]}
        except Exception as e:
            return {"error": str(e)}


class GenPotHoneypot:
    """GenPot: Generative honeypot cho web/API."""
    def __init__(self, llm_provider="anthropic"):
        self.provider = llm_provider
        self.enabled = bool(
            os.environ.get("ANTHROPIC_API_KEY") or
            os.environ.get("OPENAI_API_KEY"))

    def generate_response(self, request_data: dict,
                          context: str = "") -> str:
        """Sinh response giả mạo cho request của attacker."""
        if not self.enabled:
            return "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"ok\"}"
        prompt = (
            f"Bạn đang role-play như một web server dễ bị tổn thương. "
            f"Request từ attacker: {json.dumps(request_data)}\n"
            f"Context: {context}\n"
            f"Hãy trả về HTTP response thực tế nhưng không thể bị xâm phạm. "
            f"Chỉ trả về response thô."
        )
        if self.provider == "anthropic":
            import anthropic
            c = anthropic.Anthropic()
            r = c.messages.create(
                model="claude-sonnet-4-5", max_tokens=500,
                messages=[{"role": "user", "content": prompt}])
            return r.content[0].text
        return "HTTP/1.1 200 OK\r\n\r\n{}"


class AdaptiveHoneypotNetwork:
    """Mạng honeypot thích ứng với RL scoring."""
    def __init__(self, llm_provider="anthropic"):
        self.genpot = GenPotHoneypot(llm_provider)
        self.engagement_scores = {}

    def score_interaction(self, attacker_ip: str, response: str,
                          attacker_continued: bool):
        """RL: cập nhật engagement score dựa trên việc attacker có tiếp tục không."""
        if attacker_ip not in self.engagement_scores:
            self.engagement_scores[attacker_ip] = {
                "total": 0, "continued": 0, "responses": []}
        self.engagement_scores[attacker_ip]["total"] += 1
        if attacker_continued:
            self.engagement_scores[attacker_ip]["continued"] += 1
        self.engagement_scores[attacker_ip]["responses"].append(
            response[:100])

    def top_engaging_responses(self, limit=10):
        """Trả về responses giữ attacker lâu nhất."""
        all_responses = []
        for ip, data in self.engagement_scores.items():
            if data["total"] > 0:
                rate = data["continued"] / data["total"]
                all_responses.append({
                    "ip": ip, "engagement_rate": round(rate, 2),
                    "total": data["total"],
                    "sample_response": data["responses"][-1] if data["responses"] else "",
                })
        return sorted(all_responses, key=lambda x: x["engagement_rate"],
                       reverse=True)[:limit]


class Module(BaseModule):
    name = "deception_scale"
    module_id = "DECS"
    description = "Deception at scale (Beelzebub + GenPot + RL scoring)"

    def run(self):
        self.logger.info("[DECS] Deception at scale")
        cfg = self.config
        results = {}

        # Beelzebub deployment
        if cfg.get("beelzebub"):
            bm = BeelzebubManager(cfg["beelzebub"].get("config_dir"))
            services = cfg["beelzebub"].get("services", [
                {"name": "ssh-decoy", "protocol": "ssh", "port": 2222,
                 "description": "Ubuntu 22.04 SSH server"},
                {"name": "http-decoy", "protocol": "http", "port": 8080,
                 "description": "Apache/2.4.54 (Ubuntu) Server"},
            ])
            config = bm.generate_config(services,
                                         cfg["beelzebub"].get("llm_provider",
                                                               "openai"))
            results["beelzebub_config"] = config
            if cfg["beelzebub"].get("deploy"):
                results["beelzebub_deploy"] = bm.deploy(config)

        # GenPot test
        if cfg.get("genpot"):
            gp = GenPotHoneypot(cfg["genpot"].get("provider", "anthropic"))
            test_requests = cfg["genpot"].get("test_requests", [
                {"method": "GET", "path": "/admin", "headers": {}},
                {"method": "POST", "path": "/login",
                 "body": "user=admin&pass=admin"},
            ])
            results["genpot_responses"] = [
                {"request": r, "response": gp.generate_response(r)[:300]}
                for r in test_requests
            ]

        return results