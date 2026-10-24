"""Threat modeling automation - STRIDE với LLM."""
import os
import json
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.threat_model")

STRIDE_PROMPT = """Bạn là kiến trúc sư bảo mật. Với mô tả hệ thống sau, hãy:
1. Vẽ data flow (mô tả textual): external entities, processes, data stores, trust boundaries.
2. Áp dụng STRIDE cho từng trust boundary crossing:
   - Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
3. Với mỗi threat: title, description, STRIDE category, likelihood (1-5), impact (1-5), mitigation.
4. Ưu tiên threat theo risk = likelihood × impact.

Trả về JSON:
{
  "data_flow": {"external_entities": [...], "processes": [...], "data_stores": [...], "trust_boundaries": [...]},
  "threats": [{"title": "...", "stride": "S|T|R|I|D|E", "description": "...", "likelihood": N, "impact": N, "risk": N, "mitigation": "..."}],
  "top_5": [...]
}
"""


class ThreatModeler:
    def __init__(self, provider="anthropic"):
        self.provider = provider
        self.enabled = self._check()

    def _check(self):
        if self.provider == "anthropic":
            return bool(os.environ.get("ANTHROPIC_API_KEY"))
        return bool(os.environ.get("OPENAI_API_KEY"))

    def model_from_description(self, description: str) -> dict:
        if not self.enabled:
            return {"error": "Thiếu API key"}
        prompt = f"Mô tả hệ thống:\n\n{description}\n\nHãy phân tích STRIDE."
        if self.provider == "anthropic":
            return self._anthropic(prompt)
        return self._openai(prompt)

    def model_from_repo(self, repo_url: str) -> dict:
        """Phân tích GitHub repo (như STRIDE GPT)."""
        try:
            import requests
            # Lấy README
            owner, repo = repo_url.rstrip("/").split("/")[-2:]
            r = requests.get(
                f"https://api.github.com/repos/{owner}/{repo}/readme",
                headers={"Accept": "application/vnd.github.v3.raw"},
                timeout=15)
            readme = r.text[:5000] if r.status_code == 200 else ""
            if not readme:
                return {"error": "Không đọc được README"}
            return self.model_from_description(
                f"GitHub repo: {repo_url}\n\nREADME:\n{readme}")
        except Exception as e:
            return {"error": str(e)}

    def _anthropic(self, prompt):
        import anthropic
        client = anthropic.Anthropic()
        r = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=4000,
            system=STRIDE_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return self._parse(r.content[0].text)

    def _openai(self, prompt):
        from openai import OpenAI
        client = OpenAI()
        r = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": STRIDE_PROMPT},
                {"role": "user", "content": prompt},
            ],
            max_tokens=4000,
        )
        return self._parse(r.choices[0].message.content)

    def _parse(self, text):
        text = text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        try:
            return json.loads(text.strip())
        except Exception:
            return {"raw": text[:2000], "parse_error": True}


class Module(BaseModule):
    name = "threat_model"
    module_id = "TM"
    description = "STRIDE threat modeling với LLM"

    def run(self):
        self.logger.info("[TM] Threat modeling")
        cfg = self.config
        modeler = ThreatModeler(cfg.get("provider", "anthropic"))

        if cfg.get("description"):
            return modeler.model_from_description(cfg["description"])
        if cfg.get("repo_url"):
            return modeler.model_from_repo(cfg["repo_url"])
        return {"note": "Cần description hoặc repo_url trong config"}