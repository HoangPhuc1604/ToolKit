"""AI-powered triage - LLM + static analysis hybrid."""
import os
import json
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.ai_triage")

TRIAGE_SYSTEM_PROMPT = """Bạn là chuyên gia AppSec. Phân tích finding từ scanner và trả về JSON:
{
  "is_false_positive": true/false,
  "confidence": 0.0-1.0,
  "severity_adjusted": "critical|high|medium|low|info",
  "reasoning": "giải thích ngắn gọn",
  "remediation": "hướng khắc phục cụ thể",
  "cwe": "CWE-xxx nếu xác định"
}

Quy tắc:
- Nếu finding mơ hồ, KHÔNG có PoC, và endpoint không nhạy cảm → có thể false positive.
- Nếu finding khớp CVE nổi tiếng + version vulnerable → true positive.
- Nếu không chắc → giữ nguyên severity, không tô hồng.
- Chỉ trả về JSON, không văn bản thừa.
"""


class LLMTriage:
    """Gọi LLM để triage finding."""

    def __init__(self, provider="anthropic"):
        self.provider = provider
        self.enabled = self._check()

    def _check(self):
        if self.provider == "anthropic":
            return bool(os.environ.get("ANTHROPIC_API_KEY"))
        if self.provider == "openai":
            return bool(os.environ.get("OPENAI_API_KEY"))
        return False

    def triage(self, finding: dict) -> dict:
        if not self.enabled:
            return {"error": "Thiếu API key cho LLM triage"}

        user_msg = (
            f"Finding:\n"
            f"- Title: {finding.get('title', '')}\n"
            f"- Service: {finding.get('service', '')}\n"
            f"- Version: {finding.get('version', '')}\n"
            f"- Port: {finding.get('port', '')}\n"
            f"- CVE: {finding.get('cve', '')}\n"
            f"- Description: {finding.get('description', '')[:1000]}\n"
        )
        if self.provider == "anthropic":
            return self._anthropic(user_msg)
        return self._openai(user_msg)

    def _anthropic(self, msg):
        try:
            import anthropic
            client = anthropic.Anthropic()
            r = client.messages.create(
                model="claude-sonnet-4-5",
                max_tokens=1024,
                system=TRIAGE_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": msg}],
            )
            return self._parse(r.content[0].text)
        except Exception as e:
            return {"error": str(e)}

    def _openai(self, msg):
        try:
            from openai import OpenAI
            client = OpenAI()
            r = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": TRIAGE_SYSTEM_PROMPT},
                    {"role": "user", "content": msg},
                ],
                max_tokens=1024,
            )
            return self._parse(r.choices[0].message.content)
        except Exception as e:
            return {"error": str(e)}

    def _parse(self, text):
        """Parse JSON từ LLM output, chấp nhận có markdown code fence."""
        text = text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        try:
            return json.loads(text.strip())
        except Exception:
            return {"raw": text[:500], "parse_error": True}


class HybridTriagePipeline:
    """Kết hợp rule-based + LLM triage."""

    def __init__(self, llm_provider="anthropic"):
        self.llm = LLMTriage(llm_provider)

    # Rule-based pre-filter
    def rule_filter(self, finding):
        """Lọc false positive rõ ràng trước khi gọi LLM (tiết kiệm token)."""
        # Info-only findings không cần LLM
        if finding.get("severity") == "info":
            return {"skip_llm": True, "reason": "Info-only, không cần triage",
                    "is_false_positive": False,
                    "severity_adjusted": "info"}

        # Missing header findings - thường là false positive
        title = finding.get("title", "").lower()
        if "header" in title and "missing" in title:
            return {"skip_llm": True, "reason": "Missing header - low impact",
                    "is_false_positive": True,
                    "severity_adjusted": "low"}

        # Version quá cũ không tồn tại → nghi vấn
        version = finding.get("version", "")
        if version.startswith("0.") and "beta" in version.lower():
            return {"skip_llm": True, "reason": "Beta version - không tính",
                    "is_false_positive": True,
                    "severity_adjusted": "info"}

        return {"skip_llm": False}

    def process(self, findings: list) -> list:
        """Chạy pipeline: rule filter → LLM cho các finding còn lại."""
        processed = []
        llm_calls = 0
        for f in findings:
            rule_result = self.rule_filter(f)
            if rule_result["skip_llm"]:
                f["triage"] = rule_result
                f["triage"]["method"] = "rule"
            else:
                f["triage"] = self.llm.triage(f)
                f["triage"]["method"] = "llm"
                llm_calls += 1
            processed.append(f)

        return {
            "total": len(findings),
            "llm_calls": llm_calls,
            "rule_filtered": len(findings) - llm_calls,
            "findings": processed,
        }


class Module(BaseModule):
    name = "ai_triage"
    module_id = "AIT"
    description = "AI-powered triage (LLM + rule-based hybrid)"

    def run(self):
        self.logger.info("[AIT] AI triage pipeline")
        cfg = self.config

        findings = cfg.get("findings", [])
        if not findings:
            # Thử lấy từ state (các module trước)
            from core.state import STATE
            findings = STATE.get("all_findings", [])

        if not findings:
            return {"note": "Không có findings để triage"}

        pipeline = HybridTriagePipeline(
            cfg.get("llm_provider", "anthropic"))
        return pipeline.process(findings)