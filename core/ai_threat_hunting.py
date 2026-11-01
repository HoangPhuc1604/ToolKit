# core/ai_threat_hunting.py
import os
import json
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.aith")

HYPOTHESIS_PROMPT = """Bạn là threat hunter chuyên nghiệp theo PEAK Framework.
Dựa trên threat intelligence và môi trường, sinh 5 giả thuyết hunting.

Mỗi giả thuyết bao gồm:
{
  "hypothesis": "Mô tả giả thuyết",
  "mitre_technique": "Txxxx",
  "data_sources": ["source1", "source2"],
  "query": "SPL/KQL query để kiểm tra",
  "expected_evidence": "Bằng chứng nào sẽ xác nhận",
  "priority": "high|medium|low"
}

Trả về JSON array. Chỉ trả về JSON."""

QUERY_PROMPT = """Bạn là SIEM engineer. Chuyển giả thuyết hunting sau thành truy vấn SPL cụ thể:

Giả thuyết: {hypothesis}
MITRE Technique: {technique}
Data Sources: {data_sources}

Trả về CHỈ truy vấn SPL, không giải thích."""


class PEAKAssistant:
    """PEAK Framework threat hunting assistant."""
    def __init__(self, provider="anthropic"):
        self.provider = provider
        self.enabled = bool(
            os.environ.get("ANTHROPIC_API_KEY") or
            os.environ.get("OPENAI_API_KEY"))

    def generate_hypotheses(self, context: str, count: int = 5) -> list:
        if not self.enabled:
            return self._fallback_hypotheses()
        prompt = (f"Bối cảnh môi trường:\n{context}\n\n"
                  f"Sinh {count} giả thuyết hunting.")
        if self.provider == "anthropic":
            raw = self._call_anthropic(prompt, HYPOTHESIS_PROMPT)
        else:
            raw = self._call_openai(prompt, HYPOTHESIS_PROMPT)
        return self._parse_json_array(raw)

    def generate_query(self, hypothesis: str, technique: str,
                       data_sources: list) -> str:
        if not self.enabled:
            return f"search index=* {hypothesis[:50]} | head 100"
        prompt = QUERY_PROMPT.format(
            hypothesis=hypothesis, technique=technique,
            data_sources=", ".join(data_sources))
        if self.provider == "anthropic":
            return self._call_anthropic(prompt, "Chỉ trả về SPL query.")
        return self._call_openai(prompt, "Chỉ trả về SPL query.")

    def _call_anthropic(self, user_msg, system):
        import anthropic
        c = anthropic.Anthropic()
        r = c.messages.create(
            model="claude-sonnet-4-5", max_tokens=2000,
            system=system, messages=[{"role": "user", "content": user_msg}])
        return r.content[0].text

    def _call_openai(self, user_msg, system):
        from openai import OpenAI
        c = OpenAI()
        r = c.chat.completions.create(
            model="gpt-4o", max_tokens=2000,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user_msg}])
        return r.choices[0].message.content

    def _parse_json_array(self, text):
        text = text.strip()
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0]
        elif "```" in text:
            text = text.split("```")[1].split("```")[0]
        try:
            return json.loads(text.strip())
        except Exception:
            return [{"error": "parse_failed", "raw": text[:500]}]

    def _fallback_hypotheses(self):
        return [
            {"hypothesis": "PowerShell encoded command execution",
             "mitre_technique": "T1059.001",
             "data_sources": ["process_creation", "script_block"],
             "query": 'search index=* process_name=powershell.exe command_line="*-enc*"',
             "expected_evidence": "Base64 encoded commands",
             "priority": "high"},
            {"hypothesis": "LSASS memory access",
             "mitre_technique": "T1003.001",
             "data_sources": ["process_access"],
             "query": 'search index=* target_process=lsass.exe',
             "expected_evidence": "Non-standard process accessing LSASS",
             "priority": "high"},
            {"hypothesis": "Suspicious scheduled task creation",
             "mitre_technique": "T1053.005",
             "data_sources": ["scheduled_task", "process_creation"],
             "query": 'search index=* schtasks.exe /create',
             "expected_evidence": "Task pointing to suspicious binary",
             "priority": "medium"},
        ]


class ThelmaAgent:
    """Thelma: Two-LLM agent cho hunting automation."""
    def __init__(self, provider="anthropic"):
        self.peak = PEAKAssistant(provider)

    def hunt(self, context: str) -> dict:
        """Pipeline: sinh giả thuyết → ưu tiên → sinh query."""
        hypotheses = self.peak.generate_hypotheses(context)
        # Ưu tiên theo priority
        priority_order = {"high": 0, "medium": 1, "low": 2}
        sorted_h = sorted(hypotheses,
            key=lambda x: priority_order.get(x.get("priority", "low"), 2))
        enriched = []
        for h in sorted_h:
            query = self.peak.generate_query(
                h.get("hypothesis", ""),
                h.get("mitre_technique", ""),
                h.get("data_sources", []))
            h["generated_query"] = query
            enriched.append(h)
        return {"total": len(enriched), "hypotheses": enriched,
                "top_priority": enriched[0] if enriched else None}


class Module(BaseModule):
    name = "ai_threat_hunting"
    module_id = "AITH"
    description = "AI-Powered Threat Hunting (PEAK + Thelma)"

    def run(self):
        self.logger.info("[AITH] AI-Powered Threat Hunting")
        cfg = self.config
        provider = cfg.get("provider", "anthropic")
        context = cfg.get("context",
            f"Target environment: {self.target}. "
            f"Industry: {cfg.get('industry', 'finance')}. "
            f"SIEM: Splunk. EDR: CrowdStrike. "
            f"Known threats: ransomware, APT29.")

        if cfg.get("mode", "thelma") == "thelma":
            agent = ThelmaAgent(provider)
            results = agent.hunt(context)
        else:
            assistant = PEAKAssistant(provider)
            results = {"hypotheses": assistant.generate_hypotheses(context)}

        # Evidence grounding: link với findings từ các module trước
        from core.state import STATE
        findings = STATE.get("all_findings", [])
        if findings:
            results["evidence_context"] = {
                "total_findings": len(findings),
                "high_risk": sum(1 for f in findings
                                 if f.get("severity") in ("critical", "high")),
            }
        return results