
## 4. `core/soc_agent.py` — Autonomous SOC Analyst
##Amygdala là SOC analyst agentic mã nguồn mở, kết nối Splunk qua MCP, pull alerts bằng SPL query và feed vào Foundation-Sec-1.1-8B (Splunk security-specialized LLM) để classify severity. Từ kết quả triage, nó spawn các sub-agent để correlate events, trace lateral movement, enrich context, và score risk. Output là incident report JSON + human-readable, push lên Slack. Điểm mạnh: cắt noise 90%+, không cần human-in-the-loop trừ khi vượt escalation threshold.[reference:6] Kiến trúc: Alert Ingestor → Triage Agent → (Correlate | IOC Check | Timeline) sub-agents → Report Builder → Output Handler.[reference:7]

##
"""Autonomous SOC analyst - LLM-powered alert triage + investigation."""
import os
import json
import time
from datetime import datetime
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.soc")

TRIAGE_PROMPT = """Bạn là SOC Tier 1/2 analyst. Nhận alert JSON và trả về JSON:
{
  "severity": "critical|high|medium|low|info",
  "confidence": 0.0-1.0,
  "classification": "true_positive|false_positive|benign|needs_investigation",
  "mitre_technique": "Txxxx hoặc null",
  "summary": "1-2 câu",
  "recommended_actions": ["...", "..."]
}
Chỉ trả về JSON."""


class SplunkMCPClient:
    """Client Splunk qua MCP token-based."""

    def __init__(self, url=None, token=None):
        self.url = url or os.environ.get("SPLUNK_MCP_URL", "")
        self.token = token or os.environ.get("SPLUNK_MCP_TOKEN", "")

    def query_alerts(self, spl="search index=notable | head 50", max_results=50):
        import requests
        if not self.url:
            return {"error": "Thiếu SPLUNK_MCP_URL"}
        try:
            r = requests.post(
                f"{self.url}/api/search",
                headers={"Authorization": f"Bearer {self.token}"},
                json={"query": spl, "max_results": max_results},
                timeout=60)
            return r.json() if r.status_code == 200 else {"error": r.status_code}
        except Exception as e:
            return {"error": str(e)}


class TriageAgent:
    """LLM-powered alert triage."""

    def __init__(self, provider="anthropic", model=None):
        self.provider = provider
        self.model = model or (
            "claude-sonnet-4-5" if provider == "anthropic" else "gpt-4o")
        self.enabled = bool(
            os.environ.get("ANTHROPIC_API_KEY") or
            os.environ.get("OPENAI_API_KEY"))

    def triage(self, alert: dict) -> dict:
        if not self.enabled:
            return {"error": "Thiếu LLM API key"}
        msg = f"Alert:\n{json.dumps(alert, indent=2, default=str)[:3000]}"
        if self.provider == "anthropic":
            return self._anthropic(msg)
        return self._openai(msg)

    def _anthropic(self, msg):
        import anthropic
        c = anthropic.Anthropic()
        r = c.messages.create(
            model=self.model, max_tokens=1000,
            system=TRIAGE_PROMPT,
            messages=[{"role": "user", "content": msg}])
        return self._parse(r.content[0].text)

    def _openai(self, msg):
        from openai import OpenAI
        c = OpenAI()
        r = c.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": TRIAGE_PROMPT},
                      {"role": "user", "content": msg}],
            max_tokens=1000)
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
            return {"raw": text[:300], "parse_error": True}


class CorrelatorAgent:
    """Correlate alert với event xung quanh."""

    def __init__(self, splunk_client):
        self.splunk = splunk_client

    def correlate(self, alert: dict, window_min=15) -> dict:
        """Tìm event liên quan trước/sau alert."""
        entity = (alert.get("src_ip") or alert.get("user") or
                  alert.get("hostname") or "")
        if not entity:
            return {"note": "Không có entity để correlate"}

        spl = (f'search index=* "{entity}" earliest=-{window_min}m '
               f'latest=+{window_min}m | head 100')
        events = self.splunk.query_alerts(spl, max_results=100)

        # Trích xuất lateral movement indicators
        indicators = {
            "unique_destinations": set(),
            "unique_processes": set(),
            "failed_logins": 0,
            "success_logins": 0,
        }
        for e in events.get("results", []) if isinstance(events, dict) else []:
            if e.get("dest_ip"):
                indicators["unique_destinations"].add(e["dest_ip"])
            if e.get("process_name"):
                indicators["unique_processes"].add(e["process_name"])
            if e.get("event_type") == "failed_login":
                indicators["failed_logins"] += 1
            elif e.get("event_type") == "success_login":
                indicators["success_logins"] += 1

        return {
            "entity": entity,
            "window_min": window_min,
            "related_events": len(events.get("results", []))
                if isinstance(events, dict) else 0,
            "unique_destinations": list(indicators["unique_destinations"])[:10],
            "unique_processes": list(indicators["unique_processes"])[:10],
            "failed_logins": indicators["failed_logins"],
            "success_logins": indicators["success_logins"],
            "lateral_movement_suspected": len(indicators["unique_destinations"]) > 3,
        }


class SOCOrchestrator:
    """Điều phối các agent: triage → correlate → report."""

    def __init__(self, config):
        self.config = config
        self.splunk = SplunkMCPClient(
            config.get("splunk_mcp_url"),
            config.get("splunk_mcp_token"))
        self.triage = TriageAgent(
            config.get("provider", "anthropic"))
        self.correlator = CorrelatorAgent(self.splunk)

    def process_alert(self, alert: dict) -> dict:
        t0 = time.time()
        # 1. Triage
        triage = self.triage.triage(alert)
        # 2. Correlate nếu cần
        correlate = {}
        if triage.get("classification") in ("true_positive",
                                             "needs_investigation"):
            correlate = self.correlator.correlate(alert)
        # 3. Incident report
        report = {
            "incident_id": f"INC-{int(time.time())}",
            "alert": alert,
            "triage": triage,
            "correlation": correlate,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "processing_sec": round(time.time() - t0, 2),
        }
        # 4. Push Slack nếu critical/high
        sev = triage.get("severity", "info")
        if sev in ("critical", "high") and self.config.get("slack_webhook"):
            self._push_slack(report)
        return report

    def _push_slack(self, report):
        import requests
        text = (f"🚨 *{report['triage'].get('severity', '?').upper()}* "
                f"{report['triage'].get('summary', '')}\n"
                f"```{json.dumps(report['triage'], indent=2)}```")
        try:
            requests.post(self.config["slack_webhook"],
                          json={"text": text}, timeout=10)
        except Exception:
            pass

    def run_batch(self, alerts: list) -> dict:
        reports = [self.process_alert(a) for a in alerts]
        sev_count = {}
        for r in reports:
            s = r["triage"].get("severity", "info")
            sev_count[s] = sev_count.get(s, 0) + 1
        return {
            "total": len(reports),
            "by_severity": sev_count,
            "noise_reduction_pct": round(
                100 * (1 - sum(1 for r in reports
                               if r["triage"].get("severity") in
                               ("critical", "high")) / max(len(reports), 1)), 1),
            "reports": reports,
        }


class Module(BaseModule):
    name = "soc_agent"
    module_id = "SOC"
    description = "Autonomous SOC analyst (triage + correlate + report)"

    def run(self):
        self.logger.info("[SOC] Autonomous SOC agent")
        cfg = self.config
        orch = SOCOrchestrator(cfg)

        alerts = cfg.get("alerts", [])
        if not alerts and cfg.get("splunk_query"):
            result = orch.splunk.query_alerts(cfg["splunk_query"])
            alerts = result.get("results", []) if isinstance(result, dict) else []

        if not alerts:
            return {"note": "Không có alert để xử lý"}

        return orch.run_batch(alerts)