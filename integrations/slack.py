"""Tích hợp Slack - gửi cảnh báo finding theo severity."""
import os
import requests
from core.logger import get_logger

LOG = get_logger("ceh.slack")

SEVERITY_COLOR = {
    "critical": "#f44336", "high": "#ff9800",
    "medium": "#ffeb3b", "low": "#4caf50", "info": "#2196f3",
}
SEVERITY_EMOJI = {
    "critical": "🔴", "high": "🟠",
    "medium": "🟡", "low": "🟢", "info": "🔵",
}


class SlackIntegration:
    def __init__(self):
        self.webhook = os.environ.get("SLACK_WEBHOOK_URL", "")
        self.enabled = bool(self.webhook)

    def _post(self, payload):
        if not self.enabled:
            LOG.warning("[slack] Chưa cấu hình SLACK_WEBHOOK_URL")
            return False
        try:
            r = requests.post(self.webhook, json=payload, timeout=10)
            return r.status_code == 200
        except Exception as e:
            LOG.error(f"[slack] Exception: {e}")
            return False

    def notify_finding(self, finding: dict, campaign: str = "adhoc"):
        sev = finding.get("severity", "info").lower()
        emoji = SEVERITY_EMOJI.get(sev, "⚪")
        color = SEVERITY_COLOR.get(sev, "#888")

        payload = {
            "attachments": [{
                "color": color,
                "title": f"{emoji} [{sev.upper()}] {finding.get('title', 'Finding')}",
                "text": (
                    f"*Target*: `{finding.get('target')}`\n"
                    f"*Port*: {finding.get('port')}/{finding.get('service')}\n"
                    f"*Campaign*: {campaign}"
                ),
                "footer": "CEH Toolkit",
                "ts": int(__import__('time').time()),
            }]
        }
        if finding.get("cve"):
            payload["attachments"][0]["fields"] = [
                {"title": "CVE", "value": finding["cve"], "short": True},
            ]
        return self._post(payload)

    def notify_summary(self, campaign: str, record: dict):
        """Gửi tóm tắt 1 lần chạy campaign."""
        new = record.get("new", 0)
        resolved = record.get("resolved", 0)
        emoji = "✅" if new == 0 else "⚠️"
        payload = {
            "text": f"{emoji} *Campaign `{campaign}`* — scan #{record.get('scan_count')}\n"
                    f"• Targets: {record.get('targets')}\n"
                    f"• Total: {record.get('total_findings')}\n"
                    f"• 🆕 New: {new} | ✅ Resolved: {resolved} | "
                    f"🔄 Persistent: {record.get('persistent')}"
        }
        return self._post(payload)