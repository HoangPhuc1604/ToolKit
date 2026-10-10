"""Tích hợp Jira - tạo issue tự động cho finding Critical/High."""
import os
import requests
from base64 import b64encode
from core.logger import get_logger

LOG = get_logger("ceh.jira")


class JiraIntegration:
    def __init__(self):
        self.url = os.environ.get("JIRA_URL", "").rstrip("/")
        self.email = os.environ.get("JIRA_EMAIL", "")
        self.token = os.environ.get("JIRA_TOKEN", "")
        self.project = os.environ.get("JIRA_PROJECT", "SEC")
        self.enabled = all([self.url, self.email, self.token])

    def _auth_header(self):
        raw = f"{self.email}:{self.token}".encode()
        return {"Authorization": f"Basic {b64encode(raw).decode()}",
                "Content-Type": "application/json"}

    def create_issue(self, finding: dict):
        if not self.enabled:
            LOG.warning("[jira] Chưa cấu hình JIRA_URL/EMAIL/TOKEN")
            return None

        summary = f"[{finding.get('severity', 'INFO').upper()}] " \
                  f"{finding.get('title', 'Finding')} — " \
                  f"{finding.get('target', 'unknown')}"
        description = self._format_description(finding)

        priority_map = {
            "critical": "Highest", "high": "High",
            "medium": "Medium", "low": "Low", "info": "Lowest",
        }

        payload = {
            "fields": {
                "project": {"key": self.project},
                "summary": summary[:255],
                "description": description,
                "issuetype": {"name": "Bug"},
                "priority": {"name": priority_map.get(
                    finding.get("severity", "medium"), "Medium")},
                "labels": ["pentest", "ceh-toolkit",
                           finding.get("severity", "unknown")],
            }
        }
        try:
            r = requests.post(
                f"{self.url}/rest/api/3/issue",
                json=payload, headers=self._auth_header(), timeout=20)
            if r.status_code in (200, 201):
                key = r.json().get("key")
                LOG.info(f"[jira] Đã tạo issue {key}: {summary}")
                return key
            LOG.error(f"[jira] Lỗi {r.status_code}: {r.text[:300]}")
        except Exception as e:
            LOG.error(f"[jira] Exception: {e}")
        return None

    def _format_description(self, f: dict) -> str:
        lines = [
            f"*Target*: {f.get('target')}",
            f"*Port/Service*: {f.get('port')}/{f.get('service')}",
            f"*Severity*: {f.get('severity')}",
        ]
        if f.get("cve"):
            lines.append(f"*CVE*: {f['cve']}")
        if f.get("cwe"):
            lines.append(f"*CWE*: {f['cwe']}")
        if f.get("description"):
            lines.append(f"\n*Description*:\n{f['description']}")
        if f.get("remediation"):
            lines.append(f"\n*Remediation*:\n{f['remediation']}")
        if f.get("source_tools"):
            lines.append(f"\n*Detected by*: {', '.join(f['source_tools'])}")
        return "\n".join(lines)

    def bulk_create(self, findings: list, min_severity="high"):
        """Tạo issue cho mọi finding >= min_severity."""
        threshold = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        min_val = threshold.get(min_severity, 4)
        created = []
        for f in findings:
            if threshold.get(f.get("severity"), 0) >= min_val:
                key = self.create_issue(f)
                if key:
                    created.append(key)
        return created