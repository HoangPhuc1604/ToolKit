"""Tích hợp DefectDojo - import findings qua API."""
import os
import json
import requests
from core.logger import get_logger

LOG = get_logger("ceh.defectdojo")


class DefectDojoIntegration:
    def __init__(self):
        self.url = os.environ.get("DEFECTDOJO_URL", "").rstrip("/")
        self.token = os.environ.get("DEFECTDOJO_TOKEN", "")
        self.engagement = os.environ.get("DEFECTDOJO_ENGAGEMENT", "")
        self.enabled = all([self.url, self.token, self.engagement])

    def _headers(self):
        return {"Authorization": f"Token {self.token}",
                "Content-Type": "application/json"}

    def import_findings(self, findings: list, scan_type="Generic Findings Import",
                        product_name="CEH Toolkit"):
        """Import findings vào DefectDojo engagement."""
        if not self.enabled:
            LOG.warning("[defectdojo] Chưa cấu hình URL/TOKEN/ENGAGEMENT")
            return None

        # Chuyển sang định dạng DefectDojo generic
        dd_findings = []
        for f in findings:
            dd_findings.append({
                "title": f.get("title", "Finding")[:511],
                "severity": f.get("severity", "Info").capitalize(),
                "description": f.get("description", "")[:4000],
                "date": f.get("first_seen", "")[:10],
                "cve": f.get("cve", ""),
                "cwe": self._parse_cwe(f.get("cwe")),
                "active": True,
                "verified": False,
                "endpoints": [f"https://{f.get('target')}"] if f.get("target") else [],
            })

        payload = {
            "scan_type": scan_type,
            "engagement": int(self.engagement),
            "verified": False,
            "active": True,
            "close_old_findings": False,
            "minimum_severity": "Info",
            "skip_duplicates": True,     # DefectDojo tự dedup
            "findings": dd_findings,
        }
        try:
            r = requests.post(
                f"{self.url}/api/v2/import-scan/",
                json=payload, headers=self._headers(), timeout=60)
            if r.status_code in (200, 201):
                LOG.info(f"[defectdojo] Đã import {len(dd_findings)} findings")
                return r.json()
            LOG.error(f"[defectdojo] Lỗi {r.status_code}: {r.text[:300]}")
        except Exception as e:
            LOG.error(f"[defectdojo] Exception: {e}")
        return None

    def _parse_cwe(self, cwe_str):
        if not cwe_str:
            return None
        digits = "".join(c for c in cwe_str if c.isdigit())
        return int(digits) if digits else None