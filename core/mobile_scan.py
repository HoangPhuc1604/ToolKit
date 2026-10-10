"""Mobile app scan - MobSF REST API integration."""
import os
import hashlib
import time
import requests
from pathlib import Path
from core.base_module import BaseModule


class MobSFClient:
    """Client MobSF REST API."""

    def __init__(self, base_url=None, api_key=None):
        self.base = (base_url or os.environ.get("MOBSF_URL",
                    "http://localhost:8000")).rstrip("/")
        self.api_key = api_key or os.environ.get("MOBSF_API_KEY", "")
        if not self.api_key:
            raise ValueError("Thiếu MOBSF_API_KEY")
        self.headers = {"Authorization": self.api_key}

    def upload(self, file_path):
        """Upload APK/IPA/APPX."""
        with open(file_path, "rb") as f:
            files = {"file": (Path(file_path).name, f)}
            r = requests.post(f"{self.base}/api/v1/upload",
                              files=files, headers=self.headers, timeout=120)
        if r.status_code != 200:
            raise RuntimeError(f"Upload failed: {r.status_code} {r.text[:200]}")
        data = r.json()
        # MobSF yêu cầu lưu hash để scan
        return data.get("hash"), data

    def scan(self, file_hash, rescan=False):
        """Kích hoạt scan."""
        r = requests.post(f"{self.base}/api/v1/scan",
                          data={"hash": file_hash, "re_scan": rescan},
                          headers=self.headers, timeout=600)
        return r.json()

    def report_json(self, file_hash):
        """Lấy báo cáo JSON đầy đủ."""
        r = requests.post(f"{self.base}/api/v1/report_json",
                          data={"hash": file_hash},
                          headers=self.headers, timeout=60)
        return r.json()

    def scorecard(self, file_hash):
        r = requests.post(f"{self.base}/api/v1/scorecard",
                          data={"hash": file_hash},
                          headers=self.headers, timeout=60)
        return r.json()

    def recent_scans(self, page=1, page_size=10):
        r = requests.post(f"{self.base}/api/v1/scans",
                          data={"page": page, "page_size": page_size},
                          headers=self.headers, timeout=30)
        return r.json()


class Module(BaseModule):
    name = "mobile_scan"
    module_id = "MOB"
    description = "Mobile app static analysis (MobSF)"

    def run(self):
        apk_path = self.config.get("apk_path")
        if not apk_path or not os.path.exists(apk_path):
            return {"error": "Cần config apk_path trỏ đến file APK/IPA"}

        self.logger.info(f"[MOB] Phân tích: {apk_path}")
        try:
            client = MobSFClient(
                base_url=self.config.get("base_url"),
                api_key=self.config.get("api_key"),
            )
            file_hash, upload_info = client.upload(apk_path)
            self.logger.info(f"[MOB] Upload OK, hash={file_hash}")

            scan_result = client.scan(file_hash,
                                      rescan=self.config.get("rescan", False))
            time.sleep(2)

            report = client.report_json(file_hash)
            scorecard = client.scorecard(file_hash)

            return {
                "file_hash": file_hash,
                "app_name": report.get("app_name"),
                "package_name": report.get("package_name"),
                "version": report.get("version_name"),
                "security_score": scorecard.get("score"),
                "permissions": self._extract_permissions(report),
                "vulnerabilities": self._extract_vulns(report),
                "network_security": report.get("network_security"),
                "certificate": report.get("certificate_analysis", {}),
            }
        except Exception as e:
            return {"error": str(e)}

    def _extract_permissions(self, report):
        perms = report.get("permissions", {})
        dangerous = []
        for perm, info in perms.items():
            if info.get("status") == "dangerous":
                dangerous.append({
                    "permission": perm,
                    "description": info.get("description", ""),
                })
        return dangerous[:30]

    def _extract_vulns(self, report):
        vulns = []
        # Manifest issues
        for issue, info in report.get("manifest_analysis", {}).get(
                "manifest_issues", {}).items():
            if info.get("severity") in ("high", "warning"):
                vulns.append({
                    "type": "manifest",
                    "title": info.get("title", issue),
                    "severity": info.get("severity"),
                    "description": info.get("description", "")[:200],
                })
        # Code issues
        for issue, info in report.get("code_analysis", {}).get(
                "findings", {}).items():
            if info.get("level") in ("high", "warning"):
                vulns.append({
                    "type": "code",
                    "title": info.get("metadata", {}).get("description", issue),
                    "severity": info.get("level"),
                })
        return vulns[:40]