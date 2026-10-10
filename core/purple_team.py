"""Purple team automation - correlate attack ↔ detection."""
import json
import os
import subprocess
import requests
from datetime import datetime, timedelta
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.purple")


class DetectionSource:
    """Base class cho các nguồn detection (SIEM, EDR)."""

    def query_events(self, start, end, technique=None):
        raise NotImplementedError


class SplunkDetectionSource(DetectionSource):
    """Query Splunk qua REST API để tìm detection."""

    def __init__(self, url=None, token=None):
        self.url = url or os.environ.get("SPLUNK_URL", "")
        self.token = token or os.environ.get("SPLUNK_TOKEN", "")

    def query_events(self, start, end, technique=None):
        if not self.url:
            return []
        search = f"search index=* earliest={start} latest={end}"
        if technique:
            search += f' "{technique}"'
        try:
            r = requests.post(
                f"{self.url}/services/search/jobs/export",
                headers={"Authorization": f"Bearer {self.token}"},
                data={"search": search, "output_mode": "json"},
                verify=False, timeout=60)
            return [json.loads(line) for line in r.text.splitlines()
                    if line.strip()]
        except Exception as e:
            LOG.error(f"[purple] Splunk query lỗi: {e}")
            return []


class ElasticDetectionSource(DetectionSource):
    def __init__(self, url=None):
        self.url = url or os.environ.get("ELASTIC_URL", "")

    def query_events(self, start, end, technique=None):
        if not self.url:
            return []
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": start, "lte": end}}},
                    ]
                }
            }
        }
        if technique:
            query["query"]["bool"]["must"].append(
                {"match": {"technique": technique}})
        try:
            r = requests.post(f"{self.url}/_search", json=query, timeout=30)
            return r.json().get("hits", {}).get("hits", [])
        except Exception:
            return []


class PurpleTeamRunner:
    """Chạy attack → query detection → correlate."""

    def __init__(self, detection_source):
        self.detection = detection_source

    def run_exercise(self, technique_ids, time_window_sec=300):
        """Với mỗi technique: chạy Atomic, rồi query detection."""
        from core.adversary_emulation import AtomicRunner
        atomic = AtomicRunner()
        results = []

        for tid in technique_ids:
            start = datetime.utcnow()
            LOG.info(f"[purple] ▶ {tid}")
            attack_result = atomic.run_technique(tid, "local")

            # Chờ để telemetry kịp đến SIEM
            import time
            time.sleep(10)

            end = datetime.utcnow()
            detections = self.detection.query_events(
                start.isoformat() + "Z",
                end.isoformat() + "Z",
                technique=tid)

            results.append({
                "technique": tid,
                "attack_success": attack_result.get("success", False),
                "detections_found": len(detections),
                "detected": len(detections) > 0,
                "gap": not detections,
                "detection_samples": detections[:3],
            })

        return {
            "total": len(results),
            "detected": sum(1 for r in results if r["detected"]),
            "gaps": [r["technique"] for r in results if r["gap"]],
            "coverage_pct": round(
                100 * sum(1 for r in results if r["detected"])
                / max(len(results), 1), 1),
            "details": results,
        }

    def suggest_sigma(self, gap_techniques):
        """Gợi ý Sigma rules cho các technique bị miss."""
        # Tham chiếu SigmaHQ
        sigma_map = {
            "T1059.001": "proc_creation_win_powershell_susp",
            "T1003.001": "proc_access_lsass_memory",
            "T1055": "proc_creation_win_susp_injection",
            "T1548.003": "proc_creation_win_sudo_abuse",
            "T1071.001": "net_connection_win_http_susp",
        }
        return {t: sigma_map.get(t, "Chưa có mapping")
                for t in gap_techniques}


class Module(BaseModule):
    name = "purple_team"
    module_id = "PUR"
    description = "Purple team - correlate attacks với detections"

    def run(self):
        self.logger.info("[PUR] Purple team exercise")
        cfg = self.config

        # Chọn detection source
        source_name = cfg.get("detection_source", "splunk")
        if source_name == "splunk":
            source = SplunkDetectionSource(cfg.get("splunk_url"),
                                            cfg.get("splunk_token"))
        elif source_name == "elastic":
            source = ElasticDetectionSource(cfg.get("elastic_url"))
        else:
            return {"error": f"Detection source không hỗ trợ: {source_name}"}

        runner = PurpleTeamRunner(source)
        techniques = cfg.get("techniques", [
            "T1059.001",  # PowerShell
            "T1003.001",  # LSASS dump
            "T1055",      # Process injection
            "T1548.003",  # Sudo abuse
        ])
        result = runner.run_exercise(techniques,
                                     cfg.get("time_window_sec", 300))
        result["sigma_suggestions"] = runner.suggest_sigma(result["gaps"])
        return result