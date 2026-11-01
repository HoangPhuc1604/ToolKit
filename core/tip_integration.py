# core/tip_integration.py
import os
import json
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.tip")

try:
    from pymisp import PyMISP, MISPEvent, MISPObject
    PYMISP_AVAILABLE = True
except ImportError:
    PYMISP_AVAILABLE = False

try:
    from pycti import OpenCTIApiClient
    PYCTI_AVAILABLE = True
except ImportError:
    PYCTI_AVAILABLE = False


class MISPClient:
    """Client MISP qua PyMISP."""
    def __init__(self, url=None, api_key=None, verify_ssl=False):
        if not PYMISP_AVAILABLE:
            raise ImportError("pymisp chưa cài (pip install pymisp)")
        self.url = url or os.environ.get("MISP_URL", "")
        self.api_key = api_key or os.environ.get("MISP_API_KEY", "")
        self.misp = PyMISP(self.url, self.api_key, ssl=verify_ssl)

    def create_event(self, info: str, distribution: int = 0,
                     threat_level: int = 2, analysis: int = 1) -> dict:
        event = MISPEvent()
        event.info = info
        event.distribution = distribution
        event.threat_level_id = threat_level
        event.analysis = analysis
        result = self.misp.add_event(event)
        return {"event_id": result.get("Event", {}).get("id"),
                "info": info}

    def add_attribute(self, event_id: str, attr_type: str,
                      value: str, category: str = "Network activity",
                      to_ids: bool = True) -> dict:
        result = self.misp.add_attribute(
            event_id, {"type": attr_type, "value": value,
                        "category": category, "to_ids": to_ids})
        return {"attribute_id": result.get("Attribute", {}).get("id"),
                "value": value}

    def search(self, value: str, type_attribute: str = None) -> dict:
        result = self.misp.search(value=value, type_attribute=type_attribute)
        return {"total": len(result), "events": result[:5]}

    def export_stix(self, event_id: str) -> dict:
        return self.misp.get_event(event_id, pythonify=False)


class OpenCTIClient:
    """Client OpenCTI qua pycti."""
    def __init__(self, url=None, token=None):
        if not PYCTI_AVAILABLE:
            raise ImportError("pycti chưa cài (pip install pycti)")
        self.url = url or os.environ.get("OPENCTI_URL", "")
        self.token = token or os.environ.get("OPENCTI_TOKEN", "")
        self.client = OpenCTIApiClient(self.url, self.token)

    def create_indicator(self, name: str, pattern: str,
                         pattern_type: str = "stix",
                         valid_from: str = None) -> dict:
        from datetime import datetime
        return self.client.indicator.create(
            name=name,
            pattern=pattern,
            pattern_type=pattern_type,
            x_opencti_main_observable_type="IPv4-Addr",
            valid_from=valid_from or datetime.utcnow().isoformat() + "Z",
            update=True,
        )

    def create_observable(self, obs_type: str, value: str) -> dict:
        return self.client.stix_cyber_observable.create(
            observableData={"type": obs_type, "value": value})

    def enrich_ip(self, ip: str) -> dict:
        """Làm giàu IP với OpenCTI data."""
        obs = self.client.stix_cyber_observable.list(
            filters={"mode": "and", "filters": [
                {"key": "value", "values": [ip]}]})
        return {"found": len(obs) > 0, "observables": obs[:5]}

    def create_report(self, name: str, description: str,
                      observable_refs: list = None) -> dict:
        return self.client.report.create(
            name=name, description=description,
            published="true",
            object_refs=observable_refs or [])


class TIPSynchronizer:
    """Đồng bộ MISP ↔ OpenCTI."""
    def __init__(self, misp: MISPClient, opencti: OpenCTIClient):
        self.misp = misp
        self.opencti = opencti

    def sync_iocs(self, misp_event_id: str) -> dict:
        """Đọc IOC từ MISP event, đẩy sang OpenCTI."""
        event = self.misp.export_stix(misp_event_id)
        attrs = event.get("Event", {}).get("Attribute", [])
        synced = []
        for attr in attrs:
            obs_type_map = {"ip-src": "IPv4-Addr", "ip-dst": "IPv4-Addr",
                            "domain": "Domain-Name", "hostname": "Hostname",
                            "md5": "StixFile", "sha1": "StixFile",
                            "sha256": "StixFile", "url": "Url"}
            obs_type = obs_type_map.get(attr.get("type"))
            if not obs_type:
                continue
            try:
                self.opencti.create_observable(obs_type, attr["value"])
                synced.append({"type": obs_type, "value": attr["value"]})
            except Exception as e:
                LOG.warning(f"[TIP] Sync lỗi {attr['value']}: {e}")
        return {"synced": len(synced), "iocs": synced}


class Module(BaseModule):
    name = "tip_integration"
    module_id = "TIP"
    description = "Tích hợp MISP & OpenCTI (threat intelligence platform)"

    def run(self):
        self.logger.info("[TIP] Tích hợp Threat Intelligence Platform")
        cfg = self.config
        results = {}

        # MISP operations
        if cfg.get("misp", {}).get("enabled") and PYMISP_AVAILABLE:
            misp = MISPClient(
                cfg["misp"].get("url"),
                cfg["misp"].get("api_key"))
            if cfg["misp"].get("create_event"):
                e = cfg["misp"]["create_event"]
                results["misp_event"] = misp.create_event(
                    e.get("info", f"CEH scan {self.target}"),
                    e.get("distribution", 0),
                    e.get("threat_level", 2))
            if cfg["misp"].get("search"):
                results["misp_search"] = misp.search(cfg["misp"]["search"])

        # OpenCTI operations
        if cfg.get("opencti", {}).get("enabled") and PYCTI_AVAILABLE:
            octi = OpenCTIClient(
                cfg["opencti"].get("url"),
                cfg["opencti"].get("token"))
            if cfg["opencti"].get("enrich_ip"):
                results["opencti_enrich"] = octi.enrich_ip(
                    cfg["opencti"]["enrich_ip"])

        # Sync
        if (PYMISP_AVAILABLE and PYCTI_AVAILABLE and
                cfg.get("sync_event_id")):
            syncer = TIPSynchronizer(
                MISPClient(cfg["misp"]["url"], cfg["misp"]["api_key"]),
                OpenCTIClient(cfg["opencti"]["url"], cfg["opencti"]["token"]))
            results["sync"] = syncer.sync_iocs(cfg["sync_event_id"])

        return results