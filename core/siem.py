"""SIEM integration - đẩy event lên Splunk HEC / Elasticsearch / Syslog."""
import os
import json
import socket
import requests
from datetime import datetime
from core.logger import get_logger
from core.events import BUS

LOG = get_logger("ceh.siem")


class SIEMExporter:
    """Đẩy event từ EventBus lên SIEM."""

    def __init__(self, backend="splunk", **kwargs):
        self.backend = backend
        self.config = kwargs
        self.enabled = self._check_config()

    def _check_config(self):
        if self.backend == "splunk":
            return bool(os.environ.get("SPLUNK_HEC_URL") and
                        os.environ.get("SPLUNK_HEC_TOKEN"))
        if self.backend == "elasticsearch":
            return bool(os.environ.get("ELASTIC_URL"))
        if self.backend == "syslog":
            return bool(os.environ.get("SYSLOG_HOST"))
        return False

    def emit(self, event: dict):
        """Gửi 1 event tới backend đã chọn."""
        if not self.enabled:
            return False
        # Thêm metadata
        event.setdefault("source", "ceh-toolkit")
        event["@timestamp"] = datetime.now().isoformat()

        try:
            if self.backend == "splunk":
                return self._to_splunk(event)
            if self.backend == "elasticsearch":
                return self._to_elastic(event)
            if self.backend == "syslog":
                return self._to_syslog(event)
        except Exception as e:
            LOG.error(f"[siem] {self.backend} lỗi: {e}")
        return False

    def _to_splunk(self, event):
        url = f"{os.environ['SPLUNK_HEC_URL']}/services/collector/event"
        headers = {"Authorization": f"Splunk {os.environ['SPLUNK_HEC_TOKEN']}"}
        # Splunk HEC yêu cầu payload có "event"
        payload = {"event": event, "sourcetype": "ceh:toolkit"}
        r = requests.post(url, json=payload, headers=headers,
                          verify=False, timeout=10)
        return r.status_code == 200

    def _to_elastic(self, event):
        url = f"{os.environ['ELASTIC_URL']}/ceh-toolkit/_doc"
        headers = {"Content-Type": "application/json"}
        if os.environ.get("ELASTIC_USER") and os.environ.get("ELASTIC_PASS"):
            headers["Authorization"] = (
                f"Basic {self._basic(os.environ['ELASTIC_USER'], os.environ['ELASTIC_PASS'])}")
        r = requests.post(url, json=event, headers=headers,
                          verify=False, timeout=10)
        return r.status_code in (200, 201)

    def _to_syslog(self, event):
        """Gửi RFC5424 qua UDP."""
        host = os.environ["SYSLOG_HOST"]
        port = int(os.environ.get("SYSLOG_PORT", 514))
        # RFC5424: <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID STRUCTURED-DATA MSG
        pri = 13  # user.notice
        ts = event["@timestamp"]
        app = "ceh-toolkit"
        msg = json.dumps(event)
        syslog_msg = f"<{pri}>1 {ts} {socket.gethostname()} {app} - - - {msg}"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(syslog_msg.encode(), (host, port))
        return True

    def _basic(self, u, p):
        from base64 import b64encode
        return b64encode(f"{u}:{p}".encode()).decode()

    def subscribe_bus(self):
        """Subscribe event bus và forward mọi event."""
        import asyncio
        q = BUS.subscribe()
        LOG.info(f"[siem] Đang forward events → {self.backend}")

        async def _loop():
            while True:
                event = await q.get()
                # Chỉ gửi event quan trọng
                if event.get("type") in ("critical_findings",
                                          "module_error",
                                          "scan_end",
                                          "campaign_diff"):
                    self.emit(event)

        return asyncio.create_task(_loop())