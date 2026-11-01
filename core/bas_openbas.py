# core/bas_openbas.py
import requests
import os
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.bas")

class OpenBASClient:
    """Client cho OpenBAS API."""
    def __init__(self, base_url=None, api_key=None):
        self.base = (base_url or os.environ.get("OPENBAS_URL", "")).rstrip("/")
        self.api_key = api_key or os.environ.get("OPENBAS_API_KEY", "")
        self.headers = {"Authorization": f"Bearer {self.api_key}"}

    def list_scenarios(self):
        """Liệt kê các kịch bản tấn công."""
        if not self.base:
            return {"error": "Chưa cấu hình OPENBAS_URL"}
        try:
            r = requests.get(f"{self.base}/api/scenarios", headers=self.headers, timeout=30)
            return r.json() if r.status_code == 200 else {"error": r.status_code}
        except Exception as e:
            return {"error": str(e)}

    def execute_scenario(self, scenario_id: str):
        """Thực thi một kịch bản."""
        if not self.base:
            return {"error": "Chưa cấu hình OPENBAS_URL"}
        try:
            r = requests.post(f"{self.base}/api/scenarios/{scenario_id}/execute",
                              headers=self.headers, timeout=60)
            return r.json() if r.status_code in (200, 202) else {"error": r.status_code}
        except Exception as e:
            return {"error": str(e)}

class Module(BaseModule):
    name = "bas_openbas"
    module_id = "BAS"
    description = "Mô phỏng tấn công với OpenBAS"

    def run(self):
        self.logger.info("[BAS] Bắt đầu mô phỏng tấn công")
        cfg = self.config
        client = OpenBASClient(cfg.get("url"), cfg.get("api_key"))
        self.results["scenarios"] = client.list_scenarios()
        if cfg.get("execute_scenario_id"):
            self.results["execution"] = client.execute_scenario(cfg["execute_scenario_id"])
        return self.results