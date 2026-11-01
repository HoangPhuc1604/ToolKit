# core/satellite_security.py
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.space")

class TTCSAnalyzer:
    """Phân tích bảo mật TT&C."""
    def check_command_auth(self, ground_station_config: dict) -> dict:
        """Kiểm tra xác thực lệnh."""
        findings = []
        if not ground_station_config.get("command_auth_enabled"):
            findings.append({"issue": "Không có xác thực lệnh", "severity": "critical"})
        if not ground_station_config.get("replay_protection"):
            findings.append({"issue": "Thiếu bảo vệ replay", "severity": "high"})
        if ground_station_config.get("mac_type") in ("none", "static", "md5"):
            findings.append({"issue": f"MAC yếu: {ground_station_config.get('mac_type')}", "severity": "high"})
        return {"findings": findings, "score": max(0, 100 - len(findings) * 25)}

    def analyze_ccsds(self, telemetry_sample: bytes) -> dict:
        """Phân tích khung CCSDS (mô phỏng)."""
        # Trong thực tế, cần parse CCSDS frame
        return {"note": "Cần parser CCSDS cụ thể để phân tích"}

class Module(BaseModule):
    name = "satellite_security"
    module_id = "SPACE"
    description = "Bảo mật không gian (TT&C, ground segment)"

    def run(self):
        self.logger.info("[SPACE] Bắt đầu phân tích bảo mật không gian")
        cfg = self.config
        analyzer = TTCSAnalyzer()
        gs_config = cfg.get("ground_station", {})
        if not gs_config:
            return {"error": "Cần 'ground_station' config"}
        results = analyzer.check_command_auth(gs_config)
        self.results.update(results)
        return self.results