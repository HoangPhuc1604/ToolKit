# core/iot_firmware.py
import subprocess
import shutil
from pathlib import Path
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.iot")

class FirmwareAnalyzer:
    """Phân tích firmware IoT."""
    def __init__(self, firmware_path: str):
        self.firmware = Path(firmware_path)
        if not self.firmware.exists():
            raise FileNotFoundError(f"Không tìm thấy firmware: {firmware_path}")

    def extract_binwalk(self, output_dir="/tmp/firmware_extract"):
        """Trích xuất firmware với binwalk."""
        if not shutil.which("binwalk"):
            return {"error": "binwalk chưa cài"}
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        cmd = ["binwalk", "-e", "--directory", output_dir, str(self.firmware)]
        LOG.info(f"[IoT] Binwalk extract: {self.firmware.name}")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return {"output_dir": output_dir, "stdout": r.stdout[-1000:]}
        except Exception as e:
            return {"error": str(e)}

    def scan_with_emba(self):
        """Phân tích tự động với EMBA."""
        if not shutil.which("emba"):
            return {"error": "EMBA chưa cài"}
        cmd = ["emba", "-f", str(self.firmware)]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            return {"stdout": r.stdout[-3000:], "stderr": r.stderr[-1000:]}
        except Exception as e:
            return {"error": str(e)}

    def emulate_firmadyne(self):
        """Mô phỏng firmware với Firmadyne."""
        if not shutil.which("firmadyne"):
            return {"error": "Firmadyne chưa cài"}
        # Firmadyne thường yêu cầu thiết lập phức tạp
        return {"note": "Firmadyne cần thiết lập thủ công (xem tài liệu)"}

class Module(BaseModule):
    name = "iot_firmware"
    module_id = "IOT"
    description = "Phân tích firmware IoT (binwalk + EMBA + Firmadyne)"

    def run(self):
        self.logger.info("[IOT] Bắt đầu phân tích firmware IoT")
        cfg = self.config
        fw_path = cfg.get("firmware_path")
        if not fw_path:
            return {"error": "Cần 'firmware_path' trong config"}
        analyzer = FirmwareAnalyzer(fw_path)
        results = {}

        if cfg.get("binwalk", True):
            results["binwalk"] = analyzer.extract_binwalk()
        if cfg.get("emba"):
            results["emba"] = analyzer.scan_with_emba()
        if cfg.get("firmadyne"):
            results["firmadyne"] = analyzer.emulate_firmadyne()

        return results