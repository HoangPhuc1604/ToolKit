# core/ai_redteam.py
import subprocess
import shutil
import json
from pathlib import Path
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.ai_redteam")

class GarakRunner:
    """Chạy garak để quét lỗ hổng LLM."""
    def __init__(self):
        self.available = shutil.which("garak") is not None

    def scan(self, model_type="openai", model_name="gpt-4o-mini",
             probes=None, report_prefix="garak_report"):
        """Chạy garak scan."""
        if not self.available:
            return {"error": "garak chưa cài (pip install garak)"}
        cmd = ["garak", "--model_type", model_type, "--model_name", model_name,
               "--report_prefix", report_prefix]
        if probes:
            cmd += ["--probes", probes]
        LOG.info(f"[AI-RedTeam] Chạy garak: {' '.join(cmd)}")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            # Đọc báo cáo JSONL
            report_file = Path(f"{report_prefix}.report.jsonl")
            results = []
            if report_file.exists():
                for line in report_file.read_text().splitlines():
                    if line.strip():
                        try:
                            results.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            return {
                "stdout": r.stdout[-2000:],
                "report_file": str(report_file),
                "total_probes": len(results),
                "sample_results": results[:5]
            }
        except subprocess.TimeoutExpired:
            return {"error": "Garak timeout"}

class Module(BaseModule):
    name = "ai_redteam"
    module_id = "AIRT"
    description = "Red team các ứng dụng LLM/AI (garak)"

    def run(self):
        self.logger.info("[AIRT] Bắt đầu red team AI")
        cfg = self.config
        runner = GarakRunner()
        model_type = cfg.get("model_type", "openai")
        model_name = cfg.get("model_name", "gpt-4o-mini")
        probes = cfg.get("probes")
        results = runner.scan(model_type, model_name, probes)
        return results