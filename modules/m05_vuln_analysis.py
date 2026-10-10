"""Module 05 - Vulnerability Analysis (searchsploit, nikto, sslscan)"""
from core.base_module import BaseModule


class Module(BaseModule):
    name = "m05_vuln_analysis"
    module_id = "05"
    description = "Vulnerability Analysis (searchsploit, nikto, sslscan)"

    def run(self):
        self.logger.info(f"[M05] Vulnerability Analysis: {self.target}")
        cfg = self.config
        if cfg.get("searchsploit", True):
            self.results["searchsploit"] = self._searchsploit()
        if cfg.get("sslscan", True):
            self.results["sslscan"] = self._sslscan()
        if cfg.get("nikto", False):
            self.results["nikto"] = self._nikto()
        return self.results

    def _searchsploit(self):
        self.logger.info("[M05] Tìm exploit công khai qua searchsploit...")
        if not self._tool_available("searchsploit"):
            return self._missing_tool("searchsploit")
        # Chỉ tìm kiếm chung; kết quả chi tiết cần service/version.
        out = self._run_cmd(["searchsploit", "--json", self.target], timeout=60)
        return {"output": out[:5000]}

    def _sslscan(self):
        self.logger.info("[M05] SSL/TLS scanning...")
        if not self._tool_available("sslscan"):
            return self._missing_tool("sslscan")
        return {"output": self._run_cmd(["sslscan", self.target], timeout=60)[:4000]}

    def _nikto(self):
        self.logger.info("[M05] Nikto web scan...")
        if not self._tool_available("nikto"):
            return self._missing_tool("nikto")
        return {"output": self._run_cmd(
            ["nikto", "-h", self.target, "-Tuning", "123b"],
            timeout=180)[:8000]}