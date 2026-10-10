"""Module 11 - Web Server Hacking (whatweb, nikto, dirb, wpscan)"""
from core.base_module import BaseModule
from urllib.parse import urlparse


class Module(BaseModule):
    name = "m11_web_hacking"
    module_id = "11"
    description = "Web Hacking (whatweb, nikto, dirb, wpscan)"

    def run(self):
        self.logger.info(f"[M11] Web Hacking: {self.target}")
        cfg = self.config
        url = self._to_url(self.target)

        if cfg.get("whatweb", True):
            self.results["whatweb"] = self._whatweb(url)
        if cfg.get("nikto", True):
            self.results["nikto"] = self._nikto(url)
        if cfg.get("dirb", True):
            self.results["dirb"] = self._dirb(url, cfg.get("dirb_wordlist"))
        if cfg.get("wpscan", False):
            self.results["wpscan"] = self._wpscan(url)
        return self.results

    def _to_url(self, t):
        if t.startswith(("http://", "https://")):
            return t
        return f"http://{t}"

    def _whatweb(self, url):
        if not self._tool_available("whatweb"):
            return self._missing_tool("whatweb")
        return {"output": self._run_cmd(
            ["whatweb", "-a", "3", url], timeout=60)[:3000]}

    def _nikto(self, url):
        if not self._tool_available("nikto"):
            return self._missing_tool("nikto")
        return {"output": self._run_cmd(
            ["nikto", "-h", url, "-maxtime", "120s"], timeout=180)[:8000]}

    def _dirb(self, url, wordlist):
        if not self._tool_available("dirb"):
            return self._missing_tool("dirb")
        cmd = ["dirb", url]
        if wordlist:
            cmd.append(wordlist)
        return {"output": self._run_cmd(cmd, timeout=180)[:6000]}

    def _wpscan(self, url):
        if not self._tool_available("wpscan"):
            return self._missing_tool("wpscan")
        return {"output": self._run_cmd(
            ["wpscan", "--url", url, "--no-update", "--enumerate", "vp"],
            timeout=300)[:6000]}