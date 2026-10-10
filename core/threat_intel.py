"""Threat intelligence enrichment - VirusTotal, Shodan, Censys, OTX..."""
import os
import time
import requests
from functools import lru_cache
from core.logger import get_logger

LOG = get_logger("ceh.ti")


class ThreatIntelClient:
    """Client đa nguồn, có cache và rate-limit."""

    def __init__(self):
        self.vt_key = os.environ.get("VIRUSTOTAL_API_KEY")
        self.shodan_key = os.environ.get("SHODAN_API_KEY")
        self.censys_id = os.environ.get("CENSYS_API_ID")
        self.censys_secret = os.environ.get("CENSYS_API_SECRET")
        self.otx_key = os.environ.get("OTX_API_KEY")
        self.abuse_key = os.environ.get("ABUSEIPDB_API_KEY")
        self.greynoise_key = os.environ.get("GREYNOISE_API_KEY")
        self._rate_limiters = {}

    def _throttle(self, name, min_interval):
        """Đảm bảo khoảng cách tối thiểu giữa các request."""
        now = time.time()
        last = self._rate_limiters.get(name, 0)
        if now - last < min_interval:
            time.sleep(min_interval - (now - last))
        self._rate_limiters[name] = time.time()

    # ---------- VirusTotal ----------
    @lru_cache(maxsize=512)
    def virustotal_ip(self, ip):
        if not self.vt_key:
            return {"error": "Thiếu VIRUSTOTAL_API_KEY"}
        self._throttle("vt", 15)  # 4 req/min free
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/ip-addresses/{ip}",
                headers={"x-apikey": self.vt_key}, timeout=15)
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}"}
            data = r.json().get("data", {}).get("attributes", {})
            return {
                "reputation": data.get("reputation"),
                "as_owner": data.get("as_owner"),
                "country": data.get("country"),
                "last_analysis_stats": data.get("last_analysis_stats", {}),
                "malicious_engines": self._malicious_engines(data),
            }
        except Exception as e:
            return {"error": str(e)}

    def _malicious_engines(self, data):
        results = data.get("last_analysis_results", {})
        return [name for name, r in results.items()
                if r.get("category") == "malicious"]

    # ---------- Shodan (InternetDB - free, không cần key) ----------
    @lru_cache(maxsize=512)
    def shodan_internetdb(self, ip):
        """Shodan InternetDB: free, no key required."""
        try:
            r = requests.get(f"https://internetdb.shodan.io/{ip}",
                             timeout=10)
            if r.status_code == 404:
                return {"note": "IP không có dữ liệu Shodan"}
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}"}
            return r.json()
        except Exception as e:
            return {"error": str(e)}

    # ---------- Shodan full API ----------
    def shodan_host(self, ip):
        if not self.shodan_key:
            return {"error": "Thiếu SHODAN_API_KEY"}
        try:
            r = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": self.shodan_key}, timeout=15)
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}"}
            data = r.json()
            return {
                "org": data.get("org"),
                "os": data.get("os"),
                "ports": data.get("ports", []),
                "vulns": list(data.get("vulns", {}).keys()),
                "hostnames": data.get("hostnames", []),
                "tags": data.get("tags", []),
            }
        except Exception as e:
            return {"error": str(e)}

    # ---------- AbuseIPDB ----------
    def abuseipdb(self, ip):
        if not self.abuse_key:
            return {"error": "Thiếu ABUSEIPDB_API_KEY"}
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self.abuse_key, "Accept": "application/json"},
                timeout=15)
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}"}
            d = r.json().get("data", {})
            return {
                "abuse_confidence_score": d.get("abuseConfidenceScore"),
                "total_reports": d.get("totalReports"),
                "country": d.get("countryCode"),
                "isp": d.get("isp"),
            }
        except Exception as e:
            return {"error": str(e)}

    # ---------- GreyNoise ----------
    def greynoise(self, ip):
        if not self.greynoise_key:
            return {"error": "Thiếu GREYNOISE_API_KEY"}
        try:
            r = requests.get(
                f"https://api.greynoise.io/v3/community/{ip}",
                headers={"key": self.greynoise_key}, timeout=15)
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}"}
            d = r.json()
            return {
                "noise": d.get("noise"),
                "riot": d.get("riot"),
                "classification": d.get("classification"),
                "name": d.get("name"),
            }
        except Exception as e:
            return {"error": str(e)}

    # ---------- AlienVault OTX ----------
    def otx_ip(self, ip):
        if not self.otx_key:
            return {"error": "Thiếu OTX_API_KEY"}
        try:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": self.otx_key}, timeout=15)
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}"}
            d = r.json()
            return {
                "pulse_count": d.get("pulse_info", {}).get("count"),
                "tags": d.get("pulse_info", {}).get("tags", [])[:20],
                "malware_families": list(set(
                    p.get("malware_families", [])[0]
                    for p in d.get("pulse_info", {}).get("pulses", [])
                    if p.get("malware_families")
                ))[:10],
            }
        except Exception as e:
            return {"error": str(e)}

    def enrich_ip(self, ip, sources=None):
        """Enrich 1 IP với nhiều nguồn."""
        sources = sources or ["vt", "internetdb", "abuse", "greynoise", "otx"]
        result = {"ip": ip}
        if "vt" in sources:
            result["virustotal"] = self.virustotal_ip(ip)
        if "internetdb" in sources:
            result["shodan"] = self.shodan_internetdb(ip)
        if "abuse" in sources:
            result["abuseipdb"] = self.abuseipdb(ip)
        if "greynoise" in sources:
            result["greynoise"] = self.greynoise(ip)
        if "otx" in sources:
            result["otx"] = self.otx_ip(ip)
        return result


class Module(BaseModule):
    name = "threat_intel"
    module_id = "TI"
    description = "Threat intel enrichment cho IP/domain/hash"

    def run(self):
        client = ThreatIntelClient()
        target = self.target
        # Detect loại target
        if self._is_ip(target):
            return client.enrich_ip(target)
        # Domain: resolve rồi enrich
        import socket
        try:
            ip = socket.gethostbyname(target)
            return {"domain": target, "resolved_ip": ip,
                    "enrichment": client.enrich_ip(ip)}
        except Exception as e:
            return {"error": f"Không resolve được {target}: {e}"}

    def _is_ip(self, s):
        parts = s.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False