"""Module 02 - Footprinting & Reconnaissance (mở rộng)"""
import socket
import re
import requests
import asyncio  # Thêm thư viện này để dùng asyncio.run cho code mới
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.base_module import BaseModule

try:
    import whois
    import dns.resolver
    import dns.zone
    import dns.query
except ImportError:
    whois = None


class Module(BaseModule):
    name = "m02_footprinting"
    module_id = "02"
    description = "Footprinting & Reconnaissance (WHOIS, DNS, Subdomain, OSINT)"

    def run(self):
        self.logger.info(f"[M02] Bắt đầu Footprinting cho: {self.target}")
        cfg = self.config

        if cfg.get("whois", True):
            self.results["whois"] = self._whois()
        if cfg.get("dns", True):
            self.results["dns"] = self._dns_records()
            self.results["zone_transfer"] = self._zone_transfer()
        if cfg.get("subdomain_bruteforce", True):
            self.results["subdomains"] = self._bruteforce_subdomains(
                cfg.get("subdomain_wordlist")
            )
        if cfg.get("theharvester", False):
            self.results["theharvester"] = self._theharvester()
        if cfg.get("google_dorks", False):
            self.results["google_dorks"] = self._google_dorks()

        return self.results

    # ---------- WHOIS ----------
    def _whois(self):
        self.logger.info("[M02] WHOIS lookup...")
        if not whois:
            return {"error": "python-whois chưa cài"}
        try:
            w = whois.whois(self.target)
            return {
                "registrar": w.registrar,
                "org": w.org,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "emails": w.emails if isinstance(w.emails, list) else [w.emails],
                "country": w.country,
            }
        except Exception as e:
            return {"error": str(e)}

    # ---------- DNS ----------
    def _dns_records(self):
        self.logger.info("[M02] DNS records...")
        records = {}
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"):
            try:
                ans = dns.resolver.resolve(self.target, rtype, lifetime=5)
                records[rtype] = [str(r) for r in ans]
            except Exception:
                records[rtype] = []
        return records

    def _zone_transfer(self):
        """Thử AXFR trên mỗi NS - lỗi cấu hình phổ biến."""
        self.logger.info("[M02] Thử DNS Zone Transfer (AXFR)...")
        results = {}
        try:
            ns_records = dns.resolver.resolve(self.target, "NS", lifetime=5)
        except Exception:
            return {"error": "Không lấy được NS"}
        for ns in ns_records:
            ns_str = str(ns).rstrip(".")
            try:
                ip = socket.gethostbyname(ns_str)
                zone = dns.zone.from_xfr(dns.query.xfr(ip, self.target, timeout=5))
                results[ns_str] = [str(n) for n in zone.nodes.keys()]
                self.logger.warning(f"[M02] ZONE TRANSFER THÀNH CÔNG qua {ns_str}!")
            except Exception as e:
                results[ns_str] = f"Từ chối/không hỗ trợ ({type(e).__name__})"
        return results

    # ---------- Subdomain ----------
    def _bruteforce_subdomains(self, wordlist_path):
        """Dùng async để nhanh gấp 20-50×."""
        self.logger.info("[M02] Async subdomain bruteforce...")
        if not wordlist_path:
            return {"error": "Chưa cấu hình subdomain_wordlist"}
        try:
            with open(wordlist_path) as f:
                subs = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return {"error": f"Không tìm thấy wordlist: {wordlist_path}"}

        from core.async_recon import subdomain_bruteforce_async
        found = asyncio.run(
            subdomain_bruteforce_async(self.target, subs, concurrency=300)
        )
        return {"total_found": len(found), "subdomains": found}

    # ---------- theHarvester ----------
    def _theharvester(self):
        self.logger.info("[M02] theHarvester...")
        if not self._tool_available("theHarvester"):
            return self._missing_tool("theHarvester")
        out = self._run_cmd(
            ["theHarvester", "-d", self.target, "-b", "all", "-l", "200"],
            timeout=180,
        )
        return {"output": out[:5000]}

    # ---------- Google Dorks ----------
    def _google_dorks(self):
        self.logger.info("[M02] Sinh Google Dorks...")
        dorks = [
            f'site:{self.target}',
            f'site:{self.target} ext:pdf OR ext:doc OR ext:xls',
            f'site:{self.target} inurl:admin',
            f'site:{self.target} intitle:"index of"',
            f'site:pastebin.com "{self.target}"',
            f'"@{self.target}" filetype:xls OR filetype:csv',
        ]
        return {"dorks": dorks,
                "note": "Copy các dork vào Google/Bing thủ công để tuân thủ ToS."}