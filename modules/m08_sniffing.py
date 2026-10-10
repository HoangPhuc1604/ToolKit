"""Module 08 - Sniffing (tcpdump capture + scapy analysis)."""
import os
import tempfile
import time
from collections import Counter
from core.base_module import BaseModule


class Module(BaseModule):
    name = "m08_sniffing"
    module_id = "08"
    description = "Sniffing (tcpdump capture, scapy analysis, ARP detection)"

    def run(self):
        self.logger.info(f"[M08] Sniffing trên iface: {self.config.get('iface', 'eth0')}")
        self.logger.warning("[M08] Cần quyền root/CAP_NET_RAW.")
        cfg = self.config

        if cfg.get("tcpdump", True):
            self.results["capture"] = self._tcpdump_capture()
            if self.results["capture"].get("pcap_file"):
                self.results["analysis"] = self._analyze_pcap(
                    self.results["capture"]["pcap_file"]
                )
        if cfg.get("arp_scan", True):
            self.results["arp_scan"] = self._arp_scan()
        if cfg.get("arp_spoof_detect", False):
            self.results["arp_anomalies"] = self._detect_arp_anomalies()
        return self.results

    # ---------- Tcpdump ----------
    def _tcpdump_capture(self):
        iface = self.config.get("iface", "eth0")
        duration = self.config.get("duration", 30)
        bpf = self.config.get("bpf_filter", "")

        if not self._tool_available("tcpdump"):
            return self._missing_tool("tcpdump")

        out_file = os.path.join(
            tempfile.gettempdir(),
            f"ceh_capture_{int(time.time())}.pcap"
        )
        cmd = ["tcpdump", "-i", iface, "-w", out_file, "-G", str(duration), "-W", "1"]
        if bpf:
            cmd += bpf.split()

        self.logger.info(f"[M08] Capture {duration}s → {out_file}")
        out = self._run_cmd(cmd, timeout=duration + 10)
        return {
            "pcap_file": out_file if os.path.exists(out_file) else None,
            "duration": duration,
            "output": out[:1000]
        }

    # ---------- Scapy analysis ----------
    def _analyze_pcap(self, pcap_path):
        self.logger.info(f"[M08] Phân tích {pcap_path} bằng scapy...")
        try:
            from scapy.all import rdpcap, IP, TCP, UDP, DNS, ARP, Raw
        except ImportError:
            return {"error": "scapy chưa cài (pip install scapy)"}

        try:
            packets = rdpcap(pcap_path)
        except Exception as e:
            return {"error": f"Không đọc được pcap: {e}"}

        stats = {
            "total_packets": len(packets),
            "protocols": Counter(),
            "top_src_ips": Counter(),
            "top_dst_ips": Counter(),
            "top_dst_ports": Counter(),
            "dns_queries": [],
            "http_requests": [],
            "arp_pairs": [],
            "credentials_plain": [],   # Phát hiện plaintext creds
        }

        for pkt in packets:
            if IP in pkt:
                stats["protocols"][pkt[IP].proto] += 1
                stats["top_src_ips"][pkt[IP].src] += 1
                stats["top_dst_ips"][pkt[IP].dst] += 1

                if TCP in pkt:
                    stats["top_dst_ports"][pkt[TCP].dport] += 1
                    if pkt[TCP].dport in (80, 8080) and Raw in pkt:
                        payload = pkt[Raw].load.decode(errors="ignore")
                        if payload.startswith(("GET", "POST")):
                            stats["http_requests"].append(
                                payload.split("\r\n")[0][:200])
                            low = payload.lower()
                            for kw in ("password=", "user=", "login=", "pwd="):
                                if kw in low:
                                    stats["credentials_plain"].append(
                                        payload[:200])
                                    break

                if DNS in pkt and pkt[DNS].qd is not None:
                    try:
                        qname = pkt[DNS].qd.qname.decode(errors="ignore")
                        stats["dns_queries"].append(qname)
                    except Exception:
                        pass

            elif ARP in pkt:
                stats["arp_pairs"].append(
                    f"{pkt[ARP].psrc} → {pkt[ARP].hwsrc}")

        # Giới hạn output
        return {
            "total_packets": stats["total_packets"],
            "top_src_ips": stats["top_src_ips"].most_common(10),
            "top_dst_ips": stats["top_dst_ips"].most_common(10),
            "top_dst_ports": stats["top_dst_ports"].most_common(10),
            "dns_queries": stats["dns_queries"][:30],
            "http_requests": stats["http_requests"][:30],
            "credentials_plain": stats["credentials_plain"][:10],
            "arp_pairs": list(set(stats["arp_pairs"]))[:20],
        }

    # ---------- ARP scan ----------
    def _arp_scan(self):
        self.logger.info("[M08] ARP scan (host discovery L2)...")
        try:
            from scapy.all import ARP, Ether, srp
        except ImportError:
            return {"error": "scapy chưa cài"}

        iface = self.config.get("iface", "eth0")
        subnet = self.config.get("subnet", "192.168.1.0/24")

        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
            ans, _ = srp(pkt, timeout=3, iface=iface, verbose=False)
            hosts = [{"ip": rcv.psrc, "mac": rcv.hwsrc} for _, rcv in ans]
            for h in hosts:
                self.logger.info(f"[M08]  -> {h['ip']} ({h['mac']})")
            return {"hosts": hosts, "count": len(hosts)}
        except Exception as e:
            return {"error": str(e)}

    def _detect_arp_anomalies(self):
        """Cảnh báo khi 1 MAC map nhiều IP (dấu hiệu ARP spoofing)."""
        arp = self.results.get("arp_scan", {}).get("hosts", [])
        mac_to_ips = {}
        for h in arp:
            mac_to_ips.setdefault(h["mac"], []).append(h["ip"])
        return {
            "suspicious": {m: ips for m, ips in mac_to_ips.items()
                           if len(ips) > 1},
            "note": "Nếu 1 MAC trả về nhiều IP → nghi ngờ ARP spoofing."
        }