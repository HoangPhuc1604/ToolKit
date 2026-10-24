import importlib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.logger import get_logger

# ============ THÊM MỚI IMPORT ============
from core.events import BUS
from core.plugin_loader import discover_plugins, load_plugin
from core.ratelimit import get_limiter
# ==========================================


class Orchestrator:
    """Chạy nhiều module, có thể song song. Tích hợp core enrichment + analysis."""

    def __init__(self, target, config, parallel=True, max_workers=3, chain=False):
        self.target = target
        self.config = config
        self.parallel = parallel
        self.chain = chain
        self.max_workers = max_workers
        self.logger = get_logger("ceh.orchestrator")

        from core.state import STATE
        STATE.set("target", target)

        # Rate limiter
        rl_name = config.get("general", {}).get("rate_limit", "normal")
        self.limiter = get_limiter(rl_name)
        self.logger.info(f"Rate limit: {rl_name}")

    # =====================================================
    # HELPERS
    # =====================================================
    def _is_ip(self, s):
        parts = str(s).split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def _load_module(self, module_name):
        # Thử module nội bộ trước
        try:
            mod = importlib.import_module(f"modules.{module_name}")
            return mod.Module
        except ModuleNotFoundError:
            pass

        # Fallback: plugin động
        plugins = discover_plugins(self.config.get("general", {}).get(
            "plugin_dir", "./plugins"))
        if module_name in plugins:
            return load_plugin(plugins[module_name], module_name)

        raise ImportError(f"Không tìm thấy module/plugin: {module_name}")

    # =====================================================
    # GIAI ĐOẠN 1: ENRICHMENT (Làm giàu dữ liệu từ core/)
    # =====================================================
    def _enrich(self):
        core_actions = self.config.get("core_actions", [])
        if "threat_intel" not in core_actions:
            return

        self.logger.info("[Orchestrator] ▶ Giai đoạn 1: Enrichment (Threat Intel)")
        from core.state import STATE
        from core.threat_intel import ThreatIntelClient
        import socket

        try:
            client = ThreatIntelClient()
            if self._is_ip(self.target):
                data = client.enrich_ip(self.target)
                STATE.set("threat_intel", data)
            else:
                try:
                    ip = socket.gethostbyname(self.target)
                    data = client.enrich_ip(ip)
                    data["domain"] = self.target
                    data["resolved_ip"] = ip
                    STATE.set("threat_intel", data)
                except Exception as e:
                    STATE.set("threat_intel",
                              {"error": f"Không resolve được {self.target}: {e}"})
            self.logger.info("[Orchestrator] ✓ Enrichment xong")
        except Exception as e:
            self.logger.warning(f"[Orchestrator] Enrichment lỗi: {e}")
            STATE.set("threat_intel", {"error": str(e)})

    # =====================================================
    # GIAI ĐOẠN 3: ANALYSIS (Phân tích bằng core/)
    # =====================================================
    def _collect_findings(self, results):
        """Gom findings từ các module m03/m05/m11 thành list chuẩn cho dedup."""
        findings = []

        # --- m03 open ports ---
        m03 = results.get("m03_scanning", {}) or {}
        for p in (m03.get("open_ports") or []):
            findings.append({
                "target": self.target,
                "port": p.get("port"),
                "service": p.get("service", ""),
                "title": f"Open port {p.get('port')}/{p.get('service', '')}",
                "severity": "info",
                "source_tools": ["nmap"],
            })

        # --- m05: searchsploit, nikto, sslscan ---
        m05 = results.get("m05_vuln_analysis", {}) or {}
        for tool in ("searchsploit", "nikto", "sslscan"):
            data = m05.get(tool)
            if isinstance(data, dict) and data.get("output"):
                for line in data["output"].splitlines():
                    low = line.lower()
                    if any(k in low for k in ("cve-", "osvdb", "vulnerab",
                                               "injection", "xss", "sql",
                                               "traversal", "disclosure")):
                        findings.append({
                            "target": self.target,
                            "title": line.strip()[:200],
                            "severity": self._guess_severity(line),
                            "source_tools": [tool],
                        })

        # --- m11: whatweb, nikto, dirb, wpscan ---
        m11 = results.get("m11_web_hacking", {}) or {}
        for tool in ("nikto", "whatweb", "dirb", "wpscan"):
            data = m11.get(tool)
            if isinstance(data, dict) and data.get("output"):
                for line in data["output"].splitlines():
                    low = line.lower()
                    if any(k in low for k in ("cve-", "vulnerab", "injection",
                                               "xss", "sql", "traversal")):
                        findings.append({
                            "target": self.target,
                            "title": line.strip()[:200],
                            "severity": self._guess_severity(line),
                            "source_tools": [tool],
                        })

        return findings

    def _guess_severity(self, line):
        low = line.lower()
        if any(k in low for k in ("critical", "rce", "remote code")):
            return "critical"
        if any(k in low for k in ("sql", "injection", "auth bypass")):
            return "high"
        if any(k in low for k in ("xss", "traversal", "disclosure")):
            return "medium"
        return "low"

    def _analyze(self, results):
        core_actions = self.config.get("core_actions", [])
        from core.state import STATE

        # ----- 3.1: Dedup findings -----
        if "dedup" in core_actions:
            try:
                self.logger.info("[Orchestrator] ▶ Giai đoạn 3.1: Dedup findings")
                from core.dedup import normalize, deduplicate
                raw = self._collect_findings(results)
                if raw:
                    normalized = []
                    for f in raw:
                        tool = (f.get("source_tools") or ["unknown"])[0]
                        normalized.append(normalize(f, tool))
                    results["_deduplicated_findings"] = deduplicate(normalized)
                    self.logger.info(
                        f"[Orchestrator]   → {len(results['_deduplicated_findings'])} findings sau dedup")
            except Exception as e:
                self.logger.warning(f"[Orchestrator] Dedup lỗi: {e}")

        # ----- 3.2: Compliance mapping -----
        if "compliance" in core_actions:
            try:
                self.logger.info("[Orchestrator] ▶ Giai đoạn 3.2: Compliance mapping")
                from core.compliance import compliance_report
                findings = results.get("_deduplicated_findings", [])
                if findings:
                    results["_compliance"] = compliance_report(findings)
            except Exception as e:
                self.logger.warning(f"[Orchestrator] Compliance lỗi: {e}")

        # ----- 3.3: Attack graph -----
        if "attack_graph" in core_actions:
            try:
                self.logger.info("[Orchestrator] ▶ Giai đoạn 3.3: Attack Graph")
                from core.attack_graph import build_attack_graph, export_visjs
                G = build_attack_graph({self.target: results})
                out_html = export_visjs(G)
                results["_attack_graph_file"] = out_html
            except Exception as e:
                self.logger.warning(f"[Orchestrator] Attack graph lỗi: {e}")

        # ----- 3.4: Gắn Threat Intel vào kết quả -----
        ti = STATE.get("threat_intel")
        if ti:
            results["_threat_intel"] = ti

    # =====================================================
    # RUN CHÍNH: PIPELINE 3 GIAI ĐOẠN
    # =====================================================
    def run(self, modules):
        # Chain mode: tự thêm m03_scanning đầu danh sách
        if self.chain and "m03_scanning" not in modules:
            modules = ["m03_scanning"] + list(modules)

        BUS.emit("scan_start", {
            "target": self.target,
            "modules": modules,
        }, module="orchestrator")

        # ---------- GIAI ĐOẠN 1: ENRICHMENT ----------
        self._enrich()

        # ---------- GIAI ĐOẠN 2: EXECUTION ----------
        results = {}
        tasks = []
        for m in modules:
            try:
                cls = self._load_module(m)
                cfg = self.config.get("modules", {}).get(m, {})
                tasks.append((m, cls(self.target, cfg)))
            except Exception as e:
                self.logger.error(f"Load {m} lỗi: {e}")
                results[m] = {"error": str(e)}
                BUS.emit("module_error", {"module": m, "error": str(e)})

        # Chain mode → chạy tuần tự để chia sẻ state
        effective_parallel = self.parallel and not self.chain

        if effective_parallel:
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                fmap = {pool.submit(self._wrap_run, n, inst): n
                        for n, inst in tasks}
                for fut in as_completed(fmap):
                    name = fmap[fut]
                    try:
                        results[name] = fut.result()
                    except Exception as e:
                        results[name] = {"error": str(e)}
                        BUS.emit("module_error",
                                 {"module": name, "error": str(e)})
        else:
            for n, inst in tasks:
                try:
                    results[n] = self._wrap_run(n, inst)
                except Exception as e:
                    results[n] = {"error": str(e)}
                    BUS.emit("module_error",
                             {"module": n, "error": str(e)})

        # ---------- GIAI ĐOẠN 3: ANALYSIS ----------
        self._analyze(results)

        # ---------- MITRE mapping (giữ nguyên gốc) ----------
        from core.mitre import map_results
        results["_mitre_attack"] = map_results(results)

        BUS.emit("scan_end", {
            "target": self.target,
            "modules_done": list(results.keys()),
        }, module="orchestrator")
        return results

    def _wrap_run(self, name, instance):
        self.limiter.acquire()
        BUS.emit("module_start", {"module": name}, module=name)
        t0 = time.time()
        try:
            out = instance.run()
            self.logger.info(f"[✓] {name} xong ({time.time()-t0:.1f}s)")
            BUS.emit("module_end", {
                "module": name,
                "duration": round(time.time() - t0, 2),
                "summary": self._summarize(out),
            }, module=name)
            return out
        except Exception as e:
            BUS.emit("module_error", {"module": name, "error": str(e)})
            raise

    def _summarize(self, out):
        """Tóm tắt ngắn để gửi dashboard."""
        if not isinstance(out, dict):
            return {}
        keys = list(out.keys())[:5]
        return {k: str(out[k])[:120] for k in keys}