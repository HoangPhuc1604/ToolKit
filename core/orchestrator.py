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
    """Chạy nhiều module, có thể song song."""

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

    def run(self, modules):
        # Chain mode: tự thêm m03_scanning đầu danh sách
        if self.chain and "m03_scanning" not in modules:
            modules = ["m03_scanning"] + list(modules)

        BUS.emit("scan_start", {
            "target": self.target,
            "modules": modules,
        }, module="orchestrator")

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
            from concurrent.futures import ThreadPoolExecutor, as_completed
            import time
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                fmap = {pool.submit(self._wrap_run, n, inst): n
                        for n, inst in tasks}
                for fut in as_completed(fmap):
                    name = fmap[fut]
                    try:
                        results[name] = fut.result()
                    except Exception as e:
                        results[name] = {"error": str(e)}
                        BUS.emit("module_error", {"module": name, "error": str(e)})
        else:
            for n, inst in tasks:
                try:
                    results[n] = self._wrap_run(n, inst)
                except Exception as e:
                    results[n] = {"error": str(e)}
                    BUS.emit("module_error", {"module": n, "error": str(e)})

        # MITRE mapping
        from core.mitre import map_results
        results["_mitre_attack"] = map_results(results)

        BUS.emit("scan_end", {
            "target": self.target,
            "modules_done": list(results.keys()),
        }, module="orchestrator")
        return results

    def _wrap_run(self, name, instance):
        import time
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