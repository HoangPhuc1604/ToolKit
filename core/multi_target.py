"""Multi-target scanning - quét nhiều host/IP/CIDR song song."""
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.logger import get_logger
from core.orchestrator import Orchestrator

LOG = get_logger("ceh.multi")


def expand_targets(targets_str):
    """Mở rộng danh sách target: hỗ trợ domain, IP, CIDR, range.

    Ví dụ:
        "192.168.1.0/30"          → 4 IP
        "example.com,10.0.0.1-10" → domain + 10 IP
    """
    targets = []
    for item in targets_str.split(","):
        item = item.strip()
        if not item:
            continue
        # CIDR
        if "/" in item:
            try:
                net = ipaddress.ip_network(item, strict=False)
                targets.extend(str(ip) for ip in net.hosts())
                continue
            except ValueError:
                pass
        # IP range: 10.0.0.1-10
        if "-" in item and item.replace(".", "").replace("-", "").isdigit():
            try:
                base, end = item.rsplit("-", 1)
                prefix = ".".join(base.split(".")[:-1])
                start = int(base.split(".")[-1])
                for i in range(start, int(end) + 1):
                    targets.append(f"{prefix}.{i}")
                continue
            except Exception:
                pass
        # Domain hoặc IP đơn
        targets.append(item)
    return targets


class MultiTargetScanner:
    """Quét nhiều target song song, mỗi target có Orchestrator riêng."""

    def __init__(self, config, max_workers=4):
        self.config = config
        self.max_workers = max_workers

    def scan(self, targets, modules, chain=False):
        """Trả về {target: results}."""
        LOG.info(f"[multi] Quét {len(targets)} target với {self.max_workers} workers")
        all_results = {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(self._scan_one, t, modules, chain): t
                for t in targets
            }
            for fut in as_completed(futures):
                target = futures[fut]
                try:
                    all_results[target] = fut.result()
                    LOG.info(f"[multi] ✓ {target} xong")
                except Exception as e:
                    LOG.error(f"[multi] ✗ {target} lỗi: {e}")
                    all_results[target] = {"error": str(e)}

        return all_results

    def _scan_one(self, target, modules, chain):
        orch = Orchestrator(
            target, self.config,
            parallel=not chain,
            chain=chain,
            max_workers=self.config.get("general", {}).get("threads", 3),
        )
        return orch.run(modules)