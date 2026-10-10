"""Campaign mode - lập lịch quét định kỳ + so sánh diff findings."""
import json
import hashlib
import os
from datetime import datetime
from pathlib import Path
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from core.logger import get_logger
from core.multi_target import MultiTargetScanner, expand_targets

LOG = get_logger("ceh.campaign")

CAMPAIGN_DIR = Path("./campaigns")
CAMPAIGN_DIR.mkdir(exist_ok=True)


def finding_fingerprint(finding: dict) -> str:
    """Tạo fingerprint 64-bit ổn định cho finding[reference:2]."""
    key_parts = [
        str(finding.get("target", "")),
        str(finding.get("port", "")),
        str(finding.get("service", "")),
        str(finding.get("vuln_id", "")),
        str(finding.get("title", "")),
    ]
    raw = "|".join(key_parts).lower()
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def normalize_findings(results_by_target: dict) -> dict:
    """Chuyển kết quả thô thành dict finding chuẩn hóa có fingerprint."""
    findings = {}
    for target, mod_results in results_by_target.items():
        if not isinstance(mod_results, dict):
            continue
        # Open ports
        for port in mod_results.get("m03_scanning", {}).get("open_ports", []):
            f = {
                "target": target,
                "port": port.get("port"),
                "service": port.get("service"),
                "version": port.get("version", ""),
                "severity": "info",
                "title": f"Open port {port.get('port')}/{port.get('service')}",
            }
            fp = finding_fingerprint(f)
            findings[fp] = f

        # Vulnerability findings (nikto, searchsploit, v.v.)
        for vuln in _extract_vulns(mod_results):
            fp = finding_fingerprint(vuln)
            findings[fp] = vuln
    return findings


def _extract_vulns(mod_results):
    """Trích xuất findings nguy hiểm từ các module quét lỗ hổng."""
    vulns = []
    # Nikto
    nikto_out = (mod_results.get("m05_vuln_analysis", {}).get("nikto", {})
                 .get("output", ""))
    for line in nikto_out.splitlines():
        if "+ " in line and ("OSVDB" in line or "vulnerab" in line.lower()):
            vulns.append({
                "title": line.strip()[:200],
                "severity": "medium",
                "source": "nikto",
                "target": "",  # điền sau
            })
    return vulns


class Campaign:
    """Chiến dịch: target list + schedule + trạng thái findings."""

    def __init__(self, name: str, targets_str: str, modules: list,
                 schedule: dict, config: dict):
        self.name = name
        self.targets = expand_targets(targets_str)
        self.modules = modules
        self.schedule = schedule
        self.config = config

        self.dir = CAMPAIGN_DIR / name
        self.dir.mkdir(exist_ok=True)
        self.state_file = self.dir / "state.json"
        self.history_file = self.dir / "history.jsonl"

        self.state = self._load_state()
        self.scanner = MultiTargetScanner(config)

    # ---------- Persistence ----------
    def _load_state(self):
        if self.state_file.exists():
            return json.loads(self.state_file.read_text())
        return {"findings": {}, "last_scan": None, "scan_count": 0}

    def _save_state(self):
        self.state_file.write_text(
            json.dumps(self.state, indent=2, ensure_ascii=False, default=str))

    # ---------- Diff logic ----------
    def _compute_diff(self, current_fps: dict):
        """So sánh finding hiện tại với lần trước.
        Returns: (new, resolved, persistent)
        """
        old_fps = self.state["findings"]
        current = set(current_fps.keys())
        previous = set(old_fps.keys())

        new = current - previous
        resolved = previous - current
        persistent = current & previous

        # Auto-resolve sau N lần miss
        auto_resolve = self.config.get("campaign", {}).get(
            "auto_resolve_after_misses", 3)
        for fp in resolved:
            rec = old_fps.get(fp, {})
            misses = rec.get("consecutive_misses", 0) + 1
            if misses >= auto_resolve:
                rec["status"] = "resolved"
                rec["resolved_at"] = datetime.now().isoformat()
            else:
                rec["consecutive_misses"] = misses
            old_fps[fp] = rec

        # Cập nhật missing counter cho persistent
        for fp in persistent:
            old_fps[fp]["consecutive_misses"] = 0

        # Thêm finding mới
        for fp in new:
            current_fps[fp]["status"] = "opened"
            current_fps[fp]["first_seen"] = datetime.now().isoformat()
            current_fps[fp]["consecutive_misses"] = 0
            old_fps[fp] = current_fps[fp]

        return list(new), list(resolved), list(persistent)

    # ---------- Chạy 1 lần ----------
    def run_once(self):
        LOG.info(f"[campaign] ▶ {self.name} — {len(self.targets)} targets")
        results = self.scanner.scan(
            self.targets, self.modules,
            chain=self.config.get("campaign", {}).get("chain", False),
        )
        current_fps = normalize_findings(results)
        new, resolved, persistent = self._compute_diff(current_fps)

        record = {
            "ts": datetime.now().isoformat(),
            "scan_count": self.state["scan_count"] + 1,
            "targets": len(self.targets),
            "total_findings": len(current_fps),
            "new": len(new),
            "resolved": len(resolved),
            "persistent": len(persistent),
        }
        self.state["last_scan"] = record["ts"]
        self.state["scan_count"] = record["scan_count"]
        self._save_state()

        with open(self.history_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

        # Ghi file diff để dashboard xem
        diff_file = self.dir / f"diff_{record['scan_count']}.json"
        diff_file.write_text(json.dumps({
            "new": [self.state["findings"][fp] for fp in new],
            "resolved": [self.state["findings"][fp] for fp in resolved
                         if fp in self.state["findings"]],
        }, indent=2, ensure_ascii=False, default=str))

        # Cảnh báo finding Critical/High mới
        critical_new = [self.state["findings"][fp] for fp in new
                        if self.state["findings"][fp].get("severity")
                        in ("critical", "high")]
        if critical_new:
            from core.events import BUS
            BUS.emit("critical_findings", {
                "campaign": self.name,
                "count": len(critical_new),
                "findings": critical_new[:10],
            }, module="campaign")

        LOG.info(f"[campaign] ✓ {self.name}: +{len(new)} mới, "
                 f"-{len(resolved)} resolved, {len(persistent)} persistent")
        return record

    # ---------- Scheduler ----------
    def start_scheduler(self):
        sched = BackgroundScheduler(job_defaults={
            "coalesce": True, "max_instances": 1,
        })
        mode = self.schedule.get("mode", "interval")
        if mode == "cron":
            trigger = CronTrigger.from_crontab(
                self.schedule.get("cron", "0 */6 * * *"))
        else:
            trigger = IntervalTrigger(
                hours=self.schedule.get("interval_hours", 6))
        sched.add_job(self.run_once, trigger)
        sched.start()
        LOG.info(f"[campaign] Scheduler started ({mode})")
        return sched