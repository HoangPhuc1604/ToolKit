"""Tenant-aware orchestrator - isolation + quota per workspace."""
import uuid
from core.orchestrator import Orchestrator
from core.logger import get_logger
from auth.models import ScanRecord, Workspace

LOG = get_logger("ceh.tenancy")

# Quota theo plan
PLAN_QUOTA = {
    "free":       {"scans_per_day": 5,   "targets_per_scan": 1},
    "pro":        {"scans_per_day": 100, "targets_per_scan": 20},
    "enterprise": {"scans_per_day": -1,  "targets_per_scan": -1},  # unlimited
}


class TenantOrchestrator:
    """Orchestrator scoped theo workspace."""

    def __init__(self, workspace: Workspace, user_id: str, config: dict):
        self.workspace = workspace
        self.user_id = user_id
        self.config = config
        self.logger = get_logger(f"ceh.tenant.{workspace.id}")

    def check_quota(self, n_targets=1) -> bool:
        quota = PLAN_QUOTA.get(self.workspace.plan, PLAN_QUOTA["free"])
        # Đếm scan trong 24h qua (giả định query DB)
        today_count = self._count_scans_today()
        if quota["scans_per_day"] != -1 and today_count >= quota["scans_per_day"]:
            raise PermissionError(
                f"Workspace '{self.workspace.name}' đã đạt quota "
                f"{quota['scans_per_day']} scans/ngày. Nâng cấp plan.")
        if (quota["targets_per_scan"] != -1
                and n_targets > quota["targets_per_scan"]):
            raise PermissionError(
                f"Plan '{self.workspace.plan}' giới hạn "
                f"{quota['targets_per_scan']} targets/scan.")
        return True

    def _count_scans_today(self) -> int:
        # TODO: query DB scan records WHERE workspace_id = X AND date = today
        return 0

    def run(self, target: str, modules: list, profile: str = "normal",
            chain: bool = False) -> dict:
        self.check_quota(n_targets=1)

        scan_id = str(uuid.uuid4())
        record = ScanRecord(
            id=scan_id,
            workspace_id=self.workspace.id,
            user_id=self.user_id,
            target=target,
            modules=modules,
            profile=profile,
            status="running",
        )
        self._persist(record)
        self.logger.info(f"[tenant] scan {scan_id} workspace={self.workspace.id}")

        try:
            orch = Orchestrator(target, self.config,
                                parallel=not chain, chain=chain)
            results = orch.run(modules)
            record.results = results
            record.status = "completed"
            self._persist(record)
            return {"scan_id": scan_id, "results": results}
        except Exception as e:
            record.status = "failed"
            record.results = {"error": str(e)}
            self._persist(record)
            raise

    def _persist(self, record: ScanRecord):
        # TODO: lưu vào DB (Postgres với row-level security theo workspace_id)
        pass