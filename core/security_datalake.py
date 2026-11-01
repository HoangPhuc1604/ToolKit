# core/security_datalake.py
import os
import requests
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.datalake")

class SecurityDataLake:
    """Quản lý security data lake (ClickHouse/OpenSearch)."""
    def __init__(self, backend="clickhouse", url=None, user=None, password=None):
        self.backend = backend
        self.url = url or os.environ.get("DATALAKE_URL", "")
        self.auth = (user, password) if user else None

    def ingest(self, index: str, events: list) -> dict:
        """Ingest events vào data lake."""
        if not self.url:
            return {"error": "Chưa cấu hình DATALAKE_URL"}
        if self.backend == "clickhouse":
            # ClickHouse HTTP interface
            data = "\n".join(str(e) for e in events)
            try:
                r = requests.post(
                    f"{self.url}/?query=INSERT INTO {index} FORMAT JSONEachRow",
                    data=data,
                    auth=self.auth,
                    timeout=60
                )
                return {"status": r.status_code, "ingested": len(events)}
            except Exception as e:
                return {"error": str(e)}
        elif self.backend == "opensearch":
            bulk = []
            for e in events:
                bulk.append('{"index": {"_index": "%s"}}' % index)
                bulk.append(str(e))
            body = "\n".join(bulk) + "\n"
            try:
                r = requests.post(f"{self.url}/_bulk", data=body,
                                  headers={"Content-Type": "application/x-ndjson"},
                                  auth=self.auth, timeout=60)
                return {"status": r.status_code, "ingested": len(events)}
            except Exception as e:
                return {"error": str(e)}

    def query(self, index: str, query: str) -> dict:
        """Truy vấn data lake."""
        if self.backend == "clickhouse":
            try:
                r = requests.post(f"{self.url}/?query={query}", auth=self.auth, timeout=60)
                return {"results": r.text}
            except Exception as e:
                return {"error": str(e)}
        # OpenSearch query tương tự
        return {"error": "Chưa hỗ trợ backend này"}

class Module(BaseModule):
    name = "security_datalake"
    module_id = "DL"
    description = "Security Data Lake (ClickHouse/OpenSearch)"

    def run(self):
        self.logger.info("[DL] Khởi tạo security data lake")
        cfg = self.config
        dl = SecurityDataLake(
            backend=cfg.get("backend", "clickhouse"),
            url=cfg.get("url"),
            user=cfg.get("user"),
            password=cfg.get("password")
        )
        # Test ingest và query
        test_events = [{"timestamp": "2025-01-01T00:00:00Z", "event": "test"}]
        ingest_result = dl.ingest("test_index", test_events)
        self.results["ingest_test"] = ingest_result
        return self.results