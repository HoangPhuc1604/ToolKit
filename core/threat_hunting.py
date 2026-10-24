"""Threat hunting - PySpark + Elastic DSL hypothesis-driven hunts."""
import os
import json
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.hunt")


HUNT_TEMPLATES = {
    "T1059.001": {
        "name": "PowerShell Execution",
        "hypothesis": "Adversary dùng PowerShell để execution",
        "elastic_dsl": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"process.name": "powershell.exe"}},
                        {"match": {"process.command_line": "-enc"}},
                    ]
                }
            }
        },
        "pyspark": """
            df.filter(
                (df.process_name == "powershell.exe") &
                (df.command_line.contains("-enc"))
            ).groupBy("host", "user").count().orderBy("count", ascending=False)
        """,
    },
    "T1003.001": {
        "name": "LSASS Memory Access",
        "hypothesis": "Adversary dump credential từ LSASS",
        "elastic_dsl": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"winlog.event_id": 10}},
                        {"match": {"target.process.name": "lsass.exe"}},
                    ]
                }
            }
        },
        "pyspark": """
            df.filter(
                (df.event_id == 10) &
                (df.target_process_name == "lsass.exe")
            ).select("host", "source_process", "granted_access")
        """,
    },
    "T1055": {
        "name": "Process Injection",
        "hypothesis": "Adversary inject code vào process khác",
        "elastic_dsl": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.category": "process"}},
                        {"match": {"event.action": "CreateRemoteThread"}},
                    ]
                }
            }
        },
        "pyspark": """
            df.filter(
                (df.event_category == "process") &
                (df.event_action == "CreateRemoteThread")
            ).groupBy("host", "source_process", "target_process").count()
        """,
    },
    "T1071.001": {
        "name": "HTTP C2 Beaconing",
        "hypothesis": "Adversary dùng HTTP cho C2",
        "elastic_dsl": {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"network.protocol": "http"}},
                        {"range": {"network.bytes": {"gte": 1000}}},
                    ]
                }
            }
        },
        "pyspark": """
            df.filter(
                (df.protocol == "http") &
                (df.bytes > 1000)
            ).groupBy("src_ip", "dst_ip", "http_uri").count() \\
             .filter("count > 50").orderBy("count", ascending=False)
        """,
    },
}


class ElasticHunter:
    """Hypothesis-driven hunt qua Elasticsearch."""

    def __init__(self, url=None):
        self.url = url or os.environ.get("ELASTIC_URL", "")

    def hunt(self, technique_id: str, hours=24, index="logs-*",
             extra_filter=None) -> dict:
        import requests
        tmpl = HUNT_TEMPLATES.get(technique_id)
        if not tmpl:
            return {"error": f"Không có template cho {technique_id}"}

        dsl = tmpl["elastic_dsl"]
        # Thêm time range
        dsl["query"]["bool"].setdefault("filter", []).append(
            {"range": {"@timestamp": {"gte": f"now-{hours}h"}}})
        if extra_filter:
            dsl["query"]["bool"]["filter"].append(extra_filter)

        if not self.url:
            return {"error": "Thiếu ELASTIC_URL",
                    "dsl_would_be": dsl}

        try:
            r = requests.post(f"{self.url}/{index}/_search",
                              json=dsl, timeout=60)
            hits = r.json().get("hits", {})
            return {
                "technique": technique_id,
                "name": tmpl["name"],
                "hypothesis": tmpl["hypothesis"],
                "total_hits": hits.get("total", {}).get("value", 0),
                "samples": [h["_source"] for h in hits.get("hits", [])[:10]],
            }
        except Exception as e:
            return {"error": str(e)}


class SparkHunter:
    """Large-scale hunt với PySpark."""

    def __init__(self, master="local[*]"):
        self.master = master

    def hunt(self, technique_id: str, input_path: str,
             output_path=None) -> dict:
        try:
            from pyspark.sql import SparkSession
        except ImportError:
            return {"error": "pyspark chưa cài (pip install pyspark)"}

        tmpl = HUNT_TEMPLATES.get(technique_id)
        if not tmpl:
            return {"error": f"Không có template cho {technique_id}"}

        spark = SparkSession.builder.master(self.master) \
            .appName(f"ceh-hunt-{technique_id}").getOrCreate()
        try:
            if input_path.endswith(".json") or input_path.endswith(".jsonl"):
                df = spark.read.json(input_path)
            elif input_path.endswith(".parquet"):
                df = spark.read.parquet(input_path)
            else:
                df = spark.read.csv(input_path, header=True)

            # Rename columns để khớp template
            for col in df.columns:
                new_col = col.replace(".", "_").lower()
                if new_col != col:
                    df = df.withColumnRenamed(col, new_col)

            # Chạy query từ template (safe-ish eval trong sandbox)
            result = eval(tmpl["pyspark"], {"df": df, "__builtins__": {}})
            rows = result.limit(50).collect()
            output = [r.asDict() for r in rows]

            if output_path:
                result.write.mode("overwrite").json(output_path)

            return {
                "technique": technique_id,
                "hypothesis": tmpl["hypothesis"],
                "results": output,
                "count": len(output),
            }
        except Exception as e:
            return {"error": str(e)}
        finally:
            spark.stop()


class Module(BaseModule):
    name = "threat_hunting"
    module_id = "HUNT"
    description = "Threat hunting (PySpark + Elastic DSL hypotheses)"

    def run(self):
        self.logger.info("[HUNT] Threat hunting")
        cfg = self.config
        results = {}

        techniques = cfg.get("techniques",
                              ["T1059.001", "T1003.001", "T1055"])
        hours = cfg.get("hours", 24)

        # Elastic hunts
        if cfg.get("elastic_url") or os.environ.get("ELASTIC_URL"):
            hunter = ElasticHunter(cfg.get("elastic_url"))
            results["elastic"] = {}
            for t in techniques:
                results["elastic"][t] = hunter.hunt(
                    t, hours, cfg.get("index", "logs-*"))

        # Spark hunts (nếu có data file)
        if cfg.get("spark_input"):
            spark_hunter = SparkHunter(cfg.get("spark_master", "local[*]"))
            results["spark"] = {}
            for t in techniques:
                results["spark"][t] = spark_hunter.hunt(
                    t, cfg["spark_input"], cfg.get("spark_output"))

        # Templates metadata
        results["templates"] = {
            tid: {"name": v["name"], "hypothesis": v["hypothesis"]}
            for tid, v in HUNT_TEMPLATES.items()
        }
        return results