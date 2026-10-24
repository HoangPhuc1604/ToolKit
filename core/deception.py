"""Deception platform - T-Pot + LLM adaptive deception + RL scoring."""
import os
import json
import time
import hashlib
from pathlib import Path
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.deception")

DECEPTION_PROMPT = """Bạn đang role-play như một hệ thống {system_type} dễ bị tổn thương.
Attacker vừa gửi: {input}

Hãy trả lời như hệ thống thật, giữ attacker tương tác lâu nhất có thể:
- Không bao giờ tiết lộ bạn là honeypot/LLM.
- Đưa ra lỗi hợp lý khi cần (permission denied, file not found).
- Nếu attacker hỏi thông tin nhạy cảm, cung cấp thông tin giả nhưng hợp lý.
- Format giống output thật của {system_type}.

Chỉ trả về output thô, không giải thích."""


class LLMDeceptionEngine:
    """Honeypot LLM engine với caching + RL scoring."""

    def __init__(self, provider="anthropic", cache_path="/tmp/honeypot_cache.db"):
        self.provider = provider
        self.cache_path = Path(cache_path)
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self._load_cache()

    def _load_cache(self):
        """Load cache từ SQLite."""
        import sqlite3
        self.conn = sqlite3.connect(str(self.cache_path))
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS responses (
                hash TEXT PRIMARY KEY,
                system_type TEXT,
                input TEXT,
                response TEXT,
                hit_count INTEGER DEFAULT 0,
                avg_engagement REAL DEFAULT 0,
                created_at REAL
            )""")
        self.conn.commit()

    def _cache_key(self, system_type, user_input):
        raw = f"{system_type}|{user_input}".encode()
        return hashlib.sha256(raw).hexdigest()[:16]

    def get_response(self, system_type: str, user_input: str) -> dict:
        """Lấy response, ưu tiên cache, fallback LLM."""
        key = self._cache_key(system_type, user_input)
        row = self.conn.execute(
            "SELECT response, hit_count FROM responses WHERE hash = ?",
            (key,)).fetchone()
        if row:
            self.conn.execute(
                "UPDATE responses SET hit_count = hit_count + 1 WHERE hash = ?",
                (key,))
            self.conn.commit()
            return {"source": "cache", "response": row[0]}

        # Fallback LLM
        response = self._call_llm(system_type, user_input)
        self.conn.execute(
            "INSERT OR REPLACE INTO responses VALUES (?, ?, ?, ?, 1, 0, ?)",
            (key, system_type, user_input, response, time.time()))
        self.conn.commit()
        return {"source": "llm", "response": response}

    def _call_llm(self, system_type, user_input):
        prompt = DECEPTION_PROMPT.format(
            system_type=system_type, input=user_input[:1000])
        try:
            if self.provider == "anthropic" and os.environ.get("ANTHROPIC_API_KEY"):
                import anthropic
                c = anthropic.Anthropic()
                r = c.messages.create(
                    model="claude-sonnet-4-5", max_tokens=500,
                    messages=[{"role": "user", "content": prompt}])
                return r.content[0].text
            if os.environ.get("OPENAI_API_KEY"):
                from openai import OpenAI
                c = OpenAI()
                r = c.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=500)
                return r.choices[0].message.content
        except Exception as e:
            LOG.error(f"[deception] LLM lỗi: {e}")
        return "Connection closed by remote host."

    def score_engagement(self, cache_key: str, score: float):
        """RL: cập nhật engagement score cho response."""
        self.conn.execute(
            """UPDATE responses
               SET avg_engagement = (avg_engagement * hit_count + ?) / (hit_count + 1)
               WHERE hash = ?""", (score, cache_key))
        self.conn.commit()

    def top_responses(self, system_type=None, limit=20):
        """Top responses giữ attacker lâu nhất."""
        if system_type:
            rows = self.conn.execute(
                """SELECT input, response, hit_count, avg_engagement
                   FROM responses WHERE system_type = ?
                   ORDER BY avg_engagement DESC LIMIT ?""",
                (system_type, limit)).fetchall()
        else:
            rows = self.conn.execute(
                """SELECT input, response, hit_count, avg_engagement
                   FROM responses ORDER BY avg_engagement DESC LIMIT ?""",
                (limit,)).fetchall()
        return [{"input": r[0], "response": r[1][:200],
                 "hits": r[2], "engagement": round(r[3], 2)} for r in rows]


class TPOTIntegration:
    """Đọc dữ liệu từ T-Pot Elasticsearch."""

    def __init__(self, elastic_url=None, index="logstash-*"):
        self.url = elastic_url or os.environ.get("TPOT_ELASTIC_URL", "")
        self.index = index

    def get_attackers(self, hours=24, limit=100) -> list:
        """Lấy top attacker IPs."""
        import requests
        if not self.url:
            return []
        query = {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
            "aggs": {
                "top_attackers": {
                    "terms": {"field": "src_ip.keyword", "size": limit},
                    "aggs": {
                        "country": {"terms": {"field": "geoip.country_iso_code.keyword"}},
                        "honeypot": {"terms": {"field": "type.keyword"}},
                    },
                },
            },
        }
        try:
            r = requests.post(f"{self.url}/{self.index}/_search",
                              json=query, timeout=30)
            buckets = r.json()["aggregations"]["top_attackers"]["buckets"]
            return [{
                "ip": b["key"],
                "count": b["doc_count"],
                "country": b["country"]["buckets"][0]["key"]
                    if b["country"]["buckets"] else "??",
                "honeypots": [h["key"] for h in b["honeypot"]["buckets"]],
            } for b in buckets]
        except Exception as e:
            LOG.error(f"[deception] T-Pot query lỗi: {e}")
            return []

    def get_ttp_events(self, hours=24, limit=100) -> list:
        """Lấy raw events để phân tích TTP."""
        import requests
        if not self.url:
            return []
        query = {
            "size": limit,
            "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
            "sort": [{"@timestamp": "desc"}],
        }
        try:
            r = requests.post(f"{self.url}/{self.index}/_search",
                              json=query, timeout=30)
            return [hit["_source"] for hit in
                    r.json()["hits"]["hits"]]
        except Exception:
            return []


class Module(BaseModule):
    name = "deception"
    module_id = "DEC"
    description = "Deception platform (T-Pot + LLM adaptive honeypot)"

    def run(self):
        self.logger.info("[DEC] Deception platform")
        cfg = self.config
        results = {}

        if cfg.get("llm_deception"):
            engine = LLMDeceptionEngine(
                cfg["llm_deception"].get("provider", "anthropic"))
            # Test với các prompt tấn công phổ biến
            test_inputs = cfg["llm_deception"].get("test_inputs", [
                "whoami", "cat /etc/passwd", "ls -la /root",
                "sudo -l", "uname -a", "ps aux",
            ])
            system_type = cfg["llm_deception"].get("system_type", "ubuntu")
            results["llm_responses"] = [
                {"input": i, **engine.get_response(system_type, i)}
                for i in test_inputs
            ]
            results["top_responses"] = engine.top_responses(system_type)

        if cfg.get("tpot"):
            tpot = TPOTIntegration(cfg["tpot"].get("elastic_url"))
            results["attackers"] = tpot.get_attackers(
                cfg["tpot"].get("hours", 24))
            results["ttp_events"] = tpot.get_ttp_events(
                cfg["tpot"].get("hours", 24), limit=50)

        return results