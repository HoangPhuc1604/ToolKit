"""Dùng LLM để sinh báo cáo pentest từ kết quả JSON.

Hỗ trợ: Anthropic Claude, OpenAI GPT.
Cần API key qua ENV: ANTHROPIC_API_KEY hoặc OPENAI_API_KEY.
"""
import json
import os
from pathlib import Path

SYSTEM_PROMPT = """Bạn là một pentest report writer chuyên nghiệp.
Nhận JSON kết quả scan từ CEH Toolkit và viết báo cáo pentest bằng tiếng Việt.

Cấu trúc báo cáo:
1. **Tóm tắt điều hành** (Executive Summary) - 3-5 câu, dành cho C-level.
2. **Phạm vi & Phương pháp** - Target, module đã dùng, thời gian.
3. **Phát hiện chính** - Liệt kê các rủi ro theo mức độ (Critical/High/Medium/Low).
4. **Mapping MITRE ATT&CK** - Techniques đã phát hiện.
5. **Khuyến nghị khắc phục** - Ưu tiên theo impact.
6. **Kết luận**.

Yêu cầu:
- Viết ngắn gọn, chuyên nghiệp, có căn cứ dữ liệu.
- Không bịa thông tin ngoài JSON.
- Nếu có credentials/hash → không nhắc lại plaintext, chỉ nói "đã phát hiện".
- Dùng định dạng Markdown.
"""


class LLMReportWriter:
    def __init__(self, provider="anthropic", model=None):
        self.provider = provider
        self.model = model or (
            "claude-sonnet-4-5" if provider == "anthropic"
            else "gpt-4o-mini"
        )

    def write(self, results: dict, target: str) -> str:
        # Giới hạn dữ liệu gửi đi
        trimmed = self._trim(results)
        user_prompt = (
            f"Target: {target}\n\n"
            f"Kết quả scan JSON:\n```json\n"
            f"{json.dumps(trimmed, indent=2, ensure_ascii=False, default=str)}\n```\n\n"
            f"Hãy viết báo cáo pentest theo cấu trúc yêu cầu."
        )

        if self.provider == "anthropic":
            return self._call_anthropic(user_prompt)
        elif self.provider == "openai":
            return self._call_openai(user_prompt)
        raise ValueError(f"Provider không hỗ trợ: {self.provider}")

    def _trim(self, results, max_str=500):
        """Rút gọn string dài để tiết kiệm token."""
        if isinstance(results, dict):
            return {k: self._trim(v, max_str) for k, v in results.items()}
        if isinstance(results, list):
            return [self._trim(v, max_str) for v in results[:30]]
        if isinstance(results, str):
            return results[:max_str] + ("..." if len(results) > max_str else "")
        return results

    def _call_anthropic(self, prompt):
        try:
            import anthropic
        except ImportError:
            raise ImportError("pip install anthropic")
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise ValueError("Thiếu ANTHROPIC_API_KEY")
        client = anthropic.Anthropic(api_key=key)
        msg = client.messages.create(
            model=self.model,
            max_tokens=4000,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text

    def _call_openai(self, prompt):
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError("pip install openai")
        key = os.environ.get("OPENAI_API_KEY")
        if not key:
            raise ValueError("Thiếu OPENAI_API_KEY")
        client = OpenAI(api_key=key)
        resp = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            max_tokens=4000,
        )
        return resp.choices[0].message.content


def generate_llm_report(json_path, out_path=None, provider="anthropic"):
    """Sinh báo cáo Markdown từ file JSON."""
    json_path = Path(json_path)
    results = json.loads(json_path.read_text(encoding="utf-8"))
    target = results.get("_target", "unknown") if isinstance(results, dict) else "unknown"
    # Nếu JSON không có target, thử lấy từ tên file
    writer = LLMReportWriter(provider=provider)
    md = writer.write(results, target)

    out_path = out_path or json_path.with_suffix(".md")
    Path(out_path).write_text(md, encoding="utf-8")
    return out_path