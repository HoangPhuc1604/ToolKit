# core/soar_llm.py
import json
import os
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.soar_llm")

PLAYBOOK_SYSTEM_PROMPT = """Bạn là một SOAR engineer. Nhiệm vụ của bạn là tạo ra một playbook phản ứng sự cố an ninh mạng dưới định dạng JSON, tuân thủ nghiêm ngặt chuẩn CACAO.

Cấu trúc playbook bao gồm:
- playbook_types: ["incident-response"]
- name: Tên playbook
- description: Mô tả ngắn gọn
- workflow: Một chuỗi các bước (steps). Mỗi bước bao gồm:
    - step_id: ID duy nhất
    - name: Tên hành động
    - description: Mô tả chi tiết hành động
    - on_success: Bước tiếp theo nếu thành công
    - on_failure: Bước tiếp theo nếu thất bại (có thể là null)
    - commands: Danh sách các lệnh cần thực thi (ví dụ: `isolate_host`, `block_ip`, `notify_slack`)

Chỉ trả về JSON, không có văn bản giải thích nào khác."""

class LLMSOAR:
    """Sinh playbook CACAO bằng LLM và thực thi các hành động."""
    def __init__(self, provider="anthropic"):
        self.provider = provider
        self.enabled = bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY"))

    def generate_playbook(self, incident_data: dict) -> dict:
        if not self.enabled:
            return {"error": "Thiếu LLM API key"}
        user_msg = f"Dữ liệu sự cố:\n{json.dumps(incident_data, indent=2)}"
        if self.provider == "anthropic":
            return self._call_anthropic(user_msg)
        return self._call_openai(user_msg)

    def _call_anthropic(self, msg):
        import anthropic
        client = anthropic.Anthropic()
        r = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=2000,
            system=PLAYBOOK_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": msg}]
        )
        return self._parse_json(r.content[0].text)

    def _call_openai(self, msg):
        from openai import OpenAI
        client = OpenAI()
        r = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": PLAYBOOK_SYSTEM_PROMPT},
                {"role": "user", "content": msg}
            ],
            max_tokens=2000
        )
        return self._parse_json(r.choices[0].message.content)

    def _parse_json(self, text):
        text = text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        try:
            return json.loads(text.strip())
        except Exception:
            return {"raw": text[:500], "parse_error": True}

    def execute_playbook(self, playbook: dict) -> dict:
        """Thực thi playbook (mô phỏng). Trong thực tế, sẽ gọi API SOAR."""
        LOG.info(f"[SOAR] Bắt đầu thực thi playbook: {playbook.get('name')}")
        results = []
        # Giả sử playbook có một danh sách các bước tuyến tính
        for step in playbook.get("workflow", []):
            cmd_list = step.get("commands", [])
            LOG.info(f"[SOAR] Bước {step.get('step_id')}: {step.get('name')}")
            for cmd in cmd_list:
                # Mô phỏng gọi API SOAR hoặc chạy script
                LOG.info(f"[SOAR]   -> Thực thi lệnh: {cmd}")
                results.append({"step": step.get("step_id"), "command": cmd, "status": "success"})
        return {"playbook_executed": playbook.get("name"), "steps_results": results}

class Module(BaseModule):
    name = "soar_llm"
    module_id = "SOAR"
    description = "Tự động hóa SOAR với LLM (sinh playbook CACAO)"

    def run(self):
        self.logger.info("[SOAR] Bắt đầu tự động hóa SOAR với LLM")
        cfg = self.config
        soar = LLMSOAR(cfg.get("provider", "anthropic"))
        incident = cfg.get("incident", {})
        if not incident:
            return {"error": "Cần 'incident' data trong config"}

        playbook = soar.generate_playbook(incident)
        self.results["playbook"] = playbook

        if cfg.get("auto_execute") and not playbook.get("parse_error"):
            self.results["execution"] = soar.execute_playbook(playbook)
        return self.results