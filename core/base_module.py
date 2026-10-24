import subprocess
import shutil
from abc import ABC, abstractmethod
from core.logger import get_logger


class BaseModule(ABC):
    """Lớp cơ sở cho mọi module. Mỗi module phải định nghĩa name, description, run()."""

    name = "base"
    description = "Base module"
    module_id = "00"

    def __init__(self, target, config=None):
        self.target = target
        self.config = config or {}
        self.logger = get_logger(f"ceh.{self.name}")
        self.results = {}

    @abstractmethod
    def run(self):
        """Trả về dict kết quả."""
        pass

    # ---------- Helpers ----------
    def _tool_available(self, tool):
        return shutil.which(tool) is not None

    def _run_cmd(self, cmd, timeout=120, shell=False):
        """Chạy lệnh hệ thống, trả về stdout hoặc thông báo lỗi.
        
        Args:
            timeout: Số giây chờ. Nếu None -> chạy vô thời hạn (dùng cho nmap -p-).
        """
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, shell=shell
            )
            return proc.stdout + ("\n[STDERR]\n" + proc.stderr if proc.stderr else "")
        except subprocess.TimeoutExpired:
            return f"[!] Timeout sau {timeout}s"
        except FileNotFoundError:
            return f"[!] Không tìm thấy lệnh: {cmd if isinstance(cmd, str) else cmd[0]}"
        except Exception as e:
            return f"[!] Lỗi: {e}"

    def _missing_tool(self, tool):
        msg = f"[!] Công cụ '{tool}' không có sẵn. Bỏ qua."
        self.logger.warning(msg)
        return msg