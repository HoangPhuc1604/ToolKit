"""Agentless endpoint scan - Lynis + OpenSCAP qua SSH."""
import paramiko
import io
import re
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.agentless")


class SSHExecutor:
    """Chạy lệnh từ xa qua SSH với password hoặc key."""

    def __init__(self, host, user, password=None, key_path=None, port=22,
                 sudo_password=None):
        self.host = host
        self.user = user
        self.password = password
        self.key_path = key_path
        self.port = port
        self.sudo_password = sudo_password or password
        self.client = None

    def __enter__(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = {"hostname": self.host, "username": self.user,
                  "port": self.port, "timeout": 15}
        if self.key_path:
            kwargs["key_filename"] = self.key_path
        elif self.password:
            kwargs["password"] = self.password
        self.client.connect(**kwargs)
        return self

    def __exit__(self, *args):
        if self.client:
            self.client.close()

    def run(self, cmd, sudo=False, timeout=300):
        """Chạy lệnh; nếu sudo, pipe password vào stdin."""
        if sudo:
            full_cmd = f"sudo -S -p '' {cmd}"
            stdin, stdout, stderr = self.client.exec_command(
                full_cmd, timeout=timeout, get_pty=True)
            stdin.write(self.sudo_password + "\n")
            stdin.flush()
        else:
            stdin, stdout, stderr = self.client.exec_command(
                cmd, timeout=timeout)
        out = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")
        return out, err

    def upload(self, local_path, remote_path):
        sftp = self.client.open_sftp()
        sftp.put(local_path, remote_path)
        sftp.close()


class Module(BaseModule):
    name = "agentless_scan"
    module_id = "A1"
    description = "Agentless endpoint audit (Lynis, OpenSCAP, CIS)"

    def run(self):
        self.logger.info(f"[A1] Agentless scan: {self.target}")
        cfg = self.config
        ssh_cfg = cfg.get("ssh", {})
        user = ssh_cfg.get("user", "root")
        pwd = ssh_cfg.get("password")
        key = ssh_cfg.get("key_path")

        results = {}
        try:
            with SSHExecutor(self.target, user, pwd, key) as ssh:
                # Detect distro
                out, _ = ssh.run("cat /etc/os-release 2>/dev/null || uname -a")
                results["os_info"] = out[:500]

                if cfg.get("lynis", True):
                    results["lynis"] = self._run_lynis(ssh)

                if cfg.get("openscap", False):
                    results["openscap"] = self._run_openscap(ssh, cfg)

                if cfg.get("cis_audit", False):
                    results["cis"] = self._run_cis(ssh)

        except paramiko.AuthenticationException:
            results["error"] = "SSH auth thất bại"
        except Exception as e:
            results["error"] = f"SSH lỗi: {e}"
        return results

    def _run_lynis(self, ssh):
        """Lynis: audit hệ thống, trả về hardening index 0-100."""
        self.logger.info("[A1] Lynis audit...")
        # Kiểm tra có lynis chưa
        out, _ = ssh.run("which lynis")
        if "lynis" not in out:
            # Cài tự động (Debian/Ubuntu/RHEL)
            self.logger.info("[A1] Cài Lynis...")
            ssh.run("apt-get install -y lynis 2>/dev/null || "
                    "yum install -y lynis 2>/dev/null", sudo=True, timeout=120)

        out, err = ssh.run("lynis audit system --quick --no-colors",
                           sudo=True, timeout=600)
        hardening = self._parse_lynis_index(out)
        return {
            "hardening_index": hardening,
            "warnings": self._extract_lynis_section(out, "Warnings"),
            "suggestions": self._extract_lynis_section(out, "Suggestions")[:20],
            "raw_tail": out[-2000:],
        }

    def _parse_lynis_index(self, output):
        m = re.search(r"Hardening index\s*:\s*(\d+)", output)
        return int(m.group(1)) if m else None

    def _extract_lynis_section(self, output, section_name):
        """Trích xuất các mục trong phần [section_name]."""
        lines = output.splitlines()
        items = []
        in_section = False
        for line in lines:
            if line.strip().startswith(section_name):
                in_section = True
                continue
            if in_section:
                if not line.strip().startswith("*"):
                    break
                items.append(line.strip("* ").strip())
        return items

    def _run_openscap(self, ssh, cfg):
        """OpenSCAP: CIS/DISA-STIG compliance scan."""
        self.logger.info("[A1] OpenSCAP scan...")
        profile = cfg.get("oscap_profile", "xccdf_org.ssgproject.content_profile_cis")
        out, _ = ssh.run("which oscap")
        if "oscap" not in out:
            ssh.run("apt-get install -y libopenscap8 ssg-debderived "
                    "2>/dev/null", sudo=True, timeout=180)

        # Tìm datastream
        out, _ = ssh.run("ls /usr/share/xml/scap/ssg/content/*-ds.xml 2>/dev/null | head -1")
        ds = out.strip()
        if not ds:
            return {"error": "Không tìm thấy SCAP datastream"}

        cmd = (f"oscap xccdf eval --profile {profile} "
               f"--results /tmp/oscap-results.xml {ds}")
        out, err = ssh.run(cmd, sudo=True, timeout=900)

        # Parse kết quả
        results_out, _ = ssh.run(
            "grep -oP 'result>\\K[^<]+' /tmp/oscap-results.xml | "
            "sort | uniq -c", sudo=True)
        return {
            "profile": profile,
            "summary": results_out.strip(),
            "raw_tail": out[-2000:],
        }

    def _run_cis(self, ssh):
        """Chạy CIS-CAT hoặc kube-bench-like cho Linux."""
        out, _ = ssh.run(
            "test -f /usr/local/bin/cis-cat.sh && echo yes || echo no")
        if "no" in out:
            return {"note": "cis-cat chưa cài"}
        out, _ = ssh.run("/usr/local/bin/cis-cat.sh -a -c 2>/dev/null",
                         sudo=True, timeout=600)
        return {"output": out[-3000:]}


import paramiko