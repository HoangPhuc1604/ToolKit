"""Module 04 - Enumeration (SMB, SNMP, LDAP, NFS, SMTP)"""
from core.base_module import BaseModule


class Module(BaseModule):
    name = "m04_enumeration"
    module_id = "04"
    description = "Enumeration (SMB/NetBIOS, SNMP, LDAP, NFS, SMTP users)"

    def run(self):
        self.logger.info(f"[M04] Bắt đầu Enumeration: {self.target}")
        cfg = self.config
        if cfg.get("smb", True):
            self.results["smb"] = self._smb_enum()
        if cfg.get("snmp", True):
            self.results["snmp"] = self._snmp_enum()
        if cfg.get("ldap", False):
            self.results["ldap"] = self._ldap_enum()
        if cfg.get("nfs", False):
            self.results["nfs"] = self._nfs_enum()
        if cfg.get("smtp", False):
            self.results["smtp"] = self._smtp_enum()
        return self.results

    def _smb_enum(self):
        self.logger.info("[M04] SMB/NetBIOS enumeration...")
        out = {}
        if self._tool_available("enum4linux"):
            out["enum4linux"] = self._run_cmd(
                ["enum4linux", "-a", self.target], timeout=120)[:8000]
        elif self._tool_available("enum4linux-ng"):
            out["enum4linux-ng"] = self._run_cmd(
                ["enum4linux-ng", "-A", self.target], timeout=120)[:8000]
        else:
            out["note"] = "enum4linux chưa cài."

        if self._tool_available("smbclient"):
            out["smbclient_list"] = self._run_cmd(
                ["smbclient", "-L", self.target, "-N"], timeout=30)
        return out

    def _snmp_enum(self):
        self.logger.info("[M04] SNMP enumeration...")
        if not self._tool_available("snmpwalk"):
            return self._missing_tool("snmpwalk")
        # Thử community string mặc định "public" -> phổ biến trong lab
        return {
            "walk_public": self._run_cmd(
                ["snmpwalk", "-v", "2c", "-c", "public", self.target],
                timeout=60)[:3000]
        }

    def _ldap_enum(self):
        self.logger.info("[M04] LDAP enumeration (anonymous bind)...")
        if not self._tool_available("ldapsearch"):
            return self._missing_tool("ldapsearch")
        return {
            "root_dse": self._run_cmd(
                ["ldapsearch", "-x", "-H", f"ldap://{self.target}",
                 "-s", "base", "-b", ""], timeout=30)[:3000]
        }

    def _nfs_enum(self):
        self.logger.info("[M04] NFS enumeration...")
        if not self._tool_available("showmount"):
            return self._missing_tool("showmount")
        return {"showmount": self._run_cmd(
            ["showmount", "-e", self.target], timeout=30)}

    def _smtp_enum(self):
        self.logger.info("[M04] SMTP user enumeration (VRFY)...")
        users = ["root", "admin", "administrator", "postmaster", "webmaster", "info"]
        results = []
        for u in users:
            try:
                out = self._run_cmd(
                    ["smtp-user-enum", "-M", "VRFY", "-U", "/dev/stdin",
                     "-t", self.target],
                    timeout=20)
                # Fallback đơn giản nếu không có smtp-user-enum
                break
            except Exception:
                break
        return {"note": "Cần smtp-user-enum; thử thủ công bằng nc."}