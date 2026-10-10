"""Compliance mapping - ánh xạ findings sang PCI-DSS, ISO 27001, NIST CSF."""


# Mapping: pattern finding → controls
COMPLIANCE_MAP = {
    # PCI-DSS v4.0
    "pci-dss": {
        "Requisitos": "PCI-DSS v4.0",
        "rules": [
            {"pattern": r"open port.*(22|3389)",
             "controls": ["11.3.1", "1.2.1"],
             "desc": "Kiểm thử xâm nhập định kỳ + cấu hình firewall"},
            {"pattern": r"open port.*(3306|5432|1433)",
             "controls": ["1.3.1", "11.3.1"],
             "desc": "Hạn chế truy cập CDE + pentest hàng năm"},
            {"pattern": r"SSL|TLS|sslscan",
             "controls": ["4.2.1"],
             "desc": "Mã hóa dữ liệu chủ thẻ trên kênh công khai"},
            {"pattern": r"nikto|injection|xss",
             "controls": ["6.2.4", "11.3.2"],
             "desc": "Kiểm soát lỗ hổng ứng dụng web"},
            {"pattern": r"brute.?force|hydra",
             "controls": ["8.3.4", "8.3.6"],
             "desc": "Kiểm soát xác thực & khóa tài khoản"},
        ],
    },

    # ISO 27001:2022
    "iso-27001": {
        "Requisitos": "ISO/IEC 27001:2022",
        "rules": [
            {"pattern": r"open port",
             "controls": ["A.8.20", "A.8.21", "A.8.22"],
             "desc": "Bảo mật mạng & phân tách mạng"},
            {"pattern": r"SSL|TLS",
             "controls": ["A.8.24"],
             "desc": "Sử dụng mật mã"},
            {"pattern": r"nikto|web",
             "controls": ["A.8.25", "A.8.26", "A.8.28"],
             "desc": "Bảo mật vòng đời phát triển & mã hóa an toàn"},
            {"pattern": r"credentials|password|brute",
             "controls": ["A.5.17", "A.8.5"],
             "desc": "Quản lý thông tin xác thực & xác thực an toàn"},
            {"pattern": r"smb|snmp|ldap",
             "controls": ["A.8.20", "A.8.21"],
             "desc": "Bảo mật mạng & dịch vụ mạng"},
        ],
    },

    # NIST CSF 2.0
    "nist-csf": {
        "Requisitos": "NIST CSF 2.0",
        "rules": [
            {"pattern": r"open port",
             "controls": ["PR.PS-01", "PR.IR-01"],
             "desc": "Platform security & network protection"},
            {"pattern": r"vulnerab|nikto|nuclei",
             "controls": ["ID.RA-01", "PR.PS-02"],
             "desc": "Vulnerability identification & management"},
            {"pattern": r"credentials|brute",
             "controls": ["PR.AA-01", "PR.AA-03"],
             "desc": "Identity management & authentication"},
            {"pattern": r"ssl|tls",
             "controls": ["PR.DS-02"],
             "desc": "Data-in-transit protection"},
        ],
    },

    # SOC 2
    "soc2": {
        "Requisitos": "SOC 2 Type II",
        "rules": [
            {"pattern": r"open port|vulnerab",
             "controls": ["CC4.1", "CC7.1"],
             "desc": "Monitoring & vulnerability detection"},
            {"pattern": r"credentials|auth",
             "controls": ["CC6.1", "CC6.6"],
             "desc": "Logical access controls"},
            {"pattern": r"ssl|tls|encrypt",
             "controls": ["CC6.7"],
             "desc": "Data transmission protection"},
        ],
    },
}


import re


def map_finding(finding: dict) -> dict:
    """Trả về {framework: {controls: [...], desc: ...}} cho finding."""
    text = " ".join([
        finding.get("title", ""),
        finding.get("description", ""),
        finding.get("service", ""),
        finding.get("cwe", ""),
    ]).lower()

    result = {}
    for fw, cfg in COMPLIANCE_MAP.items():
        matched = []
        for rule in cfg["rules"]:
            if re.search(rule["pattern"], text, re.IGNORECASE):
                matched.append({
                    "controls": rule["controls"],
                    "desc": rule["desc"],
                })
        if matched:
            result[fw] = {
                "name": cfg["Requisitos"],
                "matches": matched,
            }
    return result


def compliance_report(findings: list) -> dict:
    """Tổng hợp số finding vi phạm mỗi framework."""
    summary = {fw: {"name": cfg["Requisitos"], "violations": 0,
                     "controls": {}}
               for fw, cfg in COMPLIANCE_MAP.items()}

    for f in findings:
        m = map_finding(f)
        for fw, info in m.items():
            summary[fw]["violations"] += 1
            for match in info["matches"]:
                for ctrl in match["controls"]:
                    summary[fw]["controls"][ctrl] = \
                        summary[fw]["controls"].get(ctrl, 0) + 1

    return summary