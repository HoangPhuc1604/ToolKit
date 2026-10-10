"""Map kết quả toolkit sang MITRE ATT&CK techniques."""


# Mapping: tên module/hàm → technique
TECHNIQUE_MAP = {
    # Module 02
    "m02_footprinting.whois": [
        ("T1596.002", "Search Open Technical Databases: WHOIS"),
        ("T1590.001", "Gather Victim Network Info: Domain Properties"),
    ],
    "m02_footprinting.dns": [
        ("T1590.002", "Gather Victim Network Info: DNS"),
    ],
    "m02_footprinting.zone_transfer": [
        ("T1590.002", "Gather Victim Network Info: DNS"),
    ],
    "m02_footprinting.subdomains": [
        ("T1595.001", "Active Scanning: Scanning IP Blocks"),
        ("T1590.002", "Gather Victim Network Info: DNS"),
    ],
    "m02_footprinting.google_dorks": [
        ("T1593.002", "Search Open Websites/Domains: Search Engines"),
    ],
    "m02_footprinting.theharvester": [
        ("T1589.002", "Gather Victim Identity Info: Email Addresses"),
    ],

    # Module 03
    "m03_scanning.host_discovery": [
        ("T1018", "Remote System Discovery"),
        ("T1595.001", "Active Scanning: Scanning IP Blocks"),
    ],
    "m03_scanning.port_scan": [
        ("T1046", "Network Service Discovery"),
        ("T1595.002", "Active Scanning: Vulnerability Scanning"),
    ],
    "m03_scanning.nmap_vuln": [
        ("T1595.002", "Active Scanning: Vulnerability Scanning"),
    ],

    # Module 04
    "m04_enumeration.smb": [
        ("T1087.002", "Account Discovery: Domain Account"),
        ("T1135", "Network Share Discovery"),
    ],
    "m04_enumeration.snmp": [
        ("T1046", "Network Service Discovery"),
        ("T1087.001", "Account Discovery: Local Account"),
    ],
    "m04_enumeration.ldap": [
        ("T1087.002", "Account Discovery: Domain Account"),
        ("T1069.002", "Permission Groups Discovery: Domain Groups"),
    ],
    "m04_enumeration.nfs": [
        ("T1135", "Network Share Discovery"),
    ],
    "m04_enumeration.smtp": [
        ("T1087.003", "Account Discovery: Email Account"),
    ],

    # Module 05
    "m05_vuln_analysis.searchsploit": [
        ("T1596.005", "Search Open Technical Databases: Scan Databases"),
        ("T1588.006", "Obtain Capabilities: Vulnerabilities"),
    ],
    "m05_vuln_analysis.nikto": [
        ("T1595.002", "Active Scanning: Vulnerability Scanning"),
    ],
    "m05_vuln_analysis.sslscan": [
        ("T1595.002", "Active Scanning: Vulnerability Scanning"),
    ],

    # Module 06
    "m06_system_hacking.hydra": [
        ("T1110.001", "Brute Force: Password Guessing"),
        ("T1110.003", "Brute Force: Password Spraying"),
        ("T1110.004", "Brute Force: Credential Stuffing"),
    ],
    "m06_system_hacking.john": [
        ("T1110.002", "Brute Force: Password Cracking"),
    ],
    "m06_system_hacking.hashcat": [
        ("T1110.002", "Brute Force: Password Cracking"),
    ],
    "m06_system_hacking.hash_identify": [
        ("T1033", "System Owner/User Discovery"),
    ],

    # Module 08
    "m08_sniffing.capture": [
        ("T1040", "Network Sniffing"),
    ],
    "m08_sniffing.arp_scan": [
        ("T1016.001", "System Network Configuration Discovery: Internet Connection"),
    ],
    "m08_sniffing.arp_spoof_detect": [
        ("T1557.002", "Adversary-in-the-Middle: ARP Cache Poisoning"),
    ],

    # Module 11
    "m11_web_hacking.whatweb": [
        ("T1592.002", "Gather Victim Host Info: Software"),
    ],
    "m11_web_hacking.nikto": [
        ("T1595.002", "Active Scanning: Vulnerability Scanning"),
    ],
    "m11_web_hacking.dirb": [
        ("T1083", "File and Directory Discovery"),
        ("T1595.003", "Active Scanning: Wordlist Scanning"),
    ],
    "m11_web_hacking.wpscan": [
        ("T1595.002", "Active Scanning: Vulnerability Scanning"),
    ],

    # Module 13
    "m13_wireless.scan": [
        ("T1016.002", "System Network Configuration Discovery: Wi-Fi Discovery"),
    ],
    "m13_wireless.deauth": [
        ("T1557", "Adversary-in-the-Middle"),
        ("T1498", "Network Denial of Service"),
    ],
    "m13_wireless.crack": [
        ("T1110.002", "Brute Force: Password Cracking"),
    ],

    # Module 16
    "m16_cloud.prowler": [
        ("T1526", "Cloud Service Discovery"),
        ("T1087.004", "Account Discovery: Cloud Account"),
    ],
    "m16_cloud.scoutsuite": [
        ("T1526", "Cloud Service Discovery"),
    ],
}


def map_results(results: dict) -> dict:
    """Trả về {technique_id: {name, hits: [...]}} từ kết quả toolkit."""
    hits = {}
    for module, module_data in results.items():
        if not isinstance(module_data, dict):
            continue
        for key, value in module_data.items():
            full_key = f"{module}.{key}"
            if full_key not in TECHNIQUE_MAP:
                continue
            # Chỉ ghi nhận nếu có dữ liệu thực
            if _has_data(value):
                for tech_id, tech_name in TECHNIQUE_MAP[full_key]:
                    hits.setdefault(tech_id, {
                        "name": tech_name,
                        "sources": [],
                    })
                    hits[tech_id]["sources"].append(full_key)
    return hits


def _has_data(value) -> bool:
    """Kiểm tra xem kết quả có chứa thông tin thực không."""
    if value is None:
        return False
    if isinstance(value, dict):
        if "error" in value:
            return False
        if value.get("note", "").startswith("[!]"):
            return False
        return bool(value)
    if isinstance(value, (list, str)):
        return len(value) > 0
    return True