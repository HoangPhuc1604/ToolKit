"""Scan profiles - đóng gói cấu hình sẵn cho các tình huống khác nhau."""
from copy import deepcopy


BASE = {
    "general": {"timeout": 300, "threads": 4},
    "modules": {},
    "core_actions": [],
}


PROFILES = {
    # Nhanh, ồn - dùng trong lab
    "quick": {
        "general": {"timeout": 120, "threads": 8, "rate_limit": "quick"},
        "enabled_modules": ["m02_footprinting", "m03_scanning"],
        "core_actions": ["dedup", "mitre"],
        "modules": {
            "m02_footprinting": {"subdomain_bruteforce": True,
                                  "theharvester": False, "google_dorks": False},
            "m03_scanning": {"scan_type": "basic", "ports": "1-1000", "timing": "T4"},
        },
    },

    # Cân bằng - default production
    "normal": {
        "general": {"timeout": 300, "threads": 4, "rate_limit": "normal"},
        "enabled_modules": ["m02_footprinting", "m03_scanning",
                            "m04_enumeration", "m05_vuln_analysis",
                            "m11_web_hacking"],
        "core_actions": ["dedup", "compliance", "mitre"],
        "modules": {
            "m03_scanning": {"scan_type": "service", "ports": "1-1000", "timing": "T4"},
        },
    },

    # Chậm, ít noise - tránh IDS
    "stealth": {
        "general": {"timeout": 900, "threads": 2, "rate_limit": "stealth"},
        "enabled_modules": ["m02_footprinting", "m03_scanning"],
        "core_actions": ["dedup", "mitre"],
        "modules": {
            "m03_scanning": {"scan_type": "basic", "ports": "21,22,23,25,53,80,110,143,443,445,3306,3389,8080",
                              "timing": "T1"},
            "m02_footprinting": {"subdomain_bruteforce": False,
                                  "theharvester": True},
        },
    },

    # Cực chậm + jitter cao - red team
    "paranoid": {
        "general": {"timeout": 1800, "threads": 1, "rate_limit": "paranoid"},
        "enabled_modules": ["m02_footprinting", "m03_scanning"],
        "core_actions": ["dedup", "mitre"],
        "modules": {
            "m03_scanning": {"scan_type": "basic", "ports": "22,80,443",
                              "timing": "T0"},
        },
    },

    # Đầy đủ - deep pentest
    "loud": {
        "general": {"timeout": 1800, "threads": 8, "rate_limit": "quick"},
        "enabled_modules": ["m02_footprinting", "m03_scanning", "m04_enumeration",
                            "m05_vuln_analysis", "m11_web_hacking",
                            "m06_system_hacking"],
        "core_actions": ["threat_intel", "dedup", "compliance",
                          "attack_graph", "mitre"],
        "modules": {
            "m03_scanning": {"scan_type": "full", "ports": "1-65535", "timing": "T4"},
            "m05_vuln_analysis": {"nikto": True, "searchsploit": True, "sslscan": True},
            "m06_system_hacking": {"hydra": True, "hash_identify": True},
        },
    },
}


def get_profile(name):
    """Trả về dict config cho profile. Merge vào base."""
    if name not in PROFILES:
        raise ValueError(f"Profile không tồn tại: {name}. "
                         f"Có sẵn: {list(PROFILES.keys())}")
    cfg = deepcopy(BASE)
    p = PROFILES[name]
    for section, values in p.items():
        if isinstance(values, dict) and section in cfg:
            cfg[section].update(values)
        else:
            cfg[section] = deepcopy(values)
    return cfg


def list_profiles():
    return list(PROFILES.keys())