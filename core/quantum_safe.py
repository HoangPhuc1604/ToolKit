# core/quantum_safe.py
import os
import re
import json
from pathlib import Path
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.pqc")

# Quantum-vulnerable patterns (Shor's algorithm)
PQC_PATTERNS = {
    "python": {
        r"from\s+Crypto\.PublicKey\s+import\s+(RSA|ECC|DSA)": "RSA/ECC/DSA",
        r"RSA\.generate\(": "RSA",
        r"ec\.generate_private_key\(": "ECC",
        r"ECDH\(": "ECDH",
        r"dh\.generate_parameters\(": "DH",
        r"ed25519": "Ed25519",
        r"x25519": "X25519",
        r"Cipher\.AES\.new\(.*128": "AES-128",
        r"hashlib\.md5": "MD5",
        r"hashlib\.sha1": "SHA-1",
    },
    "go": {
        r"crypto/rsa": "RSA",
        r"crypto/ecdsa": "ECDSA",
        r"crypto/ed25519": "Ed25519",
        r"crypto/dsa": "DSA",
        r"crypto/elliptic": "ECC",
    },
    "java": {
        r'"RSA"': "RSA", r'"EC"': "ECC", r'"DSA"': "DSA",
        r'"DiffieHellman"': "DH", r'"ECDH"': "ECDH",
        r'"MD5"': "MD5", r'"SHA-1"': "SHA-1",
    },
    "c": {
        r"RSA_generate_key": "RSA", r"EC_KEY_new": "ECC",
        r"ECDSA_sign": "ECDSA", r"DH_generate": "DH",
        r"EVP_PKEY_EC": "ECC EVP",
    },
}

PQC_MIGRATION_MAP = {
    "RSA": {"replace": "ML-KEM (FIPS 203) + ML-DSA (FIPS 204)",
            "risk": "CRITICAL", "hndl": True},
    "RSA/ECC/DSA": {"replace": "ML-KEM + ML-DSA",
                     "risk": "CRITICAL", "hndl": True},
    "ECC": {"replace": "ML-DSA (FIPS 204)", "risk": "CRITICAL", "hndl": True},
    "ECDSA": {"replace": "ML-DSA", "risk": "CRITICAL", "hndl": True},
    "ECDH": {"replace": "ML-KEM", "risk": "CRITICAL", "hndl": True},
    "DH": {"replace": "ML-KEM", "risk": "CRITICAL", "hndl": True},
    "Ed25519": {"replace": "ML-DSA hoặc SLH-DSA", "risk": "HIGH", "hndl": False},
    "X25519": {"replace": "ML-KEM", "risk": "HIGH", "hndl": True},
    "DSA": {"replace": "ML-DSA", "risk": "CRITICAL", "hndl": True},
    "AES-128": {"replace": "AES-256", "risk": "MEDIUM", "hndl": False},
    "MD5": {"replace": "SHA-256/SHA-3", "risk": "HIGH", "hndl": False},
    "SHA-1": {"replace": "SHA-256/SHA-3", "risk": "HIGH", "hndl": False},
    "ECC EVP": {"replace": "ML-KEM", "risk": "CRITICAL", "hndl": True},
}

LANG_EXT = {".py": "python", ".go": "go", ".java": "java",
            ".c": "c", ".h": "c", ".cpp": "c", ".cc": "c"}


class PQCAuditor:
    def __init__(self, exclude=None):
        self.exclude = set(exclude or ["vendor", "node_modules", ".git"])

    def scan(self, root: str) -> dict:
        root = Path(root)
        findings = []
        files_scanned = 0
        for ext, lang in LANG_EXT.items():
            for f in root.rglob(f"*{ext}"):
                if any(p in self.exclude for p in f.parts):
                    continue
                files_scanned += 1
                try:
                    text = f.read_text(errors="ignore")
                except Exception:
                    continue
                for pattern, label in PQC_PATTERNS.get(lang, {}).items():
                    for m in re.finditer(pattern, text):
                        line = text[:m.start()].count("\n") + 1
                        findings.append({
                            "file": str(f.relative_to(root)),
                            "line": line, "algorithm": label,
                            "code": m.group(0)[:80],
                            "language": lang,
                        })
        for f in findings:
            mig = PQC_MIGRATION_MAP.get(f["algorithm"], {})
            f["risk"] = mig.get("risk", "MEDIUM")
            f["hndl"] = mig.get("hndl", False)
            f["replacement"] = mig.get("replace", "Unknown")
        by_risk = {}
        for f in findings:
            by_risk[f["risk"]] = by_risk.get(f["risk"], 0) + 1
        return {"files_scanned": files_scanned,
                "total_findings": len(findings),
                "by_risk": by_risk,
                "findings": sorted(findings,
                    key=lambda x: {"CRITICAL": 0, "HIGH": 1,
                                    "MEDIUM": 2}.get(x["risk"], 3))}

    def roadmap(self, findings: list) -> list:
        priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
        sorted_f = sorted(findings,
            key=lambda x: (priority.get(x["risk"], 3),
                           0 if x["hndl"] else 1))
        return [{"step": i, "file": f["file"], "line": f["line"],
                 "current": f["algorithm"],
                 "replace_with": f["replacement"],
                 "risk": f["risk"],
                 "hndl_urgency": "HIGH" if f["hndl"] else "MEDIUM"}
                for i, f in enumerate(sorted_f, 1)]


class Module(BaseModule):
    name = "quantum_safe"
    module_id = "PQC"
    description = "Quantum-Safe Migration Audit (NIST FIPS 203/204/205)"

    def run(self):
        self.logger.info("[PQC] Quantum-Safe Migration Audit")
        cfg = self.config
        root = cfg.get("path")
        if not root or not Path(root).exists():
            return {"error": "Cần 'path' trỏ đến codebase"}
        auditor = PQCAuditor(cfg.get("exclude"))
        scan = auditor.scan(root)
        scan["roadmap"] = auditor.roadmap(scan["findings"])
        if cfg.get("fail_on_critical"):
            scan["ci_gate"] = "FAIL" if scan["by_risk"].get("CRITICAL", 0) else "PASS"
        return scan