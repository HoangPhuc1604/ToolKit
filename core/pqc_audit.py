"""Post-quantum cryptography migration audit."""
import re
import json
from pathlib import Path
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.pqc")

# Quantum-vulnerable patterns (Shor's algorithm)
VULNERABLE_PATTERNS = {
    "python": [
        (r"from\s+Crypto\.PublicKey\s+import\s+RSA", "RSA"),
        (r"RSA\.generate\(", "RSA key generation"),
        (r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+rsa", "RSA"),
        (r"ec\.generate_private_key\(", "ECC key gen"),
        (r"from\s+Crypto\.PublicKey\s+import\s+ECC", "ECC"),
        (r"ECDH\(", "ECDH key exchange"),
        (r"from\s+Crypto\.PublicKey\s+import\s+DSA", "DSA"),
        (r"dh\.generate_parameters\(", "DH key exchange"),
    ],
    "go": [
        (r"crypto/rsa", "RSA"),
        (r"crypto/ecdsa", "ECDSA"),
        (r"crypto/ed25519", "Ed25519"),
        (r"crypto/dsa", "DSA"),
        (r"crypto/elliptic", "ECC"),
    ],
    "java": [
        (r'"RSA"', "RSA"),
        (r'"EC"', "ECC"),
        (r'"DSA"', "DSA"),
        (r'"DiffieHellman"', "DH"),
        (r'"ECDH"', "ECDH"),
    ],
    "c": [
        (r"RSA_generate_key", "RSA"),
        (r"EC_KEY_new", "ECC"),
        (r"ECDSA_sign", "ECDSA"),
        (r"DH_generate", "DH"),
        (r"EVP_PKEY_EC", "ECC EVP"),
    ],
    "cpp": [
        (r"RSA::", "RSA"),
        (r"ECDSA<", "ECDSA"),
        (r"DH::", "DH"),
    ],
}

# Migration map
MIGRATION_MAP = {
    "RSA": {"replace": "ML-KEM (FIPS 203) cho key exchange, "
                      "ML-DSA (FIPS 204) cho signatures",
            "risk": "CRITICAL", "hndl": True},
    "RSA key generation": {"replace": "ML-KEM / ML-DSA",
                            "risk": "CRITICAL", "hndl": True},
    "ECC": {"replace": "ML-DSA (FIPS 204) cho signatures",
            "risk": "CRITICAL", "hndl": True},
    "ECC key gen": {"replace": "ML-KEM", "risk": "CRITICAL", "hndl": True},
    "ECC EVP": {"replace": "ML-KEM", "risk": "CRITICAL", "hndl": True},
    "ECDSA": {"replace": "ML-DSA", "risk": "CRITICAL", "hndl": True},
    "ECDH key exchange": {"replace": "ML-KEM", "risk": "CRITICAL",
                           "hndl": True},
    "ECDH": {"replace": "ML-KEM", "risk": "CRITICAL", "hndl": True},
    "Ed25519": {"replace": "ML-DSA hoặc SLH-DSA", "risk": "HIGH",
                 "hndl": False},
    "DSA": {"replace": "ML-DSA", "risk": "CRITICAL", "hndl": True},
    "DH": {"replace": "ML-KEM", "risk": "CRITICAL", "hndl": True},
    "DH key exchange": {"replace": "ML-KEM", "risk": "CRITICAL",
                         "hndl": True},
}

LANGUAGE_EXTENSIONS = {
    ".py": "python", ".go": "go", ".java": "java",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
}


class PQCAuditor:
    """Scan codebase cho quantum-vulnerable crypto."""

    def __init__(self, exclude_dirs=None):
        self.exclude = set(exclude_dirs or ["vendor", "third_party",
                                             "node_modules", ".git"])

    def scan(self, root: str) -> dict:
        root = Path(root)
        findings = []
        files_scanned = 0
        for ext, lang in LANGUAGE_EXTENSIONS.items():
            for f in root.rglob(f"*{ext}"):
                if any(part in self.exclude for part in f.parts):
                    continue
                files_scanned += 1
                try:
                    text = f.read_text(errors="ignore")
                except Exception:
                    continue
                for pattern, label in VULNERABLE_PATTERNS.get(lang, []):
                    for match in re.finditer(pattern, text):
                        line_no = text[:match.start()].count("\n") + 1
                        findings.append({
                            "file": str(f.relative_to(root)),
                            "line": line_no,
                            "algorithm": label,
                            "code": match.group(0)[:100],
                            "language": lang,
                        })

        # Risk scoring
        for f in findings:
            mig = MIGRATION_MAP.get(f["algorithm"], {})
            f["risk"] = mig.get("risk", "MEDIUM")
            f["hndl_exposed"] = mig.get("hndl", False)
            f["replacement"] = mig.get("replace", "Unknown")

        # Summary
        by_risk = {}
        by_algo = {}
        for f in findings:
            by_risk[f["risk"]] = by_risk.get(f["risk"], 0) + 1
            by_algo[f["algorithm"]] = by_algo.get(f["algorithm"], 0) + 1

        return {
            "files_scanned": files_scanned,
            "total_findings": len(findings),
            "by_risk": by_risk,
            "by_algorithm": by_algo,
            "findings": sorted(
                findings,
                key=lambda x: {"CRITICAL": 0, "HIGH": 1,
                               "MEDIUM": 2, "LOW": 3}.get(x["risk"], 4)),
        }

    def migration_roadmap(self, findings: list) -> list:
        """Sinh roadmap ưu tiên theo risk × HNDL exposure."""
        roadmap = []
        priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_f = sorted(
            findings,
            key=lambda x: (priority.get(x["risk"], 4),
                           0 if x["hndl_exposed"] else 1))
        for i, f in enumerate(sorted_f, 1):
            roadmap.append({
                "step": i,
                "file": f["file"],
                "line": f["line"],
                "current": f["algorithm"],
                "replace_with": f["replacement"],
                "risk": f["risk"],
                "hndl_urgency": "HIGH" if f["hndl_exposed"] else "MEDIUM",
            })
        return roadmap


class Module(BaseModule):
    name = "pqc_audit"
    module_id = "PQC"
    description = "Post-quantum cryptography migration audit"

    def run(self):
        self.logger.info("[PQC] PQC migration audit")
        cfg = self.config
        root = cfg.get("path")
        if not root or not Path(root).exists():
            return {"error": "Cần config path trỏ đến codebase"}

        auditor = PQCAuditor(cfg.get("exclude_dirs"))
        scan = auditor.scan(root)
        scan["roadmap"] = auditor.migration_roadmap(scan["findings"])

        # CI/CD gate: fail nếu có CRITICAL
        if cfg.get("fail_on_critical", False):
            scan["ci_gate"] = "FAIL" if scan["by_risk"].get("CRITICAL", 0) > 0 \
                              else "PASS"

        return scan