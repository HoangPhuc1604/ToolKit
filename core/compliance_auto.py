"""Compliance automation - evidence collection cho SOC 2 / ISO 27001."""
import json
import os
import hashlib
from datetime import datetime
from pathlib import Path
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.compliance")

# SOC 2 Trust Services Criteria (TSC) - mapping
SOC2_TSC = {
    "CC1.1": "COSO Principle 1 - Integrity and ethical values",
    "CC2.1": "COSO Principle 6 - Quality of information",
    "CC3.2": "COSO Principle 8 - Risk assessment",
    "CC4.1": "COSO Principle 10 - Monitoring activities",
    "CC5.1": "COSO Principle 12 - Control activities",
    "CC6.1": "Logical access - Infrastructure, software, data",
    "CC6.6": "Logical access - External threats",
    "CC6.7": "Transmission, movement, removal of information",
    "CC7.1": "Detection - Security events",
    "CC7.2": "Monitoring - Anomalies",
    "CC8.1": "Change management",
    "CC9.1": "Risk mitigation",
}

ISO_27001_2022 = {
    "A.5.15": "Access control",
    "A.5.17": "Authentication information",
    "A.8.5": "Secure authentication",
    "A.8.8": "Technical vulnerability management",
    "A.8.9": "Configuration management",
    "A.8.12": "Data leakage prevention",
    "A.8.16": "Monitoring activities",
    "A.8.20": "Network security",
    "A.8.24": "Use of cryptography",
    "A.8.25": "Secure development life cycle",
    "A.8.28": "Secure coding",
}


class EvidenceCollector:
    """Thu thập bằng chứng từ cloud + identity systems."""

    def __init__(self, output_dir="./compliance_evidence"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.evidence = []

    def _hash(self, content: str) -> str:
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def collect_aws(self, profile=None, region="us-east-1"):
        """Thu thập bằng chứng AWS: IAM, S3, CloudTrail, Config."""
        try:
            import boto3
        except ImportError:
            return {"error": "boto3 chưa cài (pip install boto3)"}

        session = boto3.Session(profile_name=profile, region_name=region)
        evidence = {}

        # IAM: users, MFA, root access keys
        try:
            iam = session.client("iam")
            users = iam.list_users()["Users"]
            evidence["iam_users"] = {
                "count": len(users),
                "mfa_enabled": sum(1 for u in users
                                   if iam.list_mfa_devices(
                                       UserName=u["UserName"])["MFADevices"]),
                "users_without_mfa": [
                    u["UserName"] for u in users
                    if not iam.list_mfa_devices(
                        UserName=u["UserName"])["MFADevices"]
                ],
            }
        except Exception as e:
            evidence["iam_error"] = str(e)

        # S3: public buckets
        try:
            s3 = session.client("s3")
            buckets = s3.list_buckets()["Buckets"]
            public = []
            for b in buckets:
                try:
                    acl = s3.get_bucket_acl(Bucket=b["Name"])
                    if any(g["Grantee"].get("URI", "").endswith(
                            "AllUsers") for g in acl["Grants"]):
                        public.append(b["Name"])
                except Exception:
                    pass
            evidence["s3"] = {
                "total": len(buckets),
                "public": public,
            }
        except Exception as e:
            evidence["s3_error"] = str(e)

        # CloudTrail: trails enabled
        try:
            ct = session.client("cloudtrail")
            trails = ct.describe_trails()["trailList"]
            evidence["cloudtrail"] = {
                "trails": len(trails),
                "multi_region": sum(1 for t in trails
                                    if t.get("IsMultiRegionTrail")),
            }
        except Exception as e:
            evidence["cloudtrail_error"] = str(e)

        return evidence

    def save_evidence(self, name, data):
        """Lưu bằng chứng với hash + timestamp."""
        record = {
            "name": name,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "hash": self._hash(json.dumps(data, sort_keys=True, default=str)),
            "data": data,
        }
        self.evidence.append(record)

        file_path = self.output_dir / f"{name}_{record['hash']}.json"
        file_path.write_text(
            json.dumps(record, indent=2, ensure_ascii=False, default=str))
        LOG.info(f"[compliance] Evidence saved: {file_path}")
        return str(file_path)

    def generate_audit_pack(self, framework="soc2"):
        """Sinh audit pack (JSON + manifest có chữ ký hash)."""
        manifest = {
            "framework": framework,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "evidence_count": len(self.evidence),
            "evidence": [{"name": e["name"], "hash": e["hash"],
                          "timestamp": e["timestamp"]} for e in self.evidence],
            "controls_mapped": SOC2_TSC if framework == "soc2"
                               else ISO_27001_2022,
        }
        manifest_path = self.output_dir / f"audit_pack_{framework}.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False))
        return str(manifest_path)


class Module(BaseModule):
    name = "compliance_auto"
    module_id = "CMP"
    description = "Compliance automation (SOC 2 / ISO 27001 evidence)"

    def run(self):
        self.logger.info("[CMP] Compliance automation")
        cfg = self.config
        collector = EvidenceCollector(cfg.get("output_dir",
                                               "./compliance_evidence"))
        results = {}

        if cfg.get("aws"):
            aws = collector.collect_aws(
                profile=cfg["aws"].get("profile"),
                region=cfg["aws"].get("region", "us-east-1"))
            results["aws"] = aws
            collector.save_evidence("aws_evidence", aws)

        # Lưu findings từ scan làm bằng chứng CC7.1
        if cfg.get("findings"):
            collector.save_evidence("scan_findings", cfg["findings"])

        results["audit_pack"] = collector.generate_audit_pack(
            cfg.get("framework", "soc2"))
        return results