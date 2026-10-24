"""Supply chain security - Syft + Grype + Cosign + SLSA provenance."""
import subprocess
import shutil
import json
import os
from pathlib import Path
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.schain")


class SyftScanner:
    """Generate SBOM với Syft."""

    def __init__(self):
        self.available = shutil.which("syft") is not None

    def generate(self, target: str, output_format="cyclonedx-json",
                 output_file=None) -> dict:
        if not self.available:
            return {"error": "syft chưa cài (curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh)"}
        output_file = output_file or "/tmp/sbom.cdx.json"
        cmd = ["syft", target, "-o", f"{output_format}={output_file}"]
        LOG.info(f"[schain] Syft: {target}")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if not Path(output_file).exists():
                return {"error": "SBOM chưa sinh", "stderr": r.stderr[:500]}
            sbom = json.loads(Path(output_file).read_text())
            return {
                "sbom_file": output_file,
                "components": len(sbom.get("components", [])),
                "format": output_format,
                "target": target,
            }
        except Exception as e:
            return {"error": str(e)}


class GrypeScanner:
    """Scan SBOM với Grype."""

    def __init__(self):
        self.available = shutil.which("grype") is not None

    def scan(self, sbom_file: str, fail_on="critical") -> dict:
        if not self.available:
            return {"error": "grype chưa cài"}
        cmd = ["grype", f"sbom:{sbom_file}", "-o", "json",
               "--fail-on", fail_on]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            try:
                data = json.loads(r.stdout)
            except json.JSONDecodeError:
                return {"error": "Không parse được Grype output",
                        "raw": r.stdout[:500]}
            matches = data.get("matches", [])
            by_sev = {}
            for m in matches:
                sev = m.get("vulnerability", {}).get("severity", "Unknown")
                by_sev[sev] = by_sev.get(sev, 0) + 1
            return {
                "total": len(matches),
                "by_severity": by_sev,
                "blocked": r.returncode != 0,
                "critical_cves": [
                    m["vulnerability"]["id"] for m in matches
                    if m["vulnerability"].get("severity") == "Critical"
                ][:20],
            }
        except Exception as e:
            return {"error": str(e)}


class CosignManager:
    """Keyless signing + verification với Cosign."""

    def __init__(self):
        self.available = shutil.which("cosign") is not None

    def sign_keyless(self, image_ref: str, yes=True) -> dict:
        """Keyless signing via Sigstore (cần OIDC)."""
        if not self.available:
            return {"error": "cosign chưa cài"}
        cmd = ["cosign", "sign", "--yes", image_ref]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return {
                "image": image_ref,
                "signed": r.returncode == 0,
                "output": (r.stdout + r.stderr)[-500:],
            }
        except Exception as e:
            return {"error": str(e)}

    def verify(self, image_ref: str, identity_regexp=None,
               oidc_issuer=None) -> dict:
        if not self.available:
            return {"error": "cosign chưa cài"}
        cmd = ["cosign", "verify", image_ref]
        if identity_regexp:
            cmd += ["--certificate-identity-regexp", identity_regexp]
        if oidc_issuer:
            cmd += ["--certificate-oidc-issuer", oidc_issuer]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return {"verified": r.returncode == 0,
                    "output": (r.stdout + r.stderr)[-500:]}
        except Exception as e:
            return {"error": str(e)}

    def attest_slsa(self, image_ref: str, predicate_file: str) -> dict:
        """Attest SLSA provenance."""
        if not self.available:
            return {"error": "cosign chưa cài"}
        cmd = ["cosign", "attest", "--predicate", predicate_file,
               "--type", "slsaprovenance", "--yes", image_ref]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return {"attested": r.returncode == 0,
                    "output": (r.stdout + r.stderr)[-500:]}
        except Exception as e:
            return {"error": str(e)}

    def verify_attestation(self, image_ref: str,
                            attestation_type="slsaprovenance") -> dict:
        cmd = ["cosign", "verify-attestation",
               "--type", attestation_type, image_ref]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return {"verified": r.returncode == 0,
                    "output": (r.stdout + r.stderr)[-500:]}
        except Exception as e:
            return {"error": str(e)}


class SLSAProvenance:
    """Sinh SLSA provenance predicate."""

    @staticmethod
    def build_predicate(builder_id: str, source_uri: str,
                        commit_sha: str, build_type="github-actions") -> dict:
        return {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": f"https://github.com/slsa-framework/slsa-github-generator/{build_type}@v1",
                    "externalParameters": {
                        "source": {"uri": source_uri, "digest": {"sha1": commit_sha}},
                    },
                    "resolvedDependencies": [],
                },
                "runDetails": {
                    "builder": {"id": builder_id},
                    "metadata": {"invocationId": os.environ.get("GITHUB_RUN_ID", "")},
                },
            },
        }


class Module(BaseModule):
    name = "supply_chain"
    module_id = "SC"
    description = "Supply chain security (Syft + Grype + Cosign + SLSA)"

    def run(self):
        self.logger.info("[SC] Supply chain security pipeline")
        cfg = self.config
        results = {}

        # 1. Generate SBOM
        target = cfg.get("target_image") or cfg.get("source_dir")
        sbom_file = None
        if target and cfg.get("sbom", True):
            s = SyftScanner()
            results["sbom"] = s.generate(
                target, cfg.get("sbom_format", "cyclonedx-json"))
            sbom_file = results["sbom"].get("sbom_file")

        # 2. Scan SBOM
        if sbom_file and cfg.get("scan", True):
            g = GrypeScanner()
            results["vuln_scan"] = g.scan(
                sbom_file, cfg.get("fail_on", "critical"))

        # 3. Sign image
        if target and cfg.get("sign") and target.startswith(("ghcr.io", "docker.io")):
            c = CosignManager()
            results["sign"] = c.sign_keyless(target)

        # 4. SLSA provenance
        if cfg.get("slsa"):
            predicate = SLSAProvenance.build_predicate(
                builder_id=cfg["slsa"].get("builder_id",
                                            "https://github.com/actions/runner"),
                source_uri=cfg["slsa"].get("source_uri", ""),
                commit_sha=cfg["slsa"].get("commit_sha", ""))
            pred_file = "/tmp/slsa_predicate.json"
            Path(pred_file).write_text(json.dumps(predicate, indent=2))
            results["slsa_predicate"] = pred_file

            if target and target.startswith(("ghcr.io", "docker.io")):
                c = CosignManager()
                results["attest"] = c.attest_slsa(target, pred_file)

        # 5. Verify (nếu có image ref)
        if cfg.get("verify_image"):
            c = CosignManager()
            results["verify_signature"] = c.verify(
                cfg["verify_image"],
                cfg.get("identity_regexp"),
                cfg.get("oidc_issuer"))
            results["verify_slsa"] = c.verify_attestation(
                cfg["verify_image"])

        return results