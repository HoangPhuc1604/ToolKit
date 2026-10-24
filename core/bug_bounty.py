"""Bug bounty scope validation + submission helper."""
import ipaddress
import re
import csv
import json
from pathlib import Path
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.bb")


class Scope:
    """Parse và validate scope bug bounty."""

    def __init__(self):
        self.in_scope_domains = []
        self.in_scope_wildcards = []
        self.in_scope_cidrs = []
        self.out_of_scope = []

    @classmethod
    def from_csv(cls, path):
        """Parse scope CSV (format HackerOne/Bugcrowd)."""
        s = cls()
        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                asset = (row.get("identifier") or row.get("asset")
                         or "").strip()
                scope_type = (row.get("asset_type") or row.get("type")
                              or "").strip().lower()
                eligible = (row.get("eligible_for_submission", "true")
                            .lower() == "true")
                if not asset:
                    continue
                if not eligible:
                    s.out_of_scope.append(asset)
                    continue
                if scope_type in ("url", "domain", "website"):
                    if asset.startswith("*."):
                        s.in_scope_wildcards.append(asset[2:])
                    else:
                        s.in_scope_domains.append(asset.lower())
                elif scope_type in ("cidr", "ip_range"):
                    try:
                        s.in_scope_cidrs.append(
                            ipaddress.ip_network(asset, strict=False))
                    except ValueError:
                        pass
                elif scope_type == "ip":
                    try:
                        s.in_scope_cidrs.append(
                            ipaddress.ip_network(f"{asset}/32"))
                    except ValueError:
                        pass
        LOG.info(f"[bb] Scope: {len(s.in_scope_domains)} domains, "
                 f"{len(s.in_scope_wildcards)} wildcards, "
                 f"{len(s.in_scope_cidrs)} CIDRs")
        return s

    @classmethod
    def from_json(cls, path):
        """Parse scope JSON (format program tùy chỉnh)."""
        s = cls()
        data = json.loads(Path(path).read_text())
        for entry in data.get("in_scope", []):
            asset = entry.get("asset", "")
            if asset.startswith("*."):
                s.in_scope_wildcards.append(asset[2:])
            elif "/" in asset:
                try:
                    s.in_scope_cidrs.append(
                        ipaddress.ip_network(asset, strict=False))
                except ValueError:
                    pass
            else:
                s.in_scope_domains.append(asset.lower())
        for entry in data.get("out_of_scope", []):
            s.out_of_scope.append(entry.get("asset", ""))
        return s

    def is_in_scope(self, target: str) -> dict:
        """Kiểm tra target có trong scope không."""
        target = target.strip().lower()

        # Out of scope check trước
        for oos in self.out_of_scope:
            if oos.lower() in target:
                return {"allowed": False, "reason": f"Out of scope: {oos}"}

        # CIDR check
        try:
            ip = ipaddress.ip_address(target.split(":")[0])
            for cidr in self.in_scope_cidrs:
                if ip in cidr:
                    return {"allowed": True,
                            "matched": f"CIDR {cidr}"}
        except ValueError:
            pass

        # Domain check
        for d in self.in_scope_domains:
            if target == d or target.endswith("." + d):
                return {"allowed": True, "matched": f"domain {d}"}

        # Wildcard check
        for w in self.in_scope_wildcards:
            if target.endswith("." + w) and target != w:
                return {"allowed": True, "matched": f"wildcard *.{w}"}

        return {"allowed": False, "reason": "Không khớp scope nào"}

    def validate_targets(self, targets: list) -> dict:
        """Validate nhiều target, trả về allowed / denied."""
        allowed, denied = [], []
        for t in targets:
            r = self.is_in_scope(t)
            (allowed if r["allowed"] else denied).append({
                "target": t, **r})
        return {
            "allowed": allowed,
            "denied": denied,
            "summary": f"{len(allowed)}/{len(targets)} trong scope",
        }


class Module(BaseModule):
    name = "bug_bounty"
    module_id = "BB"
    description = "Bug bounty scope validation + submission helper"

    def run(self):
        self.logger.info("[BB] Bug bounty scope validation")
        cfg = self.config

        # Load scope
        if cfg.get("scope_csv"):
            scope = Scope.from_csv(cfg["scope_csv"])
        elif cfg.get("scope_json"):
            scope = Scope.from_json(cfg["scope_json"])
        else:
            return {"error": "Cần scope_csv hoặc scope_json trong config"}

        # Validate targets
        targets = cfg.get("targets", [self.target])
        result = scope.validate_targets(targets)

        # Nếu auto_scan và có target allowed → chạy scan
        if cfg.get("auto_scan") and result["allowed"]:
            self.logger.warning(
                f"[BB] Auto-scan {len(result['allowed'])} targets allowed")
            # TODO: trigger orchestrator cho từng target allowed
            result["scan_note"] = "Auto-scan chưa implement trong demo này"

        return result