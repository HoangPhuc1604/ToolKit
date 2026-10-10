"""Deduplicate findings - chuẩn hóa + khử trùng lặp cross-tool."""
import hashlib
from collections import defaultdict


# Schema chuẩn cho mọi finding
FINDING_SCHEMA = {
    "fingerprint": str,      # ID duy nhất
    "target": str,
    "port": (int, type(None)),
    "service": str,
    "title": str,
    "description": str,
    "severity": str,         # critical | high | medium | low | info
    "cvss": (float, type(None)),
    "cwe": str,
    "cve": str,
    "source_tools": list,    # công cụ đã phát hiện
    "references": list,
    "remediation": str,
}

SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def fingerprint(finding: dict) -> str:
    """Fingerprint ổn định cross-tool, bỏ qua source_tools."""
    parts = [
        finding.get("target", ""),
        str(finding.get("port", "")),
        finding.get("service", "").lower(),
        finding.get("cve", "").upper(),
        finding.get("cwe", "").upper(),
        finding.get("title", "").lower()[:80],
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def normalize(raw_finding: dict, source_tool: str) -> dict:
    """Chuyển finding thô thành schema chuẩn."""
    f = {k: raw_finding.get(k, "" if not isinstance(v, (list, dict))
                            else [] if isinstance(v, list) else {})
         for k, v in FINDING_SCHEMA.items()}
    f["source_tools"] = [source_tool]
    f["fingerprint"] = fingerprint(f)
    return f


def deduplicate(findings: list) -> list:
    """Khử trùng lặp, merge source_tools cho các finding cùng fingerprint.

    Khi 2 tool phát hiện cùng lỗi, ta giữ 1 bản ghi với:
    - severity = max(severity 2 bên)
    - source_tools = union
    - references = union
    """
    merged = {}
    for f in findings:
        fp = f.get("fingerprint") or fingerprint(f)
        if fp not in merged:
            merged[fp] = f
            continue
        existing = merged[fp]
        # Merge
        existing["source_tools"] = list(set(
            existing.get("source_tools", []) + f.get("source_tools", [])))
        existing["references"] = list(set(
            existing.get("references", []) + f.get("references", [])))
        # Nâng severity lên mức cao hơn
        if (SEVERITY_ORDER.get(f.get("severity", "info"), 0) >
                SEVERITY_ORDER.get(existing.get("severity", "info"), 0)):
            existing["severity"] = f["severity"]
            existing["description"] = f.get("description", existing.get("description", ""))
        # Ghi lại tool đã phát hiện (cho audit)
        existing.setdefault("_cross_tool_hits", []).append({
            "tool": source_tool_placeholder(f),
            "severity": f.get("severity"),
        })

    return sorted(merged.values(),
                  key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info"), 0),
                  reverse=True)


def source_tool_placeholder(f):
    return ",".join(f.get("source_tools", []))


def group_by_severity(findings: list) -> dict:
    """Group findings theo severity để hiển thị report."""
    groups = defaultdict(list)
    for f in findings:
        groups[f.get("severity", "info")].append(f)
    return dict(groups)