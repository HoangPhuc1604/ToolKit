"""Attack graph - xây dựng và trực quan hóa đồ thị tấn công."""
import json
from pathlib import Path
import networkx as nx
from core.logger import get_logger

LOG = get_logger("ceh.graph")


def build_attack_graph(results_by_target: dict) -> nx.DiGraph:
    """Xây dựng đồ thị có hướng: Host → Service → CVE/Vuln.

    Node attributes:
        type: host | service | vuln | subnet
        label, severity, ...
    """
    G = nx.DiGraph()

    for target, mod_results in results_by_target.items():
        if not isinstance(mod_results, dict):
            continue
        # Node host
        G.add_node(target, type="host", label=target,
                   severity=_host_severity(mod_results))

        # Open ports → service nodes
        for port_info in mod_results.get("m03_scanning", {}).get("open_ports", []):
            svc_id = f"{target}:{port_info['port']}"
            G.add_node(svc_id, type="service",
                       label=f"{port_info['port']}/{port_info.get('service', '?')}",
                       port=port_info["port"],
                       service=port_info.get("service"),
                       version=port_info.get("version", ""))
            G.add_edge(target, svc_id, rel="runs")

            # Nếu service có phiên bản → có thể map CVE từ searchsploit
            # (được thêm từ module M05)

        # Vulnerabilities từ nikto / searchsploit
        vulns = _extract_vuln_list(mod_results, target)
        for v in vulns:
            vuln_id = f"vuln:{v['fingerprint']}"
            G.add_node(vuln_id, type="vuln",
                       label=v.get("title", "?")[:40],
                       severity=v.get("severity", "info"),
                       cve=v.get("cve", ""))
            # Kết nối vuln tới service (nếu có port)
            if v.get("port"):
                svc_id = f"{target}:{v['port']}"
                if G.has_node(svc_id):
                    G.add_edge(svc_id, vuln_id, rel="exposes")

    return G


def _host_severity(mod_results):
    """Xác định severity cao nhất của host."""
    order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    max_sev = "info"
    for sev in ("critical", "high", "medium", "low"):
        if sev in json.dumps(mod_results, default=str).lower():
            max_sev = sev
            break
    return max_sev


def _extract_vuln_list(mod_results, target):
    """Trích xuất danh sách vuln từ module 05 & 11."""
    from core.dedup import normalize, deduplicate
    raw = []
    m05 = mod_results.get("m05_vuln_analysis", {})
    m11 = mod_results.get("m11_web_hacking", {})

    for tool, data in [("nikto", m05.get("nikto")),
                        ("searchsploit", m05.get("searchsploit")),
                        ("nikto", m11.get("nikto"))]:
        if not isinstance(data, dict):
            continue
        out = data.get("output", "")
        for line in out.splitlines():
            if _is_vuln_line(line):
                raw.append(normalize({
                    "target": target,
                    "title": line.strip()[:200],
                    "severity": _guess_severity(line),
                }, tool))

    return deduplicate(raw)


def _is_vuln_line(line):
    keywords = ("CVE-", "OSVDB", "vulnerab", "injection",
                "XSS", "SQL", "traversal", "disclosure")
    return any(k.lower() in line.lower() for k in keywords)


def _guess_severity(line):
    low = line.lower()
    if any(k in low for k in ("critical", "rce", "remote code")):
        return "critical"
    if any(k in low for k in ("sql", "injection", "auth bypass")):
        return "high"
    if any(k in low for k in ("xss", "traversal", "disclosure")):
        return "medium"
    return "low"


def shortest_attack_path(G: nx.DiGraph, entry: str, target: str):
    """Tìm đường tấn công ngắn nhất entry → target (nếu có)."""
    if not (G.has_node(entry) and G.has_node(target)):
        return None
    try:
        return nx.shortest_path(G, entry, target)
    except nx.NetworkXNoPath:
        return None


def choke_points(G: nx.DiGraph, top_n=10):
    """Tìm node quan trọng (betweenness centrality) — điểm cần bảo vệ."""
    bc = nx.betweenness_centrality(G)
    return sorted(bc.items(), key=lambda x: x[1], reverse=True)[:top_n]


def export_visjs(G: nx.DiGraph, out_html="output/attack_graph.html"):
    """Xuất đồ thị ra HTML tương tác với vis.js."""
    nodes = []
    edges = []
    for n, attrs in G.nodes(data=True):
        color = {"host": "#4a9eff", "service": "#ff9800",
                 "vuln": "#f44336", "subnet": "#9c27b0"}.get(
                     attrs.get("type"), "#888")
        nodes.append({
            "id": n,
            "label": attrs.get("label", n),
            "title": json.dumps(attrs, default=str, indent=2),
            "group": attrs.get("type"),
            "color": color,
        })
    for u, v, attrs in G.edges(data=True):
        edges.append({
            "from": u, "to": v,
            "label": attrs.get("rel", ""),
            "arrows": "to",
        })

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Attack Graph</title>
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>body{{margin:0;background:#0f1115;color:#e5e9f0;font-family:monospace}}
#net{{width:100vw;height:100vh}}#legend{{position:fixed;top:12px;right:12px;
background:#181b22;padding:12px;border-radius:8px;font-size:12px}}
.dot{{display:inline-block;width:10px;height:10px;border-radius:50%;
margin-right:6px}}</style></head>
<body>
<div id="net"></div>
<div id="legend">
<b>Legend</b><br>
<div><span class="dot" style="background:#4a9eff"></span>Host</div>
<div><span class="dot" style="background:#ff9800"></span>Service</div>
<div><span class="dot" style="background:#f44336"></span>Vulnerability</div>
</div>
<script>
const nodes = new vis.DataSet({json.dumps(nodes)});
const edges = new vis.DataSet({json.dumps(edges)});
new vis.Network(document.getElementById('net'),
  {{nodes, edges}},
  {{physics:{{stabilization:true, barnesHut:{{gravitationalConstant:-8000}}}},
    interaction:{{hover:true}}, nodes:{{shape:'dot', size:18, font:{{color:'#e5e9f0'}}}}}});
</script></body></html>"""

    Path(out_html).parent.mkdir(parents=True, exist_ok=True)
    Path(out_html).write_text(html, encoding="utf-8")
    LOG.info(f"[graph] Đã xuất đồ thị: {out_html}")
    return out_html