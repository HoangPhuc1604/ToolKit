"""Sinh báo cáo HTML + JSON từ kết quả toàn bộ toolkit."""
import json
import os
from datetime import datetime
from jinja2 import Template
from core.logger import get_logger

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="vi"><head><meta charset="UTF-8">
<title>CEH Toolkit Report - {{ target }}</title>
<style>
  body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f5f7fa;color:#222}
  header{background:linear-gradient(135deg,#1e3c72,#2a5298);color:#fff;padding:30px;text-align:center}
  .container{max-width:1200px;margin:20px auto;padding:0 20px}
  .module{background:#fff;border-radius:10px;padding:20px;margin:20px 0;
          box-shadow:0 2px 8px rgba(0,0,0,.08)}
  .module h2{margin-top:0;color:#1e3c72;border-bottom:2px solid #eee;padding-bottom:8px}
  pre{background:#1e1e1e;color:#d4d4d4;padding:15px;border-radius:6px;overflow-x:auto;
      font-size:12px;max-height:500px}
  .badge{display:inline-block;padding:3px 10px;border-radius:12px;
         background:#e3f2fd;color:#1565c0;font-size:12px;margin-left:8px}
  .meta{color:#666;font-size:13px;text-align:center;margin-top:8px}
</style></head>
<body>
<header>
  <h1>CEH v13 Toolkit Report</h1>
  <div class="meta">Target: <b>{{ target }}</b> | {{ timestamp }}</div>
</header>
<div class="container">
{% for name, data in results.items() %}
  <div class="module">
    <h2>{{ name }} <span class="badge">Module {{ data.get('_module_id','??') }}</span></h2>
    <pre>{{ data | tojson(indent=2) }}</pre>
  </div>
{% endfor %}
</div>
</body></html>"""


def save_reports(target, results, output_dir="./output"):
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(":", "_").replace("/", "_")

    json_path = os.path.join(output_dir, f"ceh_{safe_target}_{ts}.json")
    html_path = os.path.join(output_dir, f"ceh_{safe_target}_{ts}.html")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)

    html = Template(HTML_TEMPLATE).render(
        target=target,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        results=results,
    )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    return json_path, html_path