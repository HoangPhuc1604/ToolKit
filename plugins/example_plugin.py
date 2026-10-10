"""Plugin mẫu - kiểm tra HTTP security headers."""
import requests
from core.base_module import BaseModule


class Module(BaseModule):
    name = "example_plugin"
    module_id = "99"
    description = "Kiểm tra security headers HTTP"

    def run(self):
        self.logger.info(f"[M99] Kiểm tra security headers: {self.target}")
        url = self.target if self.target.startswith("http") else f"http://{self.target}"

        try:
            r = requests.get(url, timeout=10, verify=False,
                             allow_redirects=True)
        except Exception as e:
            return {"error": str(e)}

        want = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Frame-Options": "Clickjacking protection",
            "X-Content-Type-Options": "MIME sniffing protection",
            "Referrer-Policy": "Referrer leak protection",
            "Permissions-Policy": "Browser feature control",
        }
        missing = []
        present = {}
        for h, desc in want.items():
            if h in r.headers:
                present[h] = r.headers[h]
            else:
                missing.append({"header": h, "impact": desc})

        return {
            "url": url,
            "status": r.status_code,
            "present": present,
            "missing": missing,
            "score": f"{len(present)}/{len(want)}",
        }