#!/usr/bin/env python3
"""CEH v13 Extended Toolkit - Entry point."""
import argparse
import sys
import yaml
from pathlib import Path

from core.logger import get_logger
from core.orchestrator import Orchestrator
from modules import report

LOG = get_logger("ceh.main")


def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def list_modules():
    modules_dir = Path(__file__).parent / "modules"
    print("Các module có sẵn:")
    for p in sorted(modules_dir.glob("m*.py")):
        print(f"  - {p.stem}")


def main():
    ap = argparse.ArgumentParser(
        description="CEH v13 Extended Toolkit (Modules 02-11)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ:
  python main.py scan example.com
  python main.py scan 192.168.1.10 --modules m03_scanning,m04_enumeration
  python main.py scan example.com --no-parallel --config config.yaml
  python main.py list
        """
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="Chạy quét mục tiêu")
    scan.add_argument("target", help="Domain hoặc IP")
    scan.add_argument("--config", default="config.yaml")
    
    # ============ CẬP NHẬT MỚI ============
    scan.add_argument("--profile", choices=["quick", "normal", "stealth",
                                            "paranoid", "loud"],
                      default=None, help="Dùng profile thay vì config.yaml")
    # ======================================
    
    scan.add_argument("--modules", help="Danh sách module, cách nhau bởi dấu phẩy")
    scan.add_argument("--no-parallel", action="store_true",
                      help="Chạy tuần tự thay vì song song")
    scan.add_argument("--out", default=None, help="Thư mục output")
    
    scan.add_argument("--chain", action="store_true",
                      help="Chạy tuần tự và chia sẻ state (scan chain)")

    sub.add_parser("list", help="Liệt kê module có sẵn")
    sub.add_parser("profiles", help="Liệt kê scan profiles")
    sub.add_parser("plugins", help="Liệt kê plugin")

    report_cmd = sub.add_parser("report", help="Sinh báo cáo LLM từ JSON")
    report_cmd.add_argument("json_file")
    report_cmd.add_argument("--provider", default="anthropic",
                            choices=["anthropic", "openai"])

    # ============ THÊM SUBPARSERS MỚI ============
    
    # Auth
    auth = sub.add_parser("auth", help="Quản lý user/workspace")
    auth_sub = auth.add_subparsers(dest="auth_cmd", required=True)
    auth_sub.add_parser("create-workspace")
    auth_sub.add_parser("create-user")
    auth_sub.add_parser("issue-token")

    # Agentless
    al = sub.add_parser("agentless", help="Agentless endpoint scan")
    al.add_argument("host")
    al.add_argument("--ssh-user", default="root")
    al.add_argument("--ssh-password")
    al.add_argument("--ssh-key")
    al.add_argument("--lynis", action="store_true", default=True)
    al.add_argument("--openscap", action="store_true")

    # Threat intel
    ti = sub.add_parser("threat-intel", help="Enrich IP/domain")
    ti.add_argument("target")
    ti.add_argument("--sources", default="vt,internetdb,abuse,greynoise,otx")

    # MSF
    msf = sub.add_parser("msf", help="Metasploit automation")
    msf_sub = msf.add_subparsers(dest="msf_cmd", required=True)
    msf_sub.add_parser("search").add_argument("cve")
    msf_sub.add_parser("exploit").add_argument("exploit_name")
    msf_sub.add_parser("start-rpc")

    # Mobile
    mob = sub.add_parser("mobile", help="Phân tích APK/IPA")
    mob.add_argument("apk_path")

    # Container
    k8s = sub.add_parser("container", help="Container/K8s scan")
    k8s.add_argument("--image")
    k8s.add_argument("--k8s", action="store_true")
    k8s.add_argument("--kube-hunter", action="store_true")

    # IaC
    iac = sub.add_parser("iac", help="IaC scan")
    iac.add_argument("path")
    iac.add_argument("--checkov", action="store_true", default=True)
    iac.add_argument("--tfsec", action="store_true", default=True)

    # CI/CD
    cicd = sub.add_parser("cicd", help="Sinh CI/CD config")
    cicd.add_argument("platform", choices=["github", "gitlab", "pre-commit"])
    
    # =============================================

    args = ap.parse_args()

    # Xử lý các command cơ bản hiện có (list, profiles, plugins, report, scan)
    if args.cmd == "list":
        list_modules()
        return

    elif args.cmd == "profiles":
        from core.profiles import list_profiles, PROFILES
        for name in list_profiles():
            mods = PROFILES[name].get("enabled_modules", [])
            print(f"  {name:12} → {', '.join(mods)}")
        return

    elif args.cmd == "plugins":
        from core.plugin_loader import discover_plugins
        plugins = discover_plugins("./plugins")
        if not plugins:
            print("Chưa có plugin nào trong ./plugins/")
        for name, path in plugins.items():
            print(f"  - {name} ({path})")
        return

    elif args.cmd == "report":
        from llm.report_writer import generate_llm_report
        out = generate_llm_report(args.json_file, provider=args.provider)
        print(f"[✓] Báo cáo LLM: {out}")
        return

    # TODO: Thêm logic xử lý (if/elif) cho các lệnh auth, agentless, threat-intel, msf, mobile, container, iac, cicd tại đây trong tương lai

    if args.cmd == "scan":
        if args.profile:
            from core.profiles import get_profile
            cfg = get_profile(args.profile)
        else:
            cfg_path = Path(args.config)
            cfg = load_config(cfg_path) if cfg_path.exists() else {"modules": {}}

        # Chọn module
        modules = (args.modules.split(",") if args.modules
                   else cfg.get("enabled_modules", []))

        LOG.info(f"Target  : {args.target}")
        LOG.info(f"Modules : {', '.join(modules)}")
        LOG.info("=" * 60)

        # Chạy
        orch = Orchestrator(
            args.target, 
            cfg,
            parallel=not args.no_parallel,
            max_workers=cfg.get("general", {}).get("threads", 3),
            chain=args.chain,
        )
        
        results = orch.run(modules)

        # Báo cáo
        out_dir = args.out or cfg.get("general", {}).get("output_dir", "./output")
        json_path, html_path = report.save_reports(args.target, results, out_dir)
        LOG.info("=" * 60)
        LOG.info(f"[✓] JSON : {json_path}")
        LOG.info(f"[✓] HTML : {html_path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        LOG.warning("Đã hủy bởi người dùng.")
        sys.exit(130)