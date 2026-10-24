#!/usr/bin/env python3
"""CEH v13 Extended Toolkit - Entry point."""
import argparse
import json
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
        description="CEH v13 Extended Toolkit (All Modules)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ:
  python main.py scan example.com
  python main.py scan 192.168.1.10 --modules m03_scanning,m04_enumeration
  python main.py scan example.com --profile loud
  python main.py list
        """
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    # =============================================
    # LỆNH SCAN CƠ BẢN & TIỆN ÍCH
    # =============================================
    scan = sub.add_parser("scan", help="Chạy quét mục tiêu")
    scan.add_argument("target", help="Domain hoặc IP")
    scan.add_argument("--config", default="config.yaml")
    scan.add_argument("--profile", choices=["quick", "normal", "stealth", "paranoid", "loud"], default=None)
    scan.add_argument("--modules", help="Danh sách module, cách nhau bởi dấu phẩy")
    scan.add_argument("--no-parallel", action="store_true", help="Chạy tuần tự thay vì song song")
    scan.add_argument("--out", default=None, help="Thư mục output")
    scan.add_argument("--chain", action="store_true", help="Chạy tuần tự và chia sẻ state (scan chain)")

    sub.add_parser("list", help="Liệt kê module có sẵn")
    sub.add_parser("profiles", help="Liệt kê scan profiles")
    sub.add_parser("plugins", help="Liệt kê plugin")

    report_cmd = sub.add_parser("report", help="Sinh báo cáo LLM từ JSON")
    report_cmd.add_argument("json_file")
    report_cmd.add_argument("--provider", default="anthropic", choices=["anthropic", "openai"])

    # =============================================
    # THÊM SUBPARSERS MỚI
    # =============================================
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
    # SUBPARSERS CHO CÁC MODULE MỚI
    # =============================================
    # Fuzzing
    fz = sub.add_parser("fuzz", help="Zero-day fuzzing (AFL++ / boofuzz)")
    fz_sub = fz.add_subparsers(dest="fuzz_cmd", required=True)
    fz_afl = fz_sub.add_parser("afl")
    fz_afl.add_argument("binary")
    fz_afl.add_argument("--corpus", required=True)
    fz_afl.add_argument("--timeout", type=int, default=3600)
    fz_bf = fz_sub.add_parser("boofuzz")
    fz_bf.add_argument("host")
    fz_bf.add_argument("--port", type=int, default=80)
    fz_bf.add_argument("--template", default="http", choices=["http", "ftp"])

    # Adversary emulation
    adv = sub.add_parser("adversary", help="Adversary emulation")
    adv_sub = adv.add_subparsers(dest="adv_cmd", required=True)
    adv_sub.add_parser("caldera")
    adv_atomic = adv_sub.add_parser("atomic")
    adv_atomic.add_argument("technique_id")

    # Purple team
    pt = sub.add_parser("purple", help="Purple team exercise")
    pt.add_argument("--techniques", default="T1059.001,T1003.001,T1055")

    # Cloud native
    cn = sub.add_parser("cloud-native", help="Falco + Cloud Custodian")
    cn.add_argument("--falco-rules")
    cn.add_argument("--custodian-policy")

    # AI Triage
    tr = sub.add_parser("triage", help="AI triage findings từ JSON")
    tr.add_argument("json_file")
    tr.add_argument("--provider", default="anthropic")

    # Compliance Auto
    ca = sub.add_parser("compliance-auto", help="Thu thập evidence SOC2/ISO")
    ca.add_argument("--framework", default="soc2", choices=["soc2", "iso-27001"])
    ca.add_argument("--aws", action="store_true")

    # Threat Model
    tm = sub.add_parser("threat-model", help="STRIDE threat modeling")
    tm.add_argument("--repo")
    tm.add_argument("--description")
    tm.add_argument("--provider", default="anthropic")

    # Bug Bounty
    bb = sub.add_parser("bug-bounty", help="Bug bounty scope validation")
    bb.add_argument("--scope", required=True, help="File CSV/JSON scope")
    bb.add_argument("--target", required=True)

    # Blockchain Audit
    bc = sub.add_parser("blockchain", help="Smart contract audit")
    bc.add_argument("contract_path")
    bc.add_argument("--mythril", action="store_true")

    # OT/ICS
    ot = sub.add_parser("ot-ics", help="OT/ICS scan")
    ot.add_argument("target")
    ot.add_argument("--protocols", default="modbus,dnp3,s7,bacnet")

    # =============================================
    # SUBPARSERS CHO CÁC MODULE NÂNG CAO MỚI
    # =============================================
    # Continuous fuzzing
    cfz = sub.add_parser("cfuzz", help="Continuous fuzzing (OSS-Fuzz)")
    cfz_sub = cfz.add_subparsers(dest="cfz_cmd", required=True)
    cfz_sub.add_parser("setup")
    cfz_sub.add_parser("build").add_argument("project")
    cfz_sub.add_parser("run").add_argument("project")
    cfz_sub.add_parser("coverage").add_argument("project")

    # Exploit generation
    eg = sub.add_parser("exploit-gen", help="LLM exploit generation")
    eg.add_argument("crash_file")
    eg.add_argument("--binary")
    eg.add_argument("--source")
    eg.add_argument("--provider", default="anthropic")

    # Detection codegen
    dg = sub.add_parser("detection-gen", help="Sigma rule generation")
    dg.add_argument("--description", required=True)
    dg.add_argument("--technique")
    dg.add_argument("--level", default="medium")
    dg.add_argument("--coverage-dir")

    # SOC agent
    soc = sub.add_parser("soc", help="Autonomous SOC agent")
    soc.add_argument("--query", default="search index=notable | head 20")
    soc.add_argument("--provider", default="anthropic")

    # Supply chain
    sc = sub.add_parser("supply-chain", help="SBOM + sign + SLSA")
    sc.add_argument("--image")
    sc.add_argument("--source")
    sc.add_argument("--verify")

    # Runtime enforce
    rte = sub.add_parser("runtime-enforce", help="Tetragon + KubeArmor")
    rte.add_argument("--preset", default="kill_shell_spawn")
    rte.add_argument("--apply", action="store_true")

    # Deception
    dec = sub.add_parser("deception", help="Honeypot + LLM deception")
    dec.add_argument("--test-inputs")
    dec.add_argument("--tpot-url")

    # Threat hunting
    hunt = sub.add_parser("hunt", help="Threat hunting")
    hunt.add_argument("--technique", default="T1059.001")
    hunt.add_argument("--hours", type=int, default=24)
    hunt.add_argument("--spark-input")

    # C2
    c2 = sub.add_parser("c2", help="Sliver C2 automation")
    c2.add_argument("--listener")
    c2.add_argument("--generate")
    c2.add_argument("--sessions", action="store_true")

    # PQC
    pqc = sub.add_parser("pqc", help="Post-quantum crypto audit")
    pqc.add_argument("path")
    pqc.add_argument("--fail-on-critical", action="store_true")

    # =============================================

    args = ap.parse_args()

    # Xử lý các command cơ bản hiện có (list, profiles, plugins, report)
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

    # =============================================
    # XỬ LÝ CÁC LỆNH MỚI
    # =============================================
    elif args.cmd == "auth":
        LOG.info(f"[auth] Lệnh: {args.auth_cmd}")
        LOG.warning("[auth] Cần DB backend (auths/). Chưa triển khai.")
        print(f"[!] Lệnh 'auth {args.auth_cmd}' cần DB backend. Bổ sung logic trong auths/.")
        return

    elif args.cmd == "agentless":
        from core.agentless import Module as AgentlessModule
        LOG.info(f"[agentless] Scan {args.host}")
        cfg = {"ssh": {"user": args.ssh_user, "password": args.ssh_password, "key_path": args.ssh_key}, "lynis": args.lynis, "openscap": args.openscap}
        mod = AgentlessModule(args.host, cfg)
        print(json.dumps(mod.run(), indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "threat-intel":
        from core.threat_intel import ThreatIntelClient
        import socket
        LOG.info(f"[threat-intel] Enrich {args.target}")
        client = ThreatIntelClient()
        sources = args.sources.split(",")
        parts = args.target.split(".")
        is_ip = (len(parts) == 4 and all(p.isdigit() for p in parts))
        if is_ip:
            result = client.enrich_ip(args.target, sources=sources)
        else:
            try:
                ip = socket.gethostbyname(args.target)
                result = {"domain": args.target, "resolved_ip": ip, "enrichment": client.enrich_ip(ip, sources=sources)}
            except Exception as e:
                result = {"error": f"Không resolve được {args.target}: {e}"}
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "msf":
        from core.msf_automation import MetasploitClient
        if args.msf_cmd == "start-rpc":
            print("[msf] Chạy lệnh sau để khởi động MSF RPC daemon:")
            print("      msfrpcd -P <password> -S -p 55553 -U msf")
            return
        try:
            client = MetasploitClient()
        except Exception as e:
            print(f"[!] Không kết nối MSF RPC: {e}")
            return
        if args.msf_cmd == "search":
            result = client.search_exploits(cve=args.cve)
        elif args.msf_cmd == "exploit":
            result = client.module_info("exploit", args.exploit_name)
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "mobile":
        from core.mobile_scan import Module as MobileModule
        LOG.info(f"[mobile] Phân tích {args.apk_path}")
        mod = MobileModule(args.apk_path, {"apk_path": args.apk_path})
        print(json.dumps(mod.run(), indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "container":
        from core.container_scan import Module as ContainerModule
        LOG.info(f"[container] Scan image={args.image} k8s={args.k8s}")
        mod = ContainerModule("localhost", {"image": args.image, "k8s_cluster": args.k8s, "kube_hunter": args.kube_hunter})
        print(json.dumps(mod.run(), indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "iac":
        from core.iac_scan import Module as IaCModule
        LOG.info(f"[iac] Scan {args.path}")
        mod = IaCModule(args.path, {"path": args.path, "checkov": args.checkov, "tfsec": args.tfsec})
        print(json.dumps(mod.run(), indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "cicd":
        from core.cicd import generate_github_workflow, generate_gitlab_ci, generate_pre_commit_hook
        try:
            if args.platform == "github": path = generate_github_workflow()
            elif args.platform == "gitlab": path = generate_gitlab_ci()
            elif args.platform == "pre-commit": path = generate_pre_commit_hook()
            print(f"[✓] Đã tạo: {path}")
        except Exception as e:
            print(f"[!] Lỗi: {e}")
        return

    elif args.cmd == "fuzz":
        from core.fuzzing import AFLPlusPlusRunner, BoofuzzRunner
        if args.fuzz_cmd == "afl":
            runner = AFLPlusPlusRunner(args.binary, args.corpus)
            result = runner.run(timeout=args.timeout)
        else:
            runner = BoofuzzRunner(args.host, args.port)
            harness = runner.generate_harness(args.template)
            result = runner.run_harness(harness)
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "adversary":
        from core.adversary_emulation import CalderaClient, AtomicRunner
        if args.adv_cmd == "caldera":
            result = CalderaClient().list_agents()
        else:
            result = AtomicRunner().run_technique(args.technique_id)
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "purple":
        from core.purple_team import SplunkDetectionSource, PurpleTeamRunner
        source = SplunkDetectionSource()
        runner = PurpleTeamRunner(source)
        result = runner.run_exercise(args.techniques.split(","))
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "cloud-native":
        from core.cloud_native import FalcoManager, CloudCustodianRunner
        result = {}
        if args.falco_rules: result["falco"] = FalcoManager().validate_rules(args.falco_rules)
        if args.custodian_policy: result["custodian"] = CloudCustodianRunner().validate_policy(args.custodian_policy)
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "triage":
        from core.ai_triage import HybridTriagePipeline
        data = json.loads(Path(args.json_file).read_text())
        findings = data.get("_deduplicated_findings", [])
        pipeline = HybridTriagePipeline(args.provider)
        result = pipeline.process(findings)
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "compliance-auto":
        from core.compliance_auto import EvidenceCollector
        collector = EvidenceCollector()
        result = {"framework": args.framework}
        if args.aws: result["aws"] = collector.collect_aws()
        result["audit_pack"] = collector.generate_audit_pack(args.framework)
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "threat-model":
        from core.threat_model import ThreatModeler
        modeler = ThreatModeler(args.provider)
        if args.repo: result = modeler.model_from_repo(args.repo)
        else: result = modeler.model_from_description(args.description or "")
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "bug-bounty":
        from core.bug_bounty import Scope
        scope = Scope.from_csv(args.scope) if args.scope.endswith(".csv") else Scope.from_json(args.scope)
        result = scope.validate_targets([args.target])
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "blockchain":
        from core.blockchain_audit import SlitherRunner, MythrilRunner
        result = {"slither": SlitherRunner().analyze(args.contract_path)}
        if args.mythril: result["mythril"] = MythrilRunner().analyze(args.contract_path)
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "ot-ics":
        from core.ot_ics import ICSDetector
        protocols = args.protocols.split(",")
        result = ICSDetector().scan(args.target, protocols=protocols)
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return

    # =============================================
    # HANDLERS CHO CÁC MODULE NÂNG CAO MỚI
    # =============================================
    elif args.cmd == "cfuzz":
        from core.continuous_fuzzing import OSSFuzzRunner
        runner = OSSFuzzRunner()
        if args.cfz_cmd == "setup": result = runner.setup()
        elif args.cfz_cmd == "build": result = runner.build_fuzzers(args.project)
        elif args.cfz_cmd == "run": result = runner.run_fuzzer(args.project, "fuzz_target")
        elif args.cfz_cmd == "coverage": result = runner.coverage(args.project)
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "exploit-gen":
        from core.exploit_gen import Module as ExpGenModule
        cfg = {"crash_file": args.crash_file, "binary": args.binary, "source_file": args.source, "provider": args.provider}
        mod = ExpGenModule("local", cfg)
        print(json.dumps(mod.run(), indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "detection-gen":
        from core.detection_codegen import Module as DetGenModule
        cfg = {"descriptions": [{"text": args.description, "technique": args.technique, "level": args.level}], "rule_dir": args.coverage_dir}
        mod = DetGenModule("local", cfg)
        print(json.dumps(mod.run(), indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "soc":
        from core.soc_agent import SplunkMCPClient, SOCOrchestrator
        cfg = {"provider": args.provider}
        orch = SOCOrchestrator(cfg)
        client = SplunkMCPClient()
        alerts = client.query_alerts(args.query).get("results", [])
        print(json.dumps(orch.run_batch(alerts), indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "supply-chain":
        from core.supply_chain import SyftScanner, GrypeScanner, CosignManager
        result = {}
        target = args.image or args.source
        if target:
            res = SyftScanner().generate(target)
            result["sbom"] = res
            if res.get("sbom_file"):
                result["vulns"] = GrypeScanner().scan(res["sbom_file"])
        if args.verify:
            result["verify"] = CosignManager().verify(args.verify)
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "runtime-enforce":
        from core.runtime_enforce import TetragonManager, KubeArmorManager
        tm = TetragonManager()
        res = {"tetragon_yaml": tm.generate_tracing_policy(f"ceh-{args.preset}", "sys_execve", "Sigkill")}
        if args.apply: res["applied"] = tm.apply_policy(res["tetragon_yaml"])
        print(json.dumps(res, indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "deception":
        from core.deception import LLMDeceptionEngine
        engine = LLMDeceptionEngine()
        inputs = args.test_inputs.split(",") if args.test_inputs else ["whoami", "cat /etc/passwd"]
        result = [{"input": i, **engine.get_response("ubuntu", i)} for i in inputs]
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "hunt":
        from core.threat_hunting import ElasticHunter, SparkHunter
        result = {}
        if args.spark_input:
            result["spark"] = SparkHunter().hunt(args.technique, args.spark_input)
        else:
            result["elastic"] = ElasticHunter().hunt(args.technique, args.hours)
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "c2":
        from core.c2_automation import SliverClient
        client = SliverClient()
        result = {}
        if args.listener: result["listener"] = client.start_listener(args.listener)
        if args.generate: result["implant"] = client.generate_implant(name=args.generate)
        if args.sessions: result["sessions"] = client.list_sessions()
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return

    elif args.cmd == "pqc":
        from core.pqc_audit import PQCAuditor
        auditor = PQCAuditor()
        result = auditor.scan(args.path)
        if args.fail_on_critical and result["by_risk"].get("CRITICAL", 0) > 0:
            result["ci_gate"] = "FAIL"
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return

    # =========================================================
    # LỆNH SCAN CHÍNH (giữ nguyên luồng gốc)
    # =========================================================
    if args.cmd == "scan":
        if args.profile:
            from core.profiles import get_profile
            cfg = get_profile(args.profile)
        else:
            cfg_path = Path(args.config)
            cfg = load_config(cfg_path) if cfg_path.exists() else {"modules": {}}

        modules = (args.modules.split(",") if args.modules else cfg.get("enabled_modules", []))

        LOG.info(f"Target  : {args.target}")
        LOG.info(f"Modules : {', '.join(modules)}")
        LOG.info("=" * 60)

        orch = Orchestrator(args.target, cfg, parallel=not args.no_parallel, max_workers=cfg.get("general", {}).get("threads", 3), chain=args.chain)
        results = orch.run(modules)

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