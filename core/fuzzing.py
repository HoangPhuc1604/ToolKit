"""Zero-day research - AFL++ (coverage-guided) + boofuzz (network protocol)."""
import os
import subprocess
import shutil
import json
import tempfile
from pathlib import Path
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.fuzz")


class AFLPlusPlusRunner:
    """Chạy AFL++ với harness có sẵn hoặc tự sinh."""

    def __init__(self, target_binary, corpus_dir, output_dir=None):
        self.target = target_binary
        self.corpus = corpus_dir
        self.output = output_dir or f"/tmp/afl_out_{os.getpid()}"
        self.available = shutil.which("afl-fuzz") is not None

    def instrument(self, source_dir, compiler="afl-clang-fast"):
        """Biên dịch lại source với instrumentation."""
        if not shutil.which(compiler):
            return {"error": f"{compiler} chưa cài"}
        out = []
        for src in Path(source_dir).rglob("*.c"):
            obj = src.with_suffix(".o")
            cmd = [compiler, "-c", str(src), "-o", str(obj)]
            r = subprocess.run(cmd, capture_output=True, text=True)
            out.append({"src": str(src), "ok": r.returncode == 0,
                        "err": r.stderr[:200]})
        return {"instrumented": out}

    def run(self, timeout=3600, dictionary=None, cmplog=False):
        """Chạy AFL++ trong chế độ headless."""
        if not self.available:
            return {"error": "afl-fuzz chưa cài (apt install aflplusplus)"}

        Path(self.output).mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env["AFL_SKIP_CPUFREQ"] = "1"
        env["AFL_NO_UI"] = "1"
        env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"

        cmd = ["timeout", str(timeout),
               "afl-fuzz", "-i", self.corpus, "-o", self.output,
               "-m", "none", "--", self.target, "@@"]
        if dictionary:
            cmd = cmd[:6] + ["-x", dictionary] + cmd[6:]
        if cmplog:
            cmd.insert(-2, "-c", self.output.replace("out", "cmplog"))

        LOG.info(f"[fuzz] AFL++ run: {' '.join(cmd)}")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout + 60, env=env)
            stats = self._read_stats()
            crashes = self._collect_crashes()
            return {
                "duration": timeout,
                "stats": stats,
                "crashes": crashes[:50],
                "log_tail": (r.stdout + r.stderr)[-1000:],
            }
        except subprocess.TimeoutExpired:
            return self._read_stats()

    def _read_stats(self):
        stats_file = Path(self.output) / "default" / "fuzzer_stats"
        if not stats_file.exists():
            return {}
        stats = {}
        for line in stats_file.read_text().splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                stats[k.strip()] = v.strip()
        return stats

    def _collect_crashes(self):
        crash_dir = Path(self.output) / "default" / "crashes"
        if not crash_dir.exists():
            return []
        return [{"file": str(p), "size": p.stat().st_size}
                for p in crash_dir.glob("id:*")]


class BoofuzzRunner:
    """Network protocol fuzzing với boofuzz."""

    def __init__(self, target_host, target_port, protocol="tcp"):
        self.host = target_host
        self.port = target_port
        self.proto = protocol

    def generate_harness(self, template="http"):
        """Sinh harness skeleton cho protocol phổ biến."""
        skeletons = {
            "http": f'''from boofuzz import *
def main():
    session = Session(
        target=Target(connection=TCPSocketConnection("{self.host}", {self.port})),
        sleep_time=0.1,
    )
    s_initialize("request")
    s_string("GET", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("/", name="path")
    s_delim(" ", fuzzable=False)
    s_string("HTTP/1.1", fuzzable=False)
    s_static("\\r\\n\\r\\n")
    s_delim("\\r\\n", fuzzable=False)
    session.connect(s_get("request"))
    session.fuzz()
if __name__ == "__main__": main()
''',
            "ftp": f'''from boofuzz import *
def main():
    session = Session(
        target=Target(connection=TCPSocketConnection("{self.host}", {self.port})),
    )
    s_initialize("user")
    s_static("USER ")
    s_string("anonymous")
    s_static("\\r\\n")
    s_initialize("pass")
    s_static("PASS ")
    s_string("test")
    s_static("\\r\\n")
    session.connect(s_get("user"))
    session.connect(s_get("user"), s_get("pass"))
    session.fuzz()
if __name__ == "__main__": main()
''',
        }
        return skeletons.get(template, skeletons["http"])

    def run_harness(self, harness_code, crash_dir="/tmp/boofuzz_crashes",
                    timeout=1800):
        """Lưu harness và chạy boofuzz."""
        try:
            import boofuzz  # noqa
        except ImportError:
            return {"error": "boofuzz chưa cài (pip install boofuzz)"}

        with tempfile.NamedTemporaryFile("w", suffix=".py",
                                         delete=False) as f:
            f.write(harness_code)
            harness_path = f.name

        LOG.info(f"[fuzz] boofuzz harness: {harness_path}")
        try:
            r = subprocess.run(
                ["timeout", str(timeout), "python3", harness_path],
                capture_output=True, text=True, timeout=timeout + 30)
            crashes = []
            if os.path.isdir(crash_dir):
                crashes = [str(p) for p in Path(crash_dir).glob("*")]
            return {
                "harness": harness_path,
                "crashes": crashes[:30],
                "output_tail": (r.stdout + r.stderr)[-2000:],
            }
        except subprocess.TimeoutExpired:
            return {"harness": harness_path, "error": "Timeout"}


class Module(BaseModule):
    name = "fuzzing"
    module_id = "FUZZ"
    description = "Zero-day research (AFL++ coverage-guided + boofuzz network)"

    def run(self):
        self.logger.info("[FUZZ] Zero-day research")
        cfg = self.config
        results = {}

        if cfg.get("afl"):
            afl_cfg = cfg["afl"]
            runner = AFLPlusPlusRunner(
                afl_cfg["binary"], afl_cfg["corpus"],
                afl_cfg.get("output"))
            if afl_cfg.get("instrument"):
                results["instrument"] = runner.instrument(
                    afl_cfg["source_dir"],
                    afl_cfg.get("compiler", "afl-clang-fast"))
            results["afl_run"] = runner.run(
                timeout=afl_cfg.get("timeout", 3600),
                dictionary=afl_cfg.get("dictionary"),
                cmplog=afl_cfg.get("cmplog", False))

        if cfg.get("boofuzz"):
            bf = cfg["boofuzz"]
            runner = BoofuzzRunner(bf["host"], bf["port"], bf.get("proto", "tcp"))
            harness = bf.get("harness_code") or runner.generate_harness(
                bf.get("template", "http"))
            results["boofuzz"] = runner.run_harness(
                harness, bf.get("crash_dir", "/tmp/boofuzz_crashes"),
                bf.get("timeout", 1800))

        return results