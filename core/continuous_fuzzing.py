"""Continuous fuzzing - OSS-Fuzz + ClusterFuzz orchestration.

Cho phép tự host OSS-Fuzz instance cho private projects.
"""
import subprocess
import json
import os
import shutil
from pathlib import Path
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.cfuzz")


class OSSFuzzProject:
    """Định nghĩa project OSS-Fuzz local."""

    def __init__(self, name, source_dir, dockerfile=None, build_script=None):
        self.name = name
        self.source_dir = Path(source_dir)
        self.dockerfile = dockerfile or self._default_dockerfile()
        self.build_script = build_script or self._default_build_script()

    def _default_dockerfile(self):
        return """FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make autoconf automake libtool
COPY . $SRC/project
WORKDIR $SRC/project
COPY build.sh $SRC/
"""

    def _default_build_script(self):
        return """#!/bin/bash -eu
cd $SRC/project
./autogen.sh
./configure
make -j$(nproc)
# Compile harness
$CXX $CXXFLAGS -std=c++11 -I. \\
    $SRC/project/fuzz_harness.cc -o $OUT/fuzz_target \\
    $LIB_FUZZING_ENGINE $SRC/project/.libs/libproject.a
"""


class OSSFuzzRunner:
    """Wrapper quanh infra/helper.py của OSS-Fuzz."""

    def __init__(self, ossfuzz_dir="/opt/oss-fuzz"):
        self.ossfuzz = Path(ossfuzz_dir)
        self.helper = self.ossfuzz / "infra" / "helper.py"
        self.available = self.helper.exists() and shutil.which("docker")

    def setup(self):
        """Clone OSS-Fuzz nếu chưa có."""
        if self.ossfuzz.exists():
            return {"status": "exists", "path": str(self.ossfuzz)}
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1",
                 "https://github.com/google/oss-fuzz.git", str(self.ossfuzz)],
                check=True, timeout=300)
            return {"status": "cloned", "path": str(self.ossfuzz)}
        except Exception as e:
            return {"error": str(e)}

    def build_image(self, project):
        return self._run_helper(["build_image", "--pull", project])

    def build_fuzzers(self, project, sanitizer="address"):
        return self._run_helper([
            "build_fuzzers", f"--sanitizer={sanitizer}", project])

    def run_fuzzer(self, project, harness, seconds=60):
        """Chạy fuzzer local trong Docker."""
        cmd = ["timeout", str(seconds),
               "python3", str(self.helper), "run_fuzzer",
               project, harness]
        return self._run_cmd(cmd, timeout=seconds + 30)

    def coverage(self, project):
        return self._run_helper(["coverage", project])

    def reproduce(self, testcase, project):
        """Reproduce crash từ OSS-Fuzz testcase."""
        return self._run_helper(["reproduce", testcase, project])

    def _run_helper(self, args):
        if not self.available:
            return {"error": "OSS-Fuzz chưa setup (thiếu Docker hoặc repo)"}
        cmd = ["python3", str(self.helper)] + args
        return self._run_cmd(cmd, timeout=1800)

    def _run_cmd(self, cmd, timeout=600):
        LOG.info(f"[cfuzz] {' '.join(cmd[:5])}...")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout, cwd=str(self.ossfuzz))
            return {
                "returncode": r.returncode,
                "stdout": r.stdout[-3000:],
                "stderr": r.stderr[-1000:],
            }
        except subprocess.TimeoutExpired:
            return {"error": "Timeout"}
        except Exception as e:
            return {"error": str(e)}


class ClusterFuzzLocal:
    """Tương tác với ClusterFuzz local instance qua API."""

    def __init__(self, base_url="http://localhost:9000"):
        self.base = base_url.rstrip("/")

    def list_crashes(self, project=None):
        import requests
        try:
            r = requests.get(f"{self.base}/_internal/crashes",
                             params={"project": project}, timeout=10)
            return r.json() if r.status_code == 200 else {"error": r.status_code}
        except Exception as e:
            return {"error": str(e)}

    def crash_stats(self, project):
        """Thống kê crash theo type/severity."""
        import requests
        try:
            r = requests.get(
                f"{self.base}/_internal/crash_stats",
                params={"project": project}, timeout=10)
            return r.json() if r.status_code == 200 else {"error": r.status_code}
        except Exception as e:
            return {"error": str(e)}


class Module(BaseModule):
    name = "continuous_fuzzing"
    module_id = "CFZ"
    description = "Continuous fuzzing (OSS-Fuzz + ClusterFuzz)"

    def run(self):
        self.logger.info("[CFZ] Continuous fuzzing")
        cfg = self.config
        runner = OSSFuzzRunner(cfg.get("ossfuzz_dir", "/opt/oss-fuzz"))
        results = {}

        if cfg.get("setup"):
            results["setup"] = runner.setup()

        project = cfg.get("project")
        if not project:
            return {"note": "Cần config project name", **results}

        if cfg.get("build", True):
            results["build_image"] = runner.build_image(project)
            results["build_fuzzers"] = runner.build_fuzzers(
                project, cfg.get("sanitizer", "address"))

        if cfg.get("run"):
            results["run"] = runner.run_fuzzer(
                project, cfg["harness"], cfg.get("seconds", 60))

        if cfg.get("coverage"):
            results["coverage"] = runner.coverage(project)

        # ClusterFuzz local nếu có
        if cfg.get("clusterfuzz_url"):
            cf = ClusterFuzzLocal(cfg["clusterfuzz_url"])
            results["crashes"] = cf.list_crashes(project)

        return results