"""CI/CD hooks - sinh cấu hình cho GitHub Actions / GitLab CI."""
from pathlib import Path


GITHUB_WORKFLOW = """name: CEH IaC Security Scan
on:
  pull_request:
    paths: ['**.tf', '**.yaml', '**.yml', 'Dockerfile*']
  push:
    branches: [main]
jobs:
  iac-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: '3.12'}
      - name: Install
        run: pip install checkov
      - name: Checkov scan
        run: |
          checkov -d . -o json --quiet --soft-fail > checkov.json
      - name: Upload results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: checkov-results
          path: checkov.json
      - name: Fail on critical
        run: |
          python -c "
import json
d=json.load(open('checkov.json'))
s=d[0]['summary'] if isinstance(d,list) else d['summary']
if s.get('failed',0) > 0:
    import sys; sys.exit(1)
"
"""

GITLAB_CI = """stages:
  - security

iac-scan:
  stage: security
  image: python:3.12
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      changes: ["**/*.tf", "**/*.yaml", "**/*.yml", "Dockerfile*"]
  script:
    - pip install checkov
    - checkov -d . -o json --quiet --soft-fail > checkov.json
  artifacts:
    when: always
    paths: [checkov.json]
    reports:
      junit: checkov.junit.xml
"""


def generate_github_workflow(out_path=".github/workflows/ceh-iac.yml"):
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(GITHUB_WORKFLOW)
    return str(p)


def generate_gitlab_ci(out_path=".gitlab-ci.yml"):
    Path(out_path).write_text(GITLAB_CI)
    return str(out_path)


def generate_pre_commit_hook(repo_path="."):
    """Sinh pre-commit hook chặn IaC nguy hiểm."""
    hook_dir = Path(repo_path) / ".git" / "hooks"
    if not hook_dir.exists():
        raise FileNotFoundError("Không phải git repo")
    hook = hook_dir / "pre-commit"
    hook.write_text("""#!/bin/bash
# CEH Toolkit pre-commit hook
STAGED=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\\.(tf|yaml|yml)$')
if [ -n "$STAGED" ]; then
  echo "[ceh] IaC scan cho $STAGED"
  checkov -d . -o json --quiet --soft-fail --compact > /tmp/checkov.json
  python -c "
import json,sys
try:
    d=json.load(open('/tmp/checkov.json'))
    s=d[0]['summary'] if isinstance(d,list) else d['summary']
    if s.get('failed',0) > 5:
        print(f'[ceh] {s[\\"failed\\"]} IaC issues. Sửa trước khi commit.')
        sys.exit(1)
except: pass
"
fi
""")
    hook.chmod(0o755)
    return str(hook)