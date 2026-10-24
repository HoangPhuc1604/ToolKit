"""Detection-as-code - auto-generate Sigma rules từ findings/gaps."""
import os
import json
import yaml
import subprocess
import shutil
from pathlib import Path
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.detgen")

SIGMA_SYSTEM_PROMPT = """Bạn là detection engineer. Nhận mô tả về lỗ hổng hoặc gap, sinh Sigma rule.

Trả về CHỈ YAML hợp lệ theo schema Sigma:
```yaml
title: <title>
id: <uuid>
status: experimental
description: <mô tả>
author: CEH Toolkit
date: <YYYY/MM/DD>
logsource:
  category: <process_creation|network_connection|file_event|...>
  product: <windows|linux|...>
detection:
  selection:
    <field>: <value>
  condition: selection
falsepositives:
  - <case>
level: <critical|high|medium|low>
tags:
  - attack.<tactic>
  - attack.t<id>