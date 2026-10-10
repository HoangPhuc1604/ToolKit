"""Load module từ ngoài thư mục modules/ (user viết).

Cách dùng plugin:
    1. Tạo file trong ./plugins/my_plugin.py
    2. Kế thừa BaseModule
    3. Đặt tên class = Module
    4. Thêm tên file (không .py) vào config.yaml → enabled_modules
"""
import importlib.util
import inspect
import os
import sys
from pathlib import Path
from core.base_module import BaseModule
from core.logger import get_logger

LOG = get_logger("ceh.plugins")


def discover_plugins(plugin_dir="./plugins"):
    """Tìm tất cả file .py trong plugin_dir (bỏ qua file bắt đầu bằng _)."""
    plugins = {}
    p = Path(plugin_dir)
    if not p.is_dir():
        return plugins
    for f in p.glob("*.py"):
        if f.name.startswith("_"):
            continue
        plugins[f.stem] = str(f)
    return plugins


def load_plugin(plugin_path, plugin_name=None):
    """Load 1 plugin từ đường dẫn, trả về class Module."""
    plugin_name = plugin_name or Path(plugin_path).stem
    spec = importlib.util.spec_from_file_location(
        f"ceh_plugin_{plugin_name}", plugin_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Không load được {plugin_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    if not hasattr(module, "Module"):
        raise AttributeError(f"{plugin_path} thiếu class 'Module'")
    cls = module.Module
    if not (inspect.isclass(cls) and issubclass(cls, BaseModule)):
        raise TypeError(f"{plugin_path}::Module phải kế thừa BaseModule")

    LOG.info(f"[plugin] Loaded: {plugin_name} ({cls.module_id})")
    return cls