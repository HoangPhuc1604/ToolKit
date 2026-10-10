"""Shared state - cho phép module trước truyền dữ liệu cho module sau."""
import threading


class SharedState:
    """Thread-safe key-value store dùng chung giữa các module.

    Ví dụ:
        state.set("open_ports", [22, 80, 443])   # m03_scanning
        ports = state.get("open_ports", [])      # m04_enumeration đọc
    """

    def __init__(self):
        self._data = {}
        self._lock = threading.Lock()

    def set(self, key, value):
        with self._lock:
            self._data[key] = value

    def get(self, key, default=None):
        with self._lock:
            return self._data.get(key, default)

    def update(self, kv: dict):
        with self._lock:
            self._data.update(kv)

    def all(self):
        with self._lock:
            return dict(self._data)

    # --------- Tiện ích cho scan chain ---------
    def set_open_ports(self, ports, services):
        self.set("open_ports", ports)
        self.set("services", services)

    def get_open_ports(self):
        return self.get("open_ports", [])

    def has_port(self, port):
        return port in self.get_open_ports()

    def get_web_urls(self):
        """Trả về danh sách URL http/https dựa trên port đã phát hiện."""
        urls = []
        for p in self.get_open_ports():
            if p in (80, 8080, 8000, 8888):
                urls.append(f"http://{self.get('target')}:{p}")
            elif p in (443, 8443):
                urls.append(f"https://{self.get('target')}:{p}")
        return urls


# Singleton toàn cục
STATE = SharedState()