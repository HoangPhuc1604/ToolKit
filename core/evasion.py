"""Kỹ thuật né tránh Nmap - decoy, fragment, spoof MAC, timing."""


class EvasionProfile:
    """Cấu hình né tránh cho Nmap."""

    @staticmethod
    def none():
        return {"name": "none", "args": []}

    @staticmethod
    def decoys(n=10):
        """-D RND:10 — ẩn sau 10 IP ngẫu nhiên."""
        return {"name": "decoys",
                "args": ["-D", f"RND:{n}"]}

    @staticmethod
    def fragment():
        """-f — chia gói thành mảnh 8 byte."""
        return {"name": "fragment", "args": ["-f"]}

    @staticmethod
    def mtu(size=16):
        """--mtu 16 — gói cực nhỏ, khó phân tích."""
        return {"name": "small-mtu", "args": ["--mtu", str(size)]}

    @staticmethod
    def spoof_mac(mac="0"):
        """--spoof-mac 0 — MAC ngẫu nhiên (cùng subnet)."""
        return {"name": "spoof-mac", "args": ["--spoof-mac", mac]}

    @staticmethod
    def slow(timing="T1"):
        """-T1 (sneaky) hoặc -T0 (paranoid)."""
        return {"name": f"timing-{timing}", "args": [f"-{timing}"]}

    @staticmethod
    def source_port(port=53):
        """--source-port 53 — giả DNS, thường được firewall cho qua."""
        return {"name": "src-port-53", "args": ["--source-port", str(port)]}

    @staticmethod
    def data_length(size=50):
        """--data-length 50 — thêm padding ngẫu nhiên."""
        return {"name": "pad", "args": ["--data-length", str(size)]}

    @staticmethod
    def bad_checksum():
        """--badsum — checksum sai (chỉ test firewall)."""
        return {"name": "badsum", "args": ["--badsum"]}


class EvasionStack:
    """Kết hợp nhiều kỹ thuật né tránh."""

    # Preset theo mức độ
    PRESETS = {
        "light": ["decoys", "slow"],
        "medium": ["decoys", "fragment", "slow", "source_port"],
        "heavy": ["decoys", "fragment", "mtu", "spoof_mac",
                  "slow", "source_port", "data_length"],
    }

    def __init__(self, level="medium"):
        self.level = level
        self.profiles = []

    def build_args(self) -> list:
        """Trả về list args Nmap."""
        args = []
        preset = self.PRESETS.get(self.level, [])

        for tech in preset:
            if tech == "decoys":
                args += EvasionProfile.decoys(10)["args"]
            elif tech == "fragment":
                args += EvasionProfile.fragment()["args"]
            elif tech == "mtu":
                args += EvasionProfile.mtu(16)["args"]
            elif tech == "spoof_mac":
                args += EvasionProfile.spoof_mac("0")["args"]
            elif tech == "slow":
                args += EvasionProfile.slow("T1")["args"]
            elif tech == "source_port":
                args += EvasionProfile.source_port(53)["args"]
            elif tech == "data_length":
                args += EvasionProfile.data_length(50)["args"]

        return args

    def describe(self):
        return {
            "level": self.level,
            "techniques": self.PRESETS.get(self.level, []),
            "args": self.build_args(),
            "note": "Chỉ dùng cho hệ thống được phép kiểm thử. "
                    "Spoof MAC chỉ hoạt động trong cùng broadcast domain.",
        }


def evasion_nmap_command(base_cmd: list, level="medium",
                         proxy_router=None) -> list:
    """Bổ sung args né tránh + proxy vào lệnh Nmap."""
    cmd = list(base_cmd)
    ev = EvasionStack(level)
    # Chèn evasion args trước target (giả định target là phần tử cuối)
    target = cmd[-1]
    cmd = cmd[:-1] + ev.build_args() + [target]

    if proxy_router:
        proxy_args = proxy_router.nmap_proxy_args()
        if proxy_args:
            cmd = cmd[:-1] + proxy_args + [target]

    return cmd