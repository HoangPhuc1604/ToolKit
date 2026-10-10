"""Rate limiter + jitter để tránh trigger IDS/IPS."""
import random
import time
import threading


class RateLimiter:
    """Token bucket đơn giản, thread-safe.

    Args:
        rate: số request/giây
        burst: số request tối đa trong 1 giây
        jitter: thêm ngẫu nhiên ±jitter giây (mô phỏng người dùng)
    """

    def __init__(self, rate=10, burst=20, jitter=0.0):
        self.rate = rate
        self.burst = burst
        self.jitter = jitter
        self.tokens = burst
        self.last = time.time()
        self._lock = threading.Lock()

    def _refill(self):
        now = time.time()
        elapsed = now - self.last
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.last = now

    def acquire(self, timeout=30):
        deadline = time.time() + timeout
        while True:
            with self._lock:
                self._refill()
                if self.tokens >= 1:
                    self.tokens -= 1
                    break
            if time.time() > deadline:
                raise TimeoutError("Rate limit timeout")
            time.sleep(0.05)

        if self.jitter > 0:
            time.sleep(random.uniform(0, self.jitter))


# Preset theo profile
LIMITERS = {
    "quick":    RateLimiter(rate=200, burst=500, jitter=0),
    "normal":   RateLimiter(rate=50,  burst=100, jitter=0),
    "stealth":  RateLimiter(rate=5,   burst=10,  jitter=1.5),
    "paranoid": RateLimiter(rate=1,   burst=3,   jitter=3.0),
}


def get_limiter(name="normal"):
    return LIMITERS.get(name, LIMITERS["normal"])