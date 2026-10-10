"""Event bus - phát sự kiện để WebSocket dashboard stream real-time."""
import asyncio
import json
from datetime import datetime
from collections import deque
from typing import Callable, Optional


class EventBus:
    """Singleton event bus đơn giản.

    Các module gọi `bus.emit(event_type, data)` để phát sự kiện.
    Dashboard subscribe qua `bus.subscribe_async(queue)` để nhận.
    """

    def __init__(self, history_size=1000):
        self._subscribers = set()
        self._history = deque(maxlen=history_size)
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    # --------- Publish ---------
    def emit(self, event_type: str, data: dict = None, module: str = None):
        event = {
            "ts": datetime.now().isoformat(),
            "type": event_type,
            "module": module,
            "data": data or {},
        }
        self._history.append(event)

        # Không có subscriber -> thoát nhanh
        if not self._subscribers:
            return

        # Nếu đang trong event loop -> gửi async
        try:
            loop = asyncio.get_running_loop()
            for q in list(self._subscribers):
                loop.create_task(q.put(event))
        except RuntimeError:
            # Sync context -> dùng loop đã đăng ký nếu có
            if self._loop and not self._loop.is_closed():
                for q in list(self._subscribers):
                    self._loop.call_soon_threadsafe(q.put_nowait, event)

    # --------- Subscribe ---------
    def subscribe(self) -> asyncio.Queue:
        q = asyncio.Queue(maxsize=500)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        self._subscribers.discard(q)

    def set_loop(self, loop):
        self._loop = loop

    # --------- History ---------
    def history(self, limit=200):
        return list(self._history)[-limit:]


# Singleton
BUS = EventBus()