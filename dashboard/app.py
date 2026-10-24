"""Web dashboard real-time cho CEH Toolkit."""
import asyncio
import json
import threading
import pydantic.main
from typing import Union, Set, Dict, Any
if not hasattr(pydantic.main, 'IncEx'):
    pydantic.main.IncEx = Union[Set[int], Set[str], Dict[int, Any], Dict[str, Any]]
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from core.events import BUS
from core.orchestrator import Orchestrator
from core.profiles import get_profile, list_profiles
from core.logger import get_logger

LOG = get_logger("ceh.dashboard")
app = FastAPI(title="CEH Toolkit Dashboard")

TEMPLATE_DIR = Path(__file__).parent / "templates"


class ScanRequest(BaseModel):
    target: str
    profile: str = "normal"
    modules: list[str] | None = None
    chain: bool = False


# --------- REST API ---------
@app.get("/api/profiles")
def api_profiles():
    return {"profiles": list_profiles()}


@app.post("/api/scan")
async def api_scan(req: ScanRequest):
    """Chạy scan trong background, kết quả được stream qua WebSocket."""
    def _job():
        try:
            cfg = get_profile(req.profile)
            modules = req.modules or cfg.get("enabled_modules", [])
            orch = Orchestrator(req.target, cfg,
                                parallel=not req.chain,
                                chain=req.chain)
            results = orch.run(modules)

            from modules import report
            json_path, html_path = report.save_reports(
                req.target, results,
                cfg.get("general", {}).get("output_dir", "./output"))
            BUS.emit("report_ready", {
                "json": json_path,
                "html": html_path,
            })
        except Exception as e:
            LOG.error(f"Scan job lỗi: {e}")
            BUS.emit("scan_error", {"error": str(e)})

    threading.Thread(target=_job, daemon=True).start()
    return {"status": "started", "target": req.target, "profile": req.profile}


@app.get("/api/history")
def api_history(limit: int = 200):
    return {"events": BUS.history(limit)}


# --------- WebSocket stream ---------
@app.websocket("/ws")
async def ws_stream(ws: WebSocket):
    await ws.accept()
    BUS.set_loop(asyncio.get_running_loop())
    q = BUS.subscribe()

    # Gửi history gần đây khi vừa kết nối
    for evt in BUS.history(50):
        await ws.send_json(evt)

    try:
        while True:
            event = await q.get()
            await ws.send_json(event)
    except WebSocketDisconnect:
        pass
    finally:
        BUS.unsubscribe(q)


# --------- HTML UI ---------
@app.get("/", response_class=HTMLResponse)
def index():
    return (TEMPLATE_DIR / "index.html").read_text(encoding="utf-8")