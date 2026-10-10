"""Async recon: subdomain bruteforce + TCP port scan nhanh gấp 20-50×."""
import asyncio
import socket
from core.logger import get_logger

LOG = get_logger("ceh.async")


async def _resolve(host):
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, family=socket.AF_INET)
        return host, infos[0][4][0]
    except Exception:
        return None


async def subdomain_bruteforce_async(domain, wordlist, concurrency=200):
    """Bruteforce subdomain song song bằng asyncio."""
    sem = asyncio.Semaphore(concurrency)
    results = []

    async def probe(sub):
        host = f"{sub}.{domain}"
        async with sem:
            r = await _resolve(host)
            if r:
                results.append({"host": r[0], "ip": r[1]})
                LOG.info(f"[async] -> {r[0]} ({r[1]})")

    await asyncio.gather(*(probe(s) for s in wordlist))
    return results


async def tcp_port_scan_async(host, ports, concurrency=500, timeout=2.0):
    """Quét TCP connect async (không cần root)."""
    sem = asyncio.Semaphore(concurrency)
    open_ports = []

    async def probe(port):
        async with sem:
            try:
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=timeout)
                open_ports.append(port)
                LOG.info(f"[async] port {port} MỞ")
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            except Exception:
                pass

    await asyncio.gather(*(probe(p) for p in ports))
    return sorted(open_ports)


def run_async(coro):
    """Wrapper chạy coroutine từ code sync."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        # Đang trong loop khác -> tạo task mới
        return asyncio.ensure_future(coro)
    return asyncio.run(coro)