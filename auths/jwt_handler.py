"""JWT handler - issue/verify token có tenant claim."""
import os
import hmac
import hashlib
import base64
import json
import time
from typing import Optional
from auth.models import Role


JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-in-prod")
JWT_ALGO = "HS256"
JWT_TTL = 3600  # 1 giờ


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def issue_token(user_id: str, workspace_id: str, role: Role,
                email: str = "") -> str:
    header = {"alg": JWT_ALGO, "typ": "JWT"}
    payload = {
        "sub": user_id,
        "email": email,
        "workspace_id": workspace_id,
        "role": role.value,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_TTL,
    }
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig_input = f"{h}.{p}".encode()
    sig = hmac.new(JWT_SECRET.encode(), sig_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


def verify_token(token: str) -> Optional[dict]:
    """Trả về payload nếu hợp lệ, None nếu không."""
    try:
        h, p, s = token.split(".")
        sig_input = f"{h}.{p}".encode()
        expected = hmac.new(JWT_SECRET.encode(), sig_input,
                            hashlib.sha256).digest()
        if not hmac.compare_digest(_b64url_decode(s), expected):
            return None
        payload = json.loads(_b64url_decode(p))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


def extract_tenant_context(token: str) -> Optional[dict]:
    """Trả về {user_id, workspace_id, role} từ token."""
    payload = verify_token(token)
    if not payload:
        return None
    return {
        "user_id": payload["sub"],
        "email": payload.get("email", ""),
        "workspace_id": payload["workspace_id"],
        "role": Role(payload["role"]),
    }