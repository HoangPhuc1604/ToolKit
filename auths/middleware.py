"""FastAPI middleware - trích xuất tenant context từ JWT."""
from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from auth.jwt_handler import extract_tenant_context
from auth.models import Permission, has_permission

security = HTTPBearer(auto_error=False)


async def get_tenant_context(
    request: Request,
    creds: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    """Dependency inject tenant context vào route handler."""
    if not creds:
        raise HTTPException(401, "Thiếu Authorization header")
    ctx = extract_tenant_context(creds.credentials)
    if not ctx:
        raise HTTPException(401, "Token không hợp lệ hoặc hết hạn")
    # Gắn vào request state để logging/audit
    request.state.workspace_id = ctx["workspace_id"]
    request.state.user_id = ctx["user_id"]
    request.state.role = ctx["role"]
    return ctx


def require_permission(perm: Permission):
    """Decorator factory: yêu cầu permission cụ thể."""
    async def _checker(ctx: dict = Depends(get_tenant_context)):
        if not has_permission(ctx["role"], perm):
            raise HTTPException(
                403,
                f"Role '{ctx['role'].value}' không có quyền '{perm.value}'",
            )
        return ctx
    return _checker


def tenant_filter(workspace_id: str):
    """Helper trả về dict filter để áp vào query."""
    return {"workspace_id": workspace_id}