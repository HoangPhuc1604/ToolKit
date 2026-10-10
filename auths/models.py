"""Multi-tenant models - Workspace, User, Role, Permission."""
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


class Role(str, Enum):
    """Role hierarchy: OWNER > ADMIN > ANALYST > VIEWER."""
    OWNER = "owner"       # full control, billing, delete workspace
    ADMIN = "admin"       # manage members, all scans
    ANALYST = "analyst"   # create/run scans, view own + team findings
    VIEWER = "viewer"     # read-only


ROLE_HIERARCHY = {
    Role.OWNER:  4,
    Role.ADMIN:  3,
    Role.ANALYST: 2,
    Role.VIEWER: 1,
}


class Permission(str, Enum):
    SCAN_CREATE = "scan:create"
    SCAN_READ = "scan:read"
    SCAN_DELETE = "scan:delete"
    FINDING_READ = "finding:read"
    FINDING_UPDATE = "finding:update"
    REPORT_EXPORT = "report:export"
    MEMBER_INVITE = "member:invite"
    MEMBER_REMOVE = "member:remove"
    WORKSPACE_UPDATE = "workspace:update"
    WORKSPACE_DELETE = "workspace:delete"
    BILLING_READ = "billing:read"


# Ma trận quyền theo role (kế thừa: role cao có toàn bộ quyền của role thấp)
ROLE_PERMISSIONS = {
    Role.VIEWER: {
        Permission.SCAN_READ, Permission.FINDING_READ,
    },
    Role.ANALYST: {
        Permission.SCAN_CREATE, Permission.REPORT_EXPORT,
    },
    Role.ADMIN: {
        Permission.SCAN_DELETE, Permission.FINDING_UPDATE,
        Permission.MEMBER_INVITE, Permission.MEMBER_REMOVE,
        Permission.WORKSPACE_UPDATE,
    },
    Role.OWNER: {
        Permission.WORKSPACE_DELETE, Permission.BILLING_READ,
    },
}


def effective_permissions(role: Role) -> set:
    """Trả về tập quyền đầy đủ của role (bao gồm kế thừa)."""
    perms = set()
    current_level = ROLE_HIERARCHY[role]
    for r, level in ROLE_HIERARCHY.items():
        if level <= current_level:
            perms |= ROLE_PERMISSIONS.get(r, set())
    return perms


def has_permission(role: Role, perm: Permission) -> bool:
    return perm in effective_permissions(role)


@dataclass
class Workspace:
    id: str
    name: str
    plan: str = "free"          # free | pro | enterprise
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    settings: dict = field(default_factory=dict)


@dataclass
class User:
    id: str
    email: str
    workspace_id: str
    role: Role
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_login: Optional[str] = None


@dataclass
class ScanRecord:
    """Mọi scan gắn workspace_id để đảm bảo isolation."""
    id: str
    workspace_id: str
    user_id: str
    target: str
    modules: list
    profile: str
    status: str = "pending"     # pending | running | completed | failed
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    results: dict = field(default_factory=dict)