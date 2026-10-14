from typing import Union

from fastapi import Depends, FastAPI, HTTPException, Query, UploadFile, File, Form, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import bcrypt
import base64

from .config import DB_TYPE, DatabaseType
from .repository import UserRepository
from .repository_factory import close_connections, get_repository
from .auth_helper import (
    DISABLED_STATUSES,
    create_access_token,
    get_current_user,
    require_role,
)
from .schemas import (
    AuthResponse,
    LaundryCreate,
    LaundryResponse,
    LaundryStatusUpdate,
    LaundryUpdate,
    MembershipCreate,
    MembershipResponse,
    SwitchLaundryRequest,
    UserCreate,
    UserPasswordUpdate,
    UserResponse,
    UserStatusUpdate,
    UserUpdate,
)
from .tenancy import (
    LAUNDRY_ACTIVE,
    LOVE_LAUNDRY_ID,
    PLATFORM_ADMIN,
    TENANT_ADMIN,
    TENANT_ROLES,
    active_membership,
    build_tenant_claims,
    ensure_lovelaundry,
    get_laundry_repository,
    get_membership_repository,
    get_tenancy_stores,
    is_platform_admin_token,
    normalize_status,
    validate_laundry_id,
)
from .database.main_db import ensure_indexes
from .database.connection_manager import close_all
from .security import apply_security, insecure_flags
from .routers.admin_database import router as admin_database_router
from .services import synchronization_service


import logging
import os
import sentry_sdk

# Configure logging first
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Known production frontend origins. Used as a safe default so the API is never
# wide-open ("*") yet never fully locked down (which would break the live app if
# the ALLOWED_ORIGINS env var is not injected by the platform).
DEFAULT_ALLOWED_ORIGINS = [
    "https://lovelaundry-manager.vercel.app",
    "http://localhost:5173",
    "http://localhost:3000",
]

# CORS configuration - prefer the platform-provided allowlist; otherwise use the
# known-good production origins. Never fall back to "*".
try:
    ALLOWED_ORIGINS_ENV = os.getenv("ALLOWED_ORIGINS", "")
    # Always keep the known-good production origins in the allowlist, and never
    # accept a literal "*" (Starlette refuses "*" when credentials are enabled).
    # This way a missing or misconfigured ALLOWED_ORIGINS env can never lock out
    # the live frontend.
    configured = [
        o.strip()
        for o in ALLOWED_ORIGINS_ENV.split(",")
        if o.strip() and o.strip() != "*"
    ]
    ALLOWED_ORIGINS = list(dict.fromkeys(configured + list(DEFAULT_ALLOWED_ORIGINS)))
    ALLOW_CREDENTIALS = True

    logger.info(f"CORS configured with origins: {ALLOWED_ORIGINS}, credentials: {ALLOW_CREDENTIALS}")
except Exception as e:
    logger.warning(f"CORS configuration failed, using safe default: {e}")
    ALLOWED_ORIGINS = list(DEFAULT_ALLOWED_ORIGINS)
    ALLOW_CREDENTIALS = True

ON_VERCEL = os.getenv("VERCEL") == "1"

SENTRY_DSN = os.getenv("SENTRY_DSN")
if SENTRY_DSN:
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        traces_sample_rate=0.1,
    )

app = FastAPI(title="User Service", version="1.0.0")

apply_security(app, rate_limit=300)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception", exc_info=exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


app.include_router(admin_database_router)


@app.on_event("startup")
def startup_event():
    try:
        if DB_TYPE in (DatabaseType.POSTGRESQL, DatabaseType.SQLITE):
            from .database import Base, engine
            if engine:
                Base.metadata.create_all(bind=engine)
        else:
            ensure_indexes()
    except Exception:
        logger.exception("Failed to initialize database schema on startup")

    if not ON_VERCEL:
        try:
            synchronization_service.start_worker()
        except Exception:
            logger.exception("Failed to start sync worker")


@app.on_event("shutdown")
def shutdown_event():
    try:
        synchronization_service.stop_worker()
    except Exception:
        pass
    try:
        close_connections()
    except Exception:
        pass
    try:
        close_all()
    except Exception:
        pass


@app.get("/")
def root():
    return {
        "message": "User Service API",
        "version": "1.0.0",
        "database": DB_TYPE.value,
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "security": {
            "headers": True,
            "rate_limiting": True,
            "insecure_defaults": insecure_flags(),
        },
    }


# ── Auth routes (public) ────────────────────────────────────────────────────────

class LoginPayload(BaseModel):
    username: str
    password: str


# Statuses that block a sign-in. `unset` is the column default and `active` is
# the only enabled value, so this is a blocklist rather than an allowlist: an
# account that was never given a status must keep working.
# (Single source of truth lives in auth_helper.py so get_current_user enforces
# the same blocklist on every authed request.)


@app.post("/auth/login")
def login(
    payload: LoginPayload,
    repo: UserRepository = Depends(get_repository),
    stores: tuple | None = Depends(get_tenancy_stores),
):
    user = repo.get_by_auth_id(payload.username)
    if not user:
        try:
            user = repo.get_by_email(payload.username)
        except Exception:
            user = None

    if not user or "password" not in user:
        raise HTTPException(status_code=400, detail="Invalid username or password")

    pw_bytes = payload.password.encode("utf-8")
    hash_bytes = user["password"].encode("utf-8")

    try:
        if not bcrypt.checkpw(pw_bytes, hash_bytes):
            raise ValueError("Hash mismatch")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid username or password")

    role = str(user["role_id"]).upper()

    # An administrator can disable an account, but the flag was copied into the
    # token and never acted on — a disabled user kept full access until the
    # token expired. `unset` is the column default for accounts that were never
    # given a status, so only an explicit disabled value blocks a sign-in.
    status = str(user.get("status") or "unset").strip().lower()
    if status in DISABLED_STATUSES:
        raise HTTPException(
            status_code=403,
            detail="This account has been deactivated. Contact an administrator.",
        )

    token_data = {
        "user_id": user["id"],
        "auth_id": user["auth_id"],
        "user_name": user["user_name"],
        "role": role,
        "status": user["status"],
    }

    if role != PLATFORM_ADMIN:
        laundry_repo, membership_repo = _tenancy_stores_or_default(stores)
        claims = build_tenant_claims(user["auth_id"], membership_repo, laundry_repo)
        if not claims["laundries"]:
            existing_links = membership_repo.list_for_user(user["auth_id"])
            if existing_links:
                raise HTTPException(
                    status_code=403,
                    detail="No active laundry assignment. Contact an administrator.",
                )
        if claims["laundry_id"]:
            # The token role is the ACTIVE laundry role, so capability checks
            # downstream see what this session may actually do.
            active_entry = next(
                (entry for entry in claims["laundries"] if entry["id"] == claims["laundry_id"]),
                None,
            )
            if active_entry:
                role = active_entry["role"]
                token_data["role"] = role
        token_data["laundry_id"] = claims["laundry_id"]
        token_data["laundries"] = claims["laundries"]

    user_response = {k: v for k, v in user.items() if k != "password"}
    user_response["role_id"] = role
    if role != PLATFORM_ADMIN:
        user_response["laundry_id"] = token_data.get("laundry_id")
        user_response["laundries"] = token_data.get("laundries", [])
    else:
        token_data["platform_admin"] = True
        token_data["laundry_id"] = None
        token_data["laundries"] = []
        user_response["platform_admin"] = True

    token = create_access_token(token_data)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": user_response,
    }


class BootstrapPayload(BaseModel):
    auth_id: str = Field(min_length=3, max_length=64)
    user_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=8, max_length=128)
    email: str | None = None


@app.post("/auth/bootstrap", response_model=AuthResponse, status_code=201)
def bootstrap_first_admin(
    payload: BootstrapPayload,
    repo: UserRepository = Depends(get_repository),
    stores: tuple | None = Depends(get_tenancy_stores),
):
    """Create the first PLATFORM_ADMIN on a fresh database and sign them in.

    Also seeds the LoveLaundry registry entry, so the platform starts with
    its first tenant. Fail-closed: once any user exists the endpoint refuses
    (403), so it can never be used to escalate afterwards.
    """
    try:
        existing = repo.count()
    except Exception:
        raise HTTPException(status_code=503, detail="Database is unreachable — try again shortly")
    if existing > 0:
        raise HTTPException(status_code=403, detail="Bootstrap is disabled once users exist")
    if repo.exists_by_auth_id(payload.auth_id):
        raise HTTPException(status_code=400, detail="Auth ID already exists")
    if payload.email and repo.exists_by_email(payload.email):
        raise HTTPException(status_code=400, detail="Email already exists")

    try:
        user = repo.create(
            {
                "auth_id": payload.auth_id.strip(),
                "user_name": payload.user_name.strip(),
                "password": payload.password,
                "email": payload.email.strip() if payload.email else None,
                "role_id": PLATFORM_ADMIN,
                "status": "active",
            }
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=403, detail="Bootstrap is disabled once users exist")

    laundry_repo, _ = _tenancy_stores_or_default(stores)
    ensure_lovelaundry(laundry_repo, created_by=user["auth_id"])

    token_data = {
        "user_id": user["id"],
        "auth_id": user["auth_id"],
        "user_name": user["user_name"],
        "role": PLATFORM_ADMIN,
        "status": user.get("status"),
        "platform_admin": True,
        "laundry_id": None,
        "laundries": [],
    }
    user_response = {k: v for k, v in user.items() if k != "password"}
    user_response["role_id"] = PLATFORM_ADMIN
    user_response["platform_admin"] = True
    return {
        "access_token": create_access_token(token_data),
        "token_type": "bearer",
        "user": user_response,
    }


@app.get("/auth/status")
def auth_status(current_user: dict = Depends(get_current_user)):
    return current_user


# ── Laundry registry + memberships (multi-tenant identity) ───────────────────


def require_platform_admin(current_user: dict = Depends(get_current_user)):
    if not is_platform_admin_token(current_user):
        raise HTTPException(status_code=403, detail="Platform administrator access required")
    return current_user


def _laundry_or_404(laundry_repo, laundry_id: str):
    try:
        slug = validate_laundry_id(laundry_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    laundry = laundry_repo.get(slug)
    if not laundry:
        raise HTTPException(status_code=404, detail="Laundry not found")
    return laundry


def _require_laundry_admin_or_platform(current_user, laundry_id, membership_repo, laundry_repo):
    """PLATFORM_ADMIN, legacy unenrolled admins (transitional), or an active
    ADMIN member of an ACTIVE laundry."""
    if is_platform_admin_token(current_user):
        return PLATFORM_ADMIN
    caller_auth = current_user.get("auth_id") or ""
    if not _has_any_membership(caller_auth, membership_repo):
        return TENANT_ADMIN
    active = active_membership(caller_auth, laundry_id, membership_repo, laundry_repo)
    if not active or active["membership"].get("role") != TENANT_ADMIN:
        raise HTTPException(status_code=403, detail="Laundry administrator access required")
    return TENANT_ADMIN


@app.post("/laundries", response_model=LaundryResponse, status_code=201)
def create_laundry(
    payload: LaundryCreate,
    current_user: dict = Depends(require_platform_admin),
    stores: tuple | None = Depends(get_tenancy_stores),
):
    laundry_repo, _ = _tenancy_stores_or_default(stores)
    try:
        slug = validate_laundry_id(payload.laundry_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if laundry_repo.exists(slug):
        raise HTTPException(status_code=400, detail="laundry_id is already registered")
    if not (payload.name or "").strip():
        raise HTTPException(status_code=400, detail="Laundry name is required")
    try:
        created = laundry_repo.create({**payload.model_dump(), "created_by": current_user.get("auth_id")})
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        raise HTTPException(status_code=400, detail="laundry_id or BR number is already registered")
    logger.info(f"LAUNDRY_CREATE id={slug} by={current_user.get('auth_id')}")
    return created


@app.get("/laundries")
def list_laundries(
    search: str = "",
    status: str = "",
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(require_platform_admin),
    stores: tuple | None = Depends(get_tenancy_stores),
):
    laundry_repo, _ = _tenancy_stores_or_default(stores)
    try:
        items = laundry_repo.list(search=search, status=status, limit=limit, offset=offset)
        total = laundry_repo.count(search=search, status=status)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"items": items, "total": total}


@app.get("/laundries/{laundry_id}", response_model=LaundryResponse)
def get_laundry(
    laundry_id: str,
    current_user: dict = Depends(get_current_user),
    stores: tuple | None = Depends(get_tenancy_stores),
):
    laundry_repo, membership_repo = _tenancy_stores_or_default(stores)
    laundry = _laundry_or_404(laundry_repo, laundry_id)
    if is_platform_admin_token(current_user):
        return laundry
    active = active_membership(current_user.get("auth_id") or "", laundry["laundry_id"], membership_repo, laundry_repo)
    if not active:
        # Membership in a suspended laundry may still view its own registry row.
        member = membership_repo.get(current_user.get("auth_id") or "", laundry["laundry_id"])
        if not member:
            raise HTTPException(status_code=403, detail="Not a member of this laundry")
    return laundry


@app.put("/laundries/{laundry_id}", response_model=LaundryResponse)
def update_laundry(
    laundry_id: str,
    payload: LaundryUpdate,
    current_user: dict = Depends(require_platform_admin),
    stores: tuple | None = Depends(get_tenancy_stores),
):
    laundry_repo, _ = _tenancy_stores_or_default(stores)
    _laundry_or_404(laundry_repo, laundry_id)
    try:
        updated = laundry_repo.update(validate_laundry_id(laundry_id), payload.model_dump(exclude_unset=True))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not updated:
        raise HTTPException(status_code=404, detail="Laundry not found")
    logger.info(f"LAUNDRY_UPDATE id={laundry_id} by={current_user.get('auth_id')}")
    return updated


@app.post("/laundries/{laundry_id}/status", response_model=LaundryResponse)
def set_laundry_status(
    laundry_id: str,
    payload: LaundryStatusUpdate,
    current_user: dict = Depends(require_platform_admin),
    stores: tuple | None = Depends(get_tenancy_stores),
):
    laundry_repo, _ = _tenancy_stores_or_default(stores)
    current = _laundry_or_404(laundry_repo, laundry_id)
    try:
        target = normalize_status(payload.status)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not laundry_repo.set_status(current["laundry_id"], target):
        raise HTTPException(status_code=404, detail="Laundry not found")
    logger.info(
        f"LAUNDRY_STATUS id={current['laundry_id']} {current['status']}->{target} "
        f"by={current_user.get('auth_id')}"
    )
    updated = laundry_repo.get(current["laundry_id"])
    assert updated is not None
    return updated


@app.get("/laundries/{laundry_id}/members", response_model=list[MembershipResponse])
def list_laundry_members(
    laundry_id: str,
    current_user: dict = Depends(get_current_user),
    stores: tuple | None = Depends(get_tenancy_stores),
):
    laundry_repo, membership_repo = _tenancy_stores_or_default(stores)
    laundry = _laundry_or_404(laundry_repo, laundry_id)
    _require_laundry_admin_or_platform(current_user, laundry["laundry_id"], membership_repo, laundry_repo)
    return membership_repo.list_for_laundry(laundry["laundry_id"])


@app.post("/laundries/{laundry_id}/members", response_model=MembershipResponse, status_code=201)
def add_laundry_member(
    laundry_id: str,
    payload: MembershipCreate,
    current_user: dict = Depends(get_current_user),
    repo: UserRepository = Depends(get_repository),
    stores: tuple | None = Depends(get_tenancy_stores),
):
    laundry_repo, membership_repo = _tenancy_stores_or_default(stores)
    laundry = _laundry_or_404(laundry_repo, laundry_id)
    if laundry["status"] != LAUNDRY_ACTIVE:
        raise HTTPException(status_code=400, detail="Members can only be added to an ACTIVE laundry")
    _require_laundry_admin_or_platform(current_user, laundry["laundry_id"], membership_repo, laundry_repo)
    role = (payload.role or "").strip().upper()
    if role not in TENANT_ROLES:
        raise HTTPException(status_code=400, detail=f"role must be one of {', '.join(TENANT_ROLES)}")
    target = repo.get_by_auth_id((payload.auth_id or "").strip())
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if membership_repo.get(target["auth_id"], laundry["laundry_id"]):
        raise HTTPException(status_code=400, detail="User is already a member of this laundry")
    try:
        created = membership_repo.add(target["auth_id"], laundry["laundry_id"], role)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        raise HTTPException(status_code=400, detail="User is already a member of this laundry")
    logger.info(
        f"MEMBERSHIP_ADD laundry={laundry['laundry_id']} user={target['auth_id']} "
        f"role={role} by={current_user.get('auth_id')}"
    )
    return created


@app.delete("/laundries/{laundry_id}/members/{auth_id}")
def remove_laundry_member(
    laundry_id: str,
    auth_id: str,
    current_user: dict = Depends(get_current_user),
    stores: tuple | None = Depends(get_tenancy_stores),
):
    laundry_repo, membership_repo = _tenancy_stores_or_default(stores)
    laundry = _laundry_or_404(laundry_repo, laundry_id)
    _require_laundry_admin_or_platform(current_user, laundry["laundry_id"], membership_repo, laundry_repo)
    existing = membership_repo.get(auth_id, laundry["laundry_id"])
    if not existing:
        raise HTTPException(status_code=404, detail="Membership not found")
    if (auth_id or "") == (current_user.get("auth_id") or ""):
        raise HTTPException(
            status_code=400,
            detail="You cannot remove your own membership — ask another administrator",
        )
    if existing.get("role") == TENANT_ADMIN:
        remaining_admins = [
            m for m in membership_repo.list_for_laundry(laundry["laundry_id"])
            if m.get("role") == TENANT_ADMIN
            and (m.get("status") or "").strip().lower() == "active"
            and m.get("auth_id") != existing.get("auth_id")
        ]
        if not remaining_admins:
            raise HTTPException(status_code=400, detail="Cannot remove the last administrator of a laundry")
    membership_repo.remove(auth_id, laundry["laundry_id"])
    logger.info(
        f"MEMBERSHIP_REMOVE laundry={laundry['laundry_id']} user={auth_id} by={current_user.get('auth_id')}"
    )
    return {"removed": True}


@app.post("/auth/laundry", response_model=AuthResponse)
def switch_laundry(
    payload: SwitchLaundryRequest,
    current_user: dict = Depends(get_current_user),
    repo: UserRepository = Depends(get_repository),
    stores: tuple | None = Depends(get_tenancy_stores),
):
    """Mint a token scoped to another authorized laundry (revalidates live)."""
    if is_platform_admin_token(current_user):
        raise HTTPException(status_code=400, detail="Platform administrators use laundry entry instead")
    laundry_repo, membership_repo = _tenancy_stores_or_default(stores)
    try:
        slug = validate_laundry_id(payload.laundry_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    resolved = active_membership(current_user.get("auth_id") or "", slug, membership_repo, laundry_repo)
    if not resolved:
        raise HTTPException(status_code=403, detail="No active assignment in that laundry")
    user = repo.get_by_auth_id(current_user.get("auth_id") or "")
    if not user:
        raise HTTPException(status_code=401, detail="Account no longer exists")
    claims = build_tenant_claims(user["auth_id"], membership_repo, laundry_repo)
    token_data = {
        "user_id": user["id"],
        "auth_id": user["auth_id"],
        "user_name": user["user_name"],
        "role": resolved["membership"].get("role"),
        "status": user.get("status"),
        "laundry_id": slug,
        "laundries": claims["laundries"],
    }
    user_response = {k: v for k, v in user.items() if k != "password"}
    user_response["role_id"] = resolved["membership"].get("role")
    user_response["laundry_id"] = slug
    user_response["laundries"] = claims["laundries"]
    logger.info(f"LAUNDRY_SWITCH user={user['auth_id']} laundry={slug}")
    return {
        "access_token": create_access_token(token_data),
        "token_type": "bearer",
        "user": user_response,
    }


@app.post("/laundries/{laundry_id}/enter", response_model=AuthResponse)
def enter_laundry(
    laundry_id: str,
    current_user: dict = Depends(require_platform_admin),
    repo: UserRepository = Depends(get_repository),
    stores: tuple | None = Depends(get_tenancy_stores),
):
    """Explicit audited support entry into a laundry (1-hour token)."""
    laundry_repo, membership_repo = _tenancy_stores_or_default(stores)
    laundry = _laundry_or_404(laundry_repo, laundry_id)
    if laundry["status"] != LAUNDRY_ACTIVE:
        logger.info(
            f"SUPPORT_ENTRY laundry={laundry['laundry_id']} status={laundry['status']} "
            f"by={current_user.get('auth_id')}"
        )
    user = repo.get_by_auth_id(current_user.get("auth_id") or "")
    if not user:
        raise HTTPException(status_code=401, detail="Account no longer exists")
    claims = build_tenant_claims(user["auth_id"], membership_repo, laundry_repo)
    token_data = {
        "user_id": user["id"],
        "auth_id": user["auth_id"],
        "user_name": user["user_name"],
        "role": PLATFORM_ADMIN,
        "status": user.get("status"),
        "platform_admin": True,
        "laundry_id": laundry["laundry_id"],
        "laundries": claims["laundries"],
        "support_entry": True,
    }
    user_response = {k: v for k, v in user.items() if k != "password"}
    user_response["role_id"] = PLATFORM_ADMIN
    user_response["platform_admin"] = True
    user_response["laundry_id"] = laundry["laundry_id"]
    user_response["laundries"] = claims["laundries"]
    logger.info(
        f"SUPPORT_ENTRY_GRANT laundry={laundry['laundry_id']} by={current_user.get('auth_id')}"
    )
    return {
        "access_token": create_access_token(token_data, expires_in_hours=1),
        "token_type": "bearer",
        "user": user_response,
    }


# ── User routes (admin only) ─────────────────────────────────────────────────────
# IMPORTANT: Static paths MUST come before wildcard {user_id} paths.
#
# Tenant rule: platform administrators see every account; laundry admins see
# only accounts sharing an ACTIVE laundry with them (checked per record, so
# identifier guessing across laundries returns 404, never another tenant's
# user). Creation by a laundry admin also enrolls the new account in the
# caller's active laundry.


def _caller_active_laundries(caller_auth_id: str, membership_repo, laundry_repo) -> set:
    """Laundry ids where the caller holds an operable (active/active) seat."""
    operable = set()
    for membership in membership_repo.list_for_user(caller_auth_id or ""):
        if (membership.get("status") or "").strip().lower() != "active":
            continue
        laundry = laundry_repo.get(membership.get("laundry_id") or "")
        if laundry and laundry.get("status") == LAUNDRY_ACTIVE:
            operable.add(laundry.get("laundry_id"))
    return operable


def _has_any_membership(caller_auth_id: str, membership_repo) -> bool:
    """Transitional rule: accounts enrolled nowhere keep legacy global access.

    Pre-tenancy administrators have no memberships; blocking them would lock
    every existing admin out the moment the first laundry is registered.
    Enrolling them (memberships) moves them under tenant scoping. New
    accounts always enroll at creation, so this shrinks to nothing.
    """
    return len(membership_repo.list_for_user(caller_auth_id or "")) > 0


def _require_same_laundry(caller, target_auth_id, membership_repo, laundry_repo):
    if is_platform_admin_token(caller):
        return
    caller_auth = caller.get("auth_id") or ""
    if caller_auth and caller_auth == (target_auth_id or ""):
        return
    if not _has_any_membership(caller_auth, membership_repo):
        return
    caller_laundries = _caller_active_laundries(caller_auth, membership_repo, laundry_repo)
    target_laundries = _caller_active_laundries(target_auth_id or "", membership_repo, laundry_repo)
    if not (caller_laundries & target_laundries):
        raise HTTPException(status_code=404, detail="User not found")


def _resolve_user_id(user_id: Union[int, str]):
    if DB_TYPE == DatabaseType.MONGODB:
        return str(user_id)
    return int(user_id)


def _load_visible_user(repo, membership_repo, laundry_repo, caller, *, user_id=None, auth_id=None, email=None, employee_id=None):
    """Fetch a user document with same-laundry visibility enforced.

    Lives outside any route so the response-model safety net keeps checking
    the endpoints themselves: every caller here returns through a declared
    UserResponse model.
    """
    if auth_id is not None:
        user = repo.get_by_auth_id(auth_id)
    elif email is not None:
        user = repo.get_by_email(email)
    elif employee_id is not None:
        user = repo.get_by_employee_id(employee_id)
    else:
        user = repo.get_by_id(_resolve_user_id(user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    _require_same_laundry(caller, user.get("auth_id"), membership_repo, laundry_repo)
    return user


def _load_visible_users(repo, membership_repo, laundry_repo, caller):
    """All user documents the caller may administer (platform: everyone)."""
    if is_platform_admin_token(caller):
        return repo.get_all()
    visible = []
    for user in repo.get_all():
        try:
            _require_same_laundry(caller, user.get("auth_id"), membership_repo, laundry_repo)
            visible.append(user)
        except HTTPException:
            continue
    return visible


def _tenancy_stores_or_default(stores):
    # Direct invocations (tests, scripts) bypass Depends: the parameter then
    # holds the Depends default instead of the resolved (repo, repo) tuple.
    if not isinstance(stores, tuple):
        return get_laundry_repository(), get_membership_repository()
    return stores


@app.get("/users", response_model=list[UserResponse], dependencies=[Depends(require_role(["ADMIN"]))])
def get_all_users(
    repo: UserRepository = Depends(get_repository),
    current_user: dict = Depends(get_current_user),
    stores: tuple | None = Depends(get_tenancy_stores),
):
    laundry_repo, membership_repo = _tenancy_stores_or_default(stores)
    return _load_visible_users(repo, membership_repo, laundry_repo, current_user)


@app.get("/users/count", dependencies=[Depends(require_role(["ADMIN"]))])
def count_users(
    repo: UserRepository = Depends(get_repository),
    current_user: dict = Depends(get_current_user),
    stores: tuple | None = Depends(get_tenancy_stores),
):
    laundry_repo, membership_repo = _tenancy_stores_or_default(stores)
    return {"count": len(_load_visible_users(repo, membership_repo, laundry_repo, current_user))}


@app.get("/users/auth/{auth_id}", response_model=UserResponse, dependencies=[Depends(require_role(["ADMIN"]))])
def get_user_by_auth_id(
    auth_id: str,
    repo: UserRepository = Depends(get_repository),
    current_user: dict = Depends(get_current_user),
    stores: tuple | None = Depends(get_tenancy_stores),
):
    laundry_repo, membership_repo = _tenancy_stores_or_default(stores)
    return _load_visible_user(
        repo, membership_repo, laundry_repo, current_user, auth_id=auth_id
    )


@app.get("/users/email/{email}", response_model=UserResponse, dependencies=[Depends(require_role(["ADMIN"]))])
def get_user_by_email(
    email: str,
    repo: UserRepository = Depends(get_repository),
    current_user: dict = Depends(get_current_user),
    stores: tuple | None = Depends(get_tenancy_stores),
):
    laundry_repo, membership_repo = _tenancy_stores_or_default(stores)
    return _load_visible_user(
        repo, membership_repo, laundry_repo, current_user, email=email
    )


@app.get("/users/employee/{employee_id}", response_model=UserResponse, dependencies=[Depends(require_role(["ADMIN"]))])
def get_user_by_employee_id(
    employee_id: str,
    repo: UserRepository = Depends(get_repository),
    current_user: dict = Depends(get_current_user),
    stores: tuple | None = Depends(get_tenancy_stores),
):
    laundry_repo, membership_repo = _tenancy_stores_or_default(stores)
    return _load_visible_user(
        repo, membership_repo, laundry_repo, current_user, employee_id=employee_id
    )


@app.get("/users/{user_id}", response_model=UserResponse, dependencies=[Depends(require_role(["ADMIN"]))])
def get_user(
    user_id: Union[int, str],
    repo: UserRepository = Depends(get_repository),
    current_user: dict = Depends(get_current_user),
    stores: tuple | None = Depends(get_tenancy_stores),
):
    laundry_repo, membership_repo = _tenancy_stores_or_default(stores)
    return _load_visible_user(
        repo, membership_repo, laundry_repo, current_user, user_id=user_id
    )


@app.post("/users", response_model=UserResponse, status_code=201, dependencies=[Depends(require_role(["ADMIN"]))])
def create_user(
    payload: UserCreate,
    repo: UserRepository = Depends(get_repository),
    current_user: dict = Depends(get_current_user),
    stores: tuple | None = Depends(get_tenancy_stores),
):
    if repo.exists_by_auth_id(payload.auth_id):
        raise HTTPException(status_code=400, detail="Auth ID already exists")

    if payload.email and repo.exists_by_email(payload.email):
        raise HTTPException(status_code=400, detail="Email already exists")

    if payload.employee_id and repo.exists_by_employee_id(payload.employee_id):
        raise HTTPException(status_code=400, detail="Employee ID already exists")

    new_role = (payload.role_id or "").strip().upper()
    if new_role == PLATFORM_ADMIN and not is_platform_admin_token(current_user):
        raise HTTPException(status_code=400, detail="Only a platform administrator can create platform administrators")

    data = payload.model_dump()
    data.pop("laundry_id", None)
    created = repo.create(data)

    laundry_repo, membership_repo = _tenancy_stores_or_default(stores)
    if is_platform_admin_token(current_user):
        # Platform provisioning may enroll the account immediately.
        if payload.laundry_id:
            try:
                target = validate_laundry_id(payload.laundry_id)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            laundry = laundry_repo.get(target)
            if not laundry:
                raise HTTPException(status_code=404, detail="Laundry not found")
            if laundry["status"] != LAUNDRY_ACTIVE:
                raise HTTPException(status_code=400, detail="Members can only be added to an ACTIVE laundry")
            if new_role not in TENANT_ROLES:
                raise HTTPException(status_code=400, detail=f"role must be one of {', '.join(TENANT_ROLES)}")
            membership_repo.add(created["auth_id"], target, new_role)
    else:
        # Laundry admins enroll staff into their own ACTIVE laundry only, and
        # never mint platform administrators. Legacy admins without any
        # membership keep legacy behavior (no enrollment) until migrated.
        if new_role not in TENANT_ROLES:
            raise HTTPException(status_code=400, detail=f"role must be one of {', '.join(TENANT_ROLES)}")
        if not _has_any_membership(current_user.get("auth_id") or "", membership_repo):
            if payload.laundry_id:
                try:
                    target = validate_laundry_id(payload.laundry_id)
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=str(e))
                laundry = laundry_repo.get(target)
                if not laundry:
                    raise HTTPException(status_code=404, detail="Laundry not found")
                if laundry["status"] == LAUNDRY_ACTIVE:
                    membership_repo.add(created["auth_id"], target, new_role)
            return created
        token_laundry = current_user.get("laundry_id")
        if not token_laundry:
            raise HTTPException(status_code=400, detail="Switch to a laundry before creating accounts")
        resolved = active_membership(
            current_user.get("auth_id") or "", token_laundry, membership_repo, laundry_repo
        )
        if not resolved or resolved["membership"].get("role") != TENANT_ADMIN:
            raise HTTPException(status_code=403, detail="Laundry administrator access required")
        membership_repo.add(created["auth_id"], token_laundry, new_role)

    return created


@app.put("/users/{user_id}", response_model=UserResponse, dependencies=[Depends(require_role(["ADMIN"]))])
def update_user(
    user_id: Union[int, str],
    payload: UserUpdate,
    repo: UserRepository = Depends(get_repository),
    current_user: dict = Depends(get_current_user),
    stores: tuple | None = Depends(get_tenancy_stores),
):
    if DB_TYPE == DatabaseType.MONGODB:
        user_id = str(user_id)
    else:
        user_id = int(user_id)

    laundry_repo, membership_repo = _tenancy_stores_or_default(stores)
    _load_visible_user(
        repo, membership_repo, laundry_repo, current_user, user_id=user_id
    )

    user = repo.update(user_id, payload.model_dump(exclude_unset=True))

    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.patch("/users/{user_id}/profile", response_model=UserResponse)
async def update_profile(
    user_id: Union[int, str],
    current_user: dict = Depends(get_current_user),
    repo: UserRepository = Depends(get_repository),
    stores: tuple | None = Depends(get_tenancy_stores),
    user_name: str | None = Form(None),
    bio_data: str | None = Form(None),
    email: str | None = Form(None),
    mobile_number: str | None = Form(None),
    user_dp: str | None = Form(None),
    avatar: UploadFile | None = File(None),
):
    if DB_TYPE == DatabaseType.MONGODB:
        resolved_user_id = str(user_id)
    else:
        resolved_user_id = int(user_id)

    # Only the account owner, a laundry ADMIN sharing the account's laundry,
    # or a platform administrator may update this profile.
    token_uid = str(current_user.get("user_id"))
    is_owner = token_uid == str(user_id)
    if not (
        is_owner
        or is_platform_admin_token(current_user)
        or str(current_user.get("role", "")).upper() == "ADMIN"
    ):
        raise HTTPException(status_code=403, detail="Not authorized to update this profile")

    laundry_repo, membership_repo = _tenancy_stores_or_default(stores)
    user = _load_visible_user(
        repo, membership_repo, laundry_repo, current_user, user_id=resolved_user_id
    )

    update_data = {}

    if user_name is not None and user_name.strip():
        update_data["user_name"] = user_name.strip()
    if bio_data is not None:
        update_data["bio_data"] = bio_data
    if email is not None:
        email_value = email.strip() or None
        if email_value and email_value.lower() != (user.get("email") or "").lower():
            if repo.exists_by_email(email_value):
                raise HTTPException(status_code=400, detail="Email already exists")
        update_data["email"] = email_value
    if mobile_number is not None:
        update_data["mobile_number"] = mobile_number.strip() or None
    if user_dp is not None:
        update_data["user_dp"] = user_dp

    if avatar is not None and avatar.filename:
        content = await avatar.read()
        if len(content) > 5 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="Image too large (max 5MB)")
        if not (avatar.content_type or "").startswith("image/"):
            raise HTTPException(status_code=400, detail="Please select an image file")
        avatar_b64 = base64.b64encode(content).decode("utf-8")
        update_data["user_dp"] = f"data:{avatar.content_type};base64,{avatar_b64}"

    if not update_data:
        raise HTTPException(status_code=400, detail="No profile fields to update")

    updated_user = repo.update(resolved_user_id, update_data)
    if not updated_user:
        raise HTTPException(status_code=404, detail="User not found")

    return updated_user


@app.patch("/users/{user_id}/password", dependencies=[Depends(require_role(["ADMIN"]))])
def update_password(
    user_id: Union[int, str],
    payload: UserPasswordUpdate,
    repo: UserRepository = Depends(get_repository),
    current_user: dict = Depends(get_current_user),
    stores: tuple | None = Depends(get_tenancy_stores),
):
    if DB_TYPE == DatabaseType.MONGODB:
        user_id = str(user_id)
    else:
        user_id = int(user_id)

    laundry_repo, membership_repo = _tenancy_stores_or_default(stores)
    _load_visible_user(
        repo, membership_repo, laundry_repo, current_user, user_id=user_id
    )

    if not repo.update_password(user_id, payload.password):
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "Password updated successfully"}


@app.patch("/users/{user_id}/status", dependencies=[Depends(require_role(["ADMIN"]))])
def update_status(
    user_id: Union[int, str],
    payload: UserStatusUpdate,
    repo: UserRepository = Depends(get_repository),
    current_user: dict = Depends(get_current_user),
    stores: tuple | None = Depends(get_tenancy_stores),
):
    if DB_TYPE == DatabaseType.MONGODB:
        user_id = str(user_id)
    else:
        user_id = int(user_id)

    laundry_repo, membership_repo = _tenancy_stores_or_default(stores)
    _load_visible_user(
        repo, membership_repo, laundry_repo, current_user, user_id=user_id
    )

    if not repo.update_status(user_id, payload.status):
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "Status updated successfully"}


@app.delete("/users/{user_id}", dependencies=[Depends(require_role(["ADMIN"]))])
def delete_user(
    user_id: Union[int, str],
    repo: UserRepository = Depends(get_repository),
    current_user: dict = Depends(get_current_user),
    stores: tuple | None = Depends(get_tenancy_stores),
):
    if DB_TYPE == DatabaseType.MONGODB:
        user_id = str(user_id)
    else:
        user_id = int(user_id)

    laundry_repo, membership_repo = _tenancy_stores_or_default(stores)
    _load_visible_user(
        repo, membership_repo, laundry_repo, current_user, user_id=user_id
    )

    if not repo.delete(user_id):
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User deleted successfully"}