from typing import Union

from fastapi import Depends, FastAPI, HTTPException, UploadFile, File, Form, Request
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
    UserCreate,
    UserPasswordUpdate,
    UserResponse,
    UserStatusUpdate,
    UserUpdate,
)
from .memberships import (
    ACTIVE,
    VALID_STATUSES,
    build_claims,
    effective_memberships,
    grant,
    normalize_laundry_id,
    revoke,
    stored_memberships,
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

    "https://system-lovelaundry-lk.vercel.app",
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


from .routers.laundries import router as laundries_router  # noqa: E402
app.include_router(laundries_router)
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
    # Optional: sign straight into a laundry the user is an ACTIVE member of.
    # Omitted -> the single active membership, if there is exactly one.
    laundry_id: str | None = None


# Sign-in status gate. The authoritative blocklist lives in auth_helper.py
# (DISABLED_STATUSES) and is enforced on every authenticated request; it is
# reused here so login and token verification cannot drift apart.

# A valid bcrypt hash of a random value. Verifying against it keeps the
# response time for an unknown username indistinguishable from a wrong
# password, so the endpoint cannot be used to enumerate accounts.
_DUMMY_PASSWORD_HASH = bcrypt.hashpw(b"timing-equalizer", bcrypt.gensalt()).decode("utf-8")


def _is_blocked(user: dict) -> bool:
    return str(user.get("status") or "unset").strip().lower() in DISABLED_STATUSES


@app.post("/auth/login")
def login(payload: LoginPayload, repo: UserRepository = Depends(get_repository)):
    user = repo.get_by_auth_id(payload.username)
    if not user:
        try:
            user = repo.get_by_email(payload.username)
        except Exception:
            user = None

    if not user or "password" not in user:
        # Still burn a bcrypt verification so timing does not reveal existence.
        try:
            bcrypt.checkpw(payload.password.encode("utf-8"), _DUMMY_PASSWORD_HASH.encode("utf-8"))
        except ValueError:
            pass
        raise HTTPException(status_code=400, detail="Invalid username or password")

    pw_bytes = payload.password.encode("utf-8")
    hash_bytes = user["password"].encode("utf-8")

    try:
        if not bcrypt.checkpw(pw_bytes, hash_bytes):
            raise ValueError("Hash mismatch")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid username or password")

    if _is_blocked(user):
        raise HTTPException(
            status_code=403,
            detail="This account is inactive. Contact an administrator.",
        )

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
        "platform_admin": bool(user.get("platform_admin")),
        # Tenant claims every resource service trusts. Built in one place so
        # login, bootstrap and switching cannot drift.
        **build_claims(user, payload.laundry_id),
    }

    user_response = {k: v for k, v in user.items() if k != "password"}
    user_response["laundries"] = effective_memberships(user)
    user_response["role_id"] = role
    user_response["platform_admin"] = bool(user.get("platform_admin"))

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
def bootstrap_first_admin(payload: BootstrapPayload, repo: UserRepository = Depends(get_repository)):
    """Create the first ADMIN on a fresh database and sign them in.

    Fail-closed: once any user exists the endpoint refuses (403), so it can
    never be used to escalate afterwards. Without this, a fresh database is
    a deadlock — every user route requires ADMIN, so no account could ever
    be created and nobody could log in.
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
                "role_id": "ADMIN",
                "status": "active",
                # The first account owns the platform: only a platform
                # administrator may register or enter other laundries.
                "platform_admin": True,
            }
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=403, detail="Bootstrap is disabled once users exist")

    token_data = {
        "user_id": user["id"],
        "auth_id": user["auth_id"],
        "user_name": user["user_name"],
        "role": "ADMIN",
        "status": user.get("status"),
        "platform_admin": True,
        **build_claims(user),
    }
    user_response = {k: v for k, v in user.items() if k != "password"}
    user_response["role_id"] = "ADMIN"
    user_response["laundries"] = effective_memberships(user)
    user_response["platform_admin"] = True
    return {
        "access_token": create_access_token(token_data),
        "token_type": "bearer",
        "user": user_response,
    }


@app.get("/auth/status")
def auth_status(current_user: dict = Depends(get_current_user)):
    return current_user


# ── User routes (admin only) ─────────────────────────────────────────────────────
# IMPORTANT: Static paths MUST come before wildcard {user_id} paths.

@app.get("/users", response_model=list[UserResponse], dependencies=[Depends(require_role(["ADMIN"]))])
def get_all_users(repo: UserRepository = Depends(get_repository)):
    return repo.get_all()


@app.get("/users/count", dependencies=[Depends(require_role(["ADMIN"]))])
def count_users(repo: UserRepository = Depends(get_repository)):
    return {"count": repo.count()}


@app.get("/users/auth/{auth_id}", response_model=UserResponse, dependencies=[Depends(require_role(["ADMIN"]))])
def get_user_by_auth_id(
    auth_id: str,
    repo: UserRepository = Depends(get_repository),
):
    user = repo.get_by_auth_id(auth_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.get("/users/email/{email}", response_model=UserResponse, dependencies=[Depends(require_role(["ADMIN"]))])
def get_user_by_email(
    email: str,
    repo: UserRepository = Depends(get_repository),
):
    user = repo.get_by_email(email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.get("/users/employee/{employee_id}", response_model=UserResponse, dependencies=[Depends(require_role(["ADMIN"]))])
def get_user_by_employee_id(
    employee_id: str,
    repo: UserRepository = Depends(get_repository),
):
    user = repo.get_by_employee_id(employee_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.get("/users/{user_id}", response_model=UserResponse, dependencies=[Depends(require_role(["ADMIN"]))])
def get_user(
    user_id: Union[int, str],
    repo: UserRepository = Depends(get_repository),
):
    if DB_TYPE == DatabaseType.MONGODB:
        user = repo.get_by_id(str(user_id))
    else:
        user = repo.get_by_id(int(user_id))

    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.post("/users", response_model=UserResponse, status_code=201, dependencies=[Depends(require_role(["ADMIN"]))])
def create_user(
    payload: UserCreate,
    repo: UserRepository = Depends(get_repository),
):
    if repo.exists_by_auth_id(payload.auth_id):
        raise HTTPException(status_code=400, detail="Auth ID already exists")

    if payload.email and repo.exists_by_email(payload.email):
        raise HTTPException(status_code=400, detail="Email already exists")

    if payload.employee_id and repo.exists_by_employee_id(payload.employee_id):
        raise HTTPException(status_code=400, detail="Employee ID already exists")

    return repo.create(payload.model_dump())


@app.put("/users/{user_id}", response_model=UserResponse, dependencies=[Depends(require_role(["ADMIN"]))])
def update_user(
    user_id: Union[int, str],
    payload: UserUpdate,
    repo: UserRepository = Depends(get_repository),
):
    if DB_TYPE == DatabaseType.MONGODB:
        user_id = str(user_id)
    else:
        user_id = int(user_id)

    user = repo.update(user_id, payload.model_dump(exclude_unset=True))

    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.patch("/users/{user_id}/profile", response_model=UserResponse)
async def update_profile(
    user_id: Union[int, str],
    current_user: dict = Depends(get_current_user),
    repo: UserRepository = Depends(get_repository),
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

    # Only the account owner or an ADMIN may update this profile
    token_uid = str(current_user.get("user_id"))
    is_owner = token_uid == str(user_id)
    if not (is_owner or str(current_user.get("role", "")).upper() == "ADMIN"):
        raise HTTPException(status_code=403, detail="Not authorized to update this profile")

    user = repo.get_by_id(resolved_user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

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
):
    if DB_TYPE == DatabaseType.MONGODB:
        user_id = str(user_id)
    else:
        user_id = int(user_id)

    if not repo.update_password(user_id, payload.password):
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "Password updated successfully"}


@app.patch("/users/{user_id}/status", dependencies=[Depends(require_role(["ADMIN"]))])
def update_status(
    user_id: Union[int, str],
    payload: UserStatusUpdate,
    repo: UserRepository = Depends(get_repository),
):
    if DB_TYPE == DatabaseType.MONGODB:
        user_id = str(user_id)
    else:
        user_id = int(user_id)

    if not repo.update_status(user_id, payload.status):
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "Status updated successfully"}


@app.delete("/users/{user_id}", dependencies=[Depends(require_role(["ADMIN"]))])
def delete_user(
    user_id: Union[int, str],
    repo: UserRepository = Depends(get_repository),
):
    if DB_TYPE == DatabaseType.MONGODB:
        user_id = str(user_id)
    else:
        user_id = int(user_id)

    if not repo.delete(user_id):
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User deleted successfully"}
# ── Laundry memberships ────────────────────────────────────────────────────────
# Accounts predating multi-tenancy have no stored memberships; effective_memberships()
# synthesizes the historical one so they keep working. Only explicit grants persist.


class LaundryGrantPayload(BaseModel):
    laundry_id: str = Field(min_length=1, max_length=32)
    name: str | None = Field(default=None, max_length=120)
    role: str | None = Field(default=None, max_length=32)
    status: str = ACTIVE


class LaundryStatusPayload(BaseModel):
    status: str


class SwitchLaundryPayload(BaseModel):
    laundry_id: str = Field(min_length=1, max_length=32)


class SwitchLaundryResponse(BaseModel):
    """Token plus the claims it carries — never a user document."""

    access_token: str
    token_type: str = "bearer"
    laundry_id: str
    laundries: list[dict]


def _coerce_user_id(user_id: Union[int, str]) -> Union[int, str]:
    return str(user_id) if DB_TYPE == DatabaseType.MONGODB else int(user_id)


def _load_user(repo: UserRepository, user_id: Union[int, str]) -> dict:
    user = repo.get_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def _persist_memberships(repo: UserRepository, user_id: Union[int, str], entries: list) -> list:
    if repo.update(user_id, {"laundries": entries}) is None:
        raise HTTPException(status_code=404, detail="User not found")
    return entries


@app.get("/users/{user_id}/laundries", dependencies=[Depends(require_role(["ADMIN"]))])
def list_memberships(
    user_id: Union[int, str],
    repo: UserRepository = Depends(get_repository),
):
    user = _load_user(repo, _coerce_user_id(user_id))
    return {
        "user_id": str(user.get("id")),
        "laundries": effective_memberships(user),
        "stored": bool(stored_memberships(user)),
    }


@app.post(
    "/users/{user_id}/laundries",
    status_code=201,
    dependencies=[Depends(require_role(["ADMIN"]))],
)
def grant_membership(
    user_id: Union[int, str],
    payload: LaundryGrantPayload,
    repo: UserRepository = Depends(get_repository),
):
    status = str(payload.status or ACTIVE).strip().upper()
    if status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(VALID_STATUSES)}")
    user = _load_user(repo, _coerce_user_id(user_id))
    entries = grant(
        user,
        payload.laundry_id,
        name=payload.name,
        role=payload.role,
        status=status,
    )
    return {"laundries": _persist_memberships(repo, _coerce_user_id(user_id), entries)}


@app.patch(
    "/users/{user_id}/laundries/{laundry_id}",
    dependencies=[Depends(require_role(["ADMIN"]))],
)
def set_membership_status(
    user_id: Union[int, str],
    laundry_id: str,
    payload: LaundryStatusPayload,
    repo: UserRepository = Depends(get_repository),
):
    status = str(payload.status or "").strip().upper()
    if status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(VALID_STATUSES)}")
    slug = normalize_laundry_id(laundry_id)
    user = _load_user(repo, _coerce_user_id(user_id))
    if not any(entry["id"] == slug for entry in effective_memberships(user)):
        raise HTTPException(status_code=404, detail="Membership not found")
    entries = grant(user, slug, status=status)
    return {"laundries": _persist_memberships(repo, _coerce_user_id(user_id), entries)}


@app.delete(
    "/users/{user_id}/laundries/{laundry_id}",
    dependencies=[Depends(require_role(["ADMIN"]))],
)
def revoke_membership(
    user_id: Union[int, str],
    laundry_id: str,
    repo: UserRepository = Depends(get_repository),
):
    user = _load_user(repo, _coerce_user_id(user_id))
    entries = revoke(user, laundry_id)
    _persist_memberships(repo, _coerce_user_id(user_id), entries)
    return {"message": "Membership revoked", "laundries": entries}


@app.post("/auth/switch-laundry", response_model=SwitchLaundryResponse)
def switch_laundry(
    payload: SwitchLaundryPayload,
    current_user: dict = Depends(get_current_user),
    repo: UserRepository = Depends(get_repository),
):
    """Re-issue this session's token for another laundry the user belongs to."""
    user = _load_user(repo, current_user.get("user_id"))
    if str(user.get("status") or "unset").strip().lower() in DISABLED_STATUSES:
        raise HTTPException(status_code=403, detail="This account is inactive")
    claims = build_claims(user, payload.laundry_id)
    token_data = {
        "user_id": user["id"],
        "auth_id": user["auth_id"],
        "user_name": user["user_name"],
        "role": str(user["role_id"]).upper(),
        "status": user.get("status"),
        **claims,
    }
    return {
        "access_token": create_access_token(token_data),
        "token_type": "bearer",
        "laundry_id": claims["laundry_id"],
        "laundries": claims["laundries"],
    }
