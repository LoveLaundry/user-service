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
from .client_associations import (
    list_associations as list_client_associations,
    switch_to as switch_client_laundry,
)
from .client_accounts import (
    authenticate as authenticate_client,
    build_client_token,
    client_scope_of,
    create_client_account,
    get_client_session,
    list_for_laundry as list_client_accounts,
    public_view as client_public_view,
    set_status as set_client_status,
)
from .database.main_db import ensure_indexes
from .database.connection_manager import close_all
from .security import apply_security, insecure_flags
from .routers.admin_database import router as admin_database_router
from .services import synchronization_service
from .tenancy import resolve_laundry_id


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

    # A deployment created before the platform role existed has no platform
    # administrator, so nobody could register the first laundry. Promote the
    # owner account once, at login: the earliest ADMIN, and only while no
    # platform administrator exists anywhere. Afterwards the flag is explicit.
    if not user.get("platform_admin") and str(role).upper() == "ADMIN":
        try:
            from .database.main_db import users_collection

            if users_collection.count_documents({"platform_admin": True}) == 0:
                first_admin = users_collection.find_one(
                    {"role_id": "ADMIN"}, sort=[("created_at", 1), ("_id", 1)]
                )
                if first_admin and first_admin.get("auth_id") == user["auth_id"]:
                    users_collection.update_one(
                        {"_id": first_admin["_id"]}, {"$set": {"platform_admin": True}}
                    )
                    user = dict(user, platform_admin=True)
        except Exception:
            # Never block a sign-in because the promotion probe failed.
            pass

    token_data = {
        "user_id": user["id"],
        "auth_id": user["auth_id"],
        "user_name": user["user_name"],
        "role": role,
        "status": user["status"],
        "platform_admin": bool(user.get("platform_admin"))
        or str(role).upper() == "PLATFORM_ADMIN",
        # Tenant claims every resource service trusts. Built in one place so
        # login, bootstrap and switching cannot drift.
        **build_claims(user, payload.laundry_id),
    }

    user_response = {k: v for k, v in user.items() if k != "password"}
    user_response["laundries"] = effective_memberships(user)
    user_response["role_id"] = role
    user_response["platform_admin"] = bool(user.get("platform_admin")) or str(
        role
    ).upper() == "PLATFORM_ADMIN"

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


def _membership_admin_scope(current_user: dict) -> str | None:
    """Return the laundry scope for tenant admins and support-entry sessions."""
    if current_user.get("support_entry"):
        return resolve_laundry_id(current_user)
    role = str(current_user.get("role") or "").upper()
    if current_user.get("platform_admin") or role == "PLATFORM_ADMIN":
        return None
    return resolve_laundry_id(current_user)


def _require_membership_scope(scope: str | None, laundry_id: str) -> None:
    if scope is not None and laundry_id != scope:
        raise HTTPException(
            status_code=403,
            detail="You can only manage memberships in your active laundry",
        )


@app.get("/users/{user_id}/laundries")
def list_memberships(
    user_id: Union[int, str],
    current_user: dict = Depends(require_role(["ADMIN"])),
    repo: UserRepository = Depends(get_repository),
):
    scope = _membership_admin_scope(current_user)
    user = _load_user(repo, _coerce_user_id(user_id))
    entries = effective_memberships(user)
    visible_entries = entries if scope is None else [
        entry for entry in entries if entry["id"] == scope
    ]
    stored_ids = {entry["id"] for entry in stored_memberships(user)}
    return {
        "user_id": str(user.get("id")),
        "laundries": visible_entries,
        "stored": any(entry["id"] in stored_ids for entry in visible_entries),
    }


@app.post("/users/{user_id}/laundries", status_code=201)
def grant_membership(
    user_id: Union[int, str],
    payload: LaundryGrantPayload,
    current_user: dict = Depends(require_role(["ADMIN"])),
    repo: UserRepository = Depends(get_repository),
):
    status = str(payload.status or ACTIVE).strip().upper()
    if status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(VALID_STATUSES)}")
    slug = normalize_laundry_id(payload.laundry_id)
    _require_membership_scope(_membership_admin_scope(current_user), slug)
    user = _load_user(repo, _coerce_user_id(user_id))
    entries = grant(
        user,
        slug,
        name=payload.name,
        role=payload.role,
        status=status,
    )
    return {"laundries": _persist_memberships(repo, _coerce_user_id(user_id), entries)}


@app.patch("/users/{user_id}/laundries/{laundry_id}")
def set_membership_status(
    user_id: Union[int, str],
    laundry_id: str,
    payload: LaundryStatusPayload,
    current_user: dict = Depends(require_role(["ADMIN"])),
    repo: UserRepository = Depends(get_repository),
):
    status = str(payload.status or "").strip().upper()
    if status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(VALID_STATUSES)}")
    slug = normalize_laundry_id(laundry_id)
    _require_membership_scope(_membership_admin_scope(current_user), slug)
    user = _load_user(repo, _coerce_user_id(user_id))
    if not any(entry["id"] == slug for entry in effective_memberships(user)):
        raise HTTPException(status_code=404, detail="Membership not found")
    entries = grant(user, slug, status=status)
    return {"laundries": _persist_memberships(repo, _coerce_user_id(user_id), entries)}


@app.delete("/users/{user_id}/laundries/{laundry_id}")
def revoke_membership(
    user_id: Union[int, str],
    laundry_id: str,
    current_user: dict = Depends(require_role(["ADMIN"])),
    repo: UserRepository = Depends(get_repository),
):
    slug = normalize_laundry_id(laundry_id)
    _require_membership_scope(_membership_admin_scope(current_user), slug)
    user = _load_user(repo, _coerce_user_id(user_id))
    entries = revoke(user, slug)
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


# ── Hotel client portal auth ────────────────────────────────────────────────────
# A hotel is a customer of a laundry, not a member of its staff, so client
# sessions are issued by their own endpoints and never carry a laundry
# membership claim. See client_accounts.py for why that shape is the isolation
# mechanism: every staff endpoint keeps rejecting these tokens untouched.

class ClientLoginPayload(BaseModel):
    auth_id: str
    password: str
    # Only needed when the same login exists under more than one laundry, or
    # when one login is registered on both sides of the same laundry.
    laundry_id: str | None = None
    client_type: str | None = None


class ClientCreatePayload(BaseModel):
    client_name: str
    auth_id: str
    user_name: str
    password: str
    email: str | None = None
    role: str | None = None
    client_type: str | None = "HOTEL"
    # Platform admins must name the target laundry; tenant admins default to
    # their active one and cannot reach another tenant.
    laundry_id: str | None = None


class ClientStatusPayload(BaseModel):
    status: str


@app.post("/client/auth/login")
def client_login(payload: ClientLoginPayload):
    """Sign in a hotel user. Same generic error for unknown and wrong password."""
    doc = authenticate_client(
        payload.auth_id, payload.password, payload.laundry_id, payload.client_type
    )
    if not doc:
        raise HTTPException(status_code=400, detail="Invalid username or password")
    return {
        "access_token": build_client_token(doc),
        "token_type": "bearer",
        "client": client_public_view(doc),
    }


@app.get("/client/auth/status")
def client_status(session: dict = Depends(get_client_session)):
    """Live session check for the hotel app; never returns a password hash."""
    scope = client_scope_of(session)
    return {
        "auth_id": session.get("auth_id"),
        "user_name": session.get("user_name"),
        "role_id": session.get("role"),
        "status": session.get("status"),
        "laundry_id": scope["laundry_id"],
        "client_name": scope["client_name"],
        "client_type": scope["client_type"],
    }


@app.get("/clients", dependencies=[Depends(require_role(["ADMIN"]))])
def list_clients(
    laundry_id: str | None = None,
    client_type: str | None = None,
    current_user: dict = Depends(get_current_user),
):
    scope = _membership_admin_scope(current_user)
    target = laundry_id or scope or resolve_laundry_id(current_user)
    slug = normalize_laundry_id(target)
    _require_membership_scope(scope, slug)
    return {"items": list_client_accounts(slug, client_type)}


@app.post("/clients", status_code=201, dependencies=[Depends(require_role(["ADMIN"]))])
def create_client(
    payload: ClientCreatePayload,
    current_user: dict = Depends(get_current_user),
):
    scope = _membership_admin_scope(current_user)
    target = payload.laundry_id or scope or resolve_laundry_id(current_user)
    slug = normalize_laundry_id(target)
    _require_membership_scope(scope, slug)
    doc = create_client_account(
        laundry_id=slug,
        client_name=payload.client_name,
        auth_id=payload.auth_id,
        user_name=payload.user_name,
        password=payload.password,
        email=payload.email,
        role=payload.role,
        client_type=payload.client_type or "HOTEL",
    )
    return client_public_view(doc)


@app.patch("/clients/{client_id}/status", dependencies=[Depends(require_role(["ADMIN"]))])
def update_client_status(
    client_id: str,
    payload: ClientStatusPayload,
    current_user: dict = Depends(get_current_user),
):
    scope = _membership_admin_scope(current_user)
    # Tenant admins may only touch their own clients; set_status is keyed on the
    # account id, so the ownership check happens here.
    if scope is not None:
        owned = [c["id"] for c in list_client_accounts(scope)]
        if client_id not in owned:
            raise HTTPException(status_code=404, detail="Client account not found")
    return set_client_status(client_id, payload.status)


class ClientSwitchPayload(BaseModel):
    laundry_id: str


@app.get("/client/auth/laundries")
def client_laundries(session: dict = Depends(get_client_session)):
    """Every laundry this login may enter on its own side of the business.

    A person registered as a shop under two laundries sees exactly those two.
    The same username registered as a hotel elsewhere is a different account and
    is never listed here.
    """
    scope = client_scope_of(session)
    items = list_client_associations(session.get("auth_id"), scope["client_type"])
    return {
        "current": scope["laundry_id"],
        "client_type": scope["client_type"],
        "count": len(items),
        "items": items,
    }


@app.post("/client/auth/switch")
def client_switch(payload: ClientSwitchPayload, session: dict = Depends(get_client_session)):
    """Re-issue this session for another laundry the same login belongs to.

    The token is replaced, not widened: it still carries exactly one scope, so
    switching can never make two laundries readable at once.
    """
    doc = switch_client_laundry(session, payload.laundry_id)
    return {
        "access_token": build_client_token(doc),
        "token_type": "bearer",
        "client": client_public_view(doc),
    }


@app.post("/auth/refresh")
def refresh_token(
    current_user: dict = Depends(get_current_user),
    repo: UserRepository = Depends(get_repository),
):
    """Re-issue a session token without re-entering the password.

    Only the expiry moves. Every claim is rebuilt from the database, so a role
    change, a disabled account or a revoked membership takes effect on refresh
    instead of surviving inside a stale token until it expires.
    """
    user = _load_user(repo, _coerce_user_id(current_user.get("user_id")))
    if not user or _is_blocked(user):
        raise HTTPException(
            status_code=403,
            detail="This account is inactive. Contact an administrator.",
        )

    role = str(user["role_id"]).upper()
    token_data = {
        "user_id": user["id"],
        "auth_id": user["auth_id"],
        "user_name": user["user_name"],
        "role": role,
        "status": user["status"],
        "platform_admin": bool(user.get("platform_admin"))
        or role == "PLATFORM_ADMIN",
        **build_claims(user, current_user.get("laundry_id")),
    }
    return {"access_token": create_access_token(token_data), "token_type": "bearer"}


@app.post("/client/auth/refresh")
def client_refresh_token(session: dict = Depends(get_client_session)):
    """Re-issue a hotel or shop token, re-reading the account's live state.

    switch_to() already loads the stored account for the session's current
    laundry and refuses a suspended or missing one, so refreshing cannot
    resurrect an account an administrator has just switched off.
    """
    scope = client_scope_of(session)
    doc = switch_client_laundry(session, scope["laundry_id"])
    return {
        "access_token": build_client_token(doc),
        "token_type": "bearer",
        "client": client_public_view(doc),
    }
