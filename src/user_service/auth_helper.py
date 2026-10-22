import os
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBearer
import jwt

from dotenv import load_dotenv

# pydantic-settings reads .env into its own model, but it does NOT export the
# values into os.environ, so anything that reads the environment directly
# (as this module does) needs the file loaded explicitly.
load_dotenv()

_jwt_secret = os.getenv("JWT_SECRET")
if not _jwt_secret:
    raise RuntimeError("FATAL: JWT_SECRET environment variable is not set. Refusing to start.")
JWT_SECRET = _jwt_secret
JWT_ALGORITHM = "HS256"

security = HTTPBearer()

# Statuses that block an account. `unset` is the column default and `active` is
# the only enabled value, so this is a blocklist rather than an allowlist: an
# account that was never given a status must keep working.
DISABLED_STATUSES = {"inactive", "disabled", "suspended", "blocked", "deleted"}


def create_access_token(data: dict, expires_in_hours: int = 24) -> str:
    """Create a signed JWT token containing user info."""
    payload = data.copy()
    now = datetime.now(timezone.utc)
    payload["exp"] = now + timedelta(hours=expires_in_hours)
    payload["iat"] = now
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> dict:
    """Verify and decode a JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )


def _fresh_user(auth_id: str):
    """Reload the user row from the authoritative store for revocation checks."""
    if not auth_id:
        return None
    from .repository_factory import get_repository

    gen = get_repository()
    repo = next(gen)
    try:
        return repo.get_by_auth_id(auth_id)
    finally:
        try:
            next(gen)  # let the generator's finally blocks (e.g. DB close) run
        except StopIteration:
            pass


def get_current_user(credentials=Security(security)) -> dict:
    """FastAPI dependency to validate JWT authorization header.

    The token is verified cryptographically, then the account is reloaded from
    the database so a disabled/deleted user loses access immediately — a token
    that was valid at login must not keep working until it expires.
    """
    payload = verify_token(credentials.credentials)

    auth_id = payload.get("auth_id")
    if auth_id:
        fresh = _fresh_user(auth_id)
        if fresh is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account no longer exists.",
            )
        if str(fresh.get("status") or "unset").strip().lower() in DISABLED_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This account has been deactivated. Contact an administrator.",
            )
        # Surface the live role/status so a demoted admin loses permissions at
        # the next request instead of riding out a 24-hour token.
        fresh_role = str(fresh.get("role_id") or "").upper()
        if fresh_role:
            payload["role"] = fresh_role
        payload["status"] = fresh.get("status")
        payload["user_name"] = fresh.get("user_name") or payload.get("user_name")
        # The tenant registry is gated on this flag, so it must come from the
        # database rather than the token snapshot: revoking it takes effect on
        # the next request instead of when the token expires.
        # The role is authoritative; the flag is an additional grant. Without
        # this, an account holding PLATFORM_ADMIN but not the flag reported
        # platform_admin:false while the UI treated it as a platform admin.
        payload["platform_admin"] = bool(fresh.get("platform_admin")) or str(
            fresh.get("role_id") or ""
        ).upper() == "PLATFORM_ADMIN"

    return payload


def require_role(allowed_roles: list):
    """FastAPI dependency factory to validate roles.

    ``PLATFORM_ADMIN`` outranks ``ADMIN``. The user directory is the platform
    operator's responsibility, so an account holding the platform role must not
    be locked out of a route that a laundry administrator can reach — that
    inversion is what returned 403 to the platform account while the UI showed
    it the Users page.
    """

    allowed = {str(r).upper() for r in allowed_roles}

    def dependency(current_user: dict = Security(get_current_user)):
        role = str(current_user.get("role") or "").upper()
        if role in allowed or (role == "PLATFORM_ADMIN" and "ADMIN" in allowed):
            return current_user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{role}' is not authorized to access this resource",
        )

    return dependency
