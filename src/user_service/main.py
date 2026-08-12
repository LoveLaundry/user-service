from typing import Union

from fastapi import Depends, FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import bcrypt
import base64

from .config import DB_TYPE, DatabaseType
from .repository import UserRepository
from .repository_factory import close_connections, get_repository
from .auth_helper import create_access_token, get_current_user, require_role
from .schemas import (
    UserCreate,
    UserPasswordUpdate,
    UserResponse,
    UserStatusUpdate,
    UserUpdate,
)

app = FastAPI(title="User Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup_event():
    if DB_TYPE in (DatabaseType.POSTGRESQL, DatabaseType.SQLITE):
        from .database import Base, engine
        if engine:
            Base.metadata.create_all(bind=engine)


@app.on_event("shutdown")
def shutdown_event():
    try:
        close_connections()
    except Exception:
        pass


@app.get("/")
def root():
    return {
        "message": "User Service API",
        "version": "1.0.0",
        "database": DB_TYPE.value,
    }


# ── Auth routes (public) ────────────────────────────────────────────────────────

class LoginPayload(BaseModel):
    username: str
    password: str


@app.post("/auth/login")
def login(payload: LoginPayload, repo: UserRepository = Depends(get_repository)):
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

    token_data = {
        "user_id": user["id"],
        "auth_id": user["auth_id"],
        "user_name": user["user_name"],
        "role": role,
        "status": user["status"],
    }

    user_response = {k: v for k, v in user.items() if k != "password"}
    user_response["role_id"] = role

    token = create_access_token(token_data)
    return {
        "access_token": token,
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
