from typing import Union

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .config import DB_TYPE, DatabaseType
from .repository import UserRepository
from .repository_factory import close_connections, get_repository
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

if DB_TYPE in (DatabaseType.POSTGRESQL, DatabaseType.SQLITE):
    from .database import Base, engine

    if engine:
        Base.metadata.create_all(bind=engine)


@app.on_event("shutdown")
def shutdown_event():
    close_connections()


@app.get("/")
def root():
    return {
        "message": "User Service API",
        "version": "1.0.0",
        "database": DB_TYPE.value,
    }


@app.get("/users", response_model=list[UserResponse])
def get_all_users(repo: UserRepository = Depends(get_repository)):
    return repo.get_all()


@app.get("/users/{user_id}", response_model=UserResponse)
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


@app.get("/users/auth/{auth_id}", response_model=UserResponse)
def get_user_by_auth_id(
    auth_id: str,
    repo: UserRepository = Depends(get_repository),
):
    user = repo.get_by_auth_id(auth_id)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user


@app.get("/users/email/{email}", response_model=UserResponse)
def get_user_by_email(
    email: str,
    repo: UserRepository = Depends(get_repository),
):
    user = repo.get_by_email(email)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user


@app.get("/users/employee/{employee_id}", response_model=UserResponse)
def get_user_by_employee_id(
    employee_id: str,
    repo: UserRepository = Depends(get_repository),
):
    user = repo.get_by_employee_id(employee_id)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user


@app.post("/users", response_model=UserResponse, status_code=201)
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


@app.put("/users/{user_id}", response_model=UserResponse)
def update_user(
    user_id: Union[int, str],
    payload: UserUpdate,
    repo: UserRepository = Depends(get_repository),
):
    if DB_TYPE == DatabaseType.MONGODB:
        user_id = str(user_id)
    else:
        user_id = int(user_id)

    user = repo.update(
        user_id,
        payload.model_dump(exclude_unset=True),
    )

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user


@app.patch("/users/{user_id}/password")
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


@app.patch("/users/{user_id}/status")
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


@app.delete("/users/{user_id}")
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


@app.get("/users/count")
def count_users(
    repo: UserRepository = Depends(get_repository),
):
    return {"count": repo.count()}