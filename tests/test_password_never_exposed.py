"""The bcrypt password hash must never appear in an API response.

`_serialize_document` returns the whole stored document, `password` included.
That is safe ONLY because every read route declares
`response_model=UserResponse`, which has no `password` field, and because
`/auth/login` strips the key by hand.

This is a load-bearing accident: three routes in `main.py` already return no
`response_model` at all. The moment someone adds a user-returning route
without one — or drops the model from an existing route — the hash starts
leaking and every response becomes an offline cracking target.

These tests pin the current behaviour so that regression is loud.
"""
import pytest
from fastapi.testclient import TestClient

ADMIN_USER = {
    "user_name": "Admin User",
    "email": "admin@example.com",
    "password": "correct-horse-battery-staple",
    "auth_id": "auth-admin",
    "employee_id": "EMP-1",
    "role_id": "ADMIN",
}

READ_ROUTES = [
    "/users",
    "/users/{user_id}",
    "/users/auth/{auth_id}",
    "/users/email/{email}",
    "/users/employee/{employee_id}",
]


@pytest.fixture
def client(mocked_db):
    from user_service.main import app

    return TestClient(app)


@pytest.fixture
def admin(mocked_db):
    """Create the admin user directly and return (user_id, auth_header)."""
    from user_service.mongodb_repository import MongoDBUserRepository

    created = MongoDBUserRepository().create(dict(ADMIN_USER))
    login = TestClient(_app()).post(
        "/auth/login",
        json={"username": ADMIN_USER["auth_id"], "password": ADMIN_USER["password"]},
    )
    assert login.status_code == 200, login.text
    return created["id"], {"Authorization": f"Bearer {login.json()['access_token']}"}


def _app():
    from user_service.main import app

    return app


def _walk(node):
    """Yield every dict nested anywhere inside a JSON response body."""
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item)


def test_password_hash_is_absent_from_every_read_route(client, admin, mocked_db):
    user_id, headers = admin
    paths = [route.format(user_id=user_id, auth_id=ADMIN_USER["auth_id"],
                          email=ADMIN_USER["email"],
                          employee_id=ADMIN_USER["employee_id"])
             for route in READ_ROUTES]

    for path in paths:
        response = client.get(path, headers=headers)
        assert response.status_code == 200, f"{path} -> {response.status_code}"
        for obj in _walk(response.json()):
            assert "password" not in obj, f"{path} leaked the password hash"


def test_password_hash_is_absent_from_login_body(client, admin):
    response = client.post(
        "/auth/login",
        json={"username": ADMIN_USER["auth_id"], "password": ADMIN_USER["password"]},
    )
    assert response.status_code == 200
    for obj in _walk(response.json()):
        assert "password" not in obj, "login response leaked the password hash"


def test_password_hash_is_actually_stored_hashed(admin, mocked_db):
    """Guard the guard: if nothing is stored, the tests above prove nothing."""
    stored = mocked_db["users_collection"].find_one({"auth_id": ADMIN_USER["auth_id"]})
    assert stored is not None, "fixture must create the user"
    assert stored["password"].startswith("$2b$")
    assert ADMIN_USER["password"] not in stored["password"]


# Routes that legitimately return user data without a response_model because
# they strip the hash by hand. `login` builds `user_response` as
# `{k: v for k, v in user.items() if k != "password"}` — asserted by
# test_password_hash_is_absent_from_login_body.
MANUAL_STRIP_ROUTES = {"POST login"}


def test_every_user_returning_route_declares_a_response_model():
    """The safety net is `response_model`; make sure none were dropped.

    Parses main.py rather than the route table so a route returning a user
    document without a declared model is caught even if it is unreachable
    from these tests.
    """
    import ast
    import pathlib

    import user_service

    main_py = pathlib.Path(user_service.__file__).parent / "main.py"
    tree = ast.parse(main_py.read_text())

    missing = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        returns_user = any(
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and sub.func.attr in {"get_by_id", "get_by_auth_id", "get_by_email",
                                  "get_by_employee_id", "get_all", "create",
                                  "update", "update_profile"}
            for sub in ast.walk(node)
        )
        if not returns_user:
            continue
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                if dec.func.attr in {"get", "post", "put", "patch"}:
                    has_model = any(
                        kw.arg == "response_model" for kw in dec.keywords
                    )
                    label = f"{dec.func.attr.upper()} {node.name}"
                    if not has_model and label not in MANUAL_STRIP_ROUTES:
                        missing.append(label)

    assert not missing, (
        "Route(s) return a user document without response_model and without a "
        f"hand-written strip, so the password hash is no longer filtered out: {missing}"
    )
