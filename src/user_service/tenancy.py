"""Multi-tenant identity foundation: laundry registry + memberships.

Design (see architecture_updated_system/ARCHITECTURE.md):
- Every laundry has a permanent, immutable ``laundry_id`` slug.
- Users reach laundries only through ``memberships`` (auth_id, laundry_id,
  role, status). Platform administration is a separate role, never an
  implicit all-tenant pass — except the explicit audited support-entry flow.
- JWTs carry the resolved tenant context; resource services must treat the
  token claims as the ONLY trusted tenant source, never request data.
"""
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .config import DB_TYPE, DatabaseType
from .crypto_helper import encrypt_dict, decrypt_dict, get_search_token
from .database.main_db import laundries_collection, memberships_collection

LOVE_LAUNDRY_ID = "lovelaundry"
LOVE_LAUNDRY_NAME = "LoveLaundry"

PLATFORM_ADMIN = "PLATFORM_ADMIN"
TENANT_ADMIN = "ADMIN"
TENANT_ROLES = ("ADMIN", "MANAGER", "STAFF")

LAUNDRY_ACTIVE = "ACTIVE"
LAUNDRY_SUSPENDED = "SUSPENDED"
LAUNDRY_ARCHIVED = "ARCHIVED"
LAUNDRY_STATUSES = (LAUNDRY_ACTIVE, LAUNDRY_SUSPENDED, LAUNDRY_ARCHIVED)

MEMBER_ACTIVE = "active"
MEMBER_SUSPENDED = "suspended"

_LAUNDRY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")

LAUNDRY_SENSITIVE_FIELDS = ["name", "address", "contact_number", "email", "description"]


def validate_laundry_id(laundry_id: str) -> str:
    """Normalize and validate a laundry slug. Raises ValueError if illegal."""
    slug = (laundry_id or "").strip().lower()
    if not _LAUNDRY_ID_RE.match(slug):
        raise ValueError(
            "laundry_id must be 3-64 chars of lowercase letters, digits and "
            "single hyphens, starting and ending alphanumerically"
        )
    return slug


def normalize_status(status: Optional[str]) -> str:
    status = (status or "").strip().upper()
    if status not in LAUNDRY_STATUSES:
        raise ValueError(f"status must be one of {', '.join(LAUNDRY_STATUSES)}")
    return status


def _now():
    return datetime.now(timezone.utc)


# ── Repository contracts ──────────────────────────────────────────────────


class LaundryRepository(ABC):
    @abstractmethod
    def create(self, data: Dict[str, Any]) -> Dict[str, Any]:
        pass

    @abstractmethod
    def get(self, laundry_id: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def list(self, search: str = "", status: str = "", limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def count(self, search: str = "", status: str = "") -> int:
        pass

    @abstractmethod
    def update(self, laundry_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def exists(self, laundry_id: str) -> bool:
        pass

    @abstractmethod
    def set_status(self, laundry_id: str, status: str) -> bool:
        pass


class MembershipRepository(ABC):
    @abstractmethod
    def add(self, auth_id: str, laundry_id: str, role: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def remove(self, auth_id: str, laundry_id: str) -> bool:
        pass

    @abstractmethod
    def get(self, auth_id: str, laundry_id: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def list_for_laundry(self, laundry_id: str) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def list_for_user(self, auth_id: str) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def set_status(self, auth_id: str, laundry_id: str, status: str) -> bool:
        pass


# ── MongoDB implementations ───────────────────────────────────────────────


class MongoLaundryRepository(LaundryRepository):
    def __init__(self):
        self.collection = laundries_collection
        self.collection.create_index("laundry_id", unique=True)
        self.collection.create_index("name_search")
        self.collection.create_index("br_number", unique=True, sparse=True)
        self.collection.create_index("status")
        self.collection.create_index("created_at")

    def _serialize(self, doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not doc:
            return None
        try:
            doc = decrypt_dict(doc, LAUNDRY_SENSITIVE_FIELDS)
        except Exception as e:
            raise ValueError(f"Failed to decrypt laundry: {str(e)}")
        doc["id"] = str(doc["_id"])
        del doc["_id"]
        return doc

    def _base_doc(self, data: Dict[str, Any], now) -> Dict[str, Any]:
        return {
            "laundry_id": validate_laundry_id(data["laundry_id"]),
            "name": (data.get("name") or "").strip(),
            "name_search": get_search_token(data.get("name") or ""),
            "br_number": (data.get("br_number") or "").strip() or None,
            "location": (data.get("location") or "").strip() or None,
            "address": (data.get("address") or "").strip() or None,
            "contact_number": (data.get("contact_number") or "").strip() or None,
            "email": (data.get("email") or "").strip() or None,
            "logo_url": (data.get("logo_url") or "").strip() or None,
            "icon": (data.get("icon") or "").strip() or None,
            "description": (data.get("description") or "").strip() or None,
            "status": normalize_status(data.get("status") or LAUNDRY_ACTIVE),
            "subscription_plan": (data.get("subscription_plan") or "").strip() or None,
            "plan_limits": data.get("plan_limits"),
            "created_by": (data.get("created_by") or "").strip() or None,
            "created_at": now,
            "updated_at": now,
        }

    def create(self, data: Dict[str, Any]) -> Dict[str, Any]:
        if not (data.get("name") or "").strip():
            raise ValueError("Laundry name is required")
        now = _now()
        encrypted = encrypt_dict(self._base_doc(data, now), LAUNDRY_SENSITIVE_FIELDS)
        result = self.collection.insert_one(encrypted)
        encrypted["_id"] = result.inserted_id
        serialized = self._serialize(encrypted)
        assert serialized is not None
        return serialized

    def get(self, laundry_id: str) -> Optional[Dict[str, Any]]:
        try:
            doc = self.collection.find_one({"laundry_id": (laundry_id or "").strip().lower()})
        except Exception:
            return None
        if not doc:
            return None
        try:
            return self._serialize(doc)
        except ValueError:
            return None

    def _filter(self, search: str = "", status: str = "") -> Dict[str, Any]:
        query: Dict[str, Any] = {}
        if search and search.strip():
            query["name_search"] = get_search_token(search.strip())
        if status and status.strip():
            query["status"] = normalize_status(status)
        return query

    def list(self, search: str = "", status: str = "", limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        out = []
        for doc in (
            self.collection.find(self._filter(search, status)).sort("created_at", -1).skip(offset).limit(limit)
        ):
            try:
                serialized = self._serialize(doc)
                if serialized:
                    out.append(serialized)
            except ValueError:
                pass
        return out

    def count(self, search: str = "", status: str = "") -> int:
        return self.collection.count_documents(self._filter(search, status))

    def update(self, laundry_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        allowed = (
            "name", "br_number", "location", "address", "contact_number",
            "email", "logo_url", "icon", "description", "subscription_plan", "plan_limits",
        )
        updates: Dict[str, Any] = {}
        for key in allowed:
            if key in data and data[key] is not None:
                value = data[key]
                updates[key] = value.strip() if isinstance(value, str) else value
        if "name" in updates:
            if not updates["name"]:
                raise ValueError("Laundry name is required")
            updates["name_search"] = get_search_token(updates["name"])
        if not updates:
            return self.get(laundry_id)
        updates["updated_at"] = _now()
        # Re-encrypt the full sensitive subset from the stored + updated mix.
        existing = self.collection.find_one({"laundry_id": (laundry_id or "").strip().lower()})
        if not existing:
            return None
        try:
            merged = decrypt_dict(existing, LAUNDRY_SENSITIVE_FIELDS)
        except Exception as e:
            raise ValueError(f"Failed to decrypt laundry: {str(e)}")
        merged.update(updates)
        merged.pop("_id", None)
        merged.pop("id", None)
        merged.pop("laundry_id", None)
        re_encrypted = encrypt_dict(merged, LAUNDRY_SENSITIVE_FIELDS)
        # Preserve non-sensitive stored fields the merge already carries.
        self.collection.replace_one({"_id": existing["_id"]}, {**existing, **re_encrypted})
        return self.get(laundry_id)

    def exists(self, laundry_id: str) -> bool:
        return (
            self.collection.count_documents({"laundry_id": (laundry_id or "").strip().lower()}, limit=1) > 0
        )

    def set_status(self, laundry_id: str, status: str) -> bool:
        result = self.collection.update_one(
            {"laundry_id": (laundry_id or "").strip().lower()},
            {"$set": {"status": normalize_status(status), "updated_at": _now()}},
        )
        return result.matched_count > 0


class MongoMembershipRepository(MembershipRepository):
    def __init__(self):
        self.collection = memberships_collection
        self.collection.create_index([("auth_id", 1), ("laundry_id", 1)], unique=True)
        self.collection.create_index("laundry_id")
        self.collection.create_index("auth_id")
        self.collection.create_index("created_at")

    def _serialize(self, doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not doc:
            return None
        doc = dict(doc)
        doc["id"] = str(doc["_id"])
        del doc["_id"]
        return doc

    def add(self, auth_id: str, laundry_id: str, role: str) -> Dict[str, Any]:
        role = (role or "").strip().upper()
        if role not in TENANT_ROLES:
            raise ValueError(f"role must be one of {', '.join(TENANT_ROLES)}")
        now = _now()
        doc = {
            "auth_id": (auth_id or "").strip(),
            "laundry_id": validate_laundry_id(laundry_id),
            "role": role,
            "status": MEMBER_ACTIVE,
            "created_at": now,
            "updated_at": now,
        }
        if not doc["auth_id"]:
            raise ValueError("auth_id is required")
        result = self.collection.insert_one(doc)
        doc["_id"] = result.inserted_id
        serialized = self._serialize(doc)
        assert serialized is not None
        return serialized

    def remove(self, auth_id: str, laundry_id: str) -> bool:
        result = self.collection.delete_one(
            {"auth_id": (auth_id or "").strip(), "laundry_id": (laundry_id or "").strip().lower()}
        )
        return result.deleted_count > 0

    def get(self, auth_id: str, laundry_id: str) -> Optional[Dict[str, Any]]:
        doc = self.collection.find_one(
            {"auth_id": (auth_id or "").strip(), "laundry_id": (laundry_id or "").strip().lower()}
        )
        return self._serialize(doc) if doc else None

    def list_for_laundry(self, laundry_id: str) -> List[Dict[str, Any]]:
        out = []
        for doc in (
            self.collection.find({"laundry_id": (laundry_id or "").strip().lower()}).sort("created_at", 1)
        ):
            serialized = self._serialize(doc)
            if serialized:
                out.append(serialized)
        return out

    def list_for_user(self, auth_id: str) -> List[Dict[str, Any]]:
        out = []
        for doc in self.collection.find({"auth_id": (auth_id or "").strip()}).sort("created_at", 1):
            serialized = self._serialize(doc)
            if serialized:
                out.append(serialized)
        return out

    def set_status(self, auth_id: str, laundry_id: str, status: str) -> bool:
        status = (status or "").strip().lower()
        if status not in (MEMBER_ACTIVE, MEMBER_SUSPENDED):
            raise ValueError("status must be active or suspended")
        result = self.collection.update_one(
            {"auth_id": (auth_id or "").strip(), "laundry_id": (laundry_id or "").strip().lower()},
            {"$set": {"status": status, "updated_at": _now()}},
        )
        return result.matched_count > 0


# ── PostgreSQL implementations ──────────────────────────────────────────
# NOTE: exercised through the same repository contracts; the automated suite
# runs the MongoDB backend (as with all existing tests here).


class PostgresLaundryRepository(LaundryRepository):
    def __init__(self, db):
        from .models import Laundry as LaundryModel

        self.db = db
        self.LaundryModel = LaundryModel

    def _to_dict(self, row) -> Dict[str, Any]:
        return {
            "id": row.id,
            "laundry_id": row.laundry_id,
            "name": row.name,
            "br_number": row.br_number,
            "location": row.location,
            "address": row.address,
            "contact_number": row.contact_number,
            "email": row.email,
            "logo_url": row.logo_url,
            "icon": row.icon,
            "description": row.description,
            "status": row.status,
            "subscription_plan": row.subscription_plan,
            "plan_limits": row.plan_limits,
            "created_by": row.created_by,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }

    def create(self, data: Dict[str, Any]) -> Dict[str, Any]:
        if not (data.get("name") or "").strip():
            raise ValueError("Laundry name is required")
        row = self.LaundryModel(
            laundry_id=validate_laundry_id(data["laundry_id"]),
            name=(data.get("name") or "").strip(),
            br_number=(data.get("br_number") or "").strip() or None,
            location=(data.get("location") or "").strip() or None,
            address=(data.get("address") or "").strip() or None,
            contact_number=(data.get("contact_number") or "").strip() or None,
            email=(data.get("email") or "").strip() or None,
            logo_url=(data.get("logo_url") or "").strip() or None,
            icon=(data.get("icon") or "").strip() or None,
            description=(data.get("description") or "").strip() or None,
            status=normalize_status(data.get("status") or LAUNDRY_ACTIVE),
            subscription_plan=(data.get("subscription_plan") or "").strip() or None,
            plan_limits=data.get("plan_limits"),
            created_by=(data.get("created_by") or "").strip() or None,
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return self._to_dict(row)

    def get(self, laundry_id: str) -> Optional[Dict[str, Any]]:
        row = (
            self.db.query(self.LaundryModel)
            .filter(self.LaundryModel.laundry_id == (laundry_id or "").strip().lower())
            .first()
        )
        return self._to_dict(row) if row else None

    def list(self, search: str = "", status: str = "", limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        query = self.db.query(self.LaundryModel)
        if search and search.strip():
            query = query.filter(self.LaundryModel.name.ilike(f"%{search.strip()}%"))
        if status and status.strip():
            query = query.filter(self.LaundryModel.status == normalize_status(status))
        rows = query.order_by(self.LaundryModel.created_at.desc()).offset(offset).limit(limit).all()
        return [self._to_dict(row) for row in rows]

    def count(self, search: str = "", status: str = "") -> int:
        query = self.db.query(self.LaundryModel)
        if search and search.strip():
            query = query.filter(self.LaundryModel.name.ilike(f"%{search.strip()}%"))
        if status and status.strip():
            query = query.filter(self.LaundryModel.status == normalize_status(status))
        return query.count()

    def update(self, laundry_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        row = (
            self.db.query(self.LaundryModel)
            .filter(self.LaundryModel.laundry_id == (laundry_id or "").strip().lower())
            .first()
        )
        if not row:
            return None
        allowed = (
            "name", "br_number", "location", "address", "contact_number",
            "email", "logo_url", "icon", "description", "subscription_plan", "plan_limits",
        )
        changed = False
        for key in allowed:
            if key in data and data[key] is not None:
                value = data[key]
                setattr(row, key, value.strip() if isinstance(value, str) else value)
                changed = True
        if "name" in data and data["name"] is not None and not (data["name"] or "").strip():
            raise ValueError("Laundry name is required")
        if changed:
            self.db.commit()
            self.db.refresh(row)
        return self._to_dict(row)

    def exists(self, laundry_id: str) -> bool:
        return (
            self.db.query(self.LaundryModel)
            .filter(self.LaundryModel.laundry_id == (laundry_id or "").strip().lower())
            .first()
            is not None
        )

    def set_status(self, laundry_id: str, status: str) -> bool:
        row = (
            self.db.query(self.LaundryModel)
            .filter(self.LaundryModel.laundry_id == (laundry_id or "").strip().lower())
            .first()
        )
        if not row:
            return False
        row.status = normalize_status(status)
        self.db.commit()
        return True


class PostgresMembershipRepository(MembershipRepository):
    def __init__(self, db):
        from .models import Membership as MembershipModel

        self.db = db
        self.MembershipModel = MembershipModel

    def _to_dict(self, row) -> Dict[str, Any]:
        return {
            "id": row.id,
            "auth_id": row.auth_id,
            "laundry_id": row.laundry_id,
            "role": row.role,
            "status": row.status,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }

    def add(self, auth_id: str, laundry_id: str, role: str) -> Dict[str, Any]:
        role = (role or "").strip().upper()
        if role not in TENANT_ROLES:
            raise ValueError(f"role must be one of {', '.join(TENANT_ROLES)}")
        if not (auth_id or "").strip():
            raise ValueError("auth_id is required")
        row = self.MembershipModel(
            auth_id=(auth_id or "").strip(),
            laundry_id=validate_laundry_id(laundry_id),
            role=role,
            status=MEMBER_ACTIVE,
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return self._to_dict(row)

    def remove(self, auth_id: str, laundry_id: str) -> bool:
        row = (
            self.db.query(self.MembershipModel)
            .filter(
                self.MembershipModel.auth_id == (auth_id or "").strip(),
                self.MembershipModel.laundry_id == (laundry_id or "").strip().lower(),
            )
            .first()
        )
        if not row:
            return False
        self.db.delete(row)
        self.db.commit()
        return True

    def get(self, auth_id: str, laundry_id: str) -> Optional[Dict[str, Any]]:
        row = (
            self.db.query(self.MembershipModel)
            .filter(
                self.MembershipModel.auth_id == (auth_id or "").strip(),
                self.MembershipModel.laundry_id == (laundry_id or "").strip().lower(),
            )
            .first()
        )
        return self._to_dict(row) if row else None

    def list_for_laundry(self, laundry_id: str) -> List[Dict[str, Any]]:
        rows = (
            self.db.query(self.MembershipModel)
            .filter(self.MembershipModel.laundry_id == (laundry_id or "").strip().lower())
            .order_by(self.MembershipModel.created_at.asc())
            .all()
        )
        return [self._to_dict(row) for row in rows]

    def list_for_user(self, auth_id: str) -> List[Dict[str, Any]]:
        rows = (
            self.db.query(self.MembershipModel)
            .filter(self.MembershipModel.auth_id == (auth_id or "").strip())
            .order_by(self.MembershipModel.created_at.asc())
            .all()
        )
        return [self._to_dict(row) for row in rows]

    def set_status(self, auth_id: str, laundry_id: str, status: str) -> bool:
        status = (status or "").strip().lower()
        if status not in (MEMBER_ACTIVE, MEMBER_SUSPENDED):
            raise ValueError("status must be active or suspended")
        row = (
            self.db.query(self.MembershipModel)
            .filter(
                self.MembershipModel.auth_id == (auth_id or "").strip(),
                self.MembershipModel.laundry_id == (laundry_id or "").strip().lower(),
            )
            .first()
        )
        if not row:
            return False
        row.status = status
        self.db.commit()
        return True


# ── Factories + helpers ─────────────────────────────────────────────────


_mongo_laundry_repo = None
_mongo_membership_repo = None


def get_laundry_repository(db=None):
    """Laundry registry store for the active backend."""
    if DB_TYPE == DatabaseType.MONGODB:
        global _mongo_laundry_repo
        if _mongo_laundry_repo is None:
            _mongo_laundry_repo = MongoLaundryRepository()
        return _mongo_laundry_repo
    return PostgresLaundryRepository(db)


def get_membership_repository(db=None):
    """Membership store for the active backend."""
    if DB_TYPE == DatabaseType.MONGODB:
        global _mongo_membership_repo
        if _mongo_membership_repo is None:
            _mongo_membership_repo = MongoMembershipRepository()
        return _mongo_membership_repo
    return PostgresMembershipRepository(db)


def get_tenancy_stores():
    """Request-scoped (laundry_repo, membership_repo), mirroring get_repository."""
    if DB_TYPE == DatabaseType.MONGODB:
        yield (get_laundry_repository(), get_membership_repository())
    else:
        from .database import SessionLocal

        db = SessionLocal()
        try:
            yield (get_laundry_repository(db), get_membership_repository(db))
        finally:
            db.close()


def close_tenancy():
    global _mongo_laundry_repo, _mongo_membership_repo
    _mongo_laundry_repo = None
    _mongo_membership_repo = None


def ensure_lovelaundry(laundry_repo: LaundryRepository, created_by: str = "bootstrap") -> Dict[str, Any]:
    """Register the LoveLaundry tenant if absent. Never rewrites an entry."""
    existing = laundry_repo.get(LOVE_LAUNDRY_ID)
    if existing:
        return existing
    return laundry_repo.create(
        {
            "laundry_id": LOVE_LAUNDRY_ID,
            "name": LOVE_LAUNDRY_NAME,
            "status": LAUNDRY_ACTIVE,
            "created_by": created_by,
        }
    )


def build_tenant_claims(
    auth_id: str,
    membership_repo: MembershipRepository,
    laundry_repo: LaundryRepository,
) -> Dict[str, Any]:
    """Resolve the tenant context embedded in JWTs from live memberships.

    Only memberships that are active AND whose laundry is ACTIVE are
    operable. Suspended/archived laundries and suspended memberships are
    excluded so they fail closed everywhere the claims are enforced.
    """
    operable = []
    for membership in membership_repo.list_for_user(auth_id):
        if (membership.get("status") or "").strip().lower() != MEMBER_ACTIVE:
            continue
        laundry = laundry_repo.get(membership.get("laundry_id") or "")
        if not laundry or laundry.get("status") != LAUNDRY_ACTIVE:
            continue
        operable.append(
            {
                "id": laundry.get("laundry_id"),
                "role": (membership.get("role") or "").strip().upper(),
                "status": laundry.get("status"),
            }
        )
    active = operable[0]["id"] if len(operable) == 1 else None
    return {"laundry_id": active, "laundries": operable}


def active_membership(
    auth_id: str,
    laundry_id: str,
    membership_repo: MembershipRepository,
    laundry_repo: LaundryRepository,
) -> Optional[Dict[str, Any]]:
    """The operable membership for (user, laundry), or None when blocked."""
    membership = membership_repo.get(auth_id, laundry_id)
    if not membership or (membership.get("status") or "").strip().lower() != MEMBER_ACTIVE:
        return None
    laundry = laundry_repo.get(laundry_id)
    if not laundry or laundry.get("status") != LAUNDRY_ACTIVE:
        return None
    return {"membership": membership, "laundry": laundry}


def is_platform_admin_token(payload: Dict[str, Any]) -> bool:
    return bool(payload.get("platform_admin")) or str(payload.get("role") or "").upper() == PLATFORM_ADMIN
