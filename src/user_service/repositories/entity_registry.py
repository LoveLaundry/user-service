"""
Entity registry — maps business entity names to their collections in each
database role. This is the single place that knows which collections
participate in synchronization.
"""
from pymongo.collection import Collection

from ..database import local_db, main_db, secondary_db

# entity name -> (MAIN collection, SECONDARY collection, LOCAL collection)
COLLECTION_MAP: dict[str, tuple[Collection, Collection, Collection]] = {
    "user": (
        main_db.users_collection,
        secondary_db.users_collection,
        local_db.users_collection,
    ),
}


def get_collections(entity: str) -> tuple[Collection, Collection, Collection]:
    """Return (main, secondary, local) collections for an entity name."""
    if entity not in COLLECTION_MAP:
        raise ValueError(f"Unknown sync entity: {entity!r}")
    return COLLECTION_MAP[entity]


def get_main_collection(entity: str) -> Collection:
    return get_collections(entity)[0]


def get_secondary_collection(entity: str) -> Collection:
    return get_collections(entity)[1]


def get_local_collection(entity: str) -> Collection:
    return get_collections(entity)[2]


def all_entities() -> list[str]:
    """Return every syncable entity name."""
    return list(COLLECTION_MAP.keys())


def effective_version(doc: dict) -> int:
    """Return the sync version of a stored document, defaulting legacy docs to 1."""
    return int(doc.get("sync_version") or 1)