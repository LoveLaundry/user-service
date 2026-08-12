"""
SECONDARY database — verification/replica database.

This database may ONLY be written by the synchronization service and
read by the verification service. It must NEVER be used as the normal
frontend data source.
"""
from pymongo.collection import Collection

from .connection_manager import ROLE_SECONDARY, get_database

_db = get_database(ROLE_SECONDARY)

users_collection: Collection = _db.get_collection("users")

# Sync metadata is mirrored too, so verification can compare records
# entirely within the Secondary database.
sync_status_collection: Collection = _db.get_collection("sync_status")