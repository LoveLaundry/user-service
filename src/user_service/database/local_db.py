"""
LOCAL database — admin-controlled replica.

Written ONLY when an authorized admin explicitly requests a local
synchronization (MAIN -> LOCAL). It is never a normal read source
and never writes back to MAIN.
"""
from pymongo.collection import Collection

from .connection_manager import ROLE_LOCAL, get_database

_db = get_database(ROLE_LOCAL)

users_collection: Collection = _db.get_collection("users")

# Mirror sync metadata so LOCAL sync can compare versions locally.
sync_status_collection: Collection = _db.get_collection("sync_status")