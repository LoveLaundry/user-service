"""
Database state verification script.

Shows the current state of the database to help verify migration readiness.
"""
import os
import sys
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_MAIN_URI")
MONGODB_DB = os.getenv("MONGODB_MAIN_DB", "users_db")

if not MONGODB_URI:
    print("ERROR: MONGODB_MAIN_URI not set")
    sys.exit(1)

client = MongoClient(MONGODB_URI)
db = client[MONGODB_DB]

print("=" * 60)
print("Database State Verification")
print("=" * 60)
print(f"Database: {MONGODB_DB}")
print(f"Connected: {MONGODB_URI[:50]}...")
print()

# Check collections
collections = db.list_collection_names()
print(f"Total collections: {len(collections)}")
print(f"Collections: {', '.join(sorted(collections))}")
print()

# Check entity registries
print("=== Entity Registries ===")
hotels_count = db["hotels"].count_documents({}) if "hotels" in collections else 0
shops_count = db["shops"].count_documents({}) if "shops" in collections else 0
laundries_count = db["laundries"].count_documents({}) if "laundries" in collections else 0

print(f"Hotels: {hotels_count}")
print(f"Shops: {shops_count}")
print(f"Laundries: {laundries_count}")
print()

# Check users
print("=== Users ===")
users_count = db["users"].count_documents({}) if "users" in collections else 0
print(f"Total users: {users_count}")

if users_count > 0 and "users" in collections:
    # Check for users with entity memberships
    users_with_hotels = db["users"].count_documents({"hotels": {"$exists": True, "$ne": []}})
    users_with_shops = db["users"].count_documents({"shops": {"$exists": True, "$ne": []}})
    users_with_laundries = db["users"].count_documents({"laundries": {"$exists": True, "$ne": []}})

    print(f"Users with hotel memberships: {users_with_hotels}")
    print(f"Users with shop memberships: {users_with_shops}")
    print(f"Users with laundry memberships: {users_with_laundries}")

    # Show platform admins
    platform_admins = db["users"].count_documents({"platform_admin": True})
    print(f"Platform admins: {platform_admins}")
print()

# Check client accounts
print("=== Client Accounts ===")
if "client_accounts" in collections:
    client_accounts_count = db["client_accounts"].count_documents({})
    print(f"Total client accounts: {client_accounts_count}")

    hotel_clients = db["client_accounts"].count_documents({"client_type": "HOTEL"})
    shop_clients = db["client_accounts"].count_documents({"client_type": "SHOP"})

    print(f"Hotel clients: {hotel_clients}")
    print(f"Shop clients: {shop_clients}")

    # Check for entity IDs
    hotel_clients_with_id = db["client_accounts"].count_documents({
        "client_type": "HOTEL",
        "hotel_id": {"$exists": True, "$ne": None}
    })
    shop_clients_with_id = db["client_accounts"].count_documents({
        "client_type": "SHOP",
        "shop_id": {"$exists": True, "$ne": None}
    })

    print(f"Hotel clients with hotel_id: {hotel_clients_with_id}")
    print(f"Shop clients with shop_id: {shop_clients_with_id}")
print()

# Check operational collections
print("=== Operational Collections ===")
operational_collections = ["bills", "gatepasses", "deliveries", "shop_bills", "monthly_entries"]
for coll_name in operational_collections:
    if coll_name in collections:
        count = db[coll_name].count_documents({})
        print(f"{coll_name}: {count} documents")

        # Check for hotel_id and shop_id
        if count > 0:
            hotel_id_count = db[coll_name].count_documents({"hotel_id": {"$exists": True, "$ne": None}})
            shop_id_count = db[coll_name].count_documents({"shop_id": {"$exists": True, "$ne": None}})
            client_name_count = db[coll_name].count_documents({"client_name": {"$exists": True, "$ne": None}})

            if hotel_id_count > 0 or shop_id_count > 0 or client_name_count > 0:
                print(f"  - With hotel_id: {hotel_id_count}")
                print(f"  - With shop_id: {shop_id_count}")
                print(f"  - With client_name: {client_name_count}")
print()

print("=" * 60)
print("Verification complete")
print("=" * 60)
