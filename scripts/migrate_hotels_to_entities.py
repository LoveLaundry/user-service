"""
Migration script: Convert hotel client_name strings to hotel entities.

This script migrates the system from using client_name strings to first-class
hotel entities. It:
1. Analyzes existing client_name values across all collections
2. Creates hotel entities in the hotels collection
3. Associates existing client_accounts with hotel_id
4. Backfills hotel_id on operational records

WARNING: This is a ONE-WAY migration. Test thoroughly on a staging environment
before running on production data.
"""
import os
import sys
from datetime import datetime, timezone
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_MAIN_URI")
MONGODB_DB = os.getenv("MONGODB_MAIN_DB", "users_db")
if not MONGODB_URI:
    print("ERROR: MONGODB_MAIN_URI not set in environment")
    sys.exit(1)

client = MongoClient(MONGODB_URI)
db = client[MONGODB_DB]

# Collections
hotels_collection = db["hotels"]
laundries_collection = db["laundries"]
client_accounts_collection = db["client_accounts"]
# Operational collections to backfill
bills_collection = db["bills"]
gatepasses_collection = db["gatepasses"]
deliveries_collection = db["deliveries"]
monthly_entries_collection = db["monthly_entries"]


def analyze_hotel_names():
    """Analyze all unique hotel client_name values."""
    print("\n=== Analyzing hotel client_name values ===")

    # From client_accounts
    hotel_client_names = set()
    for doc in client_accounts_collection.find({"client_type": "HOTEL"}):
        if doc.get("client_name"):
            hotel_client_names.add(doc["client_name"].strip())

    # From operational records
    for collection in [bills_collection, gatepasses_collection, deliveries_collection]:
        for doc in collection.find({"client_name": {"$exists": True, "$ne": None}}):
            if doc.get("client_name"):
                hotel_client_names.add(doc["client_name"].strip())

    print(f"Found {len(hotel_client_names)} unique hotel names")
    for name in sorted(hotel_client_names):
        print(f"  - {name}")

    return sorted(hotel_client_names)


def slugify_hotel_name(name: str) -> str:
    """Convert hotel name to a valid hotel_id slug."""
    # Convert to lowercase, replace spaces with hyphens, remove special chars
    slug = name.lower()
    slug = slug.replace(" ", "-")
    slug = slug.replace("'", "")
    slug = slug.replace(".", "")
    slug = slug.replace(",", "")
    # Keep only alphanumeric and hyphens
    slug = "".join(c for c in slug if c.isalnum() or c == "-")
    # Limit to 32 chars
    slug = slug[:32]
    # Ensure starts with alphanumeric
    if slug and not slug[0].isalnum():
        slug = "h-" + slug[1:]
    return slug


def create_hotel_entities(hotel_names: list, default_laundry_id: str = "lovelaundry"):
    """Create hotel entities from client_name values."""
    print(f"\n=== Creating hotel entities (default laundry: {default_laundry_id}) ===")

    # Verify default laundry exists
    laundry = laundries_collection.find_one({"laundry_id": default_laundry_id})
    if not laundry:
        print(f"ERROR: Default laundry '{default_laundry_id}' not found")
        return

    created = 0
    skipped = 0

    for name in hotel_names:
        slug = slugify_hotel_name(name)

        # Check if already exists
        if hotels_collection.find_one({"hotel_id": slug}):
            print(f"  SKIP: {name} -> {slug} (already exists)")
            skipped += 1
            continue

        # Create hotel entity
        hotel_doc = {
            "hotel_id": slug,
            "name": name,
            "associated_laundry_id": default_laundry_id,
            "status": "ACTIVE",
            "created_by": "migration-script",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

        hotels_collection.insert_one(hotel_doc)
        print(f"  CREATE: {name} -> {slug}")
        created += 1

    print(f"\nCreated {created} hotel entities, skipped {skipped}")
    return created


def associate_client_accounts():
    """Associate client_accounts with hotel_id."""
    print("\n=== Associating client accounts with hotel_id ===")

    updated = 0
    skipped = 0

    for doc in client_accounts_collection.find({"client_type": "HOTEL", "hotel_id": None}):
        client_name = doc.get("client_name")
        if not client_name:
            skipped += 1
            continue

        slug = slugify_hotel_name(client_name)
        hotel = hotels_collection.find_one({"hotel_id": slug})

        if not hotel:
            print(f"  SKIP: No hotel entity for '{client_name}'")
            skipped += 1
            continue

        client_accounts_collection.update_one(
            {"_id": doc["_id"]},
            {"$set": {"hotel_id": slug, "updated_at": datetime.now(timezone.utc).isoformat()}}
        )
        print(f"  UPDATE: {client_name} -> {slug}")
        updated += 1

    print(f"\nUpdated {updated} client accounts, skipped {skipped}")
    return updated


def backfill_operational_records():
    """Backfill hotel_id on operational records."""
    print("\n=== Backfilling hotel_id on operational records ===")

    collections_to_update = [
        ("bills", bills_collection),
        ("gatepasses", gatepasses_collection),
        ("deliveries", deliveries_collection),
        ("monthly_entries", monthly_entries_collection),
    ]

    total_updated = 0

    for collection_name, collection in collections_to_update:
        print(f"\n  Processing {collection_name}...")
        updated = 0
        skipped = 0

        for doc in collection.find({"client_name": {"$exists": True}, "hotel_id": None}):
            client_name = doc.get("client_name")
            if not client_name:
                skipped += 1
                continue

            slug = slugify_hotel_name(client_name)
            hotel = hotels_collection.find_one({"hotel_id": slug})

            if not hotel:
                skipped += 1
                continue

            collection.update_one(
                {"_id": doc["_id"]},
                {"$set": {"hotel_id": slug, "updated_at": datetime.now(timezone.utc).isoformat()}}
            )
            updated += 1

        print(f"    Updated {updated} records, skipped {skipped}")
        total_updated += updated

    print(f"\nTotal operational records updated: {total_updated}")
    return total_updated


def verify_migration():
    """Verify migration success."""
    print("\n=== Verifying migration ===")

    # Count hotels
    hotel_count = hotels_collection.count_documents({})
    print(f"Total hotel entities: {hotel_count}")

    # Count client accounts with hotel_id
    client_accounts_with_hotel = client_accounts_collection.count_documents({
        "client_type": "HOTEL",
        "hotel_id": {"$exists": True, "$ne": None}
    })
    print(f"Client accounts with hotel_id: {client_accounts_with_hotel}")

    # Count operational records with hotel_id
    operational_with_hotel = 0
    for collection in [bills_collection, gatepasses_collection, deliveries_collection]:
        count = collection.count_documents({"hotel_id": {"$exists": True, "$ne": None}})
        operational_with_hotel += count
    print(f"Operational records with hotel_id: {operational_with_hotel}")

    # Check for orphaned records (client_name but no hotel_id)
    orphaned_client_accounts = client_accounts_collection.count_documents({
        "client_type": "HOTEL",
        "hotel_id": None
    })
    print(f"Orphaned client accounts (no hotel_id): {orphaned_client_accounts}")

    orphaned_operational = 0
    for collection in [bills_collection, gatepasses_collection, deliveries_collection]:
        count = collection.count_documents({
            "client_name": {"$exists": True},
            "hotel_id": None
        })
        orphaned_operational += count
    print(f"Orphaned operational records (no hotel_id): {orphaned_operational}")


def main():
    import sys
    print("=" * 60)
    print("Hotel Entity Migration Script")
    print("=" * 60)

    # Check for dry-run flag
    dry_run = "--dry-run" in sys.argv or "-d" in sys.argv
    if dry_run:
        print("\n[DRY-RUN MODE] No changes will be made to the database")
        print("=" * 60)

    # Step 1: Analyze
    hotel_names = analyze_hotel_names()

    if not hotel_names:
        print("\nNo hotel names found. Nothing to migrate.")
        return

    if dry_run:
        print("\n" + "=" * 60)
        print("DRY-RUN SUMMARY")
        print("=" * 60)
        print(f"Would create {len(hotel_names)} hotel entities")
        print(f"Would associate client accounts with hotel_id")
        print(f"Would backfill operational records with hotel_id")
        print("\nTo execute the migration, run without --dry-run flag:")
        print("  python migrate_hotels_to_entities.py")
        return

    # Step 2: Create entities
    input("\nPress Enter to create hotel entities...")
    default_laundry = input("Enter default laundry_id (default: lovelaundry): ") or "lovelaundry"
    create_hotel_entities(hotel_names, default_laundry)

    # Step 3: Associate client accounts
    input("\nPress Enter to associate client accounts...")
    associate_client_accounts()

    # Step 4: Backfill operational records
    input("\nPress Enter to backfill operational records...")
    backfill_operational_records()

    # Step 5: Verify
    input("\nPress Enter to verify migration...")
    verify_migration()

    print("\n" + "=" * 60)
    print("Migration complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
