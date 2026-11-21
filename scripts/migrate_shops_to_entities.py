"""
Migration script: Convert shop client_name strings to shop entities.

This script migrates the system from using client_name strings to first-class
shop entities. It:
1. Analyzes existing shop client_name values across all collections
2. Creates shop entities in the shops collection
3. Associates existing client_accounts with shop_id
4. Backfills shop_id on operational records

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
shops_collection = db["shops"]
laundries_collection = db["laundries"]
client_accounts_collection = db["client_accounts"]
# Operational collections to backfill
shop_bills_collection = db["shop_bills"]


def analyze_shop_names():
    """Analyze all unique shop client_name values."""
    print("\n=== Analyzing shop client_name values ===")

    # From client_accounts
    shop_client_names = set()
    for doc in client_accounts_collection.find({"client_type": "SHOP"}):
        if doc.get("client_name"):
            shop_client_names.add(doc["client_name"].strip())

    # From shop_bills
    for doc in shop_bills_collection.find({"client_name": {"$exists": True, "$ne": None}}):
        if doc.get("client_name"):
            shop_client_names.add(doc["client_name"].strip())

    print(f"Found {len(shop_client_names)} unique shop names")
    for name in sorted(shop_client_names):
        print(f"  - {name}")

    return sorted(shop_client_names)


def slugify_shop_name(name: str) -> str:
    """Convert shop name to a valid shop_id slug."""
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
        slug = "s-" + slug[1:]
    return slug


def create_shop_entities(shop_names: list, default_laundry_id: str = "lovelaundry"):
    """Create shop entities from client_name values."""
    print(f"\n=== Creating shop entities (default laundry: {default_laundry_id}) ===")

    # Verify default laundry exists
    laundry = laundries_collection.find_one({"laundry_id": default_laundry_id})
    if not laundry:
        print(f"ERROR: Default laundry '{default_laundry_id}' not found")
        return

    created = 0
    skipped = 0

    for name in shop_names:
        slug = slugify_shop_name(name)

        # Check if already exists
        if shops_collection.find_one({"shop_id": slug}):
            print(f"  SKIP: {name} -> {slug} (already exists)")
            skipped += 1
            continue

        # Create shop entity
        shop_doc = {
            "shop_id": slug,
            "name": name,
            "associated_laundry_id": default_laundry_id,
            "status": "ACTIVE",
            "created_by": "migration-script",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

        shops_collection.insert_one(shop_doc)
        print(f"  CREATE: {name} -> {slug}")
        created += 1

    print(f"\nCreated {created} shop entities, skipped {skipped}")
    return created


def associate_client_accounts():
    """Associate client_accounts with shop_id."""
    print("\n=== Associating client accounts with shop_id ===")

    updated = 0
    skipped = 0

    for doc in client_accounts_collection.find({"client_type": "SHOP", "shop_id": None}):
        client_name = doc.get("client_name")
        if not client_name:
            skipped += 1
            continue

        slug = slugify_shop_name(client_name)
        shop = shops_collection.find_one({"shop_id": slug})

        if not shop:
            print(f"  SKIP: No shop entity for '{client_name}'")
            skipped += 1
            continue

        client_accounts_collection.update_one(
            {"_id": doc["_id"]},
            {"$set": {"shop_id": slug, "updated_at": datetime.now(timezone.utc).isoformat()}}
        )
        print(f"  UPDATE: {client_name} -> {slug}")
        updated += 1

    print(f"\nUpdated {updated} client accounts, skipped {skipped}")
    return updated


def backfill_operational_records():
    """Backfill shop_id on operational records."""
    print("\n=== Backfilling shop_id on operational records ===")

    updated = 0
    skipped = 0

    for doc in shop_bills_collection.find({"client_name": {"$exists": True}, "shop_id": None}):
        client_name = doc.get("client_name")
        if not client_name:
            skipped += 1
            continue

        slug = slugify_shop_name(client_name)
        shop = shops_collection.find_one({"shop_id": slug})

        if not shop:
            skipped += 1
            continue

        shop_bills_collection.update_one(
            {"_id": doc["_id"]},
            {"$set": {"shop_id": slug, "updated_at": datetime.now(timezone.utc).isoformat()}}
        )
        updated += 1

    print(f"Updated {updated} shop bills, skipped {skipped}")
    return updated


def verify_migration():
    """Verify migration success."""
    print("\n=== Verifying migration ===")

    # Count shops
    shop_count = shops_collection.count_documents({})
    print(f"Total shop entities: {shop_count}")

    # Count client accounts with shop_id
    client_accounts_with_shop = client_accounts_collection.count_documents({
        "client_type": "SHOP",
        "shop_id": {"$exists": True, "$ne": None}
    })
    print(f"Client accounts with shop_id: {client_accounts_with_shop}")

    # Count shop bills with shop_id
    shop_bills_with_shop = shop_bills_collection.count_documents({
        "shop_id": {"$exists": True, "$ne": None}
    })
    print(f"Shop bills with shop_id: {shop_bills_with_shop}")

    # Check for orphaned records (client_name but no shop_id)
    orphaned_client_accounts = client_accounts_collection.count_documents({
        "client_type": "SHOP",
        "shop_id": None
    })
    print(f"Orphaned client accounts (no shop_id): {orphaned_client_accounts}")

    orphaned_shop_bills = shop_bills_collection.count_documents({
        "client_name": {"$exists": True},
        "shop_id": None
    })
    print(f"Orphaned shop bills (no shop_id): {orphaned_shop_bills}")


def main():
    import sys
    print("=" * 60)
    print("Shop Entity Migration Script")
    print("=" * 60)

    # Check for dry-run flag
    dry_run = "--dry-run" in sys.argv or "-d" in sys.argv
    if dry_run:
        print("\n[DRY-RUN MODE] No changes will be made to the database")
        print("=" * 60)

    # Step 1: Analyze
    shop_names = analyze_shop_names()

    if not shop_names:
        print("\nNo shop names found. Nothing to migrate.")
        return

    if dry_run:
        print("\n" + "=" * 60)
        print("DRY-RUN SUMMARY")
        print("=" * 60)
        print(f"Would create {len(shop_names)} shop entities")
        print(f"Would associate client accounts with shop_id")
        print(f"Would backfill operational records with shop_id")
        print("\nTo execute the migration, run without --dry-run flag:")
        print("  python migrate_shops_to_entities.py")
        return

    # Step 2: Create entities
    input("\nPress Enter to create shop entities...")
    default_laundry = input("Enter default laundry_id (default: lovelaundry): ") or "lovelaundry"
    create_shop_entities(shop_names, default_laundry)

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
