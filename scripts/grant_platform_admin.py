"""Grant or revoke the platform-administrator flag for one account.

The flag controls access to the laundry registry (`/laundries`). Only the
bootstrap account receives it automatically, so an account created before the
registry existed has to be promoted once, explicitly:

    python scripts/grant_platform_admin.py <auth_id>            # grant
    python scripts/grant_platform_admin.py <auth_id> --revoke   # revoke
    python scripts/grant_platform_admin.py --list               # show holders

Run from the user-service directory so ``.env`` is found.
"""
import argparse
import os
import sys

from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from user_service.config import settings  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("auth_id", nargs="?", help="Account to promote or demote")
    parser.add_argument("--revoke", action="store_true", help="Remove the flag instead of granting it")
    parser.add_argument("--list", action="store_true", help="List current platform administrators")
    args = parser.parse_args()

    uri = settings.database_url
    db_name = settings.mongodb_db_name
    client = MongoClient(uri, serverSelectionTimeoutMS=10000)
    users = client[db_name]["users"]

    if args.list or not args.auth_id:
        holders = list(users.find({"platform_admin": True}, {"auth_id": 1, "user_name": 1}))
        if not holders:
            print("No platform administrators. Run with an auth_id to promote one.")
        for holder in holders:
            print(f"  {holder.get('auth_id')}  ({holder.get('user_name')})")
        return 0

    result = users.update_one(
        {"auth_id": args.auth_id},
        {"$set": {"platform_admin": not args.revoke}},
    )
    if result.matched_count == 0:
        print(f"No account with auth_id={args.auth_id!r}", file=sys.stderr)
        return 1

    verb = "revoked" if args.revoke else "granted"
    print(f"Platform administrator {verb} for {args.auth_id!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
