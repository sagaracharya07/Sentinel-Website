"""
Creates a user account directly, for use in environments where demo-account
seeding is disabled (SENTINEL_ENV=production -- see ensure_seed_data() in
app.py). This is the supported way to get a first admin account onto a
production deployment instead of relying on the seeded admin/admin123 demo
credentials.

Usage (from backend/):
    python create_admin.py <username> <password> [--role admin|user]
"""
import argparse
import sys

from app import app
from extensions import db
from models import User
from auth import create_user


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username")
    parser.add_argument("password")
    parser.add_argument("--role", choices=["admin", "user"], default="admin")
    args = parser.parse_args()

    if len(args.password) < 8:
        print("Refusing to create an account with a password under 8 characters.", file=sys.stderr)
        sys.exit(1)

    with app.app_context():
        db.create_all()
        if User.query.filter_by(username=args.username).first():
            print(f"User '{args.username}' already exists.", file=sys.stderr)
            sys.exit(1)
        create_user(args.username, args.password, role=args.role)
        print(f"Created {args.role} account: {args.username}")


if __name__ == "__main__":
    main()
