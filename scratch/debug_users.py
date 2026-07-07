
from app import app, db, User
import os

with app.app_context():
    users = User.query.all()
    print(f"Total users: {len(users)}")
    for u in users:
        try:
            email = u.email
            print(f"ID: {u.id}, OrgID: {u.org_id}, Role: {u.role}, Email: {email}")
        except Exception as e:
            print(f"ID: {u.id}, OrgID: {u.org_id}, Role: {u.role}, Email Error: {e}")
