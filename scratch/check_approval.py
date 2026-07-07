
from app import app, db, User
import os

with app.app_context():
    users = User.query.all()
    for u in users:
        print(f"ID: {u.id}, OrgID: {u.org_id}, Approved: {u.is_approved}, Verified: {u.is_verified}, Email: {u.email}")
