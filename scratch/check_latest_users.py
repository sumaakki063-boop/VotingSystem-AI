
from app import app, User
import os

with app.app_context():
    users = User.query.order_by(User.id.desc()).limit(5).all()
    print("Latest 5 users:")
    for u in users:
        print(f"ID: {u.id}, OrgID: {u.org_id}, Approved: {u.is_approved}, Verified: {u.is_verified}, Name: {u.name}")
