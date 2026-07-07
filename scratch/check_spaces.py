
from app import app, db, User
import os

with app.app_context():
    users = User.query.all()
    for u in users:
        email = u.email
        if email != email.strip():
            print(f"ID: {u.id}, OrgID: {u.org_id}, Email: '{email}' (HAS SPACES!)")
        else:
            print(f"ID: {u.id}, OrgID: {u.org_id}, Email: '{email}' (OK)")
