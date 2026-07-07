
from app import app, db, OrgUser
import os

with app.app_context():
    org_users = OrgUser.query.all()
    for u in org_users:
        print(f"OrgID: {u.org_id}, Email: {u.email}")
