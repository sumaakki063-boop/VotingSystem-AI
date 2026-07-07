
from app import app, OrgUser
import os

with app.app_context():
    ou = OrgUser.query.filter_by(org_id='ORG110').first()
    if ou:
        print(f"Found OrgUser: {ou.full_name}, Status: {ou.status}")
    else:
        print("OrgUser ORG110 NOT found.")
