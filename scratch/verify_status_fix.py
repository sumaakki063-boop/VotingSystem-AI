
from app import app, OrgUser
import os

with app.app_context():
    for oid in ['ORG010', 'ORG011', 'ORG012', 'ORG013', 'ORG110']:
        ou = OrgUser.query.filter_by(org_id=oid).first()
        if ou:
            print(f"OrgID: {ou.org_id}, Status: '{ou.status}'")
        else:
            print(f"OrgID: {oid} NOT found.")
