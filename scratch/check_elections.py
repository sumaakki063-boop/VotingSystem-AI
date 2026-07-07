
from app import app, Election
import os
from datetime import datetime

with app.app_context():
    elections = Election.query.all()
    print("Elections:")
    for e in elections:
        print(f"ID: {e.id}, Title: {e.title}, Status: {e.status}, Phase: {e.phase}, Start: {e.start_date}, End: {e.end_date}")
