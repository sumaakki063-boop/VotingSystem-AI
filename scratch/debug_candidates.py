
from app import app, db, Candidate
import os

with app.app_context():
    candidates = Candidate.query.all()
    print(f"Total candidates: {len(candidates)}")
    for c in candidates:
        print(f"ID: {c.id}, Name: {c.name}, Email: {c.email}, ElectionID: {c.election_id}")
