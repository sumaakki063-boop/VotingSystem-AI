
from app import app, Vote
import os

with app.app_context():
    votes = Vote.query.filter_by(user_id=15).all()
    print(f"User 15 has {len(votes)} votes.")
    for v in votes:
        print(f"Vote ID: {v.id}, Election: {v.election_id}, Phase: {v.phase}")
