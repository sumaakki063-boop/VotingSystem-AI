
from app import app, Vote
import os

with app.app_context():
    for uid in [11, 12, 13, 14]:
        votes = Vote.query.filter_by(user_id=uid).all()
        print(f"User {uid} has {len(votes)} votes.")
