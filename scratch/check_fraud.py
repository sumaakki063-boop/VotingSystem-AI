
from app import app, FraudLog
import os

with app.app_context():
    logs = FraudLog.query.order_by(FraudLog.id.desc()).limit(10).all()
    print("Latest Fraud Logs:")
    for l in logs:
        print(f"ID: {l.id}, User: {l.user_id}, Reason: {l.reason}, Time: {l.timestamp}")
