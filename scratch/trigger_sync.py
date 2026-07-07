
from app import app, sync_csv_to_db
import os

with app.app_context():
    sync_csv_to_db()
    print("Database status sync complete.")
