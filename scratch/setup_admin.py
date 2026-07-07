from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    # 1. Check if admin exists
    admin = User.query.filter_by(email='admin@gmail.com').first()
    if not admin:
        admin = User(
            org_id='ADMIN001',
            name='Administrator',
            email='admin@gmail.com',
            phone='0000000000',
            password_hash=generate_password_hash('1234'),
            role='admin',
            is_verified=True,
            is_approved=True
        )
        db.session.add(admin)
        print("Created admin user.")
    else:
        admin.password_hash = generate_password_hash('1234')
        admin.role = 'admin'
        admin.is_approved = True
        print("Updated admin user.")
    
    # 2. Remove BCA001 as admin if exists
    suhana = User.query.filter_by(org_id='BCA001').first()
    if suhana and suhana.role == 'admin':
        suhana.role = 'voter'
        print("BCA001 (Suhana) status reverted to voter.")
    
    db.session.commit()
    print("Done.")
