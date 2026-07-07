from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import hashlib
import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

db = SQLAlchemy()

# Encryption setup
ENCRYPTION_KEY = os.environ.get('USER_DATA_ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    # In a real app, this should be persisted in .env
    ENCRYPTION_KEY = Fernet.generate_key().decode()
    print(f"WARNING: USER_DATA_ENCRYPTION_KEY not found. Using generated key: {ENCRYPTION_KEY}")

cipher_suite = Fernet(ENCRYPTION_KEY.encode())

def encrypt_data(data):
    if not data: return None
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(data):
    if not data: return None
    try:
        return cipher_suite.decrypt(data.encode()).decode()
    except:
        return data # Return as is if decryption fails (e.g. for old data)

def hash_data(data):
    if not data: return None
    return hashlib.sha256(data.encode()).hexdigest()

# --- Organization Database (Master Data) ---
class OrgUser(db.Model):
    __bind_key__ = 'org_database'
    __tablename__ = 'organization_users'
    
    org_id = db.Column(db.String(50), primary_key=True)
    org_id_hash = db.Column(db.String(64), index=True) # For lookup
    full_name_enc = db.Column(db.Text, nullable=False)
    full_name_hash = db.Column(db.String(64), index=True) # For lookup
    email_enc = db.Column(db.Text)
    email_hash = db.Column(db.String(64), index=True) # For lookup
    phone_enc = db.Column(db.Text, nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    department = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='Active') # Active, Inactive, Deceased

    @property
    def full_name(self):
        return decrypt_data(self.full_name_enc)
    
    @full_name.setter
    def full_name(self, value):
        self.full_name_enc = encrypt_data(value)
        self.full_name_hash = hash_data(value)

    @property
    def email(self):
        return decrypt_data(self.email_enc)
    
    @email.setter
    def email(self, value):
        self.email_enc = encrypt_data(value)
        self.email_hash = hash_data(value)

    @property
    def phone(self):
        return decrypt_data(self.phone_enc)
    
    @phone.setter
    def phone(self, value):
        self.phone_enc = encrypt_data(value)

# --- Voting System Database (Main App) ---
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.String(50), unique=True, nullable=False)
    org_id_hash = db.Column(db.String(64), index=True)
    name_enc = db.Column(db.Text, nullable=False)
    name_hash = db.Column(db.String(64), index=True)
    email_enc = db.Column(db.Text, unique=True, nullable=False)
    email_hash = db.Column(db.String(64), index=True)
    phone_enc = db.Column(db.Text)
    gender = db.Column(db.String(10))
    age = db.Column(db.Integer)
    password_hash = db.Column(db.String(255), nullable=False)
    photo = db.Column(db.String(255))
    is_verified = db.Column(db.Boolean, default=False) # OTP Verification
    is_approved = db.Column(db.Boolean, default=False) # Admin Approval
    has_voted_phase1 = db.Column(db.Boolean, default=False)
    has_voted_phase2 = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(20), default='voter') # voter, admin

    @property
    def name(self):
        return decrypt_data(self.name_enc)
    
    @name.setter
    def name(self, value):
        self.name_enc = encrypt_data(value)
        self.name_hash = hash_data(value)

    @property
    def email(self):
        return decrypt_data(self.email_enc)
    
    @email.setter
    def email(self, value):
        self.email_enc = encrypt_data(value)
        self.email_hash = hash_data(value)

    @property
    def phone(self):
        return decrypt_data(self.phone_enc)
    
    @phone.setter
    def phone(self, value):
        self.phone_enc = encrypt_data(value)

class Election(db.Model):
    __tablename__ = 'elections'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    phase = db.Column(db.Integer, default=1) # 1: Nomination, 2: Final
    start_date = db.Column(db.DateTime, default=datetime.now)
    phase1_end = db.Column(db.DateTime) # End of Phase 1
    end_date = db.Column(db.DateTime)   # End of Phase 2
    status = db.Column(db.String(20), default='upcoming') # upcoming, active, completed
    is_declared = db.Column(db.Boolean, default=False) # Admin must explicitly declare results
    
    # Relationships
    candidates = db.relationship('Candidate', backref='election', lazy=True)

    votes = db.relationship('Vote', backref='election', lazy=True)

class Candidate(db.Model):
    __tablename__ = 'candidates'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100))
    photo = db.Column(db.String(255))
    education = db.Column(db.Text)
    achievements = db.Column(db.Text)
    manifesto = db.Column(db.Text)
    party_name = db.Column(db.String(100))
    party_logo = db.Column(db.String(255)) # URL or Path to symbol
    election_id = db.Column(db.Integer, db.ForeignKey('elections.id'))
    votes_count = db.Column(db.Integer, default=0) # For summary views
    
    # Manifesto Scores (0-10) for Radar Charts
    m_education = db.Column(db.Integer, default=0)
    m_jobs = db.Column(db.Integer, default=0)
    m_infrastructure = db.Column(db.Integer, default=0)
    m_healthcare = db.Column(db.Integer, default=0)
    m_economy = db.Column(db.Integer, default=0)

class Vote(db.Model):
    __tablename__ = 'votes'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidates.id'))
    election_id = db.Column(db.Integer, db.ForeignKey('elections.id'))
    encrypted_vote = db.Column(db.Text, nullable=False) # AES-256 Fernet
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255)) # For device fingerprinting
    phase = db.Column(db.Integer) # Which phase this vote corresponds to
    voting_speed_seconds = db.Column(db.Integer) # Time from login to vote
    anonymous_token = db.Column(db.String(100), unique=True) # Token to break identity link
    vote_hash = db.Column(db.String(64)) # hash(candidate_id + timestamp + salt)

class ExitPoll(db.Model):
    __tablename__ = 'exit_polls'
    
    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey('elections.id'))
    candidate_id = db.Column(db.Integer, nullable=True) # Optional: who they claim they voted for
    rating = db.Column(db.Integer) # 1-5 rating of candidate promises
    issue_priority = db.Column(db.String(50)) # jobs, environment, etc.
    influence_factor = db.Column(db.String(100)) # e.g. "Previous performance", "Manifesto"
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class FraudLog(db.Model):
    __bind_key__ = 'audit_ledger'
    __tablename__ = 'fraud_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True)
    org_id = db.Column(db.String(50), nullable=True)
    reason = db.Column(db.String(255))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    risk_score = db.Column(db.Float, default=0.0)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Receipt(db.Model):
    __tablename__ = 'receipts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    election_id = db.Column(db.Integer, db.ForeignKey('elections.id'))
    receipt_code = db.Column(db.String(50), unique=True)
    audit_key = db.Column(db.String(100)) # Mapping to PermanentAuditKey
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Explicit Relationship
    election = db.relationship('Election', backref='election_receipts')

# --- Permanent Audit Database (External Ledger) ---
class PermanentAuditKey(db.Model):
    __bind_key__ = 'audit_ledger'
    __tablename__ = 'permanent_audit_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, nullable=False)
    election_title = db.Column(db.String(150))
    user_hash = db.Column(db.String(100), nullable=False) # Hashed User ID for privacy
    unique_key = db.Column(db.String(100), unique=True, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Blockchain(db.Model):
    __bind_key__ = 'audit_ledger'
    __tablename__ = 'blockchain'
    
    index = db.Column(db.Integer, primary_key=True)
    hash = db.Column(db.String(64), nullable=False)
    previous_hash = db.Column(db.String(64), nullable=False)
    vote_data = db.Column(db.Text, nullable=False) # This will be the encrypted_vote + anonymous_token
    merkle_root = db.Column(db.String(64)) # Represents the integrity of the data within the block
    signature = db.Column(db.String(128)) # Digital signature for authenticity
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
