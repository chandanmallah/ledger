from app import db, login_manager
from flask_login import UserMixin
from datetime import datetime


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)  # Real password hash
    password_hash_dummy = db.Column(db.String(256), nullable=False)  # Dummy password hash
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    using_dummy = db.Column(db.Boolean, default=False)  # Used to track which data view the user is seeing
    
    ledgers = db.relationship('Ledger', backref='owner', lazy=True)
    connections_sent = db.relationship('Connection', 
                                      foreign_keys='Connection.user_id',
                                      backref='user_source', 
                                      lazy='dynamic')
    connections_received = db.relationship('Connection', 
                                          foreign_keys='Connection.connected_user_id',
                                          backref='user_target', 
                                          lazy='dynamic')


class Ledger(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    is_dummy = db.Column(db.Boolean, default=False, nullable=False)  # Flag for dummy ledgers
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    entries = db.relationship('LedgerEntry', backref='ledger', lazy=True, cascade="all, delete-orphan")


class LedgerEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    is_debit = db.Column(db.Boolean, default=True, nullable=False)  # True for debit, False for credit
    ledger_id = db.Column(db.Integer, db.ForeignKey('ledger.id'), nullable=False)
    connected_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    connected_entry_id = db.Column(db.Integer, db.ForeignKey('ledger_entry.id'), nullable=True)
    
    # Self-referential relationship for linked entries between users
    connected_entry = db.relationship('LedgerEntry', remote_side=[id], backref='linked_entries', uselist=False)
    connected_user = db.relationship('User')


class Connection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    connected_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'connected_user_id', name='unique_connection'),
    )
