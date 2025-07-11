from dotenv import load_dotenv
load_dotenv()

import os
import logging

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_login import LoginManager


logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
# create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "temporary_secret_key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)  

# Using SQLite for now - you can switch to PostgreSQL later
# app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///ledger.db"

# app.config["SQLALCHEMY_DATABASE_URI"] = (
#     "postgresql+psycopg2://ledger_db_buuy_user:tUm745S4BBKb0wvzB9sRnvmVAJSrjl5N@dpg-d0s00ac9c44c73cksto0-a.singapore-postgres.render.com/ledger_db_buuy"
# )
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")

app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

db.init_app(app)

with app.app_context():
    import models 

    db.create_all()

    from models import User, Ledger
    from werkzeug.security import generate_password_hash
    
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        logging.info("Creating admin user")
        admin = User(
            username='admin',
            email='admin@example.com',
            password_hash=generate_password_hash('adminpassword'),
            password_hash_dummy=generate_password_hash('admindummy'),
            is_admin=True,
            is_active=True
        )
        db.session.add(admin)
        db.session.flush() 
        
        # Create default ledgers for admin
        real_ledger = Ledger(
            name="Personal Account",
            description="Default personal account",
            is_dummy=False,
            user_id=admin.id
        )
        
        dummy_ledger = Ledger(
            name="Personal Account",
            description="Default personal account",
            is_dummy=True,
            user_id=admin.id
        )
        
        db.session.add(real_ledger)
        db.session.add(dummy_ledger)
        db.session.commit()


import routes