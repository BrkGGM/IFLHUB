from app import app, db 
import os 

from app import db, app 
with app.app_context():
    db.create_all()