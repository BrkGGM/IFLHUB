from app import app, db 
import os 

os.system("flask db init")
os.system("flask db migrate -m 'update' ")
os.system("flask db upgrade")