from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os

db_uri = 'postgresql://localhost/seanpoh'#os.getenv("CLIENT_URI")
engine = create_engine(db_uri)
connection = engine.connect()
session = sessionmaker(bind=engine)()



#connection.close()