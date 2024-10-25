from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()

db_name = os.getenv("MONGO_DB_NAME")
db_host = os.getenv("MONGO_DB_HOST")
db_port = int(os.getenv("MONGO_DB_PORT", 27017))
db_user = os.getenv("MONGO_DB_USER")
db_password = os.getenv("MONGO_DB_PASSWORD")

client = MongoClient(
    host=db_host,
    port=db_port,
    username=db_user,
    password=db_password,
    authSource=db_name
)
db = client[db_name]
