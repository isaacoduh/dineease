from pymongo import mongo_client
import pymongo
from app.config import settings

client = mongo_client.MongoClient(settings.DATABASE_URL, serverSelectionTimeoutMS=500)

try:
    conn = client.server_info()
    print(f'Connected to MongoDB {conn.get("version")}')
except Exception:
    print("Unable to connect to the MONGODB Server")

db = client[settings.MONGO_INITDB_DATABASE]
User = db.users
User.create_index([("email", pymongo.ASCENDING)], unique=True)