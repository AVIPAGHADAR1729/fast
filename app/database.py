from pymongo import mongo_client
import pymongo
from .config import settings

client = mongo_client.MongoClient(settings.DATABASE_URL)

db = client[settings.MONGO_INITDB_DATABASE]
User = db.users
Post = db.posts
ResetTokensCollection = db.reset_tokens_collection


User.create_index([("email", pymongo.ASCENDING)], unique=True)
ResetTokensCollection.create_index([("token", pymongo.ASCENDING)], unique=True)