from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from pymongo import MongoClient
from bson.objectid import ObjectId
import bcrypt

app = FastAPI()

# MongoDB connection
client = MongoClient("mongodb+srv://sushanttarapure:c5WIPD6KYtcw5YGJ@sushantati1.derguct.mongodb.net/")
db = client["authentication"]
users_collection = db["authen"]

# Pydantic models
class User(BaseModel):
    username: str
    password: str

class UserInDB(User):
    hashed_password: str

# Utility functions
def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_user(username: str):
    user = users_collection.find_one({"username": username})
    if user:
        return UserInDB(**user)
    return None

# Routes
@app.post("/register")
async def register(user: User):
    if get_user(user.username):
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    users_collection.insert_one({"username": user.username, "hashed_password": hashed_password})
    return {"msg": "User registered successfully"}

@app.post("/login")
async def login(user: User):
    db_user = get_user(user.username)
    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid username or password")
    if not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    return {"msg": "Login successful"}
