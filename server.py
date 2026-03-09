
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List
from bson import ObjectId
import os
import secrets
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI
app = FastAPI(title="New School API", version="1.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30

# Database
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
client = AsyncIOMotorClient(MONGO_URL)
db = client.newschool

# Admin email
ADMIN_EMAIL = "newschoolaide@gmail.com"

# Pydantic Models
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: Optional[str] = ""
    gender: Optional[str] = None
    birth_year: Optional[int] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class EventCreate(BaseModel):
    name: str
    description: str
    latitude: float
    longitude: float
    address: Optional[str] = ""
    start_time: datetime
    end_time: datetime
    max_participants: Optional[int] = 50
    theme: Optional[str] = "general"
    gender_filter: Optional[str] = "all"
    min_age: Optional[int] = 18
    max_age: Optional[int] = 99
    photo_base64: Optional[str] = None

class MessageCreate(BaseModel):
    content: str

class SubscriptionUpgrade(BaseModel):
    tier: str

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = await db.users.find_one({"_id": user_id})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def generate_event_id():
    return f"event_{secrets.token_hex(6)}"

# Auth Routes
@app.post("/api/auth/register")
async def register(user: UserCreate):
    existing = await db.users.find_one({"email": user.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_id = f"user_{secrets.token_hex(8)}"
    role = "admin" if user.email == ADMIN_EMAIL else "user"
    
    user_doc = {
        "_id": user_id,
        "email": user.email,
        "password_hash": get_password_hash(user.password),
        "first_name": user.first_name,
        "last_name": user.last_name,
        "gender": user.gender,
        "birth_year": user.birth_year,
        "role": role,
        "subscription_tier": "free",
        "create_credit": 1,
        "join_credit": 3,
        "is_banned": False,
        "created_at": datetime.utcnow()
    }
    
    await db.users.insert_one(user_doc)
    token = create_access_token({"sub": user_id})
    
    return {"access_token": token, "token_type": "bearer", "user": {
        "id": user_id,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "role": role,
        "subscription_tier": "free"
    }}

@app.post("/api/auth/login")
async def login(user: UserLogin):
    db_user = await db.users.find_one({"email": user.email})
    if not db_user or not verify_password(user.password, db_user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if db_user.get("is_banned"):
        raise HTTPException(status_code=403, detail="Account banned")
    
    token = create_access_token({"sub": db_user["_id"]})
    
    return {"access_token": token, "token_type": "bearer", "user": {
        "id": db_user["_id"],
        "email": db_user["email"],
        "first_name": db_user.get("first_name", ""),
        "last_name": db_user.get("last_name", ""),
        "role": db_user.get("role", "user"),
        "subscription_tier": db_user.get("subscription_tier", "free")
    }}

@app.get("/api/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return {
        "id": current_user["_id"],
        "email": current_user["email"],
        "first_name": current_user.get("first_name", ""),
        "last_name": current_user.get("last_name", ""),
        "role": current_user.get("role", "user"),
        "subscription_tier": current_user.get("subscription_tier", "free"),
        "gender": current_user.get("gender"),
        "birth_year": current_user.get("birth_year"),
        "create_credit": current_user.get("create_credit", 1),
        "join_credit": current_user.get("join_credit", 3)
    }

# Event Routes
@app.post("/api/events")
async def create_event(event: EventCreate, current_user: dict = Depends(get_current_user)):
    if current_user.get("create_credit", 0) <= 0:
        raise HTTPException(status_code=403, detail="No create credits left")
    
    event_id = generate_event_id()
    event_doc = {
        "_id": event_id,
        "name": event.name,
        "description": event.description,
        "location": {"type": "Point", "coordinates": [event.longitude, event.latitude]},
        "address": event.address,
        "start_time": event.start_time,
        "end_time": event.end_time,
        "creator_id": current_user["_id"],
        "creator_name": current_user.get("first_name", ""),
        "participants": [current_user["_id"]],
        "max_participants": event.max_participants,
        "theme": event.theme,
        "gender_filter": event.gender_filter,
        "min_age": event.min_age,
        "max_age": event.max_age,
        "photo_base64": event.photo_base64,
        "created_at": datetime.utcnow()
    }
    
    await db.events.insert_one(event_doc)
    await db.users.update_one({"_id": current_user["_id"]}, {"$inc": {"create_credit": -1}})
    
    return {"id": event_id, "message": "Event created successfully"}

@app.get("/api/events")
async def get_events(current_user: dict = Depends(get_current_user)):
    events = await db.events.find().sort("start_time", 1).to_list(100)
    result = []
    for e in events:
        participant_ids = e.get("participants", [])
        participants_data = []
        for pid in participant_ids:
            user = await db.users.find_one({"_id": pid})
            if user:
                participants_data.append({
                    "user_id": pid,
                    "first_name": user.get("first_name", "User"),
                    "photo": user.get("photo"),
                    "joined_at": e.get("created_at", datetime.utcnow()).isoformat()
                })
        
        creator = await db.users.find_one({"_id": e["creator_id"]})
        creator_name = creator.get("first_name", "Organisateur") if creator else "Organisateur"
        creator_photo = creator.get("photo") if creator else None
        
        start = e.get("start_time", datetime.utcnow())
        end = e.get("end_time", start + timedelta(hours=2))
        duration_hours = max(1, int((end - start).total_seconds() / 3600))
        
        result.append({
            "event_id": e["_id"],
            "id": e["_id"],
            "name": e["name"],
            "description": e["description"],
            "latitude": e["location"]["coordinates"][1],
            "longitude": e["location"]["coordinates"][0],
            "location_name": e.get("address", ""),
            "address": e.get("address", ""),
            "start_time": e["start_time"].isoformat(),
            "end_time": e["end_time"].isoformat(),
            "duration_hours": duration_hours,
            "creator_id": e["creator_id"],
            "creator_name": creator_name,
            "creator_photo": creator_photo,
            "participants": participants_data,
            "current_participants": len(participant_ids),
            "max_participants": e.get("max_participants", 50),
            "is_full": len(participant_ids) >= e.get("max_participants", 50),
            "theme": e.get("theme", "general"),
            "photo": e.get("photo_base64"),
            "desired_nationalities": [],
            "status": "active",
            "created_at": e.get("created_at", datetime.utcnow()).isoformat()
        })
    return {"events": result}

@app.get("/api/events/nearby")
async def get_nearby_events(latitude: float, longitude: float, radius_km: float = 50, current_user: dict = Depends(get_current_user)):
    await db.events.create_index([("location", "2dsphere")])
    
    events = await db.events.find({
        "location": {
            "$nearSphere": {
                "$geometry": {"type": "Point", "coordinates": [longitude, latitude]},
                "$maxDistance": radius_km * 1000
            }
        },
        "end_time": {"$gte": datetime.utcnow()}
    }).to_list(100)
    
    result = []
    for e in events:
        participant_ids = e.get("participants", [])
        participants_data = []
        for pid in participant_ids:
            user = await db.users.find_one({"_id": pid})
            if user:
                participants_data.append({
                    "user_id": pid,
                    "first_name": user.get("first_name", "User"),
                    "photo": user.get("photo"),
                    "joined_at": e.get("created_at", datetime.utcnow()).isoformat()
                })
        
        creator = await db.users.find_one({"_id": e["creator_id"]})
        creator_name = creator.get("first_name", "Organisateur") if creator else "Organisateur"
        creator_photo = creator.get("photo") if creator else None
        
        start = e.get("start_time", datetime.utcnow())
        end = e.get("end_time", start + timedelta(hours=2))
        duration_hours = max(1, int((end - start).total_seconds() / 3600))
        
        result.append({
            "event_id": e["_id"],
            "id": e["_id"],
            "name": e["name"],
            "description": e["description"],
            "latitude": e["location"]["coordinates"][1],
            "longitude": e["location"]["coordinates"][0],
            "location_name": e.get("address", ""),
            "address": e.get("address", ""),
            "start_time": e["start_time"].isoformat(),
            "end_time": e["end_time"].isoformat(),
            "duration_hours": duration_hours,
            "creator_id": e["creator_id"],
            "creator_name": creator_name,
            "creator_photo": creator_photo,
            "participants": participants_data,
            "current_participants": len(participant_ids),
            "max_participants": e.get("max_participants", 50),
            "is_full": len(participant_ids) >= e.get("max_participants", 50),
            "theme": e.get("theme", "general"),
            "photo": e.get("photo_base64"),
            "desired_nationalities": [],
            "status": "active",
            "created_at": e.get("created_at", datetime.utcnow()).isoformat()
        })
    return {"events": result}

@app.get("/api/events/{event_id}")
async def get_event(event_id: str, current_user: dict = Depends(get_current_user)):
    event = await db.events.find_one({"_id": event_id})
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    participant_ids = event.get("participants", [])
    participants_data = []
    for pid in participant_ids:
        user = await db.users.find_one({"_id": pid})
        if user:
            participants_data.append({
                "user_id": pid,
                "first_name": user.get("first_name", "User"),
                "photo": user.get("photo"),
                "joined_at": event.get("created_at", datetime.utcnow()).isoformat()
            })
    
    creator = await db.users.find_one({"_id": event["creator_id"]})
    creator_name = creator.get("first_name", "Organisateur") if creator else "Organisateur"
    creator_photo = creator.get("photo") if creator else None
    
    start = event.get("start_time", datetime.utcnow())
    end = event.get("end_time", start + timedelta(hours=2))
    duration_hours = max(1, int((end - start).total_seconds() / 3600))
    
    return {
        "event_id": event["_id"],
        "id": event["_id"],
        "name": event["name"],
        "description": event["description"],
        "latitude": event["location"]["coordinates"][1],
        "longitude": event["location"]["coordinates"][0],
        "location_name": event.get("address", ""),
        "address": event.get("address", ""),
        "start_time": event["start_time"].isoformat(),
        "end_time": event["end_time"].isoformat(),
        "duration_hours": duration_hours,
        "creator_id": event["creator_id"],
        "creator_name": creator_name,
        "creator_photo": creator_photo,
        "participants": participants_data,
        "current_participants": len(participant_ids),
        "max_participants": event.get("max_participants", 50),
        "is_full": len(participant_ids) >= event.get("max_participants", 50),
        "theme": event.get("theme", "general"),
        "photo": event.get("photo_base64"),
        "desired_nationalities": [],
        "status": "active",
        "created_at": event.get("created_at", datetime.utcnow()).isoformat()
    }

@app.post("/api/events/{event_id}/join")
async def join_event(event_id: str, current_user: dict = Depends(get_current_user)):
    event = await db.events.find_one({"_id": event_id})
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    if current_user["_id"] in event.get("participants", []):
        raise HTTPException(status_code=400, detail="Already joined")
    
    if len(event.get("participants", [])) >= event.get("max_participants", 50):
        raise HTTPException(status_code=400, detail="Event is full")
    
    if current_user.get("join_credit", 0) <= 0:
        raise HTTPException(status_code=403, detail="No join credits left")
    
    await db.events.update_one({"_id": event_id}, {"$push": {"participants": current_user["_id"]}})
    await db.users.update_one({"_id": current_user["_id"]}, {"$inc": {"join_credit": -1}})
    
    return {"message": "Joined successfully"}

@app.post("/api/events/{event_id}/leave")
async def leave_event(event_id: str, current_user: dict = Depends(get_current_user)):
    event = await db.events.find_one({"_id": event_id})
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    if event["creator_id"] == current_user["_id"]:
        raise HTTPException(status_code=400, detail="Creator cannot leave")
    
    await db.events.update_one({"_id": event_id}, {"$pull": {"participants": current_user["_id"]}})
    
    return {"message": "Left successfully"}

@app.get("/api/events/user/created")
async def get_user_created_events(current_user: dict = Depends(get_current_user)):
    events = await db.events.find({"creator_id": current_user["_id"]}).to_list(50)
    return [{
        "id": e["_id"],
        "name": e["name"],
        "start_time": e["start_time"].isoformat(),
        "participants": len(e.get("participants", []))
    } for e in events]

@app.get("/api/events/user/joined")
async def get_user_joined_events(current_user: dict = Depends(get_current_user)):
    events = await db.events.find({"participants": current_user["_id"]}).to_list(50)
    return [{
        "id": e["_id"],
        "name": e["name"],
        "start_time": e["start_time"].isoformat(),
        "participants": len(e.get("participants", []))
    } for e in events]

# Messages Routes
@app.get("/api/events/{event_id}/messages")
async def get_messages(event_id: str, current_user: dict = Depends(get_current_user)):
    messages = await db.messages.find({"event_id": event_id}).sort("timestamp", 1).to_list(100)
    return [{
        "id": str(m["_id"]),
        "user_id": m["user_id"],
        "user_name": m.get("user_name", ""),
        "content": m["content"],
        "timestamp": m["timestamp"].isoformat()
    } for m in messages]

@app.post("/api/events/{event_id}/messages")
async def send_message(event_id: str, message: MessageCreate, current_user: dict = Depends(get_current_user)):
    event = await db.events.find_one({"_id": event_id})
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    if current_user["_id"] not in event.get("participants", []):
        raise HTTPException(status_code=403, detail="Not a participant")
    
    msg_doc = {
        "event_id": event_id,
        "user_id": current_user["_id"],
        "user_name": current_user.get("first_name", ""),
        "content": message.content,
        "timestamp": datetime.utcnow()
    }
    
    result = await db.messages.insert_one(msg_doc)
    
    return {"id": str(result.inserted_id), "message": "Sent"}

# Chats Route
@app.get("/api/chats")
async def get_chats(current_user: dict = Depends(get_current_user)):
    events = await db.events.find({"participants": current_user["_id"]}).to_list(50)
    chats = []
    for event in events:
        last_message = await db.messages.find_one({"event_id": event["_id"]}, sort=[("timestamp", -1)])
        chats.append({
            "event_id": event["_id"],
            "event_name": event["name"],
            "last_message": last_message["content"] if last_message else "",
            "last_message_time": last_message["timestamp"].isoformat() if last_message else None,
            "participants_count": len(event.get("participants", []))
        })
    return chats

# Subscription Routes
@app.get("/api/subscriptions/tiers")
async def get_tiers(current_user: dict = Depends(get_current_user)):
    return [
        {"tier": "free", "price": 0, "monthly_limit": 3, "features": ["3 participations/mois", "1 création/mois", "Chat basique"]},
        {"tier": "standard", "price": 9.99, "monthly_limit": 15, "features": ["15 participations/mois", "5 créations/mois", "Chat illimité", "Badge Standard"]},
        {"tier": "ambassador", "price": 19.99, "monthly_limit": 999, "features": ["Participations illimitées", "Créations illimitées", "Badge Ambassadeur", "Support prioritaire"]}
    ]

@app.post("/api/subscriptions/upgrade")
async def upgrade_subscription(data: SubscriptionUpgrade, current_user: dict = Depends(get_current_user)):
    credits = {"free": (1, 3), "standard": (5, 15), "ambassador": (999, 999)}
    create_credit, join_credit = credits.get(data.tier, (1, 3))
    
    await db.users.update_one({"_id": current_user["_id"]}, {
        "$set": {"subscription_tier": data.tier, "create_credit": create_credit, "join_credit": join_credit}
    })
    
    return {"message": "Subscription updated"}

@app.post("/api/subscriptions/sync")
async def sync_subscription(data: SubscriptionUpgrade, current_user: dict = Depends(get_current_user)):
    credits = {"free": (1, 3), "standard": (5, 15), "ambassador": (999, 999)}
    create_credit, join_credit = credits.get(data.tier, (1, 3))
    
    await db.users.update_one({"_id": current_user["_id"]}, {
        "$set": {"subscription_tier": data.tier, "create_credit": create_credit, "join_credit": join_credit}
    })
    
    return {"message": "Subscription synced"}

# User history
@app.get("/api/users/history")
async def get_user_history(current_user: dict = Depends(get_current_user)):
    events = await db.events.find({
        "participants": current_user["_id"],
        "end_time": {"$lt": datetime.utcnow()}
    }).sort("end_time", -1).to_list(50)
    
    return [{
        "id": e["_id"],
        "name": e["name"],
        "start_time": e["start_time"].isoformat(),
        "end_time": e["end_time"].isoformat(),
        "theme": e.get("theme", "general")
    } for e in events]

# Health check
@app.get("/api/health")
async def health():
    return {"status": "ok"}

@app.get("/")
async def root():
    return {"message": "New School API is running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))