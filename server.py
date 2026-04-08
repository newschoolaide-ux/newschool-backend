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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="New School API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
client = AsyncIOMotorClient(MONGO_URL)
db = client.newschool

ADMIN_EMAIL = "newschoolaide@gmail.com"

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
    location_name: Optional[str] = ""
    address: Optional[str] = ""
    max_participants: Optional[int] = 50
    duration_hours: Optional[int] = 2
    duration_days: Optional[int] = 1
    theme: Optional[str] = None
    gender_filter: Optional[str] = "all"
    age_ranges: Optional[List[str]] = []
    desired_nationalities: Optional[List[str]] = []
    photo: Optional[str] = None
    photo_base64: Optional[str] = None

class MessageCreate(BaseModel):
    content: str

class SubscriptionUpgrade(BaseModel):
    tier: str

class AppleAuthRequest(BaseModel):
    identity_token: str
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    user_identifier: str
class ProfileUpdate(BaseModel):
    first_name: Optional[str] = None
    bio: Optional[str] = None
    phone: Optional[str] = None
    photo: Optional[str] = None
    languages: Optional[List[str]] = []

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
    return {
        "access_token": token,
        "token": token,
        "token_type": "bearer",
        "user": {
            "user_id": user_id,
            "id": user_id,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "role": role,
            "subscription_tier": "free"
        }
    }

@app.post("/api/auth/login")
async def login(user: UserLogin):
    db_user = await db.users.find_one({"email": user.email})
    if not db_user or not verify_password(user.password, db_user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if db_user.get("is_banned"):
        raise HTTPException(status_code=403, detail="Account banned")
    token = create_access_token({"sub": db_user["_id"]})
    return {
        "access_token": token,
        "token": token,
        "token_type": "bearer",
        "user": {
            "user_id": db_user["_id"],
            "id": db_user["_id"],
            "email": db_user["email"],
            "first_name": db_user.get("first_name", ""),
            "last_name": db_user.get("last_name", ""),
            "role": db_user.get("role", "user"),
            "subscription_tier": db_user.get("subscription_tier", "free")
        }
    }
@app.post("/api/auth/apple")
async def apple_auth(data: AppleAuthRequest):
    """Authenticate with Apple Sign In"""
    # Check if user exists by Apple user identifier
    existing_user = await db.users.find_one({"apple_user_id": data.user_identifier})
    
    if existing_user:
        # User exists, log them in
        if existing_user.get("is_banned"):
            raise HTTPException(status_code=403, detail="Account banned")
        token = create_access_token({"sub": existing_user["_id"]})
        return {
            "access_token": token,
            "token": token,
            "token_type": "bearer",
            "user": {
                "user_id": existing_user["_id"],
                "id": existing_user["_id"],
                "email": existing_user.get("email", ""),
                "first_name": existing_user.get("first_name", ""),
                "last_name": existing_user.get("last_name", ""),
                "role": existing_user.get("role", "user"),
                "subscription_tier": existing_user.get("subscription_tier", "free")
            }
        }
    
    # New user - create account
    email = data.email or f"apple_{data.user_identifier[:8]}@private.appleid.com"
    first_name = data.first_name or "Utilisateur"
    last_name = data.last_name or ""
    
    # Check if email already exists
    if data.email:
        email_exists = await db.users.find_one({"email": data.email})
        if email_exists:
            # Link Apple ID to existing account
            await db.users.update_one(
                {"_id": email_exists["_id"]},
                {"$set": {"apple_user_id": data.user_identifier}}
            )
            token = create_access_token({"sub": email_exists["_id"]})
            return {
                "access_token": token,
                "token": token,
                "token_type": "bearer",
                "user": {
                    "user_id": email_exists["_id"],
                    "id": email_exists["_id"],
                    "email": email_exists.get("email", ""),
                    "first_name": email_exists.get("first_name", ""),
                    "last_name": email_exists.get("last_name", ""),
                    "role": email_exists.get("role", "user"),
                    "subscription_tier": email_exists.get("subscription_tier", "free")
                }
            }
    
    # Create new user
    user_id = f"user_{secrets.token_hex(8)}"
    role = "admin" if email == ADMIN_EMAIL else "user"
    
    user_doc = {
        "_id": user_id,
        "email": email,
        "apple_user_id": data.user_identifier,
        "password_hash": None,
        "first_name": first_name,
        "last_name": last_name,
        "role": role,
        "subscription_tier": "free",
        "create_credit": 1,
        "join_credit": 3,
        "is_banned": False,
        "created_at": datetime.utcnow()
    }
    
    await db.users.insert_one(user_doc)
    token = create_access_token({"sub": user_id})
    
    return {
        "access_token": token,
        "token": token,
        "token_type": "bearer",
        "user": {
            "user_id": user_id,
            "id": user_id,
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
            "role": role,
            "subscription_tier": "free"
        }
    }

@app.get("/api/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return {
        "user_id": current_user["_id"],
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
@app.put("/api/users/profile")
async def update_profile(data: ProfileUpdate, current_user: dict = Depends(get_current_user)):
    """Update user profile"""
    update_data = {}
    
    if data.first_name is not None:
        update_data["first_name"] = data.first_name
    if data.bio is not None:
        update_data["bio"] = data.bio
    if data.phone is not None:
        update_data["phone"] = data.phone
    if data.photo is not None:
        update_data["photo"] = data.photo
    if data.languages is not None:
        update_data["languages"] = data.languages
    
    if update_data:
        await db.users.update_one(
            {"_id": current_user["_id"]},
            {"$set": update_data}
        )
    
    return {"message": "Profile updated successfully"}
@app.post("/api/events")
async def create_event(event: EventCreate, current_user: dict = Depends(get_current_user)):
    if current_user.get("create_credit", 0) <= 0:
        raise HTTPException(status_code=403, detail="No create credits left")
    event_id = generate_event_id()
    start_time = datetime.utcnow()
if event.duration_days and event.duration_days > 0:
    end_time = start_time + timedelta(days=event.duration_days)
else:
    end_time = start_time + timedelta(hours=event.duration_hours or 2)
    address = event.location_name or event.address or ""
    photo_data = event.photo or event.photo_base64
    event_doc = {
        "_id": event_id,
        "name": event.name,
        "description": event.description,
        "location": {"type": "Point", "coordinates": [event.longitude, event.latitude]},
        "address": address,
        "start_time": start_time,
        "end_time": end_time,
        "creator_id": current_user["_id"],
        "creator_name": current_user.get("first_name", ""),
        "participants": [current_user["_id"]],
        "max_participants": event.max_participants or 50,
        "theme": event.theme,
        "gender_filter": event.gender_filter or "all",
        "age_ranges": event.age_ranges or [],
        "desired_nationalities": event.desired_nationalities or [],
        "photo_base64": photo_data,
        "created_at": datetime.utcnow()
    }
    await db.events.insert_one(event_doc)
    await db.users.update_one({"_id": current_user["_id"]}, {"$inc": {"create_credit": -1}})
    return {
        "event_id": event_id,
        "id": event_id,
        "name": event.name,
        "description": event.description,
        "latitude": event.latitude,
        "longitude": event.longitude,
        "location_name": address,
        "address": address,
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "duration_hours": event.duration_hours or 2,
        "creator_id": current_user["_id"],
        "creator_name": current_user.get("first_name", ""),
        "creator_photo": current_user.get("photo"),
        "participants": [{"user_id": current_user["_id"], "first_name": current_user.get("first_name", "User"), "photo": current_user.get("photo"), "joined_at": datetime.utcnow().isoformat()}],
        "current_participants": 1,
        "max_participants": event.max_participants or 50,
        "is_full": False,
        "theme": event.theme,
        "photo": photo_data,
        "desired_nationalities": event.desired_nationalities or [],
        "status": "active",
        "created_at": datetime.utcnow().isoformat()
    }

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
                participants_data.append({"user_id": pid, "first_name": user.get("first_name", "User"), "photo": user.get("photo"), "joined_at": e.get("created_at", datetime.utcnow()).isoformat()})
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
            "desired_nationalities": e.get("desired_nationalities", []),
            "status": "active",
            "created_at": e.get("created_at", datetime.utcnow()).isoformat()
        })
    return result

@app.get("/api/events/nearby")
async def get_nearby_events(latitude: float, longitude: float, radius_km: float = 50, current_user: dict = Depends(get_current_user)):
    await db.events.create_index([("location", "2dsphere")])
    events = await db.events.find({"location": {"$nearSphere": {"$geometry": {"type": "Point", "coordinates": [longitude, latitude]}, "$maxDistance": radius_km * 1000}}, "end_time": {"$gte": datetime.utcnow()}}).to_list(100)
    result = []
    for e in events:
        participant_ids = e.get("participants", [])
        participants_data = []
        for pid in participant_ids:
            user = await db.users.find_one({"_id": pid})
            if user:
                participants_data.append({"user_id": pid, "first_name": user.get("first_name", "User"), "photo": user.get("photo"), "joined_at": e.get("created_at", datetime.utcnow()).isoformat()})
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
            "desired_nationalities": e.get("desired_nationalities", []),
            "status": "active",
            "created_at": e.get("created_at", datetime.utcnow()).isoformat()
        })
    return result

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
            participants_data.append({"user_id": pid, "first_name": user.get("first_name", "User"), "photo": user.get("photo"), "joined_at": event.get("created_at", datetime.utcnow()).isoformat()})
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
        "desired_nationalities": event.get("desired_nationalities", []),
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

@app.delete("/api/events/{event_id}")
async def delete_event(event_id: str, current_user: dict = Depends(get_current_user)):
    event = await db.events.find_one({"_id": event_id})
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    if event["creator_id"] != current_user["_id"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    await db.events.delete_one({"_id": event_id})
    return {"message": "Event deleted"}

@app.get("/api/events/user/created")
async def get_user_created_events(current_user: dict = Depends(get_current_user)):
    events = await db.events.find({"creator_id": current_user["_id"]}).to_list(50)
    return [{"id": e["_id"], "name": e["name"], "start_time": e["start_time"].isoformat(), "participants": len(e.get("participants", []))} for e in events]

@app.get("/api/events/user/joined")
async def get_user_joined_events(current_user: dict = Depends(get_current_user)):
    events = await db.events.find({"participants": current_user["_id"]}).to_list(50)
    return [{"id": e["_id"], "name": e["name"], "start_time": e["start_time"].isoformat(), "participants": len(e.get("participants", []))} for e in events]



@app.get("/api/events/{event_id}/messages")
async def get_messages(event_id: str, current_user: dict = Depends(get_current_user)):
    messages = await db.messages.find({"event_id": event_id}).sort("timestamp", 1).to_list(100)
    result = []
    for m in messages:
        sender = await db.users.find_one({"_id": m["user_id"]})
        result.append({
            "message_id": str(m["_id"]),
            "event_id": event_id,
            "sender_id": m["user_id"],
            "sender_name": m.get("user_name", ""),
            "sender_photo": sender.get("photo") if sender else None,
            "content": m["content"],
            "message_type": "text",
            "created_at": m["timestamp"].isoformat(),
            "is_read": True
        })

@app.get("/api/chats")
async def get_chats(current_user: dict = Depends(get_current_user)):
    events = await db.events.find({"participants": current_user["_id"]}).to_list(50)
    chats = []
    for event in events:
        last_message = await db.messages.find_one({"event_id": event["_id"]}, sort=[("timestamp", -1)])
        last_message_data = None
        if last_message:
            last_message_data = {
                "content": last_message["content"],
                "sender_name": last_message.get("user_name", ""),
                "created_at": last_message["timestamp"].isoformat()
            }
        chats.append({
            "event_id": event["_id"],
            "event_name": event["name"],
            "event_theme": event.get("theme", "general"),
            "event_photo": event.get("photo_base64"),
            "last_message": last_message_data,
            "participants_count": len(event.get("participants", [])),
            "unread_count": 0
        })
    return chats
@app.get("/api/subscriptions/tiers")
async def get_tiers(current_user: dict = Depends(get_current_user)):
    return [
        {"tier": "free", "price": 0, "monthly_limit": 4, "tagline": "Découvrez New School", "features": ["3 participations/mois", "1 création/mois"]},
        {"tier": "standard", "price": 4.99, "monthly_limit": 5, "tagline": "Multipliez les rencontres", "features": ["3 participations/mois", "2 créations/mois"]},
        {"tier": "ambassador", "price": 6.99, "monthly_limit": 999, "tagline": "Accès illimité", "features": ["Participations illimitées", "Créations illimitées"]}
    ]

@app.post("/api/subscriptions/upgrade")
async def upgrade_subscription(data: SubscriptionUpgrade, current_user: dict = Depends(get_current_user)):
    credits = {"free": (1, 3), "standard": (5, 15), "ambassador": (999, 999)}
    create_credit, join_credit = credits.get(data.tier, (1, 3))
    await db.users.update_one({"_id": current_user["_id"]}, {"$set": {"subscription_tier": data.tier, "create_credit": create_credit, "join_credit": join_credit}})
    return {"message": "Subscription updated"}

@app.post("/api/subscriptions/sync")
async def sync_subscription(data: SubscriptionUpgrade, current_user: dict = Depends(get_current_user)):
    credits = {"free": (1, 3), "standard": (5, 15), "ambassador": (999, 999)}
    create_credit, join_credit = credits.get(data.tier, (1, 3))
    await db.users.update_one({"_id": current_user["_id"]}, {"$set": {"subscription_tier": data.tier, "create_credit": create_credit, "join_credit": join_credit}})
    return {"message": "Subscription synced"}

@app.get("/api/users/history")
async def get_user_history(current_user: dict = Depends(get_current_user)):
    events = await db.events.find({"participants": current_user["_id"], "end_time": {"$lt": datetime.utcnow()}}).sort("end_time", -1).to_list(50)
    return [{"id": e["_id"], "name": e["name"], "start_time": e["start_time"].isoformat(), "end_time": e["end_time"].isoformat(), "theme": e.get("theme", "general")} for e in events]

@app.get("/api/health")
async def health():
    return {"status": "ok"}

@app.get("/")
async def root():
    return {"message": "New School API is running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
