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
import httpx
import random


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
    gender: Optional[str] = None
    birth_year: Optional[int] = None

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
async def send_push_notification(push_token: str, title: str, body: str, data: dict = None):
    """Send push notification via Expo"""
    try:
        message = {
            "to": push_token,
            "sound": "default",
            "title": title,
            "body": body,
        }
        if data:
            message["data"] = data
        
        async with httpx.AsyncClient() as client:
            await client.post(
                "https://exp.host/--/api/v2/push/send",
                json=message,
                headers={"Content-Type": "application/json"}
            )
    except Exception as e:
        logger.error(f"Email error: {e}")

def generate_event_id():
    return f"event_{secrets.token_hex(6)}"
async def send_welcome_email(to_email: str, first_name: str):
    """Send welcome email via Resend API"""
    resend_api_key = os.getenv("RESEND_API_KEY")
    
    if not resend_api_key:
        logger.error("RESEND_API_KEY not configured!")
        return
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {resend_api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "from": "New School <onboarding@resend.dev>",
                    "to": [to_email],
                    "subject": "Bienvenue sur New School ! 🎉",
                    "html": f"""
                    <html>
                    <body style="font-family: Arial, sans-serif; background-color: #0A0A0A; color: #FFFFFF; padding: 40px;">
                        <div style="max-width: 600px; margin: 0 auto; background-color: #1A1A1A; border-radius: 16px; padding: 40px;">
                            <h1 style="color: #D946EF;">🎉 Bienvenue {first_name} !</h1>
                            <p style="color: #CCCCCC; font-size: 16px;">Nous sommes ravis de t'accueillir dans la communauté <strong style="color: #D946EF;">New School</strong> !</p>
                            
                            <h2 style="color: #FFFFFF;">✨ Ce que tu peux faire :</h2>
                            <ul style="color: #CCCCCC; font-size: 15px; line-height: 2;">
                                <li>🗺️ <strong>Explorer</strong> les événements près de toi</li>
                                <li>🎯 <strong>Créer</strong> tes propres événements</li>
                                <li>💬 <strong>Discuter</strong> avec les participants</li>
                                <li>👥 <strong>Rencontrer</strong> de nouvelles personnes</li>
                            </ul>
                            
                            <p style="color: #888888; font-size: 14px; margin-top: 40px; border-top: 1px solid #333; padding-top: 20px;">
                                💜 L'équipe New School<br>
                                📧 newschoolaide@gmail.com
                            </p>
                        </div>
                    </body>
                    </html>
                    """
                }
            )
            if response.status_code == 200:
                logger.info(f"Welcome email sent to {to_email}")
            else:
                logger.error(f"Resend error: {response.text}")
    except Exception as e:
        logger.error(f"Email error: {e}")




async def send_admin_notification(user_email: str, first_name: str):
    """Send admin notification via Resend API"""
    resend_api_key = os.getenv("RESEND_API_KEY")
    
    if not resend_api_key:
        return
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {resend_api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "from": "New School <onboarding@resend.dev>",
                    "to": ["newschoolaide@gmail.com"],
                    "subject": f"🆕 Nouvelle inscription : {first_name}",
                    "html": f"""
                    <html>
                    <body style="font-family: Arial, sans-serif; padding: 20px;">
                        <h2>🎉 Nouvelle inscription sur New School !</h2>
                        <p><strong>Prénom :</strong> {first_name}</p>
                        <p><strong>Email :</strong> {user_email}</p>
                    </body>
                    </html>
                    """
                }
            )
            if response.status_code == 200:
                logger.info(f"Admin notification sent for {user_email}")
            else:
                logger.error(f"Admin notification error: {response.text}")
    except Exception as e:
        logger.error(f"Admin notification error: {e}")
 

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
    await send_welcome_email(user.email, user.first_name)
    await send_admin_notification(user.email, user.first_name)
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
@app.post("/api/auth/forgot-password")
async def forgot_password(data: dict):
    """Request password reset - sends 6-digit code via Resend"""
    email = data.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email required")
    
    user = await db.users.find_one({"email": email})
    if not user:
        return {"message": "Si cet email existe, un code a été envoyé"}
    
    # Generate 6-digit code
    reset_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    expires = datetime.utcnow() + timedelta(minutes=15)
    
    await db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {"reset_token": reset_code, "reset_token_expires": expires}}
    )
    
    # Send email via Resend
    resend_api_key = os.getenv("RESEND_API_KEY")
    if resend_api_key:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "https://api.resend.com/emails",
                    headers={
                        "Authorization": f"Bearer {resend_api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "from": "New School <onboarding@resend.dev>",
                        "to": [email],
                        "subject": "🔐 Code de réinitialisation New School",
                        "html": f"""
                        <html>
                        <body style="font-family: Arial, sans-serif; background-color: #0A0A0A; color: #FFFFFF; padding: 40px;">
                            <div style="max-width: 600px; margin: 0 auto; background-color: #1A1A1A; border-radius: 16px; padding: 40px;">
                                <h1 style="color: #D946EF;">🔐 Réinitialisation de mot de passe</h1>
                                <p style="color: #CCCCCC;">Voici ton code de vérification :</p>
                                <div style="background-color: #2A2A2A; border-radius: 12px; padding: 20px; text-align: center; margin: 20px 0;">
                                    <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #D946EF;">{reset_code}</span>
                                </div>
                                <p style="color: #888;">Ce code expire dans 15 minutes.</p>
                                <p style="color: #666; font-size: 12px;">Si tu n'as pas demandé cette réinitialisation, ignore cet email.</p>
                            </div>
                        </body>
                        </html>
                        """
                    }
                )
                print(f"RESEND STATUS: {response.status_code}")
                print(f"RESEND RESPONSE: {response.text}")
        except Exception as e:
            print(f"RESEND ERROR: {e}")
    
    return {"message": "Si cet email existe, un code a été envoyé"}
@app.post("/api/auth/reset-password")
async def reset_password(data: dict):
    """Reset password with 6-digit code"""
    email = data.get("email")
    code = data.get("code")
    new_password = data.get("new_password")
    
    if not all([email, code, new_password]):
        raise HTTPException(status_code=400, detail="Email, code and new_password required")
    
    user = await db.users.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or code")
    
    # Verify code
    if user.get("reset_token") != code:
        raise HTTPException(status_code=400, detail="Invalid code")
    
    # Check expiry
    expires = user.get("reset_token_expires")
    if not expires or expires < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Code expired")
    
    # Update password
    hashed = get_password_hash(new_password)
    await db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {"password_hash": hashed}, "$unset": {"reset_token": "", "reset_token_expires": ""}}
    )
    
    return {"message": "Password reset successfully"}


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
        "languages": current_user.get("languages", []),
        "bio": current_user.get("bio", ""),
        "photo": current_user.get("photo"),
        "create_credit": current_user.get("create_credit", 1),
        "join_credit": current_user.get("join_credit", 3),
        "created_at": current_user.get("created_at").isoformat() if current_user.get("created_at") else None
    
    }
@app.get("/api/users/{user_id}")
async def get_user_profile(user_id: str, current_user: dict = Depends(get_current_user)):
    """Get another user's public profile"""
    user = await db.users.find_one({"_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "user_id": user["_id"],
        "first_name": user.get("first_name", ""),
        "photo": user.get("photo"),
        "bio": user.get("bio", ""),
        "languages": user.get("languages", []),
        "created_at": user.get("created_at").isoformat() if user.get("created_at") else None
    }
class PushTokenRequest(BaseModel):
    push_token: str

@app.post("/api/users/push-token")
async def save_push_token(data: PushTokenRequest, current_user: dict = Depends(get_current_user)):
    """Save user's push notification token"""
    await db.users.update_one(
        {"_id": current_user["_id"]},
        {"$set": {"push_token": data.push_token}}
    )
    return {"message": "Push token saved"}

@app.delete("/api/users/push-token")
async def delete_push_token(current_user: dict = Depends(get_current_user)):
    """Remove user's push notification token"""
    await db.users.update_one(
        {"_id": current_user["_id"]},
        {"$unset": {"push_token": ""}}
    )
    return {"message": "Push token removed"}

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
    if data.gender is not None:
        update_data["gender"] = data.gender
    if data.birth_year is not None:
        update_data["birth_year"] = data.birth_year
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
    
    # Check gender filter
    gender_filter = event.get("gender_filter", "all")
    user_gender = current_user.get("gender")
    
    if gender_filter != "all":
        if not user_gender:
            raise HTTPException(status_code=403, detail="Please set your gender in your profile to join this event")
        if gender_filter == "women" and user_gender != "female":
            raise HTTPException(status_code=403, detail="This event is for women only")
        if gender_filter == "men" and user_gender != "male":
            raise HTTPException(status_code=403, detail="This event is for men only")
    
    await db.events.update_one({"_id": event_id}, {"$push": {"participants": current_user["_id"]}})
    await db.users.update_one({"_id": current_user["_id"]}, {"$inc": {"join_credit": -1}})
    
    # Send push notification to event creator
    creator = await db.users.find_one({"_id": event["creator_id"]})
    if creator and creator.get("push_token"):
        await send_push_notification(
            push_token=creator["push_token"],
            title="Nouveau participant ! 🎉",
            body=f"{current_user.get('first_name', 'Quelqu un')} a rejoint votre événement {event['name']}",
            data={"event_id": event_id}
        )
    
@app.post("/api/events/{event_id}/leave")
async def leave_event(event_id: str, current_user: dict = Depends(get_current_user)):
    event = await db.events.find_one({"_id": event_id})
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    if event["creator_id"] == current_user["_id"]:
        raise HTTPException(status_code=400, detail="Creator cannot leave")
    await db.events.update_one({"_id": event_id}, {"$pull": {"participants": current_user["_id"]}})
    return {"message": "Left successfully"}
@app.put("/api/events/{event_id}")
async def update_event(event_id: str, event: EventCreate, current_user: dict = Depends(get_current_user)):
    existing_event = await db.events.find_one({"_id": event_id})
    if not existing_event:
        raise HTTPException(status_code=404, detail="Event not found")
    if existing_event["creator_id"] != current_user["_id"]:
        raise HTTPException(status_code=403, detail="Only the creator can edit this event")
    
    address = event.location_name or event.address or ""
    photo_data = event.photo or event.photo_base64
    
    update_data = {
        "name": event.name,
        "description": event.description,
        "location": {"type": "Point", "coordinates": [event.longitude, event.latitude]},
        "address": address,
        "max_participants": event.max_participants or 50,
        "theme": event.theme,
        "gender_filter": event.gender_filter or "all",
        "age_ranges": event.age_ranges or [],
        "desired_nationalities": event.desired_nationalities or [],
    }
    
    if photo_data:
        update_data["photo_base64"] = photo_data
    
    if event.duration_days and event.duration_days > 0:
        update_data["end_time"] = existing_event["start_time"] + timedelta(days=event.duration_days)
    
    await db.events.update_one({"_id": event_id}, {"$set": update_data})
    
    return {"message": "Event updated successfully"}

@app.put("/api/events/{event_id}")
async def update_event(event_id: str, event_data: dict, current_user: dict = Depends(get_current_user)):
    """Update an event (creator only)"""
    event = await db.events.find_one({"_id": event_id})
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    if event["creator_id"] != current_user["_id"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    allowed_fields = [
        "name", "description", "location_name", "latitude", "longitude",
        "max_participants", "duration_hours", "desired_nationalities",
        "theme", "photo", "gender_filter", "age_ranges"
    ]
    
    update_data = {k: v for k, v in event_data.items() if k in allowed_fields and v is not None}
    
    if not update_data:
        raise HTTPException(status_code=400, detail="No valid fields to update")
    
    if "max_participants" in update_data:
        current_participants = len(event.get("participants", []))
        if update_data["max_participants"] < current_participants:
            raise HTTPException(
                status_code=400, 
                detail=f"Cannot set max_participants below current participant count ({current_participants})"
            )
    
    await db.events.update_one(
        {"_id": event_id},
        {"$set": update_data}
    )
    
    updated_event = await db.events.find_one({"_id": event_id})
    return updated_event
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
    return [{"event_id": e["_id"], "id": e["_id"], "name": e["name"], "start_time": e["start_time"].isoformat(), "current_participants": len(e.get("participants", [])), "max_participants": e.get("max_participants", 50)} for e in events]

@app.get("/api/events/user/joined")
async def get_user_joined_events(current_user: dict = Depends(get_current_user)):
    events = await db.events.find({"participants": current_user["_id"]}).to_list(50)
    return [{"event_id": e["_id"], "id": e["_id"], "name": e["name"], "start_time": e["start_time"].isoformat(), "current_participants": len(e.get("participants", [])), "max_participants": e.get("max_participants", 50)} for e in events]


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
    return result
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
    
    # Send push notification to all participants except sender
    for participant_id in event.get("participants", []):
        if participant_id != current_user["_id"]:
            participant = await db.users.find_one({"_id": participant_id})
            if participant and participant.get("push_token"):
                await send_push_notification(
                    push_token=participant["push_token"],
                    title=f"Nouveau message dans {event['name']}",
                    body=f"{current_user.get('first_name', 'Quelqu un')}: {message.content[:50]}",
                    data={"event_id": event_id}
                )
    
    return {
        "message_id": str(result.inserted_id),
        "event_id": event_id,
        "sender_id": current_user["_id"],
        "sender_name": current_user.get("first_name", ""),
        "sender_photo": current_user.get("photo"),
        "content": message.content,
        "message_type": "text",
        "created_at": datetime.utcnow().isoformat(),
        "is_read": False
    }

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
    print("=== HEALTH CHECK ===", flush=True)
    email_address = os.getenv("EMAIL_ADDRESS")
    email_password = os.getenv("EMAIL_PASSWORD")
    return {
        "status": "ok",
        "email_configured": bool(email_address),
        "password_configured": bool(email_password)
    }

@app.get("/")
async def root():
    return {"message": "New School API is running"}

# Admin endpoints
@app.get("/api/admin/stats")
async def get_admin_stats(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    
    users_count = await db.users.count_documents({})
    events_count = await db.events.count_documents({})
    active_events = await db.events.count_documents({"end_time": {"$gte": datetime.utcnow()}})
    messages_count = await db.messages.count_documents({})
    
    # Subscription stats
    free_count = await db.users.count_documents({"subscription_tier": "free"})
    standard_count = await db.users.count_documents({"subscription_tier": "standard"})
    ambassador_count = await db.users.count_documents({"subscription_tier": "ambassador"})
    
    return {
        "users_count": users_count,
        "events_count": events_count,
        "active_events": active_events,
        "messages_count": messages_count,
        "subscriptions": {
            "free": free_count,
            "standard": standard_count,
            "ambassador": ambassador_count
        }
    }

@app.get("/api/admin/users")
async def get_admin_users(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    
    users = await db.users.find({}).to_list(500)
    return [{
        "user_id": u["_id"],
        "email": u.get("email", ""),
        "first_name": u.get("first_name", ""),
        "subscription_tier": u.get("subscription_tier", "free"),
        "is_banned": u.get("is_banned", False),
        "created_at": u.get("created_at").isoformat() if u.get("created_at") else None
    } for u in users]

@app.get("/api/admin/reports")
async def get_admin_reports(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    
    reports = await db.reports.find({}).sort("created_at", -1).to_list(100)
    return [{
        "report_id": str(r["_id"]),
        "reporter_id": r.get("reporter_id"),
        "reported_user_id": r.get("reported_user_id"),
        "event_id": r.get("event_id"),
        "reason": r.get("reason", ""),
        "status": r.get("status", "pending"),
        "created_at": r.get("created_at").isoformat() if r.get("created_at") else None
    } for r in reports]



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
