from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from bson import ObjectId
import os
import secrets
import logging
import httpx
import random
import resend
import string
import asyncio
import base64
import io
import re
import html as html_lib
from zoneinfo import ZoneInfo

# Resend configuration
resend.api_key = os.getenv("RESEND_API_KEY")

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

# ============ PHOTOS : compression ============
# Les photos arrivent de l'app en base64, à la taille d'origine du téléphone (souvent plus de 1 Mo).
# On les réduit avant de les enregistrer : c'est ce qui remplissait la base de données.
try:
    from PIL import Image, ImageOps
except ImportError:  # Pillow absent : on garde les photos telles quelles
    Image = None

PHOTO_VERSION = 2
EVENT_PHOTO_SIDE = 1280
AVATAR_SIDE = 512

def compress_photo(data, max_side=EVENT_PHOTO_SIDE, quality=72):
    """Réduit une photo base64 (data URI ou base64 brut) en JPEG de max_side pixels au plus.
    Renvoie un data URI. En cas d'échec, renvoie la photo d'origine."""
    if not data or Image is None or not isinstance(data, str):
        return data
    try:
        raw = data.split(",", 1)[1] if data.startswith("data:") else data
        img = Image.open(io.BytesIO(base64.b64decode(raw)))
        img = ImageOps.exif_transpose(img)
        if img.mode in ("RGBA", "LA", "P"):
            img = img.convert("RGBA")
            bg = Image.new("RGB", img.size, (12, 10, 18))
            bg.paste(img, mask=img.split()[-1])
            img = bg
        elif img.mode != "RGB":
            img = img.convert("RGB")
        img.thumbnail((max_side, max_side))
        out = io.BytesIO()
        img.save(out, "JPEG", quality=quality, optimize=True, progressive=True)
        new = "data:image/jpeg;base64," + base64.b64encode(out.getvalue()).decode()
        return new if len(new) < len(data) else data
    except Exception as e:
        logger.warning(f"Photo non compressée : {e}")
        return data

async def compress_photo_async(data, max_side=EVENT_PHOTO_SIDE):
    return await asyncio.to_thread(compress_photo, data, max_side)

async def compact_existing_photos():
    """Compresse une fois les photos déjà enregistrées (Schools et profils). Sans effet au redémarrage suivant."""
    saved = 0
    try:
        for coll, field, side in ((db.events, "photo_base64", EVENT_PHOTO_SIDE), (db.users, "photo", AVATAR_SIDE)):
            ids = [d["_id"] async for d in coll.find({field: {"$type": "string"}, "photo_v": {"$ne": PHOTO_VERSION}}, {"_id": 1})]
            for _id in ids:
                doc = await coll.find_one({"_id": _id}, {field: 1})
                old = (doc or {}).get(field)
                if not old:
                    continue
                new = await compress_photo_async(old, side)
                saved += len(old) - len(new)
                await coll.update_one({"_id": _id}, {"$set": {field: new, "photo_v": PHOTO_VERSION}})
            logger.info(f"Photos compressées dans {coll.name} : {len(ids)}")
        logger.info(f"Compression des photos terminée : {saved / 1_000_000:.1f} Mo économisés")
    except Exception as e:
        logger.error(f"Compression des photos interrompue : {e}")

@app.on_event("startup")
async def start_photo_compaction():
    asyncio.create_task(compact_existing_photos())

ADMIN_EMAIL = "newschool@ab-digital1.com"

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
    campus: Optional[str] = None

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

async def require_admin(current_user: dict = Depends(get_current_user)):
    """Réservé au compte administrateur."""
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return current_user

@app.delete("/api/admin/cleanup-expired-events")
async def cleanup_expired_events(admin: dict = Depends(require_admin)):
    """Delete all expired events to free up disk space"""
    now = datetime.now(timezone.utc)
    
    # Find expired events
    expired_events = await db.events.find({}).to_list(1000)
    
    deleted_count = 0
    for event in expired_events:
        end_time = event.get("end_time")
        if not end_time:
            continue
        
        if isinstance(end_time, str):
            end_time = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
        if end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone.utc)
        
        if end_time < now:
            await db.events.delete_one({"_id": event["_id"]})
            deleted_count += 1
    
    return {"message": f"Deleted {deleted_count} expired events", "deleted_count": deleted_count}


@app.get("/api/debug/all-events")
async def debug_all_events(admin: dict = Depends(require_admin)):
    """List all events for debugging"""
    now = datetime.now(timezone.utc)
    events = await db.events.find({}).to_list(100)
    result = []
    for e in events:
        end_time = e.get("end_time")
        if isinstance(end_time, str):
            end_time = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
        elif end_time and end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone.utc)
        
        is_expired = end_time < now if end_time else True
        
        result.append({
            "id": e.get("_id"),
            "name": e.get("name"),
            "end_time": str(e.get("end_time")),
            "is_expired": is_expired,
            "has_location": e.get("location") is not None
        })
    return {"server_time_utc": str(now), "total_events": len(result), "events": result}

@app.get("/api/debug/nearby-test")
async def debug_nearby_test(admin: dict = Depends(require_admin)):
    """Test nearby query with Paris coordinates"""
    # Paris coordinates (where the Google event is)
    latitude = 48.858247
    longitude = 2.346296
    radius_km = 50
    
    now = datetime.now(timezone.utc)
    
    # Same query as the real endpoint
    events = await db.events.find({
        "location": {
            "$nearSphere": {
                "$geometry": {"type": "Point", "coordinates": [longitude, latitude]}, 
                "$maxDistance": radius_km * 1000
            }
        }
    }).to_list(100)
    
    result = []
    for e in events:
        end_time = e.get("end_time")
        if isinstance(end_time, str):
            end_time = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
        elif end_time and end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone.utc)
        
        is_expired = end_time < now if end_time else True
        
        result.append({
            "id": e.get("_id"),
            "name": e.get("name"),
            "end_time": str(e.get("end_time")),
            "is_expired": is_expired,
            "would_be_filtered": is_expired or not e.get("end_time")
        })
    
    return {"total_from_geo_query": len(events), "events": result}


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
                    "from": "New School <noreply@ab-digital1.com>",
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
                                📧 newschool@ab-digital1.com
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
                    "from": "New School <noreply@ab-digital1.com>",
                    "to": ["newschool@ab-digital1.com"],
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
 
# ============ REFERRAL LANDING PAGE ============

from fastapi.responses import HTMLResponse, Response

# ============ PARTAGE D'UNE SCHOOL ============
PUBLIC_URL = os.getenv("PUBLIC_URL", "https://newschool-backend-production.up.railway.app").rstrip("/")
APP_STORE_URL = "https://apps.apple.com/us/app/new-school-app/id6760179312"
PLAY_STORE_URL = "https://play.google.com/store/apps/details?id=com.newschoolaide.app"
def iso(d):
    """Date envoyée à l'app : toujours avec le fuseau UTC, pour que le téléphone l'affiche à l'heure locale."""
    if d is None:
        return None
    if isinstance(d, str):
        return d
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.isoformat().replace("+00:00", "Z")

PARIS = ZoneInfo("Europe/Paris")
JOURS = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"]
MOIS = ["janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."]

def _as_utc(d):
    if isinstance(d, str):
        d = datetime.fromisoformat(d.replace("Z", "+00:00"))
    return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d

def _heure(d):
    return f"{d.hour}h{d.minute:02d}" if d.minute else f"{d.hour}h"

def school_when(event):
    now = datetime.now(timezone.utc)
    start = _as_utc(event.get("start_time", now))
    end = _as_utc(event.get("end_time", start + timedelta(hours=2)))
    if end < now:
        return "Cette School est terminée", False
    s, e = start.astimezone(PARIS), end.astimezone(PARIS)
    if start <= now:
        return f"En ce moment · jusqu'à {_heure(e)}", True
    return f"{JOURS[s.weekday()].capitalize()} {s.day} {MOIS[s.month - 1]} à {_heure(s)}", True

@app.get("/s/{event_id}/image.jpg")
async def share_image(event_id: str):
    event = await db.events.find_one({"_id": event_id}, {"photo_base64": 1})
    data = (event or {}).get("photo_base64")
    if not data:
        raise HTTPException(status_code=404, detail="Pas de photo")
    raw = data.split(",", 1)[1] if data.startswith("data:") else data
    return Response(content=base64.b64decode(raw), media_type="image/jpeg", headers={"Cache-Control": "public, max-age=3600"})

@app.get("/s/{event_id}", response_class=HTMLResponse)
async def share_page(event_id: str):
    """Page web d'une School partagée : aperçu WhatsApp/Instagram, puis ouverture de l'app ou téléchargement."""
    event = await db.events.find_one({"_id": event_id}, {"photo_base64": 0})
    esc = html_lib.escape
    if not event:
        name, when, place, count, theme, active, has_photo = "School introuvable", "Ce lien n'est plus valable", "", "", "", False, False
    else:
        when, active = school_when(event)
        name = event.get("name", "School")
        place = event.get("address", "")
        n, mx = len(event.get("participants", [])), event.get("max_participants", 50)
        count = f"{n}/{mx} participants"
        theme = event.get("theme") or ""
        has_photo = bool(await db.events.count_documents({"_id": event_id, "photo_base64": {"$type": "string"}}))
    desc = " · ".join(x for x in (when, place, count) if x) + " · Rejoins-la sur New School, l'app gratuite des sorties spontanées."
    url = f"{PUBLIC_URL}/s/{event_id}"
    og_image = f'<meta property="og:image" content="{PUBLIC_URL}/s/{esc(event_id)}/image.jpg">' if has_photo else ""
    hero = f'<img class="photo" src="/s/{esc(event_id)}/image.jpg" alt="">' if has_photo else '<div class="photo empty"></div>'
    open_btn = f'<a class="btn primary" href="newschool://event/{esc(event_id)}">Ouvrir dans New School</a>' if active else ""
    page = f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(name)} · New School</title>
<meta property="og:type" content="website"><meta property="og:site_name" content="New School">
<meta property="og:title" content="{esc(name)}"><meta property="og:description" content="{esc(desc)}"><meta property="og:url" content="{esc(url)}">
{og_image}<meta name="twitter:card" content="summary_large_image"><meta name="description" content="{esc(desc)}">
<meta name="apple-itunes-app" content="app-id=6760179312, app-argument=newschool://event/{esc(event_id)}">
<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,800&family=Plus+Jakarta+Sans:wght@500;700&display=swap" rel="stylesheet">
<style>
:root{{--bg:#0C0A12;--surface:#16131F;--line:rgba(255,255,255,.1);--text:#F5F3FA;--muted:#A39DB3;--accent:#D946EF;--on:#1A0820;--live:#4ADE80}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font-family:"Plus Jakarta Sans",system-ui,sans-serif;min-height:100vh;display:flex;justify-content:center;padding:24px max(16px,env(safe-area-inset-right)) 32px max(16px,env(safe-area-inset-left))}}
main{{width:100%;max-width:420px;display:flex;flex-direction:column;gap:18px}}
.brand{{font-family:"Bricolage Grotesque",system-ui,sans-serif;font-weight:800;font-size:20px}}
.card{{background:var(--surface);border:1px solid var(--line);border-radius:24px;overflow:hidden}}
.photo{{display:block;width:100%;height:220px;object-fit:cover;background:#2A1A2F}}.photo.empty{{background:linear-gradient(135deg,#3A1B44,#16131F)}}
.body{{padding:18px 18px 20px;display:flex;flex-direction:column;gap:8px}}
.tag{{align-self:flex-start;background:var(--accent);color:var(--on);border-radius:999px;padding:5px 11px;font-size:13px;font-weight:700}}
h1{{font-family:"Bricolage Grotesque",system-ui,sans-serif;font-weight:800;font-size:28px;line-height:1.1;margin:4px 0 0;text-wrap:balance}}
.when{{color:var(--live);font-weight:700;font-size:15px}}.meta{{color:var(--muted);font-size:15px}}
.btn{{display:block;text-align:center;text-decoration:none;font-weight:700;font-size:16px;border-radius:999px;padding:16px;border:1.5px solid var(--line);color:var(--text)}}
.btn.primary{{background:var(--accent);border-color:var(--accent);color:var(--on)}}
.stores{{display:grid;grid-template-columns:1fr 1fr;gap:10px}}
p.note{{color:var(--muted);font-size:13px;text-align:center;margin:0}}
</style></head><body><main>
<div class="brand">New School</div>
<div class="card">{hero}<div class="body">{f'<span class="tag">{esc(theme)}</span>' if theme else ''}<h1>{esc(name)}</h1><div class="when">{esc(when)}</div>
{f'<div class="meta">{esc(place)}</div>' if place else ''}{f'<div class="meta">{esc(count)}</div>' if count else ''}</div></div>
{open_btn}
<div class="stores"><a class="btn" href="{APP_STORE_URL}">App Store</a><a class="btn" href="{PLAY_STORE_URL}">Google Play</a></div>
<p class="note">Pas encore l'app ? Télécharge-la gratuitement, puis rouvre ce lien pour rejoindre la School.</p>
</main></body></html>"""
    return HTMLResponse(content=page)

@app.get("/api/admin/storage")
async def admin_storage(admin: dict = Depends(require_admin)):
    """Place occupée par la base de données, pour surveiller la limite de l'hébergeur."""
    stats = await db.command("dbStats")
    return {k: stats.get(k) for k in ("collections", "objects", "dataSize", "storageSize", "indexSize")}

@app.get("/invite/{referral_code}", response_class=HTMLResponse)
async def referral_landing_page(referral_code: str):
    """Serve the referral landing page"""
    referrer = await db.users.find_one({"referral_code": referral_code})
    referrer_name = referrer.get("first_name", "Un ami") if referrer else "Un ami"
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Rejoins New School !</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }}
            .container {{ background: rgba(255,255,255,0.05); backdrop-filter: blur(10px); border-radius: 24px; padding: 40px; max-width: 400px; width: 100%; text-align: center; border: 1px solid rgba(255,255,255,0.1); }}
            h1 {{ color: #D946EF; font-size: 28px; margin-bottom: 10px; }}
            .subtitle {{ color: #fff; font-size: 18px; margin-bottom: 30px; opacity: 0.9; }}
            .gift {{ font-size: 60px; margin-bottom: 20px; }}
            input {{ width: 100%; padding: 16px; border-radius: 12px; border: 2px solid rgba(217, 70, 239, 0.3); background: rgba(255,255,255,0.1); color: #fff; font-size: 16px; outline: none; margin-bottom: 20px; }}
            input:focus {{ border-color: #D946EF; }}
            input::placeholder {{ color: rgba(255,255,255,0.5); }}
            button {{ width: 100%; padding: 16px; border-radius: 12px; border: none; background: linear-gradient(135deg, #D946EF, #8B5CF6); color: #fff; font-size: 18px; font-weight: bold; cursor: pointer; }}
            button:disabled {{ opacity: 0.5; }}
            .success {{ color: #4ade80; margin-top: 20px; display: none; }}
            .error {{ color: #f87171; margin-top: 10px; font-size: 14px; display: none; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="gift">🎁</div>
            <h1>{referrer_name} t'invite !</h1>
            <p class="subtitle">Rejoins New School et decouvre des evenements pres de chez toi</p>
            <input type="email" id="email" placeholder="Ton adresse email" required>
            <p class="error" id="error"></p>
            <button onclick="submitEmail()" id="submitBtn">Telecharger l'app</button>
            <p class="success" id="success">Parrainage active ! Redirection...</p>
        </div>
        <script>
            async function submitEmail() {{
                const email = document.getElementById('email').value.trim().toLowerCase();
                const btn = document.getElementById('submitBtn');
                const error = document.getElementById('error');
                const success = document.getElementById('success');
                error.style.display = 'none';
                if (!email || !email.includes('@')) {{ error.textContent = 'Entre une adresse email valide'; error.style.display = 'block'; return; }}
                btn.disabled = true; btn.textContent = 'Chargement...';
                try {{
                    const response = await fetch('/api/referral/register-pending', {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ email: email, referral_code: '{referral_code}' }}) }});
                    if (response.ok) {{ success.style.display = 'block'; setTimeout(() => {{ window.location.href = 'https://apps.apple.com/us/app/new-school-app/id6760179312'; }}, 1500); }}
                    else {{ const data = await response.json(); error.textContent = data.detail || 'Erreur'; error.style.display = 'block'; btn.disabled = false; btn.textContent = 'Telecharger l\\'app'; }}
                }} catch (e) {{ error.textContent = 'Erreur de connexion'; error.style.display = 'block'; btn.disabled = false; btn.textContent = 'Telecharger l\\'app'; }}
            }}
            document.getElementById('email').addEventListener('keypress', (e) => {{ if (e.key === 'Enter') submitEmail(); }});
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.post("/api/referral/register-pending")
async def register_pending_referral(data: dict):
    email = data.get("email", "").lower().strip()
    referral_code = data.get("referral_code", "")
    if not email or not referral_code:
        raise HTTPException(status_code=400, detail="Email et code requis")
    referrer = await db.users.find_one({"referral_code": referral_code})
    if not referrer:
        raise HTTPException(status_code=400, detail="Code de parrainage invalide")
    existing_user = await db.users.find_one({"email": email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email deja inscrit")
    await db.pending_referrals.update_one(
        {"email": email},
        {"$set": {"email": email, "referral_code": referral_code, "referrer_id": referrer["_id"], "created_at": datetime.utcnow()}},
        upsert=True
    )
    return {"message": "Parrainage enregistre", "success": True}

# ============ END REFERRAL LANDING PAGE ============



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
    # Check for pending referral
    pending = await db.pending_referrals.find_one({"email": user.email.lower()})
    if pending:
        referrer_id = pending.get("referrer_id")
        if referrer_id:
            await db.users.update_one({"_id": user_id}, {"$set": {"referred_by": referrer_id}})
            await db.users.update_one({"_id": referrer_id}, {"$inc": {"referral_count": 1}})
            referrer = await db.users.find_one({"_id": referrer_id})
            if referrer and referrer.get("referral_count", 0) >= 5:
                await db.users.update_one({"_id": referrer_id}, {"$set": {"subscription_tier": "standard", "subscription_expires": datetime.utcnow() + timedelta(days=180)}})
            await db.pending_referrals.delete_one({"email": user.email.lower()})
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
    print(f"=== FORGOT PASSWORD FOR: {email} ===")
    
    if not email:
        raise HTTPException(status_code=400, detail="Email required")
    
    user = await db.users.find_one({"email": email})
    if not user:
        print(f"USER NOT FOUND: {email}")
        return {"message": "Si cet email existe, un code a été envoyé"}
    
    print(f"USER FOUND: {user['_id']}")
    
    # Generate 6-digit code
    reset_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    expires = datetime.utcnow() + timedelta(minutes=15)
    
    await db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {"reset_token": reset_code, "reset_token_expires": expires}}
    )
    print(f"CODE GENERATED: {reset_code}")
    
    # Send email via Resend
    resend_api_key = os.getenv("RESEND_API_KEY")
    print(f"API KEY EXISTS: {bool(resend_api_key)}")
    print(f"API KEY VALUE: {resend_api_key[:10] if resend_api_key else 'NONE'}...")
    
    if resend_api_key:
        try:
            async with httpx.AsyncClient() as client:
                print("SENDING EMAIL...")
                response = await client.post(
                    "https://api.resend.com/emails",
                    headers={
                        "Authorization": f"Bearer {resend_api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "from": "New School <noreply@ab-digital1.com>",
                        "to": [email],
                        "subject": "Code de reinitialisation New School",
                        "html": f"""
                        <div style="font-family: Arial; max-width: 500px; margin: 0 auto; background: #1A1A1A; padding: 40px; border-radius: 16px;">
                            <h2 style="color: #D946EF;">Reinitialisation de mot de passe</h2>
                            <p style="color: #CCC;">Ton code :</p>
                            <div style="background: #2A2A2A; padding: 20px; border-radius: 10px; text-align: center;">
                                <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #D946EF;">{reset_code}</span>
                            </div>
                            <p style="color: #888;">Ce code expire dans 15 minutes.</p>
                        </div>
                        """
                    }
                )
                print(f"RESEND STATUS: {response.status_code}")
                print(f"RESEND RESPONSE: {response.text}")
        except Exception as e:
            print(f"RESEND ERROR: {e}")
    else:
        print("NO API KEY - EMAIL NOT SENT")
    
    return {"message": "Si cet email existe, un code a été envoyé"}


@app.post("/api/auth/reset-password")
async def reset_password(data: dict):
    """Reset password with 6-digit code"""
    email = data.get("email", "").lower().strip()
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
        "campus": current_user.get("campus") or None,
        "create_credit": 999,  # New School est gratuit : créations illimitées
        "join_credit": 999,  # participations illimitées
        "created_at": iso(current_user.get("created_at")) if current_user.get("created_at") else None
    
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
        "campus": user.get("campus") or None,
        "created_at": iso(user.get("created_at")) if user.get("created_at") else None
    }
class PushTokenRequest(BaseModel):
    push_token: str

@app.post("/api/users/push-token")
async def save_push_token(data: PushTokenRequest, current_user: dict = Depends(get_current_user)):
    """Save user's push notification token"""
    print(f"DEBUG: current_user keys = {current_user.keys()}")
    print(f"DEBUG: current_user _id = {current_user.get('_id')}")
    print(f"DEBUG: push_token = {data.push_token}")
    
    result = await db.users.update_one(
        {"_id": current_user["_id"]},
        {"$set": {"push_token": data.push_token}}
    )
    print(f"DEBUG: matched_count = {result.matched_count}, modified_count = {result.modified_count}")
    
    return {"message": "Push token saved"}

@app.delete("/api/users/push-token")
async def delete_push_token(current_user: dict = Depends(get_current_user)):
    """Remove user's push notification token"""
    await db.users.update_one(
        {"_id": current_user["_id"]},
        {"$unset": {"push_token": ""}}
    )
    return {"message": "Push token removed"}
@app.post("/api/users/location")
async def update_user_location(location: dict, current_user: dict = Depends(get_current_user)):
    """Update user's last known location"""
    latitude = location.get("latitude")
    longitude = location.get("longitude")
    
    if latitude is None or longitude is None:
        raise HTTPException(status_code=400, detail="latitude and longitude required")
    
    await db.users.update_one(
        {"_id": current_user["_id"]},
        {"$set": {
            "last_location": {
                "type": "Point",
                "coordinates": [longitude, latitude]
            },
            "location_updated_at": datetime.utcnow()
        }}
    )
    return {"message": "Location updated"}

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
        update_data["photo"] = await compress_photo_async(data.photo, AVATAR_SIDE)
        update_data["photo_v"] = PHOTO_VERSION
    if data.campus is not None:
        update_data["campus"] = data.campus.strip()[:60]
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
    event_id = generate_event_id()
    start_time = datetime.utcnow()
    if event.duration_days and event.duration_days > 0:
        end_time = start_time + timedelta(days=event.duration_days)
    else:
        end_time = start_time + timedelta(hours=event.duration_hours or 2)
    address = event.location_name or event.address or ""
    photo_data = await compress_photo_async(event.photo or event.photo_base64)
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
        "photo_v": PHOTO_VERSION,
        "campus": current_user.get("campus") or None,
        "created_at": datetime.utcnow()
    }
    await db.events.insert_one(event_doc)
    
    # 🔔 Notifier les utilisateurs proches (dans un rayon de 20km)
    try:
        nearby_users = await db.users.find({
            "last_location": {
                "$near": {
                    "$geometry": {"type": "Point", "coordinates": [event.longitude, event.latitude]},
                    "$maxDistance": 20000  # 20km en mètres
                }
            },
            "push_token": {"$exists": True, "$ne": None},
            "_id": {"$ne": current_user["_id"]}  # Pas le créateur
        }).to_list(100)
        
        for user in nearby_users:
            await send_push_notification(
                user["push_token"],
                "Nouvelle New School près de vous ! 📍",
                f"\"{event.name}\" vient d'être créée",
                {"type": "nearby", "event_id": event_id}
            )
    except Exception as e:
        logger.error(f"Error notifying nearby users: {e}")
    
    return {
        "event_id": event_id,
        "id": event_id,
        "name": event.name,
        "description": event.description,
        "latitude": event.latitude,
        "longitude": event.longitude,
        "location_name": address,
        "address": address,
        "start_time": iso(start_time),
        "end_time": iso(end_time),
        "duration_hours": event.duration_hours or 2,
        "creator_id": current_user["_id"],
        "creator_name": current_user.get("first_name", ""),
        "creator_photo": current_user.get("photo"),
        "participants": [{"user_id": current_user["_id"], "first_name": current_user.get("first_name", "User"), "photo": current_user.get("photo"), "joined_at": iso(datetime.utcnow())}],
        "current_participants": 1,
        "max_participants": event.max_participants or 50,
        "is_full": False,
        "theme": event.theme,
        "photo": photo_data,
        "desired_nationalities": event.desired_nationalities or [],
        "status": "active",
        "created_at": iso(datetime.utcnow())
    }
@app.get("/api/events")
async def get_events(theme: Optional[str] = None, search: Optional[str] = None, campus: Optional[str] = None,
                     current_user: dict = Depends(get_current_user)):
    # Seulement les Schools pas encore terminées, avec les filtres de l'écran Explorer
    query = {"end_time": {"$gt": datetime.utcnow()}}
    if theme:
        query["theme"] = theme
    if campus:
        query["campus"] = campus
    if search and search.strip():
        rx = {"$regex": re.escape(search.strip()[:60]), "$options": "i"}
        query["$or"] = [{"name": rx}, {"description": rx}, {"address": rx}]
    events = await db.events.find(query).sort("start_time", 1).to_list(100)
    result = []
    for e in events:
        participant_ids = e.get("participants", [])
        participants_data = []
        for pid in participant_ids:
            user = await db.users.find_one({"_id": pid})
            if user:
                participants_data.append({"user_id": pid, "first_name": user.get("first_name", "User"), "photo": user.get("photo"), "joined_at": iso(e.get("created_at", datetime.utcnow()))})
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
            "start_time": iso(e["start_time"]),
            "end_time": iso(e["end_time"]),
            "duration_hours": duration_hours,
            "creator_id": e["creator_id"],
            "creator_name": creator_name,
            "creator_photo": creator_photo,
            "participants": participants_data,
            "current_participants": len(participant_ids),
            "max_participants": e.get("max_participants", 50),
            "is_full": len(participant_ids) >= e.get("max_participants", 50),
            "theme": e.get("theme", "general"),
            "campus": e.get("campus"),
            "photo": e.get("photo_base64"),
            "desired_nationalities": e.get("desired_nationalities", []),
            "status": "active",
            "created_at": iso(e.get("created_at", datetime.utcnow()))
        })
    return result

@app.get("/api/events/nearby")
async def get_nearby_events(latitude: float, longitude: float, radius_km: float = 50, current_user: dict = Depends(get_current_user)):
    
    
    # Get current time with timezone awareness
    now = datetime.now(timezone.utc)
    
    # Query with proper date filtering
    events = await db.events.find({
        "location": {
            "$nearSphere": {
                "$geometry": {"type": "Point", "coordinates": [longitude, latitude]}, 
                "$maxDistance": radius_km * 1000
            }
        }
    }).to_list(100)
    
    result = []
    for e in events:
        # Skip events without end_time
        if not e.get("end_time"):
            continue
            
        # Handle end_time - convert to timezone aware if needed
        end_time = e.get("end_time")
        if isinstance(end_time, str):
            end_time = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
        if end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone.utc)
        
        # Skip expired events
        if end_time < now:
            continue
        
        participant_ids = e.get("participants", [])
        participants_data = []
        for pid in participant_ids:
            user = await db.users.find_one({"_id": pid})
            if user:
                participants_data.append({"user_id": pid, "first_name": user.get("first_name", "User"), "photo": user.get("photo"), "joined_at": iso(e.get("created_at", datetime.utcnow()))})
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
            "start_time": iso(e["start_time"]),
            "end_time": iso(e["end_time"]),
            "duration_hours": duration_hours,
            "creator_id": e["creator_id"],
            "creator_name": creator_name,
            "creator_photo": creator_photo,
            "participants": participants_data,
            "current_participants": len(participant_ids),
            "max_participants": e.get("max_participants", 50),
            "is_full": len(participant_ids) >= e.get("max_participants", 50),
            "theme": e.get("theme", "general"),
            "campus": e.get("campus"),
            "photo": e.get("photo_base64"),
            "desired_nationalities": e.get("desired_nationalities", []),
            "status": "active",
            "created_at": iso(e.get("created_at", datetime.utcnow()))
        })
    logger.info(f"🗺️ Returning {len(result)} events")
     
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
            participants_data.append({"user_id": pid, "first_name": user.get("first_name", "User"), "photo": user.get("photo"), "joined_at": iso(event.get("created_at", datetime.utcnow()))})
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
        "start_time": iso(event["start_time"]),
        "end_time": iso(event["end_time"]),
        "duration_hours": duration_hours,
        "creator_id": event["creator_id"],
        "creator_name": creator_name,
        "creator_photo": creator_photo,
        "participants": participants_data,
        "current_participants": len(participant_ids),
        "max_participants": event.get("max_participants", 50),
        "is_full": len(participant_ids) >= event.get("max_participants", 50),
        "theme": event.get("theme", "general"),
        "campus": event.get("campus"),
        "photo": event.get("photo_base64"),
        "desired_nationalities": event.get("desired_nationalities", []),
        "status": "active",
        "created_at": iso(event.get("created_at", datetime.utcnow()))
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
    
    # 🔔 Notifier le créateur
    creator = await db.users.find_one({"_id": event["creator_id"]})
    if creator and creator.get("push_token"):
        leaver_name = current_user.get("first_name", "Quelqu'un")
        await send_push_notification(
            creator["push_token"],
            "Départ d'un participant 👋",
            f"{leaver_name} a quitté votre New School \"{event['name']}\"",
            {"type": "leave", "event_id": event_id}
        )
    
    return {"message": "Left successfully"}
@app.put("/api/events/{event_id}")
async def update_event(event_id: str, event: EventCreate, current_user: dict = Depends(get_current_user)):
    existing_event = await db.events.find_one({"_id": event_id})
    if not existing_event:
        raise HTTPException(status_code=404, detail="Event not found")
    if existing_event["creator_id"] != current_user["_id"]:
        raise HTTPException(status_code=403, detail="Only the creator can edit this event")
    
    address = event.location_name or event.address or ""
    photo_data = await compress_photo_async(event.photo or event.photo_base64)
    
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
        update_data["photo_v"] = PHOTO_VERSION
    
    if event.duration_days and event.duration_days > 0:
        update_data["end_time"] = existing_event["start_time"] + timedelta(days=event.duration_days)
    
    await db.events.update_one({"_id": event_id}, {"$set": update_data})
    
    # 🔔 Notifier tous les participants
    for participant_id in existing_event.get("participants", []):
        if participant_id != current_user["_id"]:
            participant = await db.users.find_one({"_id": participant_id})
            if participant and participant.get("push_token"):
                await send_push_notification(
                    participant["push_token"],
                    "Événement modifié 📝",
                    f"La New School \"{event.name}\" a été mise à jour",
                    {"type": "updated", "event_id": event_id}
                )
    
    return {"message": "Event updated successfully"}


@app.delete("/api/events/{event_id}")
async def delete_event(event_id: str, current_user: dict = Depends(get_current_user)):
    event = await db.events.find_one({"_id": event_id})
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    if event["creator_id"] != current_user["_id"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # 🔔 Notifier tous les participants AVANT de supprimer
    for participant_id in event.get("participants", []):
        if participant_id != current_user["_id"]:
            participant = await db.users.find_one({"_id": participant_id})
            if participant and participant.get("push_token"):
                await send_push_notification(
                    participant["push_token"],
                    "Événement annulé 😔",
                    f"La New School \"{event['name']}\" a été annulée par le créateur",
                    {"type": "cancelled", "event_id": event_id}
                )
    
    await db.events.delete_one({"_id": event_id})
    return {"message": "Event deleted"}

@app.get("/api/events/user/created")
async def get_user_created_events(current_user: dict = Depends(get_current_user)):
    events = await db.events.find({"creator_id": current_user["_id"]}).to_list(50)
    return [{"event_id": e["_id"], "id": e["_id"], "name": e["name"], "start_time": iso(e["start_time"]), "current_participants": len(e.get("participants", [])), "max_participants": e.get("max_participants", 50)} for e in events]

@app.get("/api/events/user/joined")
async def get_user_joined_events(current_user: dict = Depends(get_current_user)):
    events = await db.events.find({"participants": current_user["_id"]}).to_list(50)
    return [{"event_id": e["_id"], "id": e["_id"], "name": e["name"], "start_time": iso(e["start_time"]), "current_participants": len(e.get("participants", [])), "max_participants": e.get("max_participants", 50)} for e in events]


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
            "created_at": iso(m["timestamp"]),
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
        "created_at": iso(datetime.utcnow()),
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
                "created_at": iso(last_message["timestamp"])
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
        {"tier": "free", "price": 0, "monthly_limit": 999, "tagline": "New School est 100 % gratuit", "features": ["Participations illimitées", "Créations illimitées"]}
    ]






@app.post("/api/subscriptions/upgrade")
async def upgrade_subscription(data: SubscriptionUpgrade, current_user: dict = Depends(get_current_user)):
    """Verify subscription with RevenueCat and upgrade"""
    revenuecat_key = os.getenv("REVENUECAT_SECRET_KEY")
    if not revenuecat_key:
        raise HTTPException(status_code=500, detail="RevenueCat not configured")
    
    app_user_id = current_user["_id"]
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://api.revenuecat.com/v1/subscribers/{app_user_id}",
                headers={"Authorization": f"Bearer {revenuecat_key}"}
            )
            
            if response.status_code != 200:
                raise HTTPException(status_code=400, detail="Could not verify subscription")
            
            subscriber_data = response.json()
            entitlements = subscriber_data.get("subscriber", {}).get("entitlements", {})
            
            new_tier = "free"
            for ent_name, ent_data in entitlements.items():
                expires = ent_data.get("expires_date")
                if expires:
                    exp_date = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                    if exp_date > datetime.now(timezone.utc):
                        if ent_name == "Prenium" or ent_name == "NEW SCHOOL Pro":
                            product_id = ent_data.get("product_identifier", "")
                            if "ambassador" in product_id.lower():
                                new_tier = "ambassador"
                                break
                            else:
                                new_tier = "standard"
            
            credits = {"free": (1, 3), "standard": (5, 15), "ambassador": (999, 999)}
            create_credit, join_credit = credits.get(new_tier, (1, 3))
            
            await db.users.update_one(
                {"_id": current_user["_id"]},
                {"$set": {"subscription_tier": new_tier, "create_credit": create_credit, "join_credit": join_credit}}
            )
            
            return {"message": "Subscription verified", "tier": new_tier}
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"RevenueCat error: {e}")
        raise HTTPException(status_code=500, detail="Subscription verification failed")

@app.post("/api/subscriptions/sync")
async def sync_subscription(data: SubscriptionUpgrade, current_user: dict = Depends(get_current_user)):
    """Sync subscription status with RevenueCat"""
    return await upgrade_subscription(data, current_user)



@app.get("/api/users/history")
async def get_user_history(current_user: dict = Depends(get_current_user)):
    events = await db.events.find({"participants": current_user["_id"], "end_time": {"$lt": datetime.utcnow()}}).sort("end_time", -1).to_list(50)
    return [{"id": e["_id"], "name": e["name"], "start_time": iso(e["start_time"]), "end_time": iso(e["end_time"]), "theme": e.get("theme", "general")} for e in events]

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
        "created_at": iso(u.get("created_at")) if u.get("created_at") else None
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
        "created_at": iso(r.get("created_at")) if r.get("created_at") else None
    } for r in reports]

# ======================= REFERRAL SYSTEM =======================

def generate_referral_code():
    """Generate a unique 8-character referral code"""
    chars = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(chars) for _ in range(8))

@app.post("/api/referral/generate-codes")
async def generate_referral_codes_for_all_users(admin: dict = Depends(require_admin)):
    """Generate referral codes for all users who don't have one"""
    users_without_code = await db.users.find({"referral_code": {"$exists": False}}).to_list(1000)
    
    for user in users_without_code:
        code = generate_referral_code()
        # Ensure unique code
        while await db.users.find_one({"referral_code": code}):
            code = generate_referral_code()
        
        await db.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"referral_code": code, "referral_count": 0}}
        )
    
    return {"message": f"Generated codes for {len(users_without_code)} users"}

@app.get("/api/referral/my-link")
async def get_my_referral_link(current_user: dict = Depends(get_current_user)):
    """Get current user's referral link"""
    user = await db.users.find_one({"_id": current_user["_id"]})
    
    if not user.get("referral_code"):
        code = generate_referral_code()
        while await db.users.find_one({"referral_code": code}):
            code = generate_referral_code()
        await db.users.update_one(
            {"_id": current_user["_id"]},
            {"$set": {"referral_code": code, "referral_count": 0}}
        )
    else:
        code = user["referral_code"]
    
    return {
        "referral_code": code,
        "referral_link": f"https://newschool-app.com/invite/{code}",
        "referral_count": user.get("referral_count", 0)
    }

@app.post("/api/auth/register-with-referral")
async def register_with_referral(email: str, password: str, first_name: str, referral_code: str = None):
    """Register a new user with optional referral code"""
    # Check if user exists
    existing = await db.users.find_one({"email": email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash password
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    # Create user
    user_id = f"user_{secrets.token_hex(12)}"
    new_user = {
        "_id": user_id,
        "email": email.lower(),
        "password_hash": password_hash,
        "first_name": first_name,
        "referral_code": generate_referral_code(),
        "referral_count": 0,
        "referred_by": referral_code,
        "subscription_tier": "free",
        "create_credit": 1,
        "join_credit": 3,
        "created_at": datetime.utcnow()
    }
    
    await db.users.insert_one(new_user)
    
    # If referral code provided, increment referrer's count
    if referral_code:
        referrer = await db.users.find_one({"referral_code": referral_code})
        if referrer:
            new_count = referrer.get("referral_count", 0) + 1
            update_data = {"referral_count": new_count}
            
            # If referrer reaches 5 referrals, give them 6 months free standard
            if new_count >= 5 and referrer.get("subscription_tier") == "free":
                update_data["subscription_tier"] = "standard"
                update_data["subscription_reward_until"] = datetime.utcnow() + timedelta(days=180)
                update_data["create_credit"] = 999
                update_data["join_credit"] = 999
            
            await db.users.update_one(
                {"_id": referrer["_id"]},
                {"$set": update_data}
            )
    
    return {"message": "User registered successfully", "user_id": user_id}

@app.post("/api/admin/send-referral-campaign")
async def send_referral_campaign(apple_only: bool = False, admin: dict = Depends(require_admin)):
    """Send referral campaign email to all users"""
    # First, generate codes for all users
    await generate_referral_codes_for_all_users(admin)
    
    # Get all users with email
    if apple_only:
        users = await db.users.find({"email": {"$regex": "@private.appleid.com$"}}).to_list(1000)
    else:
        users = await db.users.find({"email": {"$exists": True}}).to_list(1000)
    
    sent_count = 0
    errors = []
    
    for user in users:
        if not user.get("email"):
            continue
            
        referral_code = user.get("referral_code")
        referral_link = f"https://newschool-backend-production.up.railway.app/invite/{referral_code}"
        first_name = user.get("first_name", "")
        
        try:
            resend.Emails.send({
                "from": "New School <newschool@ab-digital1.com>",
                "to": user["email"],
                "subject": "🎁 Invitez 5 amis = 6 mois d'abonnement GRATUIT !",
                "html": f"""
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h1 style="color: #D946EF;">Bonjour {first_name} ! 👋</h1>
                    
                    <p>Vous faites partie des premiers membres de <strong>New School</strong>, et on voulait vous remercier ! 🎉</p>
                    
                    <p>Pour célébrer notre communauté grandissante, on lance une offre exclusive :</p>
                    
                    <div style="background: linear-gradient(135deg, #D946EF, #8B5CF6); padding: 20px; border-radius: 12px; text-align: center; margin: 20px 0;">
                        <h2 style="color: white; margin: 0;">🎁 INVITEZ 5 AMIS</h2>
                        <h3 style="color: white; margin: 10px 0;">= 6 MOIS D'ABONNEMENT STANDARD GRATUIT</h3>
                    </div>
                    
                    <p><strong>C'est simple :</strong></p>
                    <ol>
                        <li>Partagez votre lien unique ci-dessous</li>
                        <li>Vos amis s'inscrivent via ce lien</li>
                        <li>Dès 5 inscriptions, vous recevez automatiquement 6 mois gratuits !</li>
                    </ol>
                    
                    <div style="background: #1a1a1a; padding: 20px; border-radius: 12px; text-align: center; margin: 20px 0;">
                        <p style="color: #888; margin: 0 0 10px 0;">Votre lien de parrainage :</p>
                        <a href="{referral_link}" style="color: #D946EF; font-size: 18px; font-weight: bold; word-break: break-all;">{referral_link}</a>
                    </div>
                    
                    <p>À très vite sur New School ! 🚀</p>
                    
                    <p style="color: #888;">L'équipe New School</p>
                </div>
                """
            })
            sent_count += 1
        except Exception as e:
            errors.append({"email": user["email"], "error": str(e)})
    
    return {
        "message": f"Campaign sent to {sent_count} users",
        "errors": errors
    }

@app.get("/api/invite/{referral_code}")
async def get_referral_info(referral_code: str):
    """Get info about a referral code (for the invite page)"""
    referrer = await db.users.find_one({"referral_code": referral_code})
    if not referrer:
        raise HTTPException(status_code=404, detail="Invalid referral code")
    
    return {
        "referrer_name": referrer.get("first_name", "Un ami"),
        "referral_code": referral_code
    }



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))

@app.delete("/api/admin/events/{event_id}")
async def admin_delete_event(event_id: str, current_user: dict = Depends(get_current_user)):
    """Admin delete any event"""
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    result = await db.events.delete_one({"_id": event_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Event not found")
    return {"message": "Event deleted"}

@app.post("/api/admin/users/{user_id}/ban")
async def admin_ban_user(user_id: str, current_user: dict = Depends(get_current_user)):
    """Ban a user"""
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    await db.users.update_one({"_id": user_id}, {"$set": {"is_banned": True}})
    return {"message": "User banned"}
