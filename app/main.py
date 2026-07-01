import os
import re
import time
import uuid
import hmac
import hashlib
import base64
import json
import threading
from datetime import datetime
from typing import Dict, Set, List, Optional
import requests as http_requests
from fastapi import FastAPI, Request, Depends, UploadFile, File, Form, Header, HTTPException, WebSocket, WebSocketDisconnect, Query
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

FRONTEND_URL = os.getenv("FRONTEND_URL", os.getenv("ALLOWED_ORIGINS", "http://localhost:5173"))
ALLOWED_ORIGINS = [url.strip() for url in FRONTEND_URL.split(",") if url.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Custom exception handlers to match the error JSON format expected by the frontend
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": exc.detail},
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"message": "An unexpected error occurred. Please try again.", "details": str(exc)},
    )

# Upload directory
UPLOAD_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "uploads"))
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Drive video cache directory  —  downloaded once, served to all viewers
CACHE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "cache"))
os.makedirs(CACHE_DIR, exist_ok=True)

JWT_SECRET = os.getenv("JWT_SECRET", "SyncStreamSecretKeyMustBeAtLeast256BitsLongForHMACSHA256AlgorithmSyncStreamSecretKeyMustBeAtLeast256BitsLongForHMACSHA256Algorithm")
SECRET_KEY = JWT_SECRET.encode('utf-8') if isinstance(JWT_SECRET, str) else JWT_SECRET

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def base64url_decode(data: str) -> bytes:
    padding = '=' * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode(data + padding)

def create_jwt(username: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + 86400
    }
    header_encoded = base64url_encode(json.dumps(header).encode('utf-8'))
    payload_encoded = base64url_encode(json.dumps(payload).encode('utf-8'))
    
    signature_base = f"{header_encoded}.{payload_encoded}".encode('utf-8')
    signature = hmac.new(SECRET_KEY, signature_base, hashlib.sha256).digest()
    signature_encoded = base64url_encode(signature)
    
    return f"{header_encoded}.{payload_encoded}.{signature_encoded}"

def verify_jwt(token: str) -> str:
    try:
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid token format")
        
        header_encoded, payload_encoded, signature_encoded = parts
        signature_base = f"{header_encoded}.{payload_encoded}".encode('utf-8')
        expected_signature = hmac.new(SECRET_KEY, signature_base, hashlib.sha256).digest()
        expected_signature_encoded = base64url_encode(expected_signature)
        
        if not hmac.compare_digest(signature_encoded, expected_signature_encoded):
            raise ValueError("Signature mismatch")
            
        payload = json.loads(base64url_decode(payload_encoded).decode('utf-8'))
        if payload.get("exp", 0) < time.time():
            raise ValueError("Token expired")
            
        return payload["sub"]
    except Exception as e:
        raise ValueError(f"Token verification failed: {e}")

# Database context manager and session config
from contextlib import contextmanager
from .database import engine, SessionLocal, Base
from . import models
import bcrypt

# Auto-create tables on startup
import logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("syncstream")

Base.metadata.create_all(bind=engine)
logger.info("Database connection established and tables validated.")

def upload_file_to_cloud(file_name: str, content: bytes, content_type: str) -> Optional[str]:
    """
    Upload a file to Supabase Storage if configured.
    Returns the public download URL if successful, or None to fallback to local storage.
    """
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_KEY")
    supabase_bucket = os.getenv("SUPABASE_BUCKET", "videos")
    
    if supabase_url and supabase_key:
        logger.info(f"Cloud storage configured. Uploading {file_name} to Supabase Storage bucket '{supabase_bucket}'...")
        try:
            base_url = supabase_url.rstrip("/")
            upload_url = f"{base_url}/storage/v1/object/{supabase_bucket}/{file_name}"
            headers = {
                "Authorization": f"Bearer {supabase_key}",
                "apikey": supabase_key,
                "Content-Type": content_type
            }
            r = http_requests.post(upload_url, headers=headers, data=content)
            if r.status_code == 200:
                public_url = f"{base_url}/storage/v1/object/public/{supabase_bucket}/{file_name}"
                logger.info(f"Supabase upload successful! Public URL: {public_url}")
                return public_url
            else:
                logger.error(f"Supabase upload failed: status_code={r.status_code}, response={r.text}")
        except Exception as e:
            logger.error(f"Error during Supabase upload: {e}")
    return None

@contextmanager
def db_session():
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

# Password hashing using bcrypt
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False

# Seed default admin user on startup if not present
with db_session() as db:
    admin_user = db.query(models.User).filter_by(username="admin").first()
    if not admin_user:
        hashed = hash_password("admin")
        admin = models.User(username="admin", password_hash=hashed, role="ROLE_ADMIN")
        db.add(admin)

# In-memory locations and drive caches (ephemeral)
locations_db = {}      # username -> location_dict
drive_cache_db: Dict[str, dict] = {}
_cache_lock = threading.Lock()
viewer_ready_db: Dict[str, Dict[str, float]] = {}

# Pydantic models for request validation
class RegisterRequest(BaseModel):
    username: str
    password: str
    role: Optional[str] = "ROLE_VIEWER"

class LoginRequest(BaseModel):
    username: str
    password: str

class RoomRequest(BaseModel):
    name: str

class LocalVideoMetadataRequest(BaseModel):
    title: str
    fileName: str
    size: int
    duration: float
    resolution: Optional[str] = "Unknown"
    checksum: Optional[str] = None

# Video serializer
def serialize_video(v):
    if not v:
        return None
    return {
        "id": v.id,
        "title": v.title,
        "description": v.description,
        "fileName": v.local_path,
        "contentType": v.content_type,
        "size": v.file_size,
        "duration": v.duration,
        "thumbnailUrl": None,
        "uploadDate": v.upload_date,
        "checksum": v.checksum,
        "downloadUrl": v.download_url,
        "source": v.source,
        "driveFileId": v.drive_file_id,
        "resolution": v.resolution
    }

# Room serializer
def serialize_room(room, db):
    if not room:
        return None
    current_video = None
    if room.current_video_id:
        video = db.query(models.Video).filter_by(id=room.current_video_id).first()
        current_video = serialize_video(video)
    return {
        "id": room.id,
        "name": room.name,
        "code": room.code,
        "currentVideo": current_video,
        "creator": {
            "id": room.creator.id,
            "username": room.creator.username,
            "role": room.creator.role
        },
        "active": room.active,
        "createdAt": room.created_at
    }

# Dependency to retrieve the current user from JWT token
async def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization Header")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization Scheme")
    token = authorization[len("Bearer "):]
    try:
        username = verify_jwt(token)
        with db_session() as db:
            user = db.query(models.User).filter_by(username=username).first()
            if not user:
                raise HTTPException(status_code=401, detail="User not found")
            return {
                "id": user.id,
                "username": user.username,
                "role": user.role
            }
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


# REST Endpoints
@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.post("/api/auth/register")
async def register(req: RegisterRequest):
    with db_session() as db:
        existing = db.query(models.User).filter_by(username=req.username).first()
        if existing:
            return JSONResponse(status_code=400, content={"message": "Username is already taken!"})
        
        role = req.role if req.role else "ROLE_VIEWER"
        if not role.startswith("ROLE_"):
            role = "ROLE_" + role.upper()
            
        hashed = hash_password(req.password)
        new_user = models.User(username=req.username, password_hash=hashed, role=role)
        db.add(new_user)
    return "User registered successfully!"

@app.post("/api/auth/login")
async def login(req: LoginRequest):
    with db_session() as db:
        user = db.query(models.User).filter_by(username=req.username).first()
        if not user or not verify_password(req.password, user.password_hash):
            raise HTTPException(status_code=401, detail="Invalid username or password")
        
        token = create_jwt(user.username)
        return {
            "token": token,
            "tokenType": "Bearer",
            "username": user.username,
            "role": user.role
        }

# Video Management
@app.post("/api/videos/upload")
async def upload_video(
    request: Request,
    file: UploadFile = File(...),
    title: str = Form(...),
    description: Optional[str] = Form(None)
):
    original_filename = file.filename
    file_extension = os.path.splitext(original_filename)[1]
    unique_filename = f"{uuid.uuid4()}{file_extension}"
    
    file_path = os.path.join(UPLOAD_DIR, unique_filename)
    
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)
        
    checksum = hashlib.sha256(content).hexdigest()
    
    with db_session() as db:
        new_video = models.Video(
            title=title,
            description=description,
            source="upload",
            local_path=unique_filename,
            file_size=len(content),
            duration=180.0,
            checksum=checksum,
            content_type=file.content_type or "video/mp4"
        )
        db.add(new_video)
        db.flush()
        
        base_url = str(request.base_url).rstrip("/")
        new_video.download_url = f"{base_url}/api/videos/{new_video.id}/stream"
        db.commit()
        
        serialized = serialize_video(new_video)
        
    return serialized

@app.post("/api/videos/local-metadata")
async def create_local_video_metadata(req: LocalVideoMetadataRequest):
    with db_session() as db:
        new_video = models.Video(
            title=req.title,
            description=f"Local video file (Resolution: {req.resolution})",
            source="local",
            local_path=req.fileName,
            file_size=req.size,
            duration=req.duration,
            checksum=req.checksum,
            content_type="video/mp4",
            resolution=req.resolution
        )
        db.add(new_video)
        db.flush()
        
        new_video.download_url = None
        db.commit()
        
        serialized = serialize_video(new_video)
        
    return serialized

@app.get("/api/videos")
async def get_videos(search: Optional[str] = Query(None)):
    with db_session() as db:
        query = db.query(models.Video)
        if search:
            query = query.filter(models.Video.title.ilike(f"%{search}%"))
        video_list = query.all()
        return [serialize_video(v) for v in video_list]

@app.get("/api/videos/{video_id}")
async def get_video(video_id: int):
    with db_session() as db:
        video = db.query(models.Video).filter_by(id=video_id).first()
        if not video:
            raise HTTPException(status_code=404, detail="Video not found")
        return serialize_video(video)

@app.delete("/api/videos/{video_id}")
async def delete_video(video_id: int):
    with db_session() as db:
        video = db.query(models.Video).filter_by(id=video_id).first()
        if not video:
            raise HTTPException(status_code=404, detail="Video not found")
        
        if video.local_path:
            file_path = os.path.join(UPLOAD_DIR, video.local_path)
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except Exception:
                    pass
                    
        db.delete(video)
    return "Video deleted successfully"

@app.get("/api/videos/{video_id}/stream")
async def stream_video(video_id: int, request: Request):
    with db_session() as db:
        video = db.query(models.Video).filter_by(id=video_id).first()
        if not video:
            raise HTTPException(status_code=404, detail="Video not found")
            
        source = video.source
        drive_file_id = video.drive_file_id
        local_path = video.local_path
        content_type = video.content_type
        
    if source == "drive":
        return await stream_drive_video(drive_file_id, request)
        
    file_path = os.path.join(UPLOAD_DIR, local_path)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Video file not found")
        
    range_header = request.headers.get("range")
    file_size = os.path.getsize(file_path)
    start, end = 0, file_size - 1
    
    if range_header:
        range_value = range_header.strip().split("=")[-1]
        parts = range_value.split("-")
        if parts[0]:
            start = int(parts[0])
        if len(parts) > 1 and parts[1]:
            end = int(parts[1])
            
    chunk_size = min(1024 * 1024, end - start + 1)
    end = start + chunk_size - 1
    
    headers = {
        "Content-Range": f"bytes {start}-{end}/{file_size}",
        "Accept-Ranges": "bytes",
        "Content-Length": str(chunk_size),
        "Content-Type": content_type,
    }
    
    def file_iterator():
        with open(file_path, "rb") as f:
            f.seek(start)
            bytes_to_read = chunk_size
            while bytes_to_read > 0:
                chunk = f.read(min(8192, bytes_to_read))
                if not chunk:
                    break
                yield chunk
                bytes_to_read -= len(chunk)
                
    return StreamingResponse(file_iterator(), status_code=206, headers=headers)

# Room Management
def generate_room_code(db) -> str:
    import random
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    while True:
        code = "".join(random.choice(chars) for _ in range(6))
        existing = db.query(models.Room).filter_by(code=code).first()
        if not existing:
            return code

@app.post("/api/rooms")
async def create_room(req: RoomRequest, user: dict = Depends(get_current_user)):
    with db_session() as db:
        code = generate_room_code(db)
        new_room = models.Room(
            name=req.name,
            code=code,
            creator_id=user["id"],
            current_video_id=None,
            active=True
        )
        db.add(new_room)
        db.flush()
        
        # Initialize playback state
        new_state = models.PlaybackState(
            room_code=code,
            playing=False,
            current_time=0.0,
            last_updated_by_id=user["id"]
        )
        db.add(new_state)
        db.commit()
        
        serialized = serialize_room(new_room, db)
        
    return serialized

@app.get("/api/rooms")
async def get_all_rooms():
    with db_session() as db:
        rooms = db.query(models.Room).all()
        return [serialize_room(r, db) for r in rooms]

@app.post("/api/rooms/join/{code}")
async def join_room(code: str):
    with db_session() as db:
        room = db.query(models.Room).filter_by(code=code).first()
        if not room:
            raise HTTPException(status_code=404, detail="Room not found")
        if not room.active:
            room.active = True
            db.commit()
        return serialize_room(room, db)

@app.get("/api/rooms/{code}")
async def get_room(code: str):
    with db_session() as db:
        room = db.query(models.Room).filter_by(code=code).first()
        if not room:
            raise HTTPException(status_code=404, detail="Room not found")
        return serialize_room(room, db)

@app.get("/api/rooms/{code}/participants")
async def get_participants(code: str):
    return list(room_manager.get_members(code))

@app.get("/api/rooms/{code}/analytics")
async def get_analytics(code: str):
    with db_session() as db:
        room = db.query(models.Room).filter_by(code=code).first()
        if not room:
            raise HTTPException(status_code=404, detail="Room not found")
            
        state = db.query(models.PlaybackState).filter_by(room_code=code).first()
        playing = state.playing if state else False
        video_title = room.current_video.title if room.current_video else "No Active Video"
        current_video_id = room.current_video_id
        
    active_viewers = len(room_manager.get_members(code))
    peak_users = room_manager.peak_users.get(code, 0)
    avg_latency = room_manager.get_avg_latency(code)
    
    playback_status = "PLAYING" if playing else "PAUSED"
    if not current_video_id:
        playback_status = "IDLE"
        
    return {
        "activeViewers": active_viewers,
        "peakUsers": peak_users,
        "averageLatency": avg_latency,
        "playbackStatus": playback_status,
        "currentVideoTitle": video_title
    }

@app.post("/api/rooms/{code}/change-video/{video_id}")
async def change_room_video(code: str, video_id: int, user: dict = Depends(get_current_user)):
    with db_session() as db:
        room = db.query(models.Room).filter_by(code=code).first()
        if not room:
            raise HTTPException(status_code=404, detail="Room not found")
            
        if room.creator.username != user["username"] and user["role"] != "ROLE_ADMIN":
            raise HTTPException(status_code=403, detail="Unauthorized: Only room administrator can change video")
            
        video = db.query(models.Video).filter_by(id=video_id).first()
        if not video:
            raise HTTPException(status_code=404, detail="Video not found")
            
        room.current_video_id = video.id
        
        # Reset playback state
        state = db.query(models.PlaybackState).filter_by(room_code=code).first()
        if not state:
            state = models.PlaybackState(room_code=code)
            db.add(state)
        state.playing = False
        state.current_time = 0.0
        state.last_updated_by_id = user["id"]
        state.last_updated_at = datetime.now().isoformat()
        
        db.commit()
        
        serialized_room = serialize_room(room, db)
        source = video.source
        drive_file_id = video.drive_file_id
        content_type = video.content_type

    # Reset viewer pre-buffer gate for this room
    viewer_ready_db[code] = {}

    # If it's a Drive video, start background caching immediately so viewers
    # get the cached version as soon as they start loading the video.
    if source == "drive" and drive_file_id:
        _start_background_download(drive_file_id, content_type)
        print(f"[Cache] Triggered background download on video change: {drive_file_id}", flush=True)
    
    return serialized_room

@app.delete("/api/rooms/{code}")
async def end_room_session(code: str, user: dict = Depends(get_current_user)):
    with db_session() as db:
        room = db.query(models.Room).filter_by(code=code).first()
        if not room:
            raise HTTPException(status_code=404, detail="Room not found")
            
        if room.creator.username != user["username"] and user["role"] != "ROLE_ADMIN":
            raise HTTPException(status_code=403, detail="Unauthorized: Only room administrator can end session")
            
        room.active = False
    return "Session ended successfully"

@app.get("/api/rooms/{code}/chat-history")
async def get_chat_history(code: str):
    with db_session() as db:
        history = db.query(models.ChatMessage).filter_by(room_code=code).order_by(models.ChatMessage.id.asc()).all()
        return [
            {
                "id": msg.id,
                "sender": msg.sender,
                "content": msg.content,
                "type": msg.type,
                "timestamp": msg.timestamp
            }
            for msg in history
        ]


# ─────────────────────────────────────────────
# Google Drive Integration
# ─────────────────────────────────────────────

def parse_drive_folder_id(url_or_id: str) -> str:
    """Extract folder ID from a Google Drive URL or return ID directly."""
    if 'drive.google.com' in url_or_id or '/' in url_or_id:
        match = re.search(r'/folders/([a-zA-Z0-9_-]+)', url_or_id)
        if match:
            return match.group(1)
        match = re.search(r'id=([a-zA-Z0-9_-]+)', url_or_id)
        if match:
            return match.group(1)
        raise HTTPException(400, "Could not extract folder ID from the provided URL.")
    return url_or_id.strip()


def fetch_drive_folder_files(folder_id: str) -> list:
    """Fetch video file entries from a public Google Drive folder by parsing its HTML."""
    url = f"https://drive.google.com/drive/folders/{folder_id}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
    }
    try:
        resp = http_requests.get(url, headers=headers, timeout=20)
    except Exception as e:
        raise HTTPException(500, f"Failed to connect to Google Drive: {e}")

    if resp.status_code == 403:
        raise HTTPException(403, "Access denied. Set the folder to 'Anyone with the link can view'.")
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, f"Google Drive returned HTTP {resp.status_code}")

    html = resp.text
    if any(p in html for p in ['You need permission', 'Request access', 'To view this page, you need to sign in']):
        raise HTTPException(403, "This Google Drive folder is private. Change sharing to 'Anyone with the link can view'.")

    video_ext = r'(?:mp4|mkv|avi|mov|webm|m4v|mpg|mpeg|wmv|flv|3gp|ts|m2ts)'
    # Drive file IDs are 25–55 alphanumeric chars (+ _ -)
    drive_id_re = r'((?:1[0-9A-Za-z_-]|0[A-Za-z0-9_-])[a-zA-Z0-9_-]{18,53})'
    name_re = rf'"([^"<>]+\.{video_ext})"'

    files = []
    seen_ids: set = set()
    seen_names: set = set()

    # Strategy A: video filename occurs first, ID follows within 2 000 chars
    for nm in re.finditer(name_re, html, re.IGNORECASE):
        name = nm.group(1).split('/')[-1]
        if name in seen_names:
            continue
        window = html[nm.start(): min(len(html), nm.end() + 2000)]
        id_m = re.search(drive_id_re, window)
        if id_m:
            fid = id_m.group(1)
            if fid not in seen_ids:
                seen_ids.add(fid)
                seen_names.add(name)
                files.append({"driveFileId": fid, "name": name})

    # Strategy B: ID first, filename follows within 1 000 chars
    if not files:
        for id_m in re.finditer(drive_id_re, html):
            fid = id_m.group(1)
            if fid in seen_ids:
                continue
            window = html[id_m.end(): min(len(html), id_m.end() + 1000)]
            nm = re.search(name_re, window, re.IGNORECASE)
            if nm:
                name = nm.group(1).split('/')[-1]
                seen_ids.add(fid)
                files.append({"driveFileId": fid, "name": name})

    return files


class DriveFolder(BaseModel):
    folderUrl: str


@app.post("/api/drive/folder")
async def load_drive_folder(req: DriveFolder, request: Request):
    """Load video files from a public Google Drive folder into the video library."""
    try:
        folder_id = parse_drive_folder_id(req.folderUrl)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Invalid Google Drive URL: {e}")

    drive_files = fetch_drive_folder_files(folder_id)

    if not drive_files:
        raise HTTPException(
            404,
            "No video files found in this folder. "
            "Make sure the folder is public and contains MP4/MKV/AVI/etc. files."
        )

    with db_session() as db:
        existing_drive = db.query(models.Video).filter_by(source="drive").all()
        existing_drive_ids = {v.drive_file_id for v in existing_drive if v.drive_file_id}
        
        base_url = str(request.base_url).rstrip("/")
        added = []
        for df in drive_files:
            fid = df["driveFileId"]
            if fid not in existing_drive_ids:
                new_video = models.Video(
                    title=df["name"],
                    description="Streamed from Google Drive",
                    source="drive",
                    local_path=None,
                    file_size=0,
                    duration=180.0,
                    checksum=None,
                    content_type="video/mp4",
                    download_url=f"{base_url}/api/drive/stream/{fid}",
                    drive_file_id=fid
                )
                db.add(new_video)
                db.flush()
                existing_drive_ids.add(fid)
                added.append(serialize_video(new_video))
                
                # Start caching immediately in background
                _start_background_download(fid, "video/mp4")
        
        all_drive_vids = db.query(models.Video).filter_by(source="drive").all()
        serialized_all_drive = [serialize_video(v) for v in all_drive_vids]

    return {"added": len(added), "total": len(drive_files), "videos": serialized_all_drive}



# ─── Drive stream helpers ───────────────────────────────────────────────────

# 2 MB chunks — large enough that the browser can build a solid play buffer
# quickly (same order of magnitude as YouTube's initial segment size).
_DRIVE_CHUNK_SIZE = 2 * 1024 * 1024  # 2 MB


def _resolve_drive_response(
    session: http_requests.Session,
    file_id: str,
    req_headers: dict,
) -> http_requests.Response:
    """
    Resolve a Google Drive download URL, handling the virus-scan confirm page
    that Drive shows for large files.  Returns a streaming Response object
    whose body is the actual video data.
    """
    drive_url = f"https://drive.google.com/uc?export=download&id={file_id}"
    resp = session.get(drive_url, headers=req_headers, stream=True,
                       allow_redirects=True, timeout=30)

    content_type_hdr = resp.headers.get("Content-Type", "")
    if "text/html" not in content_type_hdr:
        return resp  # Already a direct video stream — done.

    # ── Virus-scan warning page: find the bypass token ──────────────────────
    # 1. Cookie-based confirm token (common for smaller large files)
    confirm_token = next(
        (v for k, v in session.cookies.items() if "download_warning" in k.lower()),
        None,
    )
    if confirm_token:
        conf_url = f"{drive_url}&confirm={confirm_token}&uuid={uuid.uuid4()}"
        return session.get(conf_url, headers=req_headers, stream=True,
                           allow_redirects=True, timeout=30)

    body_text = resp.text

    # 2. Parse the download form hidden inputs
    form_match = re.search(
        r'<form id="download-form" action="([^"]+)"[^>]*>(.*?)</form>',
        body_text, re.DOTALL,
    )
    if form_match:
        action_url = form_match.group(1)
        inputs_html = form_match.group(2)
        params = [
            f"{m.group(1)}={m.group(2)}"
            for m in re.finditer(
                r'<input type="hidden" name="([^"]+)" value="([^"]*)"',
                inputs_html,
            )
        ]
        if params:
            conf_url = f"{action_url}?{'&'.join(params)}"
            return session.get(conf_url, headers=req_headers, stream=True,
                               allow_redirects=True, timeout=30)

    # 3. Legacy href-based confirm link
    m = re.search(
        r'href="(https://drive\.google\.com/uc\?[^"]*confirm=[^"]+)"', body_text
    ) or re.search(r'href="(/uc\?[^"]*confirm=[^"]+)"', body_text)
    if m:
        conf_url = m.group(1).replace("&amp;", "&")
        if conf_url.startswith("/"):
            conf_url = "https://drive.google.com" + conf_url
        return session.get(conf_url, headers=req_headers, stream=True,
                           allow_redirects=True, timeout=30)

    # Could not bypass — return whatever we have and let the client deal with it
    return resp


@app.get("/api/drive/prefetch/{file_id}")
async def prefetch_drive_video(file_id: str):
    """
    Warm-up endpoint called by the frontend before playback begins.

    It opens a connection to Google Drive, resolves any confirm-bypass,
    reads the response headers (getting Content-Length when available), then
    immediately closes the body.  The result is returned to the frontend so
    it can:
      • know the real file size (for progress-bar estimates)
      • confirm the stream URL is reachable before setting <video src>
    The side-effect is that the server-side TCP connection to Drive is
    already established and warmed up for the first real range request.
    """
    req_headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        # Request only the first 4 MB so we don't download the whole file.
        "Range": "bytes=0-4194303",
    }
    try:
        session = http_requests.Session()
        resp = _resolve_drive_response(session, file_id, req_headers)

        content_length = resp.headers.get("Content-Length") or resp.headers.get("content-length")
        content_range  = resp.headers.get("Content-Range")  or resp.headers.get("content-range")
        content_type   = resp.headers.get("Content-Type",   "video/mp4")

        # Extract total file size from Content-Range: bytes 0-N/TOTAL
        total_size = None
        if content_range:
            m = re.search(r"/(\d+)$", content_range)
            if m:
                total_size = int(m.group(1))

        # Close the response body — we only needed the headers.
        resp.close()

        return {
            "ready": True,
            "fileId": file_id,
            "contentType": content_type,
            "contentLength": int(content_length) if content_length else None,
            "totalSize": total_size,
        }
    except Exception as e:
        # Non-fatal: frontend will still attempt to play, just without warmup.
        return {"ready": False, "fileId": file_id, "error": str(e)}



# ─────────────────────────────────────────────────────────────────────────────
# Server-Side Cache System
# ─────────────────────────────────────────────────────────────────────────────

def _cache_path(file_id: str) -> str:
    """Return the local file path for a cached Drive file."""
    # Sanitise file_id so it is safe as a filename
    safe = re.sub(r"[^A-Za-z0-9_-]", "_", file_id)
    return os.path.join(CACHE_DIR, f"{safe}.bin")


def _start_background_download(file_id: str, content_type: str = "video/mp4") -> None:
    """
    Start downloading a Google Drive file to the local cache in a background
    thread.  Safe to call multiple times — subsequent calls are no-ops if a
    download is already in progress or complete.
    """
    with _cache_lock:
        existing = drive_cache_db.get(file_id, {})
        if existing.get("status") in ("downloading", "complete"):
            return  # Already running or done — nothing to do
        path = _cache_path(file_id)
        drive_cache_db[file_id] = {
            "status": "downloading",
            "cached_bytes": 0,
            "total_size": None,
            "content_type": content_type,
            "path": path,
            "error": None,
            "started_at": datetime.now().isoformat(),
        }

    def _download_worker():
        WORKER_CHUNK = 512 * 1024  # 512 KB write chunks
        path = _cache_path(file_id)
        session = http_requests.Session()
        req_headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
        }
        sha256_hash = hashlib.sha256()
        try:
            print(f"[Cache] Starting download: {file_id}", flush=True)
            resp = _resolve_drive_response(session, file_id, req_headers)

            # Read total size from headers
            total_size = None
            cl = resp.headers.get("Content-Length") or resp.headers.get("content-length")
            if cl:
                total_size = int(cl)
            cr = resp.headers.get("Content-Range") or resp.headers.get("content-range")
            if cr:
                m = re.search(r"/(\d+)$", cr)
                if m:
                    total_size = int(m.group(1))
            ct = resp.headers.get("Content-Type", "video/mp4")

            with _cache_lock:
                drive_cache_db[file_id]["total_size"] = total_size
                drive_cache_db[file_id]["content_type"] = ct

            written = 0
            with open(path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=WORKER_CHUNK):
                    if not chunk:
                        continue
                    f.write(chunk)
                    sha256_hash.update(chunk)
                    written += len(chunk)
                    with _cache_lock:
                        drive_cache_db[file_id]["cached_bytes"] = written

            checksum = sha256_hash.hexdigest()
            with _cache_lock:
                drive_cache_db[file_id]["status"] = "complete"
                drive_cache_db[file_id]["cached_bytes"] = written
                drive_cache_db[file_id]["total_size"] = written  # authoritative
                drive_cache_db[file_id]["checksum"] = checksum
                drive_cache_db[file_id]["completed_at"] = datetime.now().isoformat()

            # Update database
            with db_session() as db:
                db_vids = db.query(models.Video).filter_by(source="drive", drive_file_id=file_id).all()
                for v in db_vids:
                    v.file_size = written
                    v.checksum = checksum
                db.commit()

            print(f"[Cache] Complete: {file_id} ({written:,} bytes, checksum: {checksum})", flush=True)

        except Exception as exc:
            print(f"[Cache] Error downloading {file_id}: {exc}", flush=True)
            with _cache_lock:
                drive_cache_db[file_id]["status"] = "error"
                drive_cache_db[file_id]["error"] = str(exc)

    t = threading.Thread(target=_download_worker, daemon=True)
    t.start()


def _serve_local_file(path: str, total_size: int, content_type: str, range_header: Optional[str]):
    """
    Serve a fully-cached local file with proper HTTP Range support.
    Returns a StreamingResponse with status 206.
    """
    start, end = 0, total_size - 1

    if range_header:
        try:
            raw = range_header.strip().split("=")[-1]
            parts = raw.split("-")
            if parts[0]:
                start = int(parts[0])
            if len(parts) > 1 and parts[1]:
                end = int(parts[1])
        except ValueError:
            pass

    # Clamp to file bounds
    end = min(end, total_size - 1)
    length = end - start + 1

    headers = {
        "Content-Range": f"bytes {start}-{end}/{total_size}",
        "Accept-Ranges": "bytes",
        "Content-Length": str(length),
        "Content-Type": content_type,
    }

    READ_CHUNK = 1 * 1024 * 1024  # 1 MB read chunks

    def _iter():
        with open(path, "rb") as f:
            f.seek(start)
            remaining = length
            while remaining > 0:
                data = f.read(min(READ_CHUNK, remaining))
                if not data:
                    break
                yield data
                remaining -= len(data)

    return StreamingResponse(_iter(), status_code=206, headers=headers)


# ─────────────────────────────────────────────────────────────────────────────
# Upgraded Drive stream endpoint  (cache-aware)
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/drive/stream/{file_id}")
async def stream_drive_video(file_id: str, request: Request):
    """
    Stream a Google Drive video.

    Priority order:
      1. Complete cache  → serve straight from local file (fastest, no Drive hit)
      2. No / partial cache → proxy from Google Drive AND trigger background
         download so the next viewer gets the cached version
    """
    range_header = request.headers.get("range")
    entry = drive_cache_db.get(file_id)

    # ── 1. Fully cached: serve from disk ──────────────────────────────────────
    if entry and entry.get("status") == "complete":
        path = entry["path"]
        total = entry["total_size"] or os.path.getsize(path)
        ct    = entry.get("content_type", "video/mp4")
        print(f"[Cache] Serving {file_id} from local cache ({total:,} bytes)", flush=True)
        return _serve_local_file(path, total, ct, range_header)

    # ── 2. Not cached (or still downloading) → proxy + trigger download ───────
    # Start background download if not already running
    _start_background_download(file_id)

    req_headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
    }
    if range_header:
        req_headers["Range"] = range_header

    session = http_requests.Session()
    try:
        resp = _resolve_drive_response(session, file_id, req_headers)

        out_headers: dict = {"Accept-Ranges": "bytes"}
        out_headers["Content-Type"] = resp.headers.get("Content-Type", "video/mp4")

        for hdr in ("Content-Length", "Content-Range"):
            val = resp.headers.get(hdr)
            if val:
                out_headers[hdr] = val

        status_code = resp.status_code if resp.status_code in (200, 206) else 200

        def generate():
            for chunk in resp.iter_content(chunk_size=_DRIVE_CHUNK_SIZE):
                if chunk:
                    yield chunk

        return StreamingResponse(generate(), status_code=status_code, headers=out_headers)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to stream from Google Drive: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Cache management REST endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/drive/cache")
async def list_cached_files():
    """List all cached Drive files and their download status."""
    result = []
    for fid, info in drive_cache_db.items():
        total   = info.get("total_size") or 0
        cached  = info.get("cached_bytes", 0)
        percent = round(cached / total * 100, 1) if total else 0
        result.append({
            "fileId":       fid,
            "status":       info.get("status"),
            "cachedBytes":  cached,
            "totalSize":    total,
            "percent":      percent,
            "contentType":  info.get("content_type"),
            "startedAt":    info.get("started_at"),
            "completedAt":  info.get("completed_at"),
            "error":        info.get("error"),
            "checksum":     info.get("checksum"),
        })
    return result


@app.get("/api/drive/cache/{file_id}")
async def get_cache_status(file_id: str):
    """Return the current download/cache status for a single Drive file."""
    info = drive_cache_db.get(file_id)
    if not info:
        # Also check if the file already exists on disk from a previous run
        path = _cache_path(file_id)
        if os.path.exists(path):
            size = os.path.getsize(path)
            # Calculate checksum
            try:
                with open(path, "rb") as f:
                    chk = hashlib.sha256(f.read()).hexdigest()
            except Exception:
                chk = None
            with _cache_lock:
                drive_cache_db[file_id] = {
                    "status": "complete",
                    "cached_bytes": size,
                    "total_size": size,
                    "content_type": "video/mp4",
                    "path": path,
                    "error": None,
                    "checksum": chk,
                }
            info = drive_cache_db[file_id]
        else:
            return {"fileId": file_id, "status": "not_cached", "cachedBytes": 0,
                    "totalSize": None, "percent": 0}

    total   = info.get("total_size") or 0
    cached  = info.get("cached_bytes", 0)
    percent = round(cached / total * 100, 1) if total else 0
    return {
        "fileId":      file_id,
        "status":      info.get("status"),
        "cachedBytes": cached,
        "totalSize":   total,
        "percent":     percent,
        "contentType": info.get("content_type"),
        "error":       info.get("error"),
        "checksum":    info.get("checksum"),
    }


@app.delete("/api/drive/cache/{file_id}")
async def evict_cache(file_id: str):
    """Remove a cached Drive file from disk and the in-memory registry."""
    info = drive_cache_db.pop(file_id, None)
    path = _cache_path(file_id)
    if os.path.exists(path):
        try:
            os.remove(path)
        except Exception:
            pass
    if not info and not os.path.exists(path):
        raise HTTPException(404, "No cached file found for this ID")
    return {"message": f"Cache evicted for {file_id}"}


# ─────────────────────────────────────────────────────────────────────────────
# Viewer Pre-Buffer Readiness endpoint
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/rooms/{code}/viewer-readiness")
async def get_viewer_readiness(code: str):
    """
    Return the current viewer buffering readiness for a room.
    Used by the admin to know when all viewers have buffered enough to play.
    """
    with db_session() as db:
        room = db.query(models.Room).filter_by(code=code).first()
        if not room:
            raise HTTPException(404, "Room not found")

    members        = room_manager.get_members(code)
    total_viewers  = len(members)
    ready_info     = viewer_ready_db.get(code, {})

    _READY_THRESHOLD = 5.0  # seconds that count as "ready"

    viewers_detail = [
        {
            "username":       u,
            "bufferedSeconds": ready_info.get(u, 0.0),
            "isReady":        ready_info.get(u, 0.0) >= _READY_THRESHOLD,
        }
        for u in members
    ]

    ready_count = sum(1 for v in viewers_detail if v["isReady"])
    all_ready   = total_viewers > 0 and ready_count >= total_viewers

    return {
        "totalViewers":  total_viewers,
        "readyViewers":  ready_count,
        "allReady":      all_ready,
        "viewers":       viewers_detail,
    }



class StompConnection:
    def __init__(self, websocket: WebSocket):
        self.websocket = websocket
        self.username = None
        self.room_code = None
        self.subscriptions = {} # subscription_id -> destination

def match_destination(subscription: str, target: str) -> bool:
    if subscription == target:
        return True
    if "/typing/" in subscription and "/typing/" in target:
        sub_prefix = subscription.split("/typing/")[0]
        target_prefix = target.split("/typing/")[0]
        return sub_prefix == target_prefix
    return False

def parse_stomp_frame(frame_text: str):
    if frame_text.endswith('\x00'):
        frame_text = frame_text[:-1]
    
    lines = frame_text.split('\n')
    if not lines or not lines[0].strip():
        return None
        
    command = lines[0].strip()
    headers = {}
    idx = 1
    while idx < len(lines) and lines[idx].strip():
        line = lines[idx]
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip()] = v.strip()
        idx += 1
    
    body = '\n'.join(lines[idx+1:])
    return {"command": command, "headers": headers, "body": body}

def make_stomp_frame(command: str, headers: dict, body: str = ""):
    header_lines = "\n".join(f"{k}:{v}" for k, v in headers.items())
    frame = f"{command}\n{header_lines}\n\n{body}\x00"
    return frame

class StompRoomManager:
    def __init__(self):
        self.room_members: Dict[str, Set[str]] = {}
        self.peak_users: Dict[str, int] = {}
        self.latencies: Dict[str, List[float]] = {}
        self.connections: Dict[WebSocket, StompConnection] = {}

    def add_member(self, room_code: str, username: str):
        if room_code not in self.room_members:
            self.room_members[room_code] = set()
        self.room_members[room_code].add(username)
        current_count = len(self.room_members[room_code])
        if current_count > self.peak_users.get(room_code, 0):
            self.peak_users[room_code] = current_count

    def remove_member(self, room_code: str, username: str):
        if room_code in self.room_members:
            self.room_members[room_code].discard(username)

    def get_members(self, room_code: str) -> set:
        return self.room_members.get(room_code, set())

    def record_latency(self, room_code: str, latency: float):
        if room_code not in self.latencies:
            self.latencies[room_code] = []
        self.latencies[room_code].append(latency)

    def get_avg_latency(self, room_code: str) -> float:
        lats = self.latencies.get(room_code, [])
        if not lats:
            return 0.0
        return sum(lats) / len(lats)

    async def broadcast(self, destination: str, body: str, headers: dict = None):
        if headers is None:
            headers = {}
            
        for conn in list(self.connections.values()):
            for sub_id, sub_dest in conn.subscriptions.items():
                if match_destination(sub_dest, destination):
                    msg_headers = {
                        "subscription": sub_id,
                        "message-id": f"msg-{id(conn)}-{int(time.time()*1000)}",
                        "destination": destination,
                        "content-type": "application/json"
                    }
                    msg_headers.update(headers)
                    frame = make_stomp_frame("MESSAGE", msg_headers, body)
                    try:
                        await conn.websocket.send_text(frame)
                    except Exception:
                        pass

room_manager = StompRoomManager()

@app.websocket("/ws-sync/websocket")
async def websocket_endpoint(websocket: WebSocket):
    subprotocol = None
    sec_proto = websocket.headers.get("sec-websocket-protocol")
    if sec_proto:
        for proto in sec_proto.split(","):
            proto = proto.strip()
            if proto in ("v10.stomp", "v11.stomp"):
                subprotocol = proto
                break
    await websocket.accept(subprotocol=subprotocol)
    print(f"[WS] Connection accepted with subprotocol: {subprotocol}", flush=True)
    conn = StompConnection(websocket)
    room_manager.connections[websocket] = conn
    
    try:
        while True:
            data = await websocket.receive_text()
            print(f"[WS] Received raw data: {repr(data)}", flush=True)
            if not data.strip():
                # STOMP heartbeat
                continue
                
            frame = parse_stomp_frame(data)
            if not frame:
                print("[WS] Failed to parse STOMP frame", flush=True)
                continue
                
            cmd = frame["command"]
            headers = frame["headers"]
            body = frame["body"]
            print(f"[WS] Command: {cmd}, Destination: {headers.get('destination')}", flush=True)
            
            if cmd in ("CONNECT", "STOMP"):
                # Handle auth token from headers
                auth_header = headers.get("Authorization")
                if auth_header and auth_header.startswith("Bearer "):
                    token = auth_header[len("Bearer "):]
                    try:
                        conn.username = verify_jwt(token)
                    except Exception:
                        pass
                
                resp = make_stomp_frame("CONNECTED", {
                    "version": "1.1",
                    "heart-beat": "0,0"
                })
                await websocket.send_text(resp)
                
            elif cmd == "SUBSCRIBE":
                sub_id = headers.get("id")
                dest = headers.get("destination")
                if sub_id and dest:
                    conn.subscriptions[sub_id] = dest
                    
            elif cmd == "UNSUBSCRIBE":
                sub_id = headers.get("id")
                if sub_id and sub_id in conn.subscriptions:
                    del conn.subscriptions[sub_id]
                    
            elif cmd == "SEND":
                dest = headers.get("destination", "")
                
                # Check room code in destination path
                # e.g., /app/room/{roomCode}/join
                parts = dest.split('/')
                room_code = None
                action = None
                
                if len(parts) >= 4 and parts[1] == "app" and parts[2] == "room":
                    room_code = parts[3]
                    action = parts[4] if len(parts) > 4 else None
                    conn.room_code = room_code
                
                if not room_code:
                    continue
                    
                if action == "join":
                    if conn.username:
                        room_manager.add_member(room_code, conn.username)
                        
                        join_msg = {
                            "sender": "System",
                            "content": f"{conn.username} joined the room",
                            "type": "JOIN",
                            "timestamp": datetime.now().isoformat()
                        }
                        await room_manager.broadcast(f"/topic/room/{room_code}/chat", json.dumps(join_msg))
                        
                        members = list(room_manager.get_members(room_code))
                        await room_manager.broadcast(f"/topic/room/{room_code}/participants", json.dumps(members))
                        
                elif action == "leave":
                    if conn.username:
                        room_manager.remove_member(room_code, conn.username)
                        
                        leave_msg = {
                            "sender": "System",
                            "content": f"{conn.username} left the room",
                            "type": "LEAVE",
                            "timestamp": datetime.now().isoformat()
                        }
                        await room_manager.broadcast(f"/topic/room/{room_code}/chat", json.dumps(leave_msg))
                        
                        members = list(room_manager.get_members(room_code))
                        await room_manager.broadcast(f"/topic/room/{room_code}/participants", json.dumps(members))
                elif action == "chat":
                    if conn.username:
                        try:
                            msg_data = json.loads(body)
                        except Exception:
                            msg_data = {"content": body}
                            
                        with db_session() as db:
                            new_msg = models.ChatMessage(
                                room_code=room_code,
                                sender=conn.username,
                                content=msg_data.get("content", ""),
                                type=msg_data.get("type", "TEXT")
                            )
                            db.add(new_msg)
                            db.flush()
                            
                            saved_msg = {
                                "id": new_msg.id,
                                "sender": new_msg.sender,
                                "content": new_msg.content,
                                "type": new_msg.type,
                                "timestamp": new_msg.timestamp
                            }
                            db.commit()
                        
                        await room_manager.broadcast(f"/topic/room/{room_code}/chat", json.dumps(saved_msg))
                        
                elif action == "sync":
                    if conn.username:
                        with db_session() as db:
                            room = db.query(models.Room).filter_by(code=room_code).first()
                            user = db.query(models.User).filter_by(username=conn.username).first()
                            
                            is_admin = user.role == "ROLE_ADMIN" if user else False
                            is_creator = room and room.creator.username == conn.username
                            
                            if not (is_creator or is_admin):
                                continue
                                
                            try:
                                msg_data = json.loads(body)
                            except Exception:
                                msg_data = {}
                                
                            client_time = msg_data.get("clientTime")
                            if client_time:
                                latency = int(time.time() * 1000) - client_time
                                if latency > 0:
                                    room_manager.record_latency(room_code, latency)
                                    
                            # Update playback state in db
                            action_type = msg_data.get("action", "")
                            current_time = msg_data.get("currentTime", 0.0)
                            
                            state = db.query(models.PlaybackState).filter_by(room_code=room_code).first()
                            if not state:
                                state = models.PlaybackState(room_code=room_code)
                                db.add(state)
                                
                            # Only PLAY/PAUSE change the playing state; SEEK/BUFFERING/ERROR preserve it
                            if action_type == "PLAY":
                                is_playing = True
                            elif action_type == "PAUSE":
                                is_playing = False
                            else:
                                is_playing = state.playing
                            
                            state.playing = is_playing
                            state.current_time = current_time
                            state.last_updated_by_id = user.id if user else None
                            state.last_updated_at = datetime.now().isoformat()
                            db.commit()
                            
                        # Always include the authoritative playing state in the broadcast
                        msg_data["sender"] = conn.username
                        msg_data["playing"] = is_playing
                        await room_manager.broadcast(f"/topic/room/{room_code}/sync", json.dumps(msg_data))
                        
                elif action == "location":
                    if conn.username:
                        try:
                            msg_data = json.loads(body)
                        except Exception:
                            msg_data = {}
                            
                        loc = {
                            "username": conn.username,
                            "latitude": msg_data.get("latitude", 0.0),
                            "longitude": msg_data.get("longitude", 0.0),
                            "lastUpdated": datetime.now().isoformat()
                        }
                        locations_db[conn.username] = loc
                        await room_manager.broadcast(f"/topic/room/{room_code}/location", json.dumps(loc))
                        
                elif action == "typing":
                    if conn.username:
                        await room_manager.broadcast(f"/topic/room/{room_code}/typing/{conn.username}", body)
 
                elif action == "viewer_ready":
                    # Viewer reports if they are ready (meaning local download & verification complete).
                    # Body: {"isReady": true, "bufferedSeconds": 6.2}
                    if conn.username:
                        try:
                            msg_data = json.loads(body)
                        except Exception:
                            msg_data = {}
 
                        is_ready = bool(msg_data.get("isReady", False))
                        buffered = float(msg_data.get("bufferedSeconds", 0.0))
                        _READY_THRESHOLD = 5.0
                        
                        ready_val = 10.0 if (is_ready or buffered >= _READY_THRESHOLD) else 0.0
 
                        if room_code not in viewer_ready_db:
                            viewer_ready_db[room_code] = {}
                        viewer_ready_db[room_code][conn.username] = ready_val
 
                        # Tally readiness across all room members
                        members       = room_manager.get_members(room_code)
                        total         = len(members)
                        ready_info    = viewer_ready_db.get(room_code, {})
                        ready_count   = sum(
                            1 for u in members if ready_info.get(u, 0.0) >= _READY_THRESHOLD
                        )
                        all_ready     = total > 0 and ready_count >= total
 
                        viewers_detail = [
                            {
                                "username":       u,
                                "bufferedSeconds": ready_info.get(u, 0.0),
                                "isReady":        ready_info.get(u, 0.0) >= _READY_THRESHOLD,
                            }
                            for u in members
                        ]
 
                        status_msg = {
                            "type":         "VIEWER_READY_STATUS",
                            "readyViewers": ready_count,
                            "totalViewers": total,
                            "allReady":     all_ready,
                            "viewers":      viewers_detail,
                        }
 
                        print(
                            f"[ViewerReady] {room_code}: {ready_count}/{total} ready "
                            f"(last: {conn.username} is_ready={is_ready})",
                            flush=True,
                        )
 
                        # Broadcast to the whole room — admin listens to unlock Play
                        await room_manager.broadcast(
                            f"/topic/room/{room_code}/sync", json.dumps(status_msg)
                        )
 
                elif action == "kick":
                    # Check if target username is in the sub-path
                    # e.g., /app/room/{roomCode}/kick/{targetUsername}
                    if len(parts) >= 6:
                        target_username = parts[5]
                        with db_session() as db:
                            room = db.query(models.Room).filter_by(code=room_code).first()
                            user = db.query(models.User).filter_by(username=conn.username).first()
                            
                            is_creator = room and room.creator.username == conn.username
                            is_admin = user.role == "ROLE_ADMIN" if user else False
                            
                        if is_creator or is_admin:
                            room_manager.remove_member(room_code, target_username)
                            
                            # Send kick command on target kick subscription
                            await room_manager.broadcast(f"/topic/room/{room_code}/kick/{target_username}", "kicked")
                            
                            leave_msg = {
                                "sender": "System",
                                "content": f"{target_username} was kicked by the host",
                                "type": "LEAVE",
                                "timestamp": datetime.now().isoformat()
                            }
                            await room_manager.broadcast(f"/topic/room/{room_code}/chat", json.dumps(leave_msg))
                            
                            members = list(room_manager.get_members(room_code))
                            await room_manager.broadcast(f"/topic/room/{room_code}/participants", json.dumps(members))
                            
            elif cmd == "DISCONNECT":
                break
                
    except WebSocketDisconnect:
        print("[WS] WebSocketDisconnect", flush=True)
    except Exception as e:
        import traceback
        print(f"[WS] Exception in websocket: {e}", flush=True)
        traceback.print_exc()
    finally:
        print("[WS] Connection cleanup", flush=True)
        # Cleanup connection
        if websocket in room_manager.connections:
            c = room_manager.connections[websocket]
            del room_manager.connections[websocket]
            if c.username and c.room_code:
                room_manager.remove_member(c.room_code, c.username)
                
                # Broadcast participant update
                members = list(room_manager.get_members(c.room_code))
                await room_manager.broadcast(f"/topic/room/{c.room_code}/participants", json.dumps(members))
                
                # Broadcast system message
                leave_msg = {
                    "sender": "System",
                    "content": f"{c.username} left the room",
                    "type": "LEAVE",
                    "timestamp": datetime.now().isoformat()
                }
                await room_manager.broadcast(f"/topic/room/{c.room_code}/chat", json.dumps(leave_msg))
