from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, BigInteger
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="ROLE_VIEWER")
    created_at = Column(DateTime, default=datetime.utcnow)
    active = Column(Boolean, default=True)

class Video(Base):
    __tablename__ = "videos"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    source = Column(String, nullable=False) # "upload", "drive", "local"
    drive_file_id = Column(String, nullable=True)
    local_path = Column(String, nullable=True)
    file_size = Column(BigInteger, default=0)
    duration = Column(Float, default=0.0)
    checksum = Column(String, nullable=True)
    upload_date = Column(String, default=lambda: datetime.now().isoformat())
    content_type = Column(String, default="video/mp4")
    download_url = Column(String, nullable=True)
    resolution = Column(String, nullable=True)

class Room(Base):
    __tablename__ = "rooms"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    creator_id = Column(Integer, ForeignKey("users.id"))
    current_video_id = Column(Integer, ForeignKey("videos.id"), nullable=True)
    active = Column(Boolean, default=True)
    created_at = Column(String, default=lambda: datetime.now().isoformat())

    creator = relationship("User", foreign_keys=[creator_id])
    current_video = relationship("Video", foreign_keys=[current_video_id])

class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(Integer, primary_key=True, index=True)
    room_code = Column(String, index=True, nullable=False)
    sender = Column(String, nullable=False)
    content = Column(String, nullable=False)
    type = Column(String, default="TEXT") # "TEXT", "IMAGE", "JOIN", "LEAVE"
    timestamp = Column(String, default=lambda: datetime.now().isoformat())

class PlaybackState(Base):
    __tablename__ = "playback_states"

    id = Column(Integer, primary_key=True, index=True)
    room_code = Column(String, unique=True, index=True, nullable=False)
    playing = Column(Boolean, default=False)
    current_time = Column(Float, default=0.0)
    last_updated_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    last_updated_at = Column(String, default=lambda: datetime.now().isoformat())

    last_updated_by = relationship("User", foreign_keys=[last_updated_by_id])
