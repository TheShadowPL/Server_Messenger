# models.py
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta, timezone

bcrypt = Bcrypt()

engine = create_engine('sqlite:///messenger.db')
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_active = Column(Boolean, default=False)
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Chat(Base):
    __tablename__ = 'chats'

    id = Column(Integer, primary_key=True)
    first_user = Column(Integer, unique=False, nullable=False)
    second_user = Column(Integer, unique=False, nullable=False)

class Message(Base):
    __tablename__ = 'messages'

    id = Column(Integer, primary_key=True)
    chat_id = Column(Integer, ForeignKey('chats.id'), nullable=False)
    message = Column(Text, nullable=False)
    author_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class GroupChat(Base):
    __tablename__ = 'group_chats'

    id = Column(Integer, primary_key=True)
    chat_id = Column(Integer, unique=True, nullable=False)
    members = Column(Text , unique=False, nullable=False)

    messages = relationship("GroupMessages", back_populates="group_chat", cascade="all, delete-orphan")


class GroupMessages(Base):
    __tablename__ = 'group_messages'

    id = Column(Integer, primary_key=True)
    group_chat_id = Column(Integer, ForeignKey('group_chats.id', ondelete='CASCADE'), nullable=False)
    sender_id = Column(Integer, nullable=False)
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    group_chat = relationship("GroupChat", back_populates="messages")

Base.metadata.create_all(engine)
