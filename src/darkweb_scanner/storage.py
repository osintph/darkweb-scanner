"""
Storage layer — SQLite (default) or PostgreSQL via SQLAlchemy.
Stores crawl results, keyword hits, and crawl session metadata.
"""

import logging
import os
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String, Text, create_engine, func
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


class CrawlSession(Base):
    __tablename__ = "crawl_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    ended_at = Column(DateTime, nullable=True)
    seed_urls = Column(Text)  # JSON list
    pages_crawled = Column(Integer, default=0)
    hits_found = Column(Integer, default=0)
    status = Column(String(50), default="running")  # running | completed | failed


class CrawledPage(Base):
    __tablename__ = "crawled_pages"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, nullable=True)
    url = Column(Text, nullable=False)
    crawled_at = Column(DateTime, default=datetime.utcnow)
    status_code = Column(Integer)
    depth = Column(Integer, default=0)
    had_error = Column(Boolean, default=False)
    error_message = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_crawled_pages_url", "url"),
        Index("ix_crawled_pages_session", "session_id"),
    )


class KeywordHitRecord(Base):
    __tablename__ = "keyword_hits"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, nullable=True)
    url = Column(Text, nullable=False)
    keyword = Column(String(500), nullable=False)
    category = Column(String(200), nullable=False)
    context = Column(Text)
    position = Column(Integer)
    depth = Column(Integer, default=0)
    found_at = Column(DateTime, default=datetime.utcnow)
    alerted = Column(Boolean, default=False)

    __table_args__ = (
        Index("ix_keyword_hits_keyword", "keyword"),
        Index("ix_keyword_hits_category", "category"),
        Index("ix_keyword_hits_found_at", "found_at"),
        Index("ix_keyword_hits_session", "session_id"),
    )


class Storage:
    def __init__(self, database_url: Optional[str] = None):
        self.database_url = database_url or os.getenv(
            "DATABASE_URL", "sqlite:////app/data/results.db"
        )
        connect_args = {}
        if self.database_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False

        self.engine = create_engine(
            self.database_url,
            connect_args=connect_args,
            echo=False,
        )
        self._SessionFactory = sessionmaker(bind=self.engine)
        self._create_tables()

    def _create_tables(self):
        Base.metadata.create_all(self.engine)
        logger.info("Database tables ready")

    def get_session(self) -> Session:
        return self._SessionFactory()

    # --- Crawl Sessions ---

    def create_crawl_session(self, seed_urls: list[str]) -> int:
        import json

        with self.get_session() as session:
            record = CrawlSession(seed_urls=json.dumps(seed_urls))
            session.add(record)
            session.commit()
            session.refresh(record)
            return record.id

    def update_crawl_session(
        self, session_id: int, pages_crawled: int, hits_found: int, status: str = "completed"
    ):
        with self.get_session() as session:
            record = session.get(CrawlSession, session_id)
            if record:
                record.ended_at = datetime.utcnow()
                record.pages_crawled = pages_crawled
                record.hits_found = hits_found
                record.status = status
                session.commit()

    # --- Pages ---

    def save_page(
        self,
        url: str,
        status_code: int,
        depth: int,
        session_id: Optional[int] = None,
        error: Optional[str] = None,
    ):
        with self.get_session() as session:
            record = CrawledPage(
                session_id=session_id,
                url=url,
                status_code=status_code,
                depth=depth,
                had_error=bool(error),
                error_message=error,
            )
            session.add(record)
            session.commit()

    # --- Keyword Hits ---

    def save_hit(
        self,
        url: str,
        keyword: str,
        category: str,
        context: str,
        position: int,
        depth: int,
        session_id: Optional[int] = None,
    ) -> int:
        with self.get_session() as session:
            record = KeywordHitRecord(
                session_id=session_id,
                url=url,
                keyword=keyword,
                category=category,
                context=context,
                position=position,
                depth=depth,
            )
            session.add(record)
            session.commit()
            session.refresh(record)
            return record.id

    def mark_alerted(self, hit_id: int):
        with self.get_session() as session:
            record = session.get(KeywordHitRecord, hit_id)
            if record:
                record.alerted = True
                session.commit()

    def get_recent_hits(self, limit: int = 100) -> list[KeywordHitRecord]:
        with self.get_session() as session:
            return (
                session.query(KeywordHitRecord)
                .order_by(KeywordHitRecord.found_at.desc())
                .limit(limit)
                .all()
            )

    def get_hits_by_keyword(self, keyword: str, limit: int = 50) -> list[KeywordHitRecord]:
        with self.get_session() as session:
            return (
                session.query(KeywordHitRecord)
                .filter(KeywordHitRecord.keyword == keyword)
                .order_by(KeywordHitRecord.found_at.desc())
                .limit(limit)
                .all()
            )

    def get_stats(self) -> dict:
        with self.get_session() as session:
            total_hits = session.query(func.count(KeywordHitRecord.id)).scalar()
            total_pages = session.query(func.count(CrawledPage.id)).scalar()
            total_sessions = session.query(func.count(CrawlSession.id)).scalar()
            top_keywords = (
                session.query(
                    KeywordHitRecord.keyword, func.count(KeywordHitRecord.id).label("count")
                )
                .group_by(KeywordHitRecord.keyword)
                .order_by(func.count(KeywordHitRecord.id).desc())
                .limit(10)
                .all()
            )
            return {
                "total_hits": total_hits or 0,
                "total_pages": total_pages or 0,
                "total_sessions": total_sessions or 0,
                "top_keywords": [{"keyword": k, "count": c} for k, c in top_keywords],
            }


    # --- Users ---

    def get_user_by_id(self, user_id: int):
        with self.get_session() as session:
            return session.get(User, user_id)

    def get_user_by_username(self, username: str):
        with self.get_session() as session:
            return session.query(User).filter(User.username == username).first()

    def get_user_by_email(self, email: str):
        with self.get_session() as session:
            return session.query(User).filter(User.email == email).first()

    def get_user_by_oauth(self, provider: str, oauth_id: str):
        with self.get_session() as session:
            return session.query(User).filter(
                User.oauth_provider == provider,
                User.oauth_id == oauth_id
            ).first()

    def create_user(self, username: str, password_hash: str = None,
                    email: str = None, oauth_provider: str = None,
                    oauth_id: str = None, is_admin: bool = False):
        with self.get_session() as session:
            user = User(
                username=username,
                email=email,
                password_hash=password_hash,
                oauth_provider=oauth_provider,
                oauth_id=oauth_id,
                is_admin=is_admin,
            )
            session.add(user)
            session.commit()
            session.refresh(user)
            return user.id

    def update_user_login(self, user_id: int):
        with self.get_session() as session:
            user = session.get(User, user_id)
            if user:
                user.last_login = datetime.utcnow()
                session.commit()

    def enable_totp(self, user_id: int, secret: str):
        with self.get_session() as session:
            user = session.get(User, user_id)
            if user:
                user.totp_secret = secret
                user.totp_enabled = True
                session.commit()

    def disable_totp(self, user_id: int):
        with self.get_session() as session:
            user = session.get(User, user_id)
            if user:
                user.totp_secret = None
                user.totp_enabled = False
                session.commit()

    def count_users(self) -> int:
        with self.get_session() as session:
            return session.query(func.count(User.id)).scalar() or 0

    def get_unalerted_hits(self) -> list[KeywordHitRecord]:
        with self.get_session() as session:
            return session.query(KeywordHitRecord).filter(KeywordHitRecord.alerted.is_(False)).all()


# ── User model (added for authentication) ────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=True)
    password_hash = Column(String(255), nullable=True)  # None for OAuth-only users
    totp_secret = Column(String(64), nullable=True)
    totp_enabled = Column(Boolean, default=False)
    oauth_provider = Column(String(50), nullable=True)  # "google" | "github" | None
    oauth_id = Column(String(255), nullable=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_users_username", "username"),
        Index("ix_users_email", "email"),
        Index("ix_users_oauth", "oauth_provider", "oauth_id"),
    )
