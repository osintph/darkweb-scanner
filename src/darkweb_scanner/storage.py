"""
Storage layer — SQLite (default) or PostgreSQL via SQLAlchemy.
Stores crawl results, keyword hits, and crawl session metadata.
"""

import json
import logging
import os
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String, Text, create_engine, func
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


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




class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(50), default="running")  # running | completed
    target_count = Column(Integer, default=0)


class InvestigationTarget(Base):
    __tablename__ = "investigation_targets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(Integer, nullable=False, index=True)
    value = Column(String(512), nullable=False)
    target_type = Column(String(50), nullable=False)  # email | name | keyword
    breaches = Column(Text, default="[]")   # JSON list of breach dicts
    darkweb_hits = Column(Text, default="[]")  # JSON list of hit dicts
    breach_count = Column(Integer, default=0)
    darkweb_count = Column(Integer, default=0)
    error = Column(Text, nullable=True)
    checked_at = Column(DateTime, default=datetime.utcnow)



class IPInvestigation(Base):
    __tablename__ = "ip_investigations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(50), default="running")
    abuseipdb_data = Column(Text, nullable=True)   # JSON
    virustotal_data = Column(Text, nullable=True)  # JSON
    abuse_score = Column(Integer, nullable=True)
    vt_malicious = Column(Integer, nullable=True)
    country = Column(String(10), nullable=True)
    isp = Column(String(255), nullable=True)

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

    def list_users(self):
        with self.get_session() as session:
            return session.query(User).order_by(User.created_at).all()

    def delete_user(self, user_id: int):
        with self.get_session() as session:
            user = session.get(User, user_id)
            if user:
                session.delete(user)
                session.commit()

    def update_user_password(self, user_id: int, password_hash: str):
        with self.get_session() as session:
            user = session.get(User, user_id)
            if user:
                user.password_hash = password_hash
                session.commit()



    def count_session_hits(self, session_id: int) -> int:
        with self.get_session() as session:
            return (
                session.query(func.count(KeywordHitRecord.id))
                .filter(KeywordHitRecord.session_id == session_id)
                .scalar() or 0
            )

    def count_session_pages(self, session_id: int) -> int:
        with self.get_session() as session:
            return (
                session.query(func.count(CrawledPage.id))
                .filter(CrawledPage.session_id == session_id)
                .scalar() or 0
            )

    def get_sessions(self, limit: int = 20) -> list[dict]:
        with self.get_session() as session:
            rows = (
                session.query(CrawlSession)
                .order_by(CrawlSession.started_at.desc())
                .limit(limit)
                .all()
            )
            return [
                {
                    "id": r.id,
                    "started_at": r.started_at.isoformat() if r.started_at else None,
                    "ended_at": r.ended_at.isoformat() if r.ended_at else None,
                    "seed_urls": r.seed_urls or "[]",
                    "pages_crawled": r.pages_crawled or 0,
                    "hits_found": r.hits_found or 0,
                    "status": r.status or "completed",
                }
                for r in rows
            ]

    def get_hits_by_session(self, session_id: int, limit: int = 200):
        with self.get_session() as session:
            return (
                session.query(KeywordHitRecord)
                .filter(KeywordHitRecord.session_id == session_id)
                .order_by(KeywordHitRecord.found_at.desc())
                .limit(limit)
                .all()
            )

    def get_hits_for_report(self, limit: int = 500):
        with self.get_session() as session:
            return (
                session.query(KeywordHitRecord)
                .order_by(KeywordHitRecord.found_at.desc())
                .limit(limit)
                .all()
            )
    # ── Investigations ──────────────────────────────────────────────────────────

    def create_investigation(self, name: str, targets: list) -> int:
        with self.get_session() as session:
            record = Investigation(
                name=name,
                status="running",
                target_count=len(targets),
            )
            session.add(record)
            session.commit()
            return record.id

    def save_investigation_target(
        self,
        investigation_id: int,
        value: str,
        target_type: str,
        breaches: list,
        darkweb_hits: list,
        error: Optional[str] = None,
    ):
        with self.get_session() as session:
            record = InvestigationTarget(
                investigation_id=investigation_id,
                value=value,
                target_type=target_type,
                breaches=json.dumps(breaches),
                darkweb_hits=json.dumps(darkweb_hits),
                breach_count=len(breaches),
                darkweb_count=len(darkweb_hits),
                error=error,
            )
            session.add(record)
            session.commit()

    def complete_investigation(self, investigation_id: int):
        with self.get_session() as session:
            record = session.get(Investigation, investigation_id)
            if record:
                record.status = "completed"
                record.completed_at = datetime.utcnow()
                session.commit()

    def get_investigations(self, limit: int = 50) -> list[dict]:
        with self.get_session() as session:
            rows = (
                session.query(Investigation)
                .order_by(Investigation.created_at.desc())
                .limit(limit)
                .all()
            )
            return [
                {
                    "id": r.id,
                    "name": r.name,
                    "status": r.status,
                    "target_count": r.target_count,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                    "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                }
                for r in rows
            ]

    def get_investigation_targets(self, investigation_id: int) -> list[dict]:
        with self.get_session() as session:
            rows = (
                session.query(InvestigationTarget)
                .filter(InvestigationTarget.investigation_id == investigation_id)
                .order_by(InvestigationTarget.id.asc())
                .all()
            )
            results = []
            for r in rows:
                try:
                    breaches = json.loads(r.breaches or "[]")
                except Exception:
                    breaches = []
                try:
                    darkweb_hits = json.loads(r.darkweb_hits or "[]")
                except Exception:
                    darkweb_hits = []
                results.append({
                    "id": r.id,
                    "value": r.value,
                    "target_type": r.target_type,
                    "breaches": breaches,
                    "darkweb_hits": darkweb_hits,
                    "breach_count": r.breach_count or 0,
                    "darkweb_count": r.darkweb_count or 0,
                    "error": r.error,
                    "checked_at": r.checked_at.isoformat() if r.checked_at else None,
                })
            return results

    def delete_investigation(self, investigation_id: int):
        with self.get_session() as session:
            session.query(InvestigationTarget).filter(
                InvestigationTarget.investigation_id == investigation_id
            ).delete()
            record = session.get(Investigation, investigation_id)
            if record:
                session.delete(record)
            session.commit()

    def search_hits(self, query: str, limit: int = 50) -> list[dict]:
        """Search existing dark web keyword hits for a given string."""
        with self.get_session() as session:
            rows = (
                session.query(KeywordHitRecord)
                .filter(KeywordHitRecord.context.ilike(f"%{query}%"))
                .order_by(KeywordHitRecord.found_at.desc())
                .limit(limit)
                .all()
            )
            return [
                {
                    "url": r.url,
                    "keyword": r.keyword,
                    "category": r.category,
                    "context": r.context,
                    "found_at": r.found_at.isoformat() if r.found_at else None,
                }
                for r in rows
            ]


    # ── IP Investigations ───────────────────────────────────────────────────────

    def save_ip_investigation(self, ip: str, abuseipdb_data: dict, virustotal_data: dict) -> int:
        abuse_score = None
        vt_malicious = None
        country = None
        isp = None
        if abuseipdb_data and not abuseipdb_data.get("error"):
            abuse_score = abuseipdb_data.get("abuse_confidence_score")
            country = abuseipdb_data.get("country_code")
            isp = abuseipdb_data.get("isp")
        if virustotal_data and not virustotal_data.get("error"):
            vt_malicious = virustotal_data.get("analysis_stats", {}).get("malicious", 0)
            if not country:
                country = virustotal_data.get("country")
            if not isp:
                isp = virustotal_data.get("as_owner")
        with self.get_session() as session:
            record = IPInvestigation(
                ip=ip,
                status="completed",
                abuseipdb_data=json.dumps(abuseipdb_data),
                virustotal_data=json.dumps(virustotal_data),
                abuse_score=abuse_score,
                vt_malicious=vt_malicious,
                country=country,
                isp=isp,
            )
            session.add(record)
            session.commit()
            return record.id

    def get_ip_investigations(self, limit: int = 50) -> list[dict]:
        with self.get_session() as session:
            rows = (
                session.query(IPInvestigation)
                .order_by(IPInvestigation.created_at.desc())
                .limit(limit)
                .all()
            )
            return [
                {
                    "id": r.id,
                    "ip": r.ip,
                    "status": r.status,
                    "abuse_score": r.abuse_score,
                    "vt_malicious": r.vt_malicious,
                    "country": r.country,
                    "isp": r.isp,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in rows
            ]

    def get_ip_investigation(self, inv_id: int) -> Optional[dict]:
        with self.get_session() as session:
            r = session.get(IPInvestigation, inv_id)
            if not r:
                return None
            try:
                abuse = json.loads(r.abuseipdb_data or "{}")
            except Exception:
                abuse = {}
            try:
                vt = json.loads(r.virustotal_data or "{}")
            except Exception:
                vt = {}
            return {
                "id": r.id,
                "ip": r.ip,
                "status": r.status,
                "abuse_score": r.abuse_score,
                "vt_malicious": r.vt_malicious,
                "country": r.country,
                "isp": r.isp,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "abuseipdb": abuse,
                "virustotal": vt,
            }

    def delete_ip_investigation(self, inv_id: int):
        with self.get_session() as session:
            r = session.get(IPInvestigation, inv_id)
            if r:
                session.delete(r)
                session.commit()


    def get_active_session(self):
        with self.get_session() as session:
            r = (
                session.query(CrawlSession)
                .filter(CrawlSession.status == "running")
                .order_by(CrawlSession.started_at.desc())
                .first()
            )
            if r is None:
                return None
            return {
                "id": r.id,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "pages_crawled": r.pages_crawled or 0,
                "hits_found": r.hits_found or 0,
                "status": r.status,
            }


