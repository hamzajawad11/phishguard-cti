from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    original_input: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_url: Mapped[str] = mapped_column(Text, nullable=False)
    domain: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), index=True, nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    reasons_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    iocs_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    enrichment_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)


class FeedCache(Base):
    __tablename__ = "feed_cache"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    source_name: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    cached_json: Mapped[str] = mapped_column(Text, nullable=False)
