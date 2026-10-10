from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.db.database import Base


class AnalysisLog(Base):
    __tablename__ = "analysis_logs"
    __table_args__ = (
        Index("idx_sha256", "sha256"),
        Index("idx_created_at", "created_at"),
        Index("idx_binary_label", "binary_label"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    binary_label: Mapped[str] = mapped_column(String(20), nullable=False)
    malware_prob: Mapped[float] = mapped_column(Float, nullable=False)
    threat_family: Mapped[str | None] = mapped_column(String(50))
    threat_level: Mapped[str] = mapped_column(String(20), nullable=False)
    yara_matches: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    feature_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    result_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
