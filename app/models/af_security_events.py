import uuid
from sqlalchemy import (
    Column,
    String,
    Text,
    Boolean,
    Integer,
    ForeignKey,
    DateTime,
    func,
)
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB
from sqlalchemy.orm import relationship

from app.core.database import Base

class SecurityEvent(Base):
    __tablename__ = "af_security_events"
    __table_args__ = {"schema": "public"}
    event_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    event_type = Column(String(50), nullable=False)
    event_description = Column(Text)
    severity = Column(String(20), nullable=False, default="info")

    ip_address = Column(INET)
    user_agent = Column(Text)
    event_metadata = Column(
        "metadata",          # nombre real en la tabla
        JSONB
    )

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # relationships
    user = relationship("Users", back_populates="security_events")

    __table_args__ = {
        "comment": "Registro de eventos de seguridad del sistema"
    }
