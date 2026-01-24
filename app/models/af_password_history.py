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


class PasswordHistory(Base):
    """
    Modelo ORM para el historial de contraseñas.

    Permite:
    - Prevenir reutilización de contraseñas
    - Auditar cambios de credenciales
    - Cumplir políticas de seguridad
    """
    __tablename__ = "af_password_history"
    __table_args__ = {"schema": "public"}

    # Identificador único del registro
    history_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    # Usuario al que pertenece la contraseña
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id", ondelete="CASCADE"),
        nullable=False,
    )

    # Hash de la contraseña anterior
    password_hash = Column(
        Text,
        nullable=False
    )

    # Fecha del cambio de contraseña
    changed_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    # Usuario que realizó el cambio (admin / sistema)
    changed_by = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id"),
        nullable=True,
    )

    # Motivo del cambio (reset, expiration, manual, etc.)
    change_reason = Column(
        String(50),
        nullable=False
    )

    # IP desde donde se realizó el cambio
    ip_address = Column(
        INET
    )

    # User-Agent del cliente
    user_agent = Column(
        Text
    )

    # Relación con el usuario dueño de la contraseña
    user = relationship(
        "Users",
        foreign_keys=[user_id],
        back_populates="password_history"
    )

    # Relación con el usuario que realizó el cambio
    changed_by_user = relationship(
        "Users",
        foreign_keys=[changed_by]
    )

    __table_args__ = {
        "comment": "Historial de cambios de contraseña para prevenir reuso"
    }
