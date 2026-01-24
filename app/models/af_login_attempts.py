import uuid
from sqlalchemy import (
    Column, String, DateTime, ForeignKey, Text, Boolean, JSON
)
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.sql import func
from app.core.database import Base


class LoginAttempt(Base):
    """
    Modelo ORM para registrar intentos de inicio de sesión.

    Este modelo permite:
    - Auditar intentos exitosos y fallidos
    - Detectar ataques de fuerza bruta
    - Analizar patrones por IP o email
    """
    __tablename__ = "af_login_attempts"
    __table_args__ = {"schema": "public"}

    # Identificador único del intento
    attempt_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    # Usuario asociado (puede ser NULL si no existe)
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id"),
        nullable=True
    )

    # Email utilizado en el intento
    email = Column(
        Text,
        nullable=True
    )

    # Indica si el intento fue exitoso
    success = Column(
        Boolean,
        nullable=False
    )

    # Motivo del fallo (credenciales inválidas, cuenta bloqueada, etc.)
    reason = Column(
        Text,
        nullable=True
    )

    # IP desde donde se realizó el intento
    ip = Column(
        INET
    )

    # Fecha y hora del intento
    at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )
