import uuid
from sqlalchemy import (
    Column,
    String,
    Integer,
    DateTime,
    ForeignKey,
    Text,
    Index,
)
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from app.core.database import Base


class AfOtpCode(Base):
    """
    Modelo ORM para códigos OTP (One-Time Password).

    Usado para:
    - Autenticación de dos factores (2FA)
    - Recuperación de contraseña
    - Flujos sensibles de seguridad

    Incluye control de:
    - Expiración
    - Uso único
    - Intentos fallidos
    """
    __tablename__ = "af_otp_codes"
    __table_args__ = {"schema": "public"}

    # Identificador único del OTP
    otp_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Usuario asociado al OTP
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ⚠️ Código OTP en texto plano (no recomendado en producción)
    otp_code = Column(
        String(10)
    )

    # Hash del OTP (forma segura de validación)
    otp_hash = Column(
        Text
    )

    # Propósito del OTP (login_2fa, password_reset, etc.)
    purpose = Column(
        String(50),
        nullable=False,
        index=True,
        doc="login_2fa, password_reset, etc",
    )

    # Fecha de expiración del OTP
    expires_at = Column(
        DateTime(timezone=True),
        nullable=False,
    )

    # Fecha en que el OTP fue utilizado
    used_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Número de intentos fallidos
    failed_attempts = Column(
        Integer,
        nullable=False,
        default=0,
    )

    # IP desde donde se usó el OTP
    ip_address = Column(
        INET,
        nullable=True,
    )

    # User-Agent del cliente
    user_agent = Column(
        Text,
        nullable=True,
    )

    # Fecha de creación del OTP
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Relación con el usuario
    user = relationship(
        "Users",
        back_populates="otp_codes"
    )

    __table_args__ = (
        # Índice por fecha de expiración
        Index("ix_otp_expires_at", "expires_at"),
        # Índice parcial: OTPs activos (no usados) por usuario
        Index(
            "ix_otp_user_active",
            "user_id",
            postgresql_where=(used_at.is_(None)),
        ),
    )
