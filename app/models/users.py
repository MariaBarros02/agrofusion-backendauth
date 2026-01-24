import uuid
from sqlalchemy import (
    Column,
    String,
    Text,
    Boolean,
    Integer,
    DateTime,
    ForeignKey,
    func
)
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID, INET
from app.core.database import Base


class Users(Base):
    """
    Modelo ORM principal de usuarios.

    Representa:
    - Identidad
    - Estado
    - Seguridad
    - Relaciones de autenticación
    """
    __tablename__ = "users"
    __table_args__ = {"schema": "public"}

    # Identificador del usuario
    user_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    # Credenciales
    email = Column(Text, nullable=False, unique=True, index=True)
    name = Column(String(120), nullable=False)
    password_hash = Column(Text, nullable=False)

    # Estado del usuario
    status_term_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.cat_terms.term_id"),
        nullable=False
    )

    # MFA habilitado
    is_mfa_enabled = Column(Boolean, nullable=False, default=False)

    # Auditoría
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )

    updated_at = Column(DateTime(timezone=True))

    # Seguridad
    failed_attempts = Column(Integer, nullable=False, default=0)

    locked_at = Column(DateTime(timezone=True))
    last_login_at = Column(DateTime(timezone=True))
    last_login_ip = Column(INET)

    deleted_at = Column(DateTime(timezone=True))

    # Auditoría de cambios
    created_by = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id")
    )

    updated_by = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id")
    )

    # Estado de verificación
    email_verified_at = Column(DateTime(timezone=True))
    password_changed_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    # Control de concurrencia
    row_version = Column(Integer, default=1)

    # ------------------------
    # Relaciones
    # ------------------------

    sessions = relationship(
        "AuthSession",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    otp_codes = relationship(
        "AfOtpCode",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    email_verification_tokens = relationship(
        "EmailVerificationToken",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    password_history = relationship(
        "PasswordHistory",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="PasswordHistory.user_id"
    )

    security_events = relationship(
        "SecurityEvent",
        back_populates="user"
    )
