import uuid
from sqlalchemy import (
    Column,
    String,
    DateTime,
    ForeignKey,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import relationship

from app.core.database import Base


class PasswordResetToken(Base):
    """
    Modelo ORM para tokens de recuperación de contraseña.

    Gestiona:
    - Tokens únicos
    - Expiración
    - Invalidación manual
    - Auditoría de IP y User-Agent
    """
    __tablename__ = "af_password_reset_tokens"
    __table_args__ = {"schema": "public"}

    # Identificador único del token
    reset_token_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Usuario asociado
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Token en texto plano
    token = Column(
        String(255),
        nullable=False,
        unique=True,
    )

    # Hash del token
    token_hash = Column(
        String(255),
        nullable=False,
    )

    # Email destino del reset
    email = Column(
        String(255),
        nullable=False,
    )

    # Código adicional opcional
    reset_code = Column(
        String(10),
        nullable=True,
    )

    # Expiración automática del token
    expires_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now() + func.interval("30 minutes"),
    )

    # Fecha de uso
    used_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Fecha de creación
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Auditoría de red
    ip_address = Column(
        INET,
        nullable=True,
    )

    user_agent = Column(
        Text,
        nullable=True,
    )

    # Invalidación manual del token
    invalidated_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    invalidation_reason = Column(
        String(200),
        nullable=True,
    )

    # Relación opcional con el usuario
    user = relationship("Users")

    def __repr__(self):
        """
        Representación legible del token (debug / logs).
        """
        return (
            f"<AfPasswordResetToken("
            f"id={self.reset_token_id}, "
            f"user_id={self.user_id}, "
            f"email={self.email}, "
            f"expires_at={self.expires_at}"
            f")>"
        )
