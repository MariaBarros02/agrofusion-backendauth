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


class EmailVerificationToken(Base):
    """
    Modelo ORM para tokens de verificación de email.

    Este modelo almacena tokens temporales utilizados para:
    - Verificación de correo electrónico
    - Activación de cuentas de usuario
    - Flujos de confirmación de identidad por email

    Los tokens:
    - Están asociados a un usuario
    - Tienen fecha de expiración
    - Solo pueden usarse una vez
    """
    __tablename__ = "af_email_verification_tokens"
    __table_args__ = {"schema": "public"}

    # Identificador único del token de verificación
    verification_token_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    # Usuario asociado al token
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Token en texto plano (enviado por email)
    token = Column(
        String(255),
        nullable=False,
        unique=True
    )

    # Hash del token (verificación segura)
    token_hash = Column(
        String(255),
        nullable=False
    )

    # Propósito del token (ej: email_verification)
    purpose = Column(
        String(50),
        nullable=False,
        default="email_verification"
    )

    # Email que se está verificando
    email = Column(
        String(255),
        nullable=False
    )

    # Fecha de expiración del token
    expires_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now() + func.interval("24 hours"),
    )

    # Fecha en que el token fue utilizado
    used_at = Column(
        DateTime(timezone=True)
    )

    # Fecha de creación del token
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    # IP desde la cual se solicitó el token
    ip_address = Column(
        INET
    )

    # User-Agent del cliente
    user_agent = Column(
        Text
    )

    # Relación con el usuario propietario del token
    user = relationship(
        "Users",
        back_populates="email_verification_tokens"
    )

    # Comentario descriptivo de la tabla
    __table_args__ = {
        "comment": "Tokens para verificación de email y activación de cuentas"
    }
