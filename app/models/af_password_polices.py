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


class PasswordPolicy(Base):
    """
    Modelo ORM que define las políticas de seguridad para contraseñas.

    Permite configurar:
    - Longitud mínima y máxima
    - Reglas de complejidad
    - Expiración de contraseñas
    - Historial permitido
    """
    __tablename__ = "af_password_policies"
    __table_args__ = {"schema": "public"}

    # Identificador único de la política
    policy_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Nombre descriptivo de la política
    policy_name = Column(String(100), nullable=False, unique=True)

    # Longitud mínima y máxima permitida
    min_length = Column(Integer, nullable=False, default=8)
    max_length = Column(Integer, nullable=False, default=128)

    # Reglas de complejidad
    require_uppercase = Column(Boolean, nullable=False, default=True)
    require_lowercase = Column(Boolean, nullable=False, default=True)
    require_numbers = Column(Boolean, nullable=False, default=True)
    require_special_chars = Column(Boolean, nullable=False, default=True)

    # Caracteres especiales permitidos
    special_chars_allowed = Column(
        String(50),
        default="!@#$%^&*()_+-=[]{}|;:,.<>?"
    )

    # Cantidad de contraseñas anteriores a recordar
    password_history_count = Column(Integer, nullable=False, default=5)

    # Días de expiración de la contraseña (opcional)
    password_expiration_days = Column(Integer)

    # Indica si la política está activa
    is_active = Column(Boolean, nullable=False, default=True)

    # Auditoría
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    __table_args__ = {
        "comment": "Políticas de seguridad para contraseñas del sistema"
    }
