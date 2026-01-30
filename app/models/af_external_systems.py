from sqlalchemy import (
    Column,
    String,
    Text,
    Boolean,
    Integer,
    ForeignKey,
    DateTime
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import uuid

from app.core.database import Base  


class AfExternalSystem(Base):
    __tablename__ = "af_external_systems"
    __table_args__ = {"schema": "public"}

    #  PK
    ext_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    #  Info general
    name = Column(String(60), nullable=False, unique=True)
    description = Column(String)
    base_url = Column(Text)
    module_icon = Column(String)

    #  Estado
    status_term_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.cat_terms.term_id"),
        nullable=False
    )
    is_active = Column(Boolean, default=True)

    #  Auditoría
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    updated_at = Column(DateTime(timezone=True))
    deleted_at = Column(DateTime(timezone=True))

    created_by = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id")
    )

    #  Relación con proyecto externo
    external_project_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.af_external_projects.external_project_id"),
        index=True
    )

    external_project = relationship(
        "AfExternalProject",
        back_populates="external_systems"
    )

    #  Config DB externa
    db_host = Column(String(255))
    db_port = Column(Integer, default=5432)
    db_name = Column(String(100))
    db_schema = Column(String(100), default="public")
    db_user = Column(String(100))
    db_password_encrypted = Column(Text)
    ssl_enabled = Column(Boolean, default=True)

    #  Health check
    last_test_at = Column(DateTime(timezone=True))
    last_test_status = Column(String(20))
    last_test_error = Column(Text)

    #  Relaciones opcionales
    status_term = relationship("CatTerm")
    creator = relationship("Users")



    def __repr__(self) -> str:
        return f"<AfExternalSystem {self.name} ({self.ext_id})>"
