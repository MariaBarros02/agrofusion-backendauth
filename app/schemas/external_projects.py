from pydantic import BaseModel
from uuid import UUID
from datetime import datetime
from typing import Optional


class ExternalProjectResponse(BaseModel):
    """
    Representa un proyecto externo disponible para integración.

    Este schema se utiliza como respuesta en endpoints que
    listan proyectos externos asociados al usuario o al sistema,
    por ejemplo en flujos de SSO.
    """

    # Identificador único del proyecto externo
    external_project_id: UUID

    # Código de la instancia o entorno del proyecto (opcional)
    # Ejemplo: "prod", "staging", "qa"
    instance_code: Optional[str]

    # Nombre del proyecto externo
    project_name: Optional[str]

    # Nombre del cliente o empresa propietaria del proyecto
    client_name: Optional[str]

    # Indica si el proyecto se encuentra activo
    is_active: bool

    class Config:
        """
        Configuración del schema.

        from_attributes permite construir el schema directamente
        desde modelos ORM (por ejemplo SQLAlchemy),
        sin necesidad de convertirlos manualmente a dict.
        """
        from_attributes = True  #  clave para SQLAlchemy
