
from sqlalchemy.orm import Session
from typing import List
from app.schemas.external_projects import ExternalProjectResponse, ExternalSystemResponse
from fastapi import HTTPException, Response, status
from app.core.errors import auth_error
from uuid import UUID
from app.repositories.ext_pro_repository import ExtProRepository

class ExtProService: 
    """
    Servicio principal de autenticación.

    Maneja:
    - Obtener proyectos externos activos
    - Obtener imagen principal de un proyecto externo 
    """
    def __init__(self):
        self.ext_pro_repo = ExtProRepository()

    def get_external_projects(self, db:Session) -> List[ExternalProjectResponse]:
        """
        Retorna los proyectos externos activos disponibles para SSO.
        """
        external_projects = self.ext_pro_repo.get_active_ext_pro(db)
        return [
        ExternalProjectResponse(
            external_project_id=p.external_project_id,
            instance_code=p.instance_code,
            project_name=p.project_name,
            client_name=p.client_name,
            is_active=p.is_active,
            description=p.description,
            project_image_url=(f"/external-projects/{p.external_project_id}/image"
            if p.project_image else None),
            systems=[
                ExternalSystemResponse(
                    ext_id=s.ext_id,
                    name=s.name,
                    base_url=s.base_url,
                    is_active=s.is_active,
                    description=s.description,
                    module_icon=s.module_icon
                )
                for s in p.external_systems
                if s.is_active
            ]
        )
        for p in external_projects
    ]

    def get_external_project_image(
        self,
        db: Session,
        project_id: UUID
    ) -> Response:
        """
        Retorna la imagen principal de un proyecto externo activo.

        :param db: Sesión activa de base de datos
        :param project_id: ID del proyecto externo
        :return: Response con la imagen del proyecto
        """

        project = self.ext_pro_repo.get_external_project_by_id(
            db,
            project_id=project_id
        )

        if not project:
            raise auth_error("EXT_PROJECT_NOT_FOUND", status.HTTP_404_NOT_FOUND)

        if not project.is_active:
            raise auth_error("EXT_PROJECT_INACTIVE", status.HTTP_401_UNAUTHORIZED)

        if not project.project_image:
            raise auth_error("EXT_PRO_IMG_NOT_FOUND", status.HTTP_404_NOT_FOUND)

        return Response(
            content=project.project_image,
            media_type=project.project_image_mime_type or "image/png"
        )
