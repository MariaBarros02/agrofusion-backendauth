from typing import List
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from uuid import UUID
from app.core.database import get_db
from app.dependencies.auth import get_current_user
from app.schemas.external_projects import ExternalProjectResponse
from app.services.ext_pro_service import ExtProService



# ======================================================
# Router de Usuarios
# ======================================================
# Prefijo global: /users
# Tag utilizado por Swagger/OpenAPI para agrupar endpoints
# ======================================================
router = APIRouter(prefix="/external-projects", tags=["External projects"])

@router.get("", response_model=List[ExternalProjectResponse], summary="Listar proyectos externos",
    description="Retorna la lista de proyectos externos activos disponibles para integración SSO.",
    responses={
        200: {"description": "Lista de proyectos externos"},
    })
def get_external_projects(db: Session = Depends(get_db)):
    """
    ### Proyectos externos disponibles

    Retorna los proyectos externos activos
    habilitados para integración SSO.

    :param db: Sesión activa de base de datos
    :return: Lista de proyectos externos activos
    """
    service = ExtProService()
    return service.get_external_projects(db)



@router.get("/{project_id}/image", summary="Listar imagen principal del proyecto externo",
    description="Retorna la imagen principal de un proyecto externos activos disponible para integración SSO.",
    responses={
        200: {"description": "Imagen de proyecto externo"},
    })
def get_external_project_image(
    project_id: UUID,
    db: Session = Depends(get_db),
    
):
    """
    Endpoint que expone la imagen principal
    de un proyecto externo.

    :param project_id: UUID del proyecto externo
    :return: Imagen del proyecto
    """
    service = ExtProService()
    return service.get_external_project_image(
        db=db,
        project_id= project_id
    )

