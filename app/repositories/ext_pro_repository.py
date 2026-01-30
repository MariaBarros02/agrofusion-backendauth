from typing import List
from app.models.af_external_projects import AfExternalProject
from sqlalchemy.orm import Session, selectinload




class ExtProRepository: 

    """
    Repositorio encargado de la gestión de proyectos externo.

    Centraliza:
    - Búsqueda de proyectos externos
    """
    
    def get_active_ext_pro(self, db: Session) -> List[AfExternalProject]:
        """
        Obtiene todos los proyectos externos activos.

        :param db: Sesión activa de base de datos
        :return: Lista de proyectos externos activos
        """
        external_projects = (
    
            db.query(AfExternalProject)
            .options(selectinload(AfExternalProject.external_systems))
            .filter(AfExternalProject.is_active.is_(True))
            .all()
  
        )
        return external_projects
    
        
    def get_external_project_by_id(self, db: Session, *, project_id: str):
        """
    Obtiene un proyecto interno por su id único.

    :param db: Sesión activa de base de datos
    :param code: Id único del proyecto
    :return: Instancia de Project o None
    """
        return (
            db.query(AfExternalProject)
            .filter(AfExternalProject.external_project_id == project_id)
            .first()
        )