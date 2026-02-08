from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.services.users_service import UsersService
from app.dependencies.auth import get_current_user
from typing import Optional
from fastapi import Query
# ======================================================
# Router de Usuarios
# ======================================================
# Prefijo global: /users
# Tag utilizado por Swagger/OpenAPI para agrupar endpoints
# ======================================================
router = APIRouter(prefix="/users", tags=["Users"])

@router.get("/user-exists", summary="Obtener un usuario del sistema por su correo electrónico o número de identificación", 
            description="Devuelve el objeto usuario si existe en el sistema y devuelve codigo error si este no existe",
            responses={
                200: {"description": "Objeto usuario"},
                404: {"description": "Usuario no encontrado / no existe"}
            })
def user_exists(email: Optional[str] = Query(None), numDoc: Optional[str] = Query(None),  db: Session = Depends(get_db), current_user = Depends(get_current_user),
):
    service = UsersService();
    return service.user_exists(db, email, numDoc)

