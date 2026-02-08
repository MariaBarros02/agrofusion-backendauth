from sqlalchemy.orm import Session
from app.repositories.users_repository import UsersRepository
from app.models.users import Users
from fastapi import status, HTTPException
from app.core.errors import auth_error

class UsersService: 
    """
    Servicio principal de usuarios.

    Maneja:
    - Obtener usuario
    """

    def __init__(self):
        self.users_repo = UsersRepository()

    def user_exists(self, db: Session, email: str | None = None,
    numDoc: str | None = None,) -> Users: 
        if not email and not numDoc:
            raise HTTPException(
            status_code=400,
            detail="Debe proporcionar email o número de identificación"
        )
        user = self.users_repo.user_exists(db, email, numDoc)

        if not user:
            raise auth_error("USER_NOT_FOUND_EXISTS", status.HTTP_404_NOT_FOUND)
        
        return user
