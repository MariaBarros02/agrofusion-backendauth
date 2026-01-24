"""
Dependencias de autenticación y autorización.

Este módulo define dependencias de FastAPI para:
- Extraer y validar tokens Bearer
- Verificar sesiones activas
- Obtener el usuario autenticado actual
"""
from fastapi import Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.core.database import get_db
from app.models.af_auth_tokens import AuthToken
from app.core.errors import auth_error
from app.core.security import decode_access_token

# Esquema de autenticación Bearer para Swagger y validación automática de headers

security = HTTPBearer(auto_error=True)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    """
    Obtiene el usuario autenticado a partir del token Bearer.

    Flujo de validación:
    1. Extrae el token del header Authorization
    2. Decodifica y valida el JWT
    3. Verifica que el token exista y no esté revocado en la base de datos
    4. Valida la sesión asociada al token
    5. Actualiza la última actividad de la sesión

    Args:
        credentials (HTTPAuthorizationCredentials): Credenciales Bearer.
        db (Session): Sesión de base de datos.

    Returns:
        dict: Información del contexto autenticado:
            - user: Usuario autenticado
            - session: Sesión activa
            - token: Registro del token

    Raises:
        HTTPException: Si el token o la sesión no son válidos.
    """

    # Extracción del token JWT desde el header Authorization
    token = credentials.credentials

    # Decodificación y validación criptográfica del token JWT

    try:
        payload = decode_access_token(token)
    except Exception:
        raise auth_error(
            code="AUTH_INVALID_TOKEN",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    # Verificación del token en la base de datos (revocado o inexistente)

    token_db = (
        db.query(AuthToken)
        .filter(
            AuthToken.access_token == token,
            AuthToken.revoked_at.is_(None),
        )
        .first()
    )

    if not token_db:
        raise auth_error(
            code="AUTH_TOKEN_REVOKED",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    now = datetime.now(timezone.utc)

    # Validación de expiración del token de acceso

    if token_db.access_expires_at < now:
        raise auth_error(
            code="AUTH_TOKEN_EXPIRED",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    session = token_db.session

    # La sesión fue terminada explícitamente (logout, cierre forzado, etc.)

    if session.terminated_at is not None:
        raise auth_error(
            code="AUTH_SESSION_TERMINATED",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    if session.expires_at < now:
        raise auth_error(
            code="AUTH_SESSION_EXPIRED",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    session.last_activity_at = datetime.now(timezone.utc)
    db.commit()
    return  {
        "user": session.user,
        "session": session,
        "token": token_db
    }
