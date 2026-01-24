"""
Utilidades de seguridad y autenticación.

Este módulo contiene funciones para:
- Hash y verificación de contraseñas
- Creación y validación de tokens JWT
- Manejo de políticas de seguridad (bloqueos, expiraciones)
"""

from datetime import datetime, timedelta, timezone
from http.client import HTTPException
import uuid
from fastapi import status
import secrets
from jose import jwt, JWTError
from passlib.context import CryptContext
from app.core.config import settings
from datetime import timedelta


# Tiempo de bloqueo de cuenta tras múltiples intentos fallidos

ACCOUNT_LOCK_DURATION = timedelta(minutes=30)

# Número máximo de intentos fallidos antes de bloquear la cuenta

MAX_FAILED_LOGIN_ATTEMPTS = 3
# Contexto de cifrado para manejo seguro de contraseñas

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

#Password
def verify_password(plain: str, hashed: str) -> bool:
    """
    Verifica una contraseña en texto plano contra su hash.

    Args:
        plain (str): Contraseña en texto plano.
        hashed (str): Hash almacenado de la contraseña.

    Returns:
        bool: True si la contraseña coincide, False en caso contrario.
    """
    return pwd_context.verify(plain, hashed)

def get_password_hash(password: str) -> str:
    """
    Genera un hash seguro a partir de una contraseña en texto plano.

    Args:
        password (str): Contraseña en texto plano.

    Returns:
        str: Hash cifrado de la contraseña.
    """
    return pwd_context.hash(password)

def create_access_token(
    data: dict,
    expires_delta: timedelta | None = None
) -> str:
    """
    Crea un token JWT de acceso.

    El token incluye claims estándar como:
    - sub (sujeto)
    - exp (expiración)
    - iat (emitido en)
    - nbf (no válido antes de)
    - iss (emisor)

    Args:
        data (dict): Información a incluir en el token (debe contener 'sub').
        expires_delta (timedelta, opcional): Tiempo de expiración personalizado.

    Returns:
        str: Token JWT firmado.
    """
    # Validación obligatoria del sujeto del token

    if "sub" not in data:
        raise ValueError("JWT requiere claim 'sub'")
    # Timestamp actual en UTC

    now = datetime.now(timezone.utc)

    to_encode = data.copy()

    expire = now + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    # Copia segura del payload original

    to_encode.update({
        "iat": now,
        "nbf": now,
        "exp": expire,
        "jti": str(uuid.uuid4()),
        "iss": settings.jwt_issuer,
        "type": "access"
    })

    encoded_jwt = jwt.encode(
        to_encode,
        settings.secret_key,
        algorithm=settings.algorithm
    )
    # Firma y codificación del token JWT

    return encoded_jwt


def create_refresh_token():
    """
    Genera un token de refresco seguro.

    Returns:
        str: Token aleatorio de alta entropía.
    """
    return secrets.token_urlsafe(64)

def decode_access_token(token: str) -> dict:
    """
    Decodifica y valida un token JWT de acceso.

    Realiza validaciones explícitas de:
    - Firma
    - Expiración
    - Integridad del token

    Args:
        token (str): Token JWT recibido.

    Returns:
        dict: Payload decodificado del token.

    Raises:
        HTTPException: Si el token es inválido o está expirado.
    """
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm]
        )

        # Validación explícita de exp
        exp = payload.get("exp")
        if exp is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token sin expiración"
            )

        if datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expirado"
            )

        return payload

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido"
        )
