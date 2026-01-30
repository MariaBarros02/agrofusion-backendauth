from pydantic import BaseModel, EmailStr
from typing import Union, List, Dict, TypedDict
from uuid import UUID

from app.models.users import Users
from app.models.af_auth_sessions import AuthSession
from app.models.af_auth_tokens import AuthToken
from app.schemas.external_projects import ExternalProjectResponse


# =========================
# REQUEST SCHEMAS
# =========================

class LoginRequest(BaseModel):
    """
    Payload enviado por el cliente para iniciar sesión.

    Contiene las credenciales básicas del usuario.
    """
    email: EmailStr
    password: str


class SSOTokenRequest(BaseModel):
    """
    Request para generar un token SSO.

    Indica el proyecto externo destino.
    """
    project_code: str


class RefreshTokenRequest(BaseModel):
    """
    Request para renovar tokens de acceso.

    Se utiliza cuando el access_token ha expirado.
    """
    refresh_token: str


class VerifyOtpRequest(BaseModel):
    """
    Payload para verificar un código OTP (MFA).

    Se utiliza después de un login que requiere
    autenticación de segundo factor.
    """
    email: str
    otp_code: str


class ResetPasswordRequest(BaseModel):
    """
    Request para solicitar el reseteo de contraseña.

    Incluye:
    - Email del usuario
    - Tokens auxiliares (ej. captcha, CSRF, etc.)
    """
    email: EmailStr
    tokens: Dict[str, str]


class NewPasswordRequest(BaseModel):
    """
    Payload para establecer una nueva contraseña.

    Se utiliza junto con un token válido de reseteo.
    """
    new_password: str
    confirm_password: str


# =========================
# RESPONSE SCHEMAS
# =========================

class SSOTokenResponse(BaseModel):
    """
    Response que contiene el token SSO generado.
    """
    sso_token: str


class LoginSuccessResponse(BaseModel):
    """
    Respuesta devuelta cuando el login es exitoso.

    Incluye:
    - Tokens de autenticación
    - Tipo de token
    - Proyectos externos disponibles para SSO
    """
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class LoginMFARequiredResponse(BaseModel):
    """
    Respuesta devuelta cuando el login requiere MFA.

    Indica al cliente que debe enviar un OTP.
    """
    mfa_required: bool = True
    otp_purpose: str
    expires_in: int


# Union de respuestas posibles del endpoint /login
LoginResponse = Union[
    LoginSuccessResponse,
    LoginMFARequiredResponse
]


class ResetPasswordResponse(BaseModel):
    """
    Respuesta genérica para flujos de reseteo de contraseña.

    Puede utilizarse tanto para solicitud como para confirmación.
    """
    message: str
    token: str


# =========================
# CONTEXTOS INTERNOS
# =========================

class AuthContext(TypedDict):
    """
    Contexto de autenticación inyectado por dependencias.

    No es expuesto al cliente, se usa internamente
    en endpoints protegidos.
    """
    user: Users
    session: AuthSession
    token: AuthToken
