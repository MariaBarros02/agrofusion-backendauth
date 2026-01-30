from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from app.schemas.auth import (
    LoginSuccessResponse,
    LoginRequest,
    LoginResponse,
    NewPasswordRequest,
    ResetPasswordRequest,
    ResetPasswordResponse,
    VerifyOtpRequest,
    SSOTokenRequest,
    SSOTokenResponse,
    AuthContext,
)
from app.services.auth_service import AuthService
from app.services.sso_service import SsoService
from app.core.database import get_db
from app.dependencies.auth import get_current_user
from app.schemas.auth import RefreshTokenRequest


# ======================================================
# Router de Autenticación
# ======================================================
# Prefijo global: /auth
# Tag utilizado por Swagger/OpenAPI para agrupar endpoints
# ======================================================
router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Iniciar sesión",
    description=(
        "Autentica a un usuario mediante email y contraseña.\n\n"
        "El endpoint puede retornar:\n"
        "- Autenticación exitosa\n"
        "- Solicitud de verificación OTP (MFA)\n"
        "- Error por credenciales inválidas o cuenta bloqueada\n\n"
        "Todos los intentos son registrados para auditoría."
    ),
    responses={
        200: {"description": "Login exitoso o desafío OTP"},
        401: {"description": "Credenciales inválidas"},
        423: {"description": "Cuenta bloqueada"},
    },
)
def login(request: Request, payload: LoginRequest, db: Session = Depends(get_db)):
    """
    ### Inicio de sesión de usuario

    Autentica a un usuario utilizando email y contraseña.

    **Flujo de autenticación:**
    - Valida credenciales del usuario
    - Evalúa políticas de seguridad (intentos fallidos, bloqueo, MFA)
    - Puede requerir verificación OTP si el usuario tiene MFA activo
    - Registra el intento de login para auditoría

    **Posibles resultados:**
    - Login exitoso (tokens de acceso y refresh)
    - Solicitud de verificación OTP
    - Error de autenticación

    **Auditoría y seguridad:**
    - Se registra IP y User-Agent
    - Se contabilizan intentos fallidos

    :param request: Objeto Request para obtener IP y User-Agent
    :param payload: Datos de login (email y contraseña)
    :param db: Sesión activa de base de datos
    :return: LoginResponse
    """
    service = AuthService()
    return service.login(
        db,
        payload,
        ip=request.client.host,
        user_agent=request.headers.get("user-agent"),
    )


@router.post("/verify-otp", response_model=LoginSuccessResponse,
    summary="Verificar código OTP",
    description=(
        "Verifica un código OTP como segundo factor de autenticación (MFA).\n\n"
        "Validaciones:\n"
        "- Código válido\n"
        "- No expirado\n"
        "- No utilizado previamente\n"
        "- No excede intentos máximos"
    ),
    responses={
        200: {"description": "OTP válido, login completado"},
        400: {"description": "Código OTP inválido o expirado"},
        423: {"description": "OTP bloqueado por demasiados intentos"},
    })
def verify_otp(
    request: Request, payload: VerifyOtpRequest, db: Session = Depends(get_db)
):
    """
    ### Verificación de OTP (Segundo Factor)

    Valida un código OTP enviado al usuario como parte del proceso MFA.

    **Requisitos previos:**
    - El usuario debe haber iniciado sesión previamente
    - El login debe haber requerido MFA

    **Validaciones realizadas:**
    - Código OTP válido
    - No expirado
    - No utilizado previamente
    - No excede intentos máximos

    :param request: Objeto Request (IP y User-Agent)
    :param payload: Código OTP y propósito
    :param db: Sesión activa de base de datos
    :return: LoginSuccessResponse con tokens activos
    """
    service = AuthService()
    return service.verify_otp(
        db,
        payload,
        ip=request.client.host,
        user_agent=request.headers.get("user-agent"),
    )


@router.post("/sso-token", response_model=SSOTokenResponse,
    summary="Generar token SSO",
    description=(
        "Genera un token de Single Sign-On (SSO) para un proyecto externo.\n\n"
        "Requiere:\n"
        "- Usuario autenticado\n"
        "- Sesión activa\n"
        "- Token de acceso válido"
    ),
    responses={
        200: {"description": "Token SSO generado correctamente"},
        401: {"description": "No autenticado"},
        403: {"description": "Acceso no autorizado al proyecto"},
        404: {"description": "Proyecto externo no encontrado"},
    })
def generate_sso_token(
    request: Request,
    payload: SSOTokenRequest,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_user),
):
    """
    ### Generación de token SSO

    Genera un token de Single Sign-On para permitir acceso a
    un proyecto o sistema externo.

    **Requisitos de seguridad:**
    - Usuario autenticado
    - Sesión activa
    - Token de acceso válido

    **Uso típico:**
    - Integraciones entre plataformas
    - Acceso federado a proyectos externos

    :param request: Objeto Request
    :param payload: Código del proyecto externo
    :param db: Sesión activa de base de datos
    :param auth: Contexto de autenticación actual (usuario, sesión, token)
    :return: SSOTokenResponse
    """
    service = SsoService()
    return service.generate_sso_token(
        db=db,
        user=auth["user"],
        session=auth["session"],
        token=auth["token"],
        project_code=payload.project_code,
        ip=request.client.host,
        user_agent=request.headers.get("user-agent"),
    )


@router.post("/refresh", response_model=LoginResponse,
    summary="Renovar tokens",
    description=(
        "Renueva el token de acceso utilizando un refresh token válido.\n\n"
        "El refresh token debe:\n"
        "- No estar revocado\n"
        "- No estar expirado"
    ),
    responses={
        200: {"description": "Tokens renovados correctamente"},
        401: {"description": "Refresh token inválido o expirado"},
    })
def refresh_token(payload: RefreshTokenRequest, db: Session = Depends(get_db)):
    """
    ### Renovación de tokens

    Genera un nuevo token de acceso utilizando un refresh token válido.

    **Validaciones:**
    - Refresh token válido
    - No revocado
    - No expirado

    :param payload: Refresh token
    :param db: Sesión activa de base de datos
    :return: LoginResponse con nuevos tokens
    """
    service = AuthService()
    return service.refresh_token(db, payload.refresh_token)


@router.post("/logout",
    summary="Cerrar sesión",
    description=(
        "Finaliza la sesión activa del usuario.\n\n"
        "Acciones:\n"
        "- Revoca los tokens activos\n"
        "- Marca la sesión como terminada"
    ),
    responses={
        200: {"description": "Sesión cerrada correctamente"},
        401: {"description": "No autenticado"},
    })
def logout(
    db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)
):
    """
    ### Cierre de sesión

    Finaliza la sesión activa del usuario.

    **Acciones realizadas:**
    - Revoca todos los tokens asociados a la sesión
    - Marca la sesión como terminada
    - Registra evento de seguridad

    :param db: Sesión activa de base de datos
    :param current_user: Contexto de autenticación actual
    :return: Resultado de logout
    """
    service = AuthService()
    return service.logout(
        db,
        session_id=current_user["session"].sso_session_id,
        user_id=current_user["user"].user_id,
    )


@router.post("/request-reset-password", response_model=ResetPasswordResponse,
    summary="Solicitar reseteo de contraseña",
    description=(
        "Inicia el proceso de recuperación de contraseña.\n\n"
        "El sistema:\n"
        "- Genera un token seguro\n"
        "- Envía un email con enlace de recuperación\n"
        "- Registra el evento para auditoría"
    ),
    responses={
        200: {"description": "Email de recuperación enviado"},
        404: {"description": "Usuario no encontrado"},
    })
def request_reset_password(
    request: Request, payload: ResetPasswordRequest, db: Session = Depends(get_db)
):
    """
    ### Solicitud de reseteo de contraseña

    Inicia el proceso de recuperación de contraseña.

    **Proceso:**
    - Genera token seguro de reseteo
    - Envía email con enlace de recuperación
    - Registra evento de seguridad

    :param request: Objeto Request
    :param payload: Email del usuario y datos auxiliares
    :param db: Sesión activa de base de datos
    :return: ResetPasswordResponse
    """
    service = AuthService()
    return service.request_reset_password(
        db,
        payload.email,
        payload.tokens,
        ip=request.client.host,
        user_agent=request.headers.get("user-agent"),
    )


@router.post("/reset-password/{token}", response_model=ResetPasswordResponse,
    summary="Resetear contraseña",
    description=(
        "Permite establecer una nueva contraseña utilizando un token válido.\n\n"
        "Validaciones:\n"
        "- Token válido y no expirado\n"
        "- Contraseñas coinciden\n"
        "- Cumple política de seguridad"
    ),
    responses={
        200: {"description": "Contraseña actualizada correctamente"},
        400: {"description": "Token inválido o contraseñas no coinciden"},
        410: {"description": "Token expirado"},
    })
def reset_password(
    token: str,
    request: Request,
    payload: NewPasswordRequest,
    db: Session = Depends(get_db),
):
    """
    ### Reseteo de contraseña

    Permite establecer una nueva contraseña usando un token válido.

    **Validaciones de seguridad:**
    - Token válido y no expirado
    - Contraseñas coinciden
    - Cumple política de contraseñas
    - Token no usado previamente

    :param token: Token de reseteo
    :param request: Objeto Request
    :param payload: Nueva contraseña y confirmación
    :param db: Sesión activa de base de datos
    :return: ResetPasswordResponse
    """
    service = AuthService()
    return service.reset_password(
        db,
        token=token,
        new_password=payload.new_password,
        confirm_password=payload.confirm_password,
        ip=request.client.host,
        user_agent=request.headers.get("user-agent"),
    )


