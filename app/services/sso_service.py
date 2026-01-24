from sqlalchemy.orm import Session
from datetime import timezone, datetime, timedelta
from app.models.users import Users
from app.models.af_auth_sessions import AuthSession
from app.models.af_auth_tokens import AuthToken
from app.repositories.audit_repository import AuditRepository
from app.models.af_external_projects import AfExternalProject
from app.core.errors import auth_error
from fastapi import status
from jose import jwt
from app.core.config import settings


class SsoService:
    """
    Servicio encargado de la generación de tokens SSO (Single Sign-On)
    para proyectos externos autorizados.

    Este servicio crea tokens JWT firmados con clave privada (RS256),
    permitiendo a proyectos externos confiar en la identidad del usuario
    autenticado en el sistema central.
    """

    def __init__(self):
        # Repositorio de auditoría para registrar eventos de seguridad y SSO
        self.audit_repo = AuditRepository()

    def generate_sso_token(
        self,
        db: Session,
        user: Users,
        session: AuthSession,
        token: AuthToken,
        project_code: str,
        ip: str,
        user_agent: str
    ):
        """
        Genera un token SSO JWT para un proyecto externo específico.

        El token permite que un proyecto externo valide la identidad
        del usuario sin requerir nuevas credenciales.

        :param db: Sesión activa de base de datos
        :param user: Usuario autenticado
        :param session: Sesión SSO activa del usuario
        :param token: Token de autenticación actual (access/refresh)
        :param project_code: Código del proyecto externo destino
        :param ip: Dirección IP desde la cual se solicita el token
        :param user_agent: User-Agent del cliente
        :raises HTTPException: Si el proyecto no existe o no es válido
        :return: Diccionario con el token SSO generado
        """

        # ---------- VALIDAR PROYECTO EXTERNO ----------
        # Se valida que el proyecto externo exista y esté registrado
        project = self.audit_repo.get_projectExt_by_code(db, code=project_code)

        if not project:
            raise auth_error(
                "AUTH_PROJECT_NOT_FOUND",
                status.HTTP_404_NOT_FOUND
            )

        # ---------- VALIDACIÓN DE ACCESO (FUTURA) ----------
        # Punto de control para validar que el usuario tenga
        # permisos explícitos sobre el proyecto externo
        # if not self.users_repo.has_access_to_project(db, user.user_id, project_code):
        #     raise auth_error("AUTH_PROJECT_FORBIDDEN", status.HTTP_401_UNAUTHORIZED)

        now = datetime.now(timezone.utc)

        # ---------- PAYLOAD JWT ----------
        # Datos estándar y personalizados incluidos en el token SSO
        payload = {
            "iss": "agrofusion-auth",           # Emisor del token
            "aud": project_code,               # Audiencia (proyecto destino)
            "sub": str(user.user_id),           # Identificador del usuario
            "email": user.email,               # Email del usuario autenticado
            "iat": int(now.timestamp()),        # Fecha de emisión
            "exp": int((now + timedelta(minutes=2)).timestamp())  # Expiración corta
        }

        # ---------- FIRMA JWT ----------
        # Se firma el token con clave privada RSA usando RS256
        sso_token = jwt.encode(
            payload,
            settings.sso_private_key,
            algorithm="RS256"
        )

        # ---------- AUDITORÍA ----------
        # Se registra el evento de emisión de token SSO
        self.audit_repo.log_event(
            db=db,
            action_code="SSO_TOKEN_ISSUED",
            outcome="success",
            project_id=project.external_project_id,
            module_code="AUTH_SSO",
            actor_id=user.user_id,
            ip=ip,
            user_agent=user_agent,
            metadata={
                "project_code": project_code
            }
        )

        # ---------- RESPUESTA ----------
        return {"sso_token": sso_token}
