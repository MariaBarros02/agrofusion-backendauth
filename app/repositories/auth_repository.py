import secrets
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta
from app.models.af_auth_sessions import AuthSession
from app.models.af_auth_tokens import AuthToken
from app.models.af_password_reset_tokens import PasswordResetToken
from app.core.config import settings
import hashlib


class AuthRepository:
    """
    Repositorio encargado de la gestión de autenticación y sesiones.

    Responsabilidades:
    - Crear y finalizar sesiones de usuario
    - Emitir y revocar tokens de acceso / refresh
    - Gestionar tokens de reseteo de contraseña
    """

    def create_session(self, db: Session, *, user_id, expires_at, ip, user_agent):
        """
        Crea una nueva sesión de autenticación para un usuario.

        :param db: Sesión activa de base de datos
        :param user_id: ID del usuario autenticado
        :param expires_at: Fecha de expiración de la sesión
        :param ip: Dirección IP del cliente
        :param user_agent: User-Agent del cliente
        :return: Instancia de AuthSession persistida
        """
        session = AuthSession(
            user_id=user_id,
            expires_at=expires_at,
            ip=ip,
            user_agent=user_agent
        )
        db.add(session)
        db.flush()  # asegura que el ID esté disponible sin hacer commit
        return session

    def create_tokens(
        self,
        db: Session,
        *,
        session_id,
        access_token,
        refresh_token,
        access_expires_at,
        refresh_expires_at
    ):
        """
        Crea los tokens de acceso y refresh asociados a una sesión.

        :param db: Sesión activa de base de datos
        :param session_id: ID de la sesión SSO
        :param access_token: JWT de acceso
        :param refresh_token: Token de refresco
        :param access_expires_at: Expiración del access token
        :param refresh_expires_at: Expiración del refresh token
        :return: Instancia de AuthToken
        """
        token = AuthToken(
            sso_session_id=session_id,
            access_token=access_token,
            refresh_token=refresh_token,
            access_expires_at=access_expires_at,
            refresh_expires_at=refresh_expires_at
        )
        db.add(token)
        return token

    def revoke_token_session(self, db: Session, session_id, reason: str):
        """
        Revoca todos los tokens activos asociados a una sesión específica.

        :param db: Sesión activa de base de datos
        :param session_id: ID de la sesión a revocar
        :param reason: Motivo de la revocación
        """
        db.query(AuthToken).filter(
            AuthToken.sso_session_id == session_id,
            AuthToken.revoked_at.is_(None)
        ).update({
            "revoked_at": datetime.now(timezone.utc),
            "revoked_reason": reason
        })

    def revoke_by_session(self, db: Session, *, session_id, reason: str) -> int:
        """
        Revoca manualmente los tokens activos de una sesión.

        :param db: Sesión activa de base de datos
        :param session_id: ID de la sesión
        :param reason: Motivo de la revocación
        :return: Cantidad de tokens revocados
        """
        now = datetime.now(timezone.utc)
        tokens = (
            db.query(AuthToken)
            .filter(
                AuthToken.sso_session_id == session_id,
                AuthToken.revoked_at.is_(None)
            )
            .all()
        )
        for token in tokens:
            token.revoked_at = now
            token.revoked_reason = reason
        return len(tokens)

    def terminate_session(self, db: Session, *, session_id) -> None:
        """
        Marca una sesión como terminada (logout explícito).

        :param db: Sesión activa de base de datos
        :param session_id: ID de la sesión a finalizar
        """
        session = (
            db.query(AuthSession)
            .filter(
                AuthSession.sso_session_id == session_id,
                AuthSession.terminated_at.is_(None)
            )
            .first()
        )

        if session:
            session.terminated_at = datetime.now(timezone.utc)

    def gen_pass_reset_token(
        self,
        db: Session,
        user,
        *,
        ip: str | None = None,
        user_agent: str | None = None
    ) -> str:
        """
        Genera un token seguro para el reseteo de contraseña.

        - El token plano solo se devuelve para envío por email
        - En base de datos se almacena un hash SHA-256
        - El token expira en 30 minutos

        :param db: Sesión activa de base de datos
        :param user: Usuario solicitante
        :param ip: IP del solicitante
        :param user_agent: User-Agent del solicitante
        :return: Token plano para envío por email
        """

        # Token aleatorio seguro
        raw_token = secrets.token_urlsafe(48)

        # Hash del token usando secret_key del sistema
        hash_input = f"{raw_token}:{settings.secret_key}"
        token_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()

        expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)

        reset_token = PasswordResetToken(
            user_id=user.user_id,
            token=raw_token,  # puede eliminarse si no se desea guardar el token plano
            token_hash=token_hash,
            email=user.email,
            expires_at=expires_at,
            ip_address=ip,
            user_agent=user_agent,
        )

        db.add(reset_token)
        db.commit()

        return raw_token

    def get_valid_pass_reset_token(
        self,
        db: Session,
        raw_token: str
    ) -> PasswordResetToken | None:
        """
        Obtiene un token de reseteo de contraseña válido.

        Reglas:
        - El token debe existir
        - El hash debe coincidir
        - No debe estar usado
        - No debe estar invalidado
        - No debe estar expirado

        :param db: Sesión activa de base de datos
        :param raw_token: Token plano recibido
        :return: PasswordResetToken válido o None
        """

        if not raw_token:
            return None

        # Recalcular hash del token recibido
        token_hash = hashlib.sha256(
            f"{raw_token}:{settings.secret_key}".encode("utf-8")
        ).hexdigest()

        token = (
            db.query(PasswordResetToken)
            .filter(
                PasswordResetToken.token_hash == token_hash,
                PasswordResetToken.used_at.is_(None),
                PasswordResetToken.invalidated_at.is_(None),
                PasswordResetToken.expires_at > datetime.now(timezone.utc),
            )
            .first()
        )

        return token

    def invalidate_all_reset_tokens(
        self,
        db: Session,
        *,
        user_id,
        reason: str,
    ) -> int:
        """
        Invalida todos los tokens de reseteo de contraseña activos de un usuario.

        Usado cuando:
        - Se cambia la contraseña exitosamente
        - Se detecta actividad sospechosa

        :param db: Sesión activa de base de datos
        :param user_id: ID del usuario
        :param reason: Motivo de invalidación
        :return: Cantidad de tokens invalidados
        """

        now = datetime.now(timezone.utc)

        tokens = (
            db.query(PasswordResetToken)
            .filter(
                PasswordResetToken.user_id == user_id,
                PasswordResetToken.used_at.is_(None),
                PasswordResetToken.invalidated_at.is_(None),
                PasswordResetToken.expires_at > now,
            )
            .all()
        )

        for token in tokens:
            token.invalidated_at = now
            token.invalidation_reason = reason

        return len(tokens)


    def terminate_all_user_sessions(self, db: Session, *, user_id, reason: str) -> int:
            """
            Finaliza todas las sesiones activas de un usuario y revoca sus tokens.
            """
            now = datetime.now(timezone.utc)
            
            # 1. Obtener IDs de sesiones activas para revocar tokens después
            active_sessions = (
                db.query(AuthSession.sso_session_id)
                .filter(
                    AuthSession.user_id == user_id,
                    AuthSession.terminated_at.is_(None)
                )
                .all()
            )
            session_ids = [s.sso_session_id for s in active_sessions]

            if not session_ids:
                return 0

            # 2. Revocar todos los tokens de esas sesiones
            db.query(AuthToken).filter(
                AuthToken.sso_session_id.in_(session_ids),
                AuthToken.revoked_at.is_(None)
            ).update(
                {"revoked_at": now, "revoked_reason": reason},
                synchronize_session=False
            )

            # 3. Terminar las sesiones
            count = db.query(AuthSession).filter(
                AuthSession.sso_session_id.in_(session_ids)
            ).update(
                {"terminated_at": now},
                synchronize_session=False
            )

            return count