from sqlalchemy.orm import Session
from app.models.users import Users 
from app.models.af_login_attempts import LoginAttempt  
from datetime import datetime, timezone
from app.core.security import ACCOUNT_LOCK_DURATION, MAX_FAILED_LOGIN_ATTEMPTS
from app.models.af_password_history import PasswordHistory
from app.models.af_password_polices import PasswordPolicy


class UsersRepository:
    """
    Repositorio de acceso a datos relacionados con usuarios.

    Responsabilidades principales:
    - Búsqueda de usuarios
    - Control de bloqueo de cuenta
    - Registro de intentos de login
    - Gestión del historial de contraseñas
    - Obtención de políticas de contraseña activas
    """

    def get_by_email(self, db: Session, email: str) -> Users | None:
        """
        Obtiene un usuario por su email.

        :param db: Sesión activa de base de datos
        :param email: Email del usuario
        :return: Instancia Users o None si no existe
        """
        return db.query(Users).filter(Users.email == email).first()

    def is_account_lock_expired(self, locked_at) -> bool:
        """
        Determina si un bloqueo de cuenta ya expiró.

        Si el usuario no está bloqueado (`locked_at` es None),
        se considera que el bloqueo NO ha expirado.

        :param locked_at: Fecha/hora en que se bloqueó la cuenta
        :return: True si el bloqueo ya expiró, False en caso contrario
        """
        if not locked_at:
            return False
        return datetime.now(timezone.utc) >= locked_at + ACCOUNT_LOCK_DURATION
    
    def register_login_attempt(
        self,
        db: Session,
        *,
        user: Users | None,
        email: str,
        success: bool,
        reason: str,
        ip: str
    ) -> None:
        """
        Registra un intento de inicio de sesión.

        Se registra incluso si el usuario no existe, permitiendo:
        - Auditoría completa
        - Detección de ataques de enumeración de cuentas
        - Análisis de intentos fallidos por email

        :param db: Sesión activa de base de datos
        :param user: Usuario autenticado o None si no existe
        :param email: Email utilizado en el intento
        :param success: Indica si el intento fue exitoso
        :param reason: Motivo del fallo o resultado
        :param ip: Dirección IP del cliente
        """

        attempt = LoginAttempt(
            user_id=user.user_id if user else None,
            email=email,
            success=success,
            reason=reason,
            ip=ip
        )

        db.add(attempt)
        db.commit()
    
    def add_password_history(
        self,
        db: Session,
        *,
        user_id,
        password_hash: str,
        changed_by=None,
        change_reason: str,
        ip: str | None = None,
        user_agent: str | None = None,
    ) -> PasswordHistory:
        """
        Registra un cambio de contraseña en el historial del usuario.

        Se utiliza para:
        - Evitar reutilización de contraseñas
        - Auditoría de cambios de credenciales
        - Cumplimiento de políticas de seguridad

        :param db: Sesión activa de base de datos
        :param user_id: ID del usuario
        :param password_hash: Hash de la nueva contraseña
        :param changed_by: Usuario o sistema que realizó el cambio
        :param change_reason: Motivo del cambio (reset, expiración, manual, etc.)
        :param ip: IP desde donde se realizó el cambio
        :param user_agent: User-Agent del cliente
        :return: Registro de PasswordHistory creado
        """

        history = PasswordHistory(
            user_id=user_id,
            password_hash=password_hash,
            changed_by=changed_by,
            change_reason=change_reason,
            ip_address=ip,
            user_agent=user_agent,
        )

        db.add(history)
        return history

    def get_active_policy(self, db: Session) -> PasswordPolicy:
        """
        Obtiene la política de contraseñas activa más reciente.

        Se espera que exista siempre una política activa.
        En caso contrario, se lanza una excepción crítica.

        :param db: Sesión activa de base de datos
        :return: Instancia PasswordPolicy activa
        :raises RuntimeError: Si no existe una política activa
        """
        policy = (
            db.query(PasswordPolicy)
            .filter(PasswordPolicy.is_active.is_(True))
            .order_by(PasswordPolicy.created_at.desc())
            .first()
        )

        if not policy:
            raise RuntimeError("No active password policy found")

        return policy
