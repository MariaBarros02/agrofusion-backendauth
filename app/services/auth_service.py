import token
from sqlalchemy.orm import Session
from typing import List, Dict
from app.repositories.users_repository import UsersRepository
from app.repositories.audit_repository import AuditRepository
from app.schemas.auth import LoginRequest, LoginSuccessResponse, ResetPasswordResponse, VerifyOtpRequest, LoginResponse
from app.repositories.auth_repository import AuthRepository
from app.models.af_auth_sessions import AuthSession
from app.models.af_auth_tokens import AuthToken
from app.core.security import get_password_hash, verify_password, create_access_token, create_refresh_token,  ACCOUNT_LOCK_DURATION , MAX_FAILED_LOGIN_ATTEMPTS
from app.core.errors import auth_error
from datetime import datetime, timezone, timedelta
from app.models.af_otp_codes import AfOtpCode
from app.utils.otp import generate_otp_code, hash_otp_code, verify_otp_code
from app.repositories.otp_repository import OtpRepository
from app.repositories.email_repository import EmailRepository
from app.models.af_security_events import SecurityEvent
from app.services.passwordPolicy_service import PasswordPolicyService
from app.schemas.external_projects import ExternalProjectResponse

from fastapi import HTTPException, status


# =========================
# Configuración de tiempos
# =========================
ACCESS_TTL = timedelta(minutes=15)      # Vida útil del access token
REFRESH_TTL = timedelta(days=7)         # Vida útil del refresh token
SESSION_TTL = timedelta(hours=8)        # Duración máxima de la sesión SSO


OTP_PURPOSE_LOGIN = "login_2fa"
OTP_TTL = timedelta(minutes=5)
OTP_RESEND_WINDOW_MIN = 15
OTP_RESEND_MAX = 3
OTP_COOLDOWN_SECONDS = 60

class AuthService:
    """
    Servicio principal de autenticación.

    Maneja:
    - Login con password
    - MFA (OTP)
    - Emisión y refresh de tokens
    - Reset de contraseña
    - Logout
    - Auditoría y eventos de seguridad
    """
    def __init__(self):
        self.users_repo = UsersRepository()
        self.audit_repo = AuditRepository()
        self.auth_repo = AuthRepository()
        self.otp_repo = OtpRepository()
        self.email_repo = EmailRepository()
        self.password_policy_service = PasswordPolicyService()
    
    def get_external_projects(self, db:Session) -> List[ExternalProjectResponse]:
        """
        Retorna los proyectos externos activos disponibles para SSO.
        """
        external_projects = self.audit_repo.get_active_ext_pro(db)
        return external_projects;

    def login(self, db: Session, data: LoginRequest, ip: str, user_agent: str) -> LoginSuccessResponse:
        """
        Realiza el proceso de login principal.

        Flujo:
        - Validación de usuario
        - Validación de estado de cuenta
        - Verificación de contraseña
        - MFA si está habilitado
        - Creación de sesión y tokens
        - Auditoría completa
        """
        
        user = self.users_repo.get_by_email(db, data.email)

        project = self.audit_repo.get_project_by_code(db, code="AGROFUSION")
        if not project:
            raise RuntimeError("Project AGROFUSION not found")
        # ---------- USER NOT FOUND ----------
        if not user:
            self.audit_repo.log_login_event(
                db=db,
                action_code="AUTH_LOGIN_ATTEMPT",
                outcome="failure",
                project_id=project.af_project_id,
                actor_id=None,
                email=data.email,
                ip=ip,
                user_agent=user_agent,
                reason="invalid_credentials",
            )
            db.commit()
            raise auth_error("AUTH_USER_NOT_FOUND", status.HTTP_401_UNAUTHORIZED)

        # ---------- ACCOUNT DELETED ----------
        if user.deleted_at:
            self.users_repo.register_login_attempt(db, user=user, email=data.email, success=False, reason="AUTH_USER_DELETED", ip=ip)

            self.audit_repo.log_login_event(
                db=db,
                action_code="AUTH_LOGIN_ATTEMPT",
                outcome="rejected",
                actor_id=user.user_id,
                email=data.email,
                project_id=project.af_project_id,
                ip=ip,
                user_agent=user_agent,
                reason="user_deleted",
            )
            db.commit()
            raise auth_error("AUTH_USER_DELETED", status.HTTP_403_FORBIDDEN)

        # ---------- ACCOUNT NOT VERIFIED ----------
        if not user.email_verified_at:
            self.users_repo.register_login_attempt(db, user=user, email=data.email, success=False, reason="AUTH_ACCOUNT_NOT_ACTIVATED", ip=ip)

            self.audit_repo.log_login_event(
                db=db,
                action_code="AUTH_LOGIN_ATTEMPT",
                outcome="rejected",
                actor_id=user.user_id,
                email=data.email,
                project_id=project.af_project_id,
                ip=ip,
                user_agent=user_agent,
                reason="account_not_verified",
            )
            db.commit()
            raise auth_error("AUTH_ACCOUNT_NOT_ACTIVATED", status.HTTP_403_FORBIDDEN)

        # ---------- ACCOUNT LOCKED ----------
        if user.locked_at and not self.users_repo.is_account_lock_expired(user.locked_at):
            unlock_time = user.locked_at + ACCOUNT_LOCK_DURATION
            remaining = max(0, int((unlock_time - datetime.now(timezone.utc)).total_seconds()))
            self.users_repo.register_login_attempt(db, user=user, email=data.email, success=False, reason="AUTH_USER_BLOCKED", ip=ip)

            self.audit_repo.log_login_event(
                db=db,
                action_code="AUTH_LOGIN_ATTEMPT",
                outcome="rejected",
                actor_id=user.user_id,
                email=data.email,
                ip=ip,
                project_id=project.af_project_id,
                user_agent=user_agent,
                reason="account_blocked",
            )
            db.commit()
            raise auth_error("AUTH_USER_BLOCKED", status.HTTP_403_FORBIDDEN, {"retry_after_seconds": remaining})

        # ---------- INVALID PASSWORD ----------
        if not verify_password(data.password, user.password_hash):
            user.failed_attempts += 1
            if user.failed_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
                user.locked_at = datetime.now(timezone.utc)
            self.users_repo.register_login_attempt(db, user=user, email=data.email, success=False, reason="AUTH_INVALID_PASSWORD", ip=ip)
            self.audit_repo.log_login_event(
                db=db,
                action_code="AUTH_LOGIN_FAILED",
                outcome="failure",
                actor_id=user.user_id,
                email=data.email,
                ip=ip,
                project_id=project.af_project_id,
                user_agent=user_agent,
                reason="invalid_password",
                attempts_count=user.failed_attempts,
                account_locked=user.failed_attempts >= MAX_FAILED_LOGIN_ATTEMPTS,
            )
            db.commit()
            raise auth_error("AUTH_INVALID_PASSWORD", status.HTTP_401_UNAUTHORIZED)

        # ---------- SUCCESS ----------
        now = datetime.now(timezone.utc)
        user.failed_attempts = 0
        user.locked_at = None
        user.last_login_at = now

        if user.is_mfa_enabled:
            self.otp_repo.inv_active_otps(db, user_id=user.user_id, purpose="login_2fa")

            otp_code = generate_otp_code()
            otp = self.otp_repo.create_otp(
                db = db,
                user_id = user.user_id,
                otp_code = otp_code,
                purpose = "login_2fa",
                expires_at = now + timedelta(minutes=5),
                ip_address = ip,
                user_agent = user_agent
            )

            self.email_repo.enqueue_otp_email(
                db=db,
                user=user,
                otp_code=otp_code,
                ip=ip
            )

            self.audit_repo.log_event(
                db=db,
                action_code="OTP_GENERATED",
                outcome="success",
                module_code="MFA_MANAGEMENT",
                project_id=project.af_project_id,
                actor_id=user.user_id,
                ip=ip,
                user_agent=user_agent,
                metadata={
                    "otp_purpose": otp.purpose,
                    "expires_in": "5 minutes",
                    "sent_to_email": user.email,
                },
            )
            db.commit()

            return {
                "mfa_required": True,
                "otp_purpose": "login_2fa",
                "expires_in": 300,
            }

        session = AuthSession(
            user_id=user.user_id,
            issued_at=now,
            expires_at=now + SESSION_TTL,
            ip=ip,
            user_agent=user_agent,
        )

        db.add(session)
        db.flush()  # ✅ obtenemos sso_session_id sin commit

        access_token = create_access_token(
            {"sub": str(user.user_id), "sid": str(session.sso_session_id)},
            expires_delta=ACCESS_TTL,
        )

        refresh_token = create_refresh_token()

        token = AuthToken(
            sso_session_id=session.sso_session_id,
            access_token=access_token,
            refresh_token=refresh_token,
            access_expires_at=now + ACCESS_TTL,
            refresh_expires_at=now + REFRESH_TTL,
        )

        db.add(token)

        self.audit_repo.log_login_event(
            db=db,
            action_code="AUTH_LOGIN_SUCCESS",
            outcome="success",
            actor_id=user.user_id,
            email=user.email,
            ip=ip,
            project_id=project.af_project_id,
            user_agent=user_agent,
            session_id=session.sso_session_id,
        )
        self.audit_repo.log_event(
            db=db,
            action_code="TOKENS_ISSUED",
            outcome="success",
            module_code="TOKEN_MANAGEMENT",
            project_id=project.af_project_id,
            actor_id=user.user_id,
            session_id=session.sso_session_id,
            ip=ip,
            user_agent=user_agent,
            metadata={
                "access_expires_at": token.access_expires_at.isoformat(),
                "refresh_expires_at": token.refresh_expires_at.isoformat(),
            },
        )
        self.audit_repo.log_event(
            db=db,
            action_code="SESSION_CREATED",
            outcome="success",
            module_code="SSO_AUTH",
            project_id=project.af_project_id,
            actor_id=user.user_id,
            session_id=session.sso_session_id,
            ip=ip,
            user_agent=user_agent,
        )
        external_projects = self.audit_repo.get_active_ext_pro(db=db)

        db.commit()

        return LoginSuccessResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=int(ACCESS_TTL.total_seconds()),
            external_projects = external_projects
        )
    
    def refresh(self, db:Session, refresh_token:str) -> LoginResponse:
        """
        Renueva un access token usando un refresh token válido.

        Flujo:
        - Valida existencia del refresh token
        - Verifica que no esté revocado ni expirado
        - Valida estado de la sesión
        - Revoca el token anterior
        - Emite un nuevo par de tokens
        """

        token = db.query(AuthToken).filter(
            AuthToken.refresh_token == refresh_token
        ).first()
        if not token:
            raise auth_error(code="AUTH_INVALID_REFRESH_TOKEN")
        if token.revoked_at or token.refresh_expires_at < datetime.now(timezone.utc):
            raise auth_error(code="AUTH_REFRESH_EXPIRED")
        
        session = token.session
        if session.terminated_at or session.expires_at < datetime.now(timezone.utc):
            raise auth_error(code="AUTH_SESSION_EXPIRED")
        
        token.revoked_at = datetime.now(timezone.utc)
        token.revoked_reason = "REFRESHED"
        
        now = datetime.now(timezone.utc)
        new_access = create_access_token(
            {"sub": str(session.user_id), "sid": str(session.sso_session_id)}, expires_delta=timedelta(minutes=15))
        
        new_refresh = create_refresh_token()

        new_token = AuthToken(
            sso_session_id=session.sso_session_id, access_token=new_access, refresh_token=new_refresh, access_expires_at=now + timedelta(minutes=15), refresh_expires_at=now + timedelta(days=7)
        )
        self.audit_repo.log_event(
            db=db,
            action_code="TOKENS_REFRESHED",
            outcome="success",
            module_code="TOKEN_REFRESH",
            project_id=session.project_id if hasattr(session, "project_id") else None,
            actor_id=session.user_id,
            session_id=session.sso_session_id,
            metadata={
                "old_token_revoked_at": token.revoked_at.isoformat(),
                "new_access_expires_at": new_token.access_expires_at.isoformat(),
            },
        )

        db.add(new_token)
        db.commit()
        return LoginResponse(
            access_token=new_access,
            refresh_token=new_refresh,
            expires_in=900
        )
    
    def verify_otp(self, db: Session, data:VerifyOtpRequest, ip:str, user_agent:str) -> LoginSuccessResponse:
        """
        Verifica un código OTP como segundo factor de autenticación (MFA).

        Validaciones:
        - Usuario y proyecto válidos
        - OTP existente, no usado y no expirado
        - Control de intentos fallidos
        """
        user=self.users_repo.get_by_email(db, data.email)
        project = self.audit_repo.get_project_by_code(db, code="AGROFUSION")
        if not user or not project:
            raise auth_error("AUTH_INVALID_OTP", status.HTTP_401_UNAUTHORIZED)

        otp=(
            db.query(AfOtpCode).filter(
                AfOtpCode.user_id==user.user_id,
                AfOtpCode.purpose=="login_2fa",
                AfOtpCode.used_at.is_(None),
        ).order_by(AfOtpCode.expires_at.desc()).first()
        )

        if not otp:
            raise auth_error("AUTH_INVALID_OTP", status.HTTP_401_UNAUTHORIZED)
        
        now=datetime.now(timezone.utc)

        #EXPIRED
        if otp.expires_at <now:
            self.audit_repo.opt_failed(
                db, user, project, ip, user_agent, "expired", otp.failed_attempts
            )
            raise auth_error("AUTH_OTP_EXPIRED", status.HTTP_401_UNAUTHORIZED)
        
        #MAX ATTEMPTS
        if otp.failed_attempts >=5:
            self.audit_repo.opt_failed(
                db, user, project, ip, user_agent, "max_attempts", otp.failed_attempts
            )
            raise auth_error("AUTH_OTP_BLOCKED", status.HTTP_401_UNAUTHORIZED)
        
        if not verify_otp_code(data.otp_code, otp.otp_hash):
            otp.failed_attempts += 1

            # Determinar razón real
            if otp.failed_attempts >= 5:
                otp.expires_at = now
                reason = "max_attempts"
                error_code = "AUTH_OTP_BLOCKED"
            else:
                reason = "invalid_code"
                error_code = "AUTH_INVALID_OTP"

            self.audit_repo.opt_failed(
                db,
                user,
                project,
                ip,
                user_agent,
                reason,
                otp.failed_attempts,
            )

            db.commit()
            raise auth_error(error_code, status.HTTP_401_UNAUTHORIZED)
        

        #SUCCESS
        otp.used_at = now
        session = AuthSession(
            user_id=user.user_id, issued_at=now, expires_at=now + SESSION_TTL, ip=ip, user_agent=user_agent)
        
        db.add(session)
        db.flush()
        access_token = create_access_token(
            {"sub": str(user.user_id), "sid": str(session.sso_session_id)}, expires_delta=ACCESS_TTL)
        

        refresh_token = create_refresh_token()

        token = AuthToken(
            sso_session_id=session.sso_session_id,
            access_token=access_token,
            refresh_token=refresh_token,
            access_expires_at=now + ACCESS_TTL,
            refresh_expires_at=now + REFRESH_TTL
        )

        db.add(token)

        self.audit_repo.log_event(
            db=db,
            action_code="OTP_VERIFIED",
            outcome="success",
            module_code="SSO_AUTH",
            project_id=project.af_project_id,
            actor_id=user.user_id,
            session_id=session.sso_session_id,
            ip=ip,
            user_agent=user_agent,
            metadata={
                "otp_verified": True,
                "verification_time": now.isoformat(),
            },
        )

        self.audit_repo.log_event(
            db=db,
            action_code="SESSION_CREATED",
            outcome="success",
            module_code="SSO_AUTH",
            project_id=project.af_project_id,
            actor_id=user.user_id,
            session_id=session.sso_session_id,
            ip=ip,
            user_agent=user_agent,
        )

        self.audit_repo.log_event(
            db=db,
            action_code="TOKENS_ISSUED",
            outcome="success",
            module_code="TOKEN_MANAGEMENT",
            project_id=project.af_project_id,
            actor_id=user.user_id,
            session_id=session.sso_session_id,
            ip=ip,
            user_agent=user_agent,
            metadata={
                "access_expires_at": token.access_expires_at.isoformat(),
                "refresh_expires_at": token.refresh_expires_at.isoformat(),
            },
        )

        external_projects = self.audit_repo.get_active_ext_pro(db=db)


        db.commit()
        return LoginSuccessResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=int(ACCESS_TTL.total_seconds()),
            external_projects = external_projects
        )
    
    def resend_otp(self, db, user, ip: str, user_agent: str):
        """
        Reenvía un código OTP para autenticación de segundo factor (MFA).

        Este método se utiliza cuando un usuario solicita un nuevo OTP
        durante el proceso de login con MFA.

        Controles de seguridad implementados:
        - Cooldown entre reenvíos para evitar spam
        - Rate limit por ventana de tiempo
        - Invalidación de OTPs activos previos
        - Auditoría del evento
        """
        now = datetime.now(timezone.utc)

        last_otp = self.otp_repo.get_last_otp(
            db, user.user_id, OTP_PURPOSE_LOGIN
        )

        # ---------- COOLDOWN ----------
        if last_otp:
            elapsed = (now - last_otp.created_at).total_seconds()
            if elapsed < OTP_COOLDOWN_SECONDS:
                raise auth_error(
                    "OTP_RESEND_TOO_SOON",
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    {"retry_after_seconds": int(OTP_COOLDOWN_SECONDS - elapsed)},
                )

        # ---------- RATE LIMIT ----------
        sent_count = self.otp_repo.count_recent_otps(
            db,
            user.user_id,
            OTP_PURPOSE_LOGIN,
            OTP_RESEND_WINDOW_MIN,
        )

        if sent_count >= OTP_RESEND_MAX:
            raise auth_error(
                "OTP_RATE_LIMIT_EXCEEDED",
                status.HTTP_429_TOO_MANY_REQUESTS,
                {"window_minutes": OTP_RESEND_WINDOW_MIN},
            )

        # ---------- INVALIDAR OTPs PREVIOS ----------
        self.otp_repo.invalidate_active_otps(
            db, user.user_id, OTP_PURPOSE_LOGIN
        )

        # ---------- GENERAR OTP ----------
        otp_code = generate_otp_code()
        otp_hash = hash_otp_code(otp_code)

        otp = AfOtpCode(
            user_id=user.user_id,
            otp_hash=otp_hash,
            purpose=OTP_PURPOSE_LOGIN,
            expires_at=now + OTP_TTL,
            ip_address=ip,
            user_agent=user_agent,
        )

        db.add(otp)
        db.flush()

        # ---------- EMAIL QUEUE ----------
        self.email_repo.queue_otp_email(
            db=db,
            user=user,
            otp_code=otp_code,
            ip=ip,
        )

        # ---------- AUDIT ----------
        self.audit_repo.log_event(
            db=db,
            action_code="OTP_RESENT",
            outcome="success",
            actor_id=user.user_id,
            ip=ip,
            user_agent=user_agent,
            metadata={
                "purpose": OTP_PURPOSE_LOGIN,
                "expires_in": "5 minutes",
            },
        )

        db.commit()

        return {
            "message": "OTP resent successfully",
            "expires_in": int(OTP_TTL.total_seconds()),
        }

    def request_reset_password(self, db: Session, email: str,tokens: Dict[str,str], ip: str, user_agent: str) -> ResetPasswordResponse:
        """
        Solicita el reseteo de contraseña vía email.

        Flujo:
        - Valida usuario
        - Genera token de reseteo
        - Registra evento de seguridad
        - Envía email con link de recuperación
        """
        
        user = self.users_repo.get_by_email(db, email)
        project = self.audit_repo.get_project_by_code(db, code="AGROFUSION")
        if not project:
            raise RuntimeError("Project AGROFUSION not found")
        if not user:
            raise auth_error("AUTH_USER_NOT_FOUND", status.HTTP_401_UNAUTHORIZED)
        if user.deleted_at:
            raise auth_error("AUTH_USER_DELETED", status.HTTP_401_UNAUTHORIZED)
        if not user.email_verified_at:
            raise auth_error("AUTH_ACCOUNT_NOT_ACTIVATED", status.HTTP_401_UNAUTHORIZED)

        reset_token = self.auth_repo.gen_pass_reset_token(db, user)

        self.audit_repo.log_event(
            db,
            action_code="PASSWORD_RESET_REQUESTED",
            outcome="success",
            module_code="AUTH",
            project_id=project.af_project_id,
            actor_id=user.user_id,
            ip=ip,
            user_agent=user_agent,
            metadata={
                "user_email": user.email,
                "reset_method": "email_token",
                "expires_in_minutes": 30,
            },
            )
    
       
        db.add(
        SecurityEvent(
            user_id=user.user_id,
            event_type="password_reset_requested",
            event_description="Password reset email requested",
            severity="info",
            ip_address=ip,
            user_agent=user_agent,
            event_metadata={
                "email": user.email,
            },
            )
        )

        self.email_repo.enqueue_reset_pass_email(
            db,
            user=user,
            token=reset_token,
            tokens=tokens,
            ip=ip,
        )
        db.commit()
        return ResetPasswordResponse(
            message="AUTH_PASSWORD_RESET_EMAIL_SENT",
            token=reset_token
        )

    def reset_password(
        self,
        db: Session,
        token: str,
        new_password: str,
        confirm_password: str,
        ip: str | None,
        user_agent: str | None,
    ) -> ResetPasswordResponse:
        """
        Completa el proceso de reseteo de contraseña.

        Validaciones:
        - Token válido
        - Coincidencia de contraseñas
        - No reutilización de password
        - Cumplimiento de políticas
        """
        if new_password != confirm_password:
            raise auth_error("AUTH_PASSWORD_MISMATCH", status.HTTP_400_BAD_REQUEST)

        reset_token = self.auth_repo.get_valid_pass_reset_token(db, token)

        if not reset_token:
            raise auth_error("AUTH_INVALID_RESET_TOKEN", status.HTTP_401_UNAUTHORIZED)

        user = reset_token.user

        if verify_password(new_password, user.password_hash):
            raise auth_error(
                "AUTH_PASSWORD_REUSE",
                status.HTTP_400_BAD_REQUEST
            )

        active_policy = self.users_repo.get_active_policy(db)
        
        self.password_policy_service.validate_password(
            password=new_password,  policy=active_policy
        )

        new_password_hash = get_password_hash(new_password)

        self.users_repo.add_password_history(
            db,
            user_id=user.user_id,
            password_hash=new_password_hash,
            change_reason="PASSWORD_RESET",
            ip=ip,
            user_agent=user_agent,
        )

        user.password_hash = new_password_hash
        user.password_changed_at = datetime.now(timezone.utc)

        reset_token.used_at = datetime.now(timezone.utc)


        self.auth_repo.invalidate_all_reset_tokens(
            db,
            user_id=user.user_id,
            reason="password_reset_completed"
        )
        db.add(
            SecurityEvent(
                user_id=user.user_id,
                event_type="PASSWORD_RESET_COMPLETED",
                event_description="Password reset completed via email token",
                severity="info",
                ip_address=ip,
                user_agent=user_agent,
                event_metadata={
                    "reset_token_id": str(reset_token.reset_token_id),
                    "method": "email_token",
                },
            )
        )

        project = self.audit_repo.get_project_by_code(db, code="AGROFUSION")
        if not project:
            raise RuntimeError("Project AGROFUSION not found")

        self.audit_repo.log_event(
            db,
            action_code="PASSWORD_RESET_COMPLETED",
            outcome="success",
            module_code="AUTH",
            project_id=project.af_project_id,
            actor_id=user.user_id,
            ip=ip,
            user_agent=user_agent,
            metadata={
                "user_email_masked": user.email[:2] + "***",
                "reset_method": "email_token",
            },
        )
        db.commit()

        return ResetPasswordResponse(
            message="AUTH_PASSWORD_RESET_SUCCESS",
            token=reset_token.token
        )
    def logout(self, db:Session, *, session_id: str, user_id) -> dict:
        """
        Cierra la sesión activa del usuario.

        Acciones:
        - Revoca todos los tokens de la sesión
        - Marca la sesión como terminada
        - Registra evento de auditoría
        """
        
        revoked_count = self.auth_repo.revoke_by_session(db, session_id=session_id, reason="USER_LOGOUT")
        project = self.audit_repo.get_project_by_code(db, code="AGROFUSION")
        self.auth_repo.terminate_session(db, session_id=session_id)
        self.audit_repo.log_event(
            db=db,
            action_code="SESSION_TERMINATED",
            outcome="success",
            module_code="AUTH_LOGOUT",
            project_id=project.af_project_id,
            actor_id=user_id,
            session_id=session_id,
        )
        db.commit()

        return {"success": True, "revoked_tokens": revoked_count, "message":True}