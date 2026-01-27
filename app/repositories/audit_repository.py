# app/repositories/audit_repository.py

from sqlalchemy.orm import Session
from typing import List
from app.models.af_audit_log import AuditLog
from app.models.af_projects import Project
from app.models.cat_terms import CatTerm
from app.models.af_external_projects import AfExternalProject
import hashlib
import json


class AuditRepository:
    """
    Repositorio encargado de la gestión de eventos de auditoría.

    Centraliza:
    - Búsqueda de proyectos
    - Resolución de términos de acción (CatTerm)
    - Registro de eventos de auditoría (login, OTP, eventos genéricos)
    """

    def get_project_by_code(self, db: Session, *, code: str):
        """
        Obtiene un proyecto interno por su código único.

        :param db: Sesión activa de base de datos
        :param code: Código único del proyecto
        :return: Instancia de Project o None
        """
        return (
            db.query(Project)
            .filter(Project.code == code)
            .first()
        )

    def get_projectExt_by_code(self, db: Session, *, code: str):
        """
        Obtiene un proyecto externo activo usando su código de instancia.

        :param db: Sesión activa de base de datos
        :param code: Código de instancia del proyecto externo
        :return: Instancia de AfExternalProject o None
        """
        return (
            db.query(AfExternalProject)
            .filter(AfExternalProject.instance_code == code)
            .first()
        )

    def _get_action_term_id(self, db: Session, *, action_code: str) -> str:
        """
        Resuelve el term_id correspondiente a un action_code de auditoría.

        Busca el término dentro del vocabulario AUDIT_ACTION.

        :param db: Sesión activa de base de datos
        :param action_code: Código de acción (LOGIN_SUCCESS, OTP_FAILED, etc.)
        :return: UUID del término encontrado
        :raises RuntimeError: si el término no existe
        """
        term = (
            db.query(CatTerm)
            .join(CatTerm.vocabulary)
            .filter(
                CatTerm.code == action_code,
                CatTerm.vocabulary.has(vocabulary_code="AUDIT_ACTION")
            )
            .first()
        )

        if not term:
            raise RuntimeError(f"Audit action term not found: {action_code}")

        return term.term_id

    def get_active_ext_pro(self, db: Session) -> List[AfExternalProject]:
        """
        Obtiene todos los proyectos externos activos.

        :param db: Sesión activa de base de datos
        :return: Lista de proyectos externos activos
        """
        external_projects = (
            db.query(AfExternalProject)
            .filter(
                AfExternalProject.is_active == True,
            ).all()
        )
        return external_projects

    def log_login_event(
        self,
        db: Session,
        *,
        action_code: str,
        outcome: str,
        project_id,
        actor_id=None,
        mfa_required: None,
        email: str | None = None,
        ip: str | None = None,
        user_agent: str | None = None,
        session_id=None,
        reason: str | None = None,
        attempts_count: int | None = None,
        account_locked: bool | None = None,
    ) -> None:
        """
        Registra eventos de autenticación (login).

        Cubre escenarios como:
        - Login exitoso
        - Login fallido
        - Cuenta bloqueada

        La información adicional se guarda en target_json y se firma con hash SHA-256.
        """

        # Metadata base del evento de login
        metadata = {
            "actor_id": str(actor_id) , 
            "mfa_required": mfa_required, 
            "email": email,
            "ip_address": ip,
            "user_agent": user_agent,
            "login_method": "email_password",
        }

        # Motivo del fallo (si existe)
        if reason:
            metadata["reason"] = reason

        # Cantidad de intentos fallidos acumulados
        if attempts_count is not None:
            metadata["attempts_count"] = attempts_count
            
            if attempts_count >= 3:
                metadata["account_locked"] = True

        # Indica si la cuenta fue bloqueada
        if account_locked is not None:
            metadata["account_locked"] = account_locked

        # Serialización del payload para generación de hash
        payload_str = json.dumps(metadata, sort_keys=True)
        payload_hash = hashlib.sha256(payload_str.encode()).hexdigest()

        # Resolución del término de acción
        action_term_id = self._get_action_term_id(db, action_code=action_code)

        # Construcción del registro de auditoría
        log = AuditLog(
            actor_id=actor_id,
            action_code=action_code,
            action_term_id=action_term_id,
            outcome=outcome,
            target_json=metadata,
            actor_ip=ip,
            session_id=session_id,
            module_code="AUTH",
            project_id=project_id,
            payload_hash=payload_hash,
            device_info={"user_agent": user_agent} if user_agent else None,
        )

        # Se agrega a la sesión (commit externo)
        db.add(log)

    def log_event(
        self,
        db: Session,
        *,
        action_code: str,
        outcome: str,
        module_code: str,
        project_id,
        actor_id=None,
        session_id=None,
        ip: str | None = None,
        user_agent: str | None = None,
        metadata: dict | None = None,
    ) -> None:
        """
        Registra un evento genérico de auditoría.

        Usado para eventos no específicos de login:
        - Operaciones del sistema
        - Eventos administrativos
        - Acciones funcionales
        """

        # Payload del evento (metadata arbitraria)
        payload = metadata or {}

        # Generación del hash de integridad
        payload_str = json.dumps(payload, sort_keys=True)
        payload_hash = hashlib.sha256(payload_str.encode()).hexdigest()

        # Resolución del término de acción
        action_term_id = self._get_action_term_id(db, action_code=action_code)

        # Construcción del registro de auditoría
        log = AuditLog(
            actor_id=actor_id,
            action_code=action_code,
            action_term_id=action_term_id,
            outcome=outcome,
            target_json=payload,
            actor_ip=ip,
            session_id=session_id,
            module_code=module_code,
            project_id=project_id,
            payload_hash=payload_hash,
            device_info={"user_agent": user_agent} if user_agent else None,
        )

        # Se agrega a la sesión (commit externo)
        db.add(log)

    def opt_failed(
        self,
        db: Session,
        user,
        project,
        ip: str | None,
        user_agent: str | None,
        reason: str,
        attempts_count: int,
    ) -> None:
        """
        Registra eventos de fallo de OTP.

        Casos cubiertos:
        - OTP expirado
        - Código inválido
        - Máximo de intentos alcanzado
        """

        # Mapeo de razón técnica a código de acción de auditoría
        action_map = {
            "expired": "OTP_EXPIRED",
            "invalid_code": "OTP_FAILED",
            "max_attempts": "OTP_BLOCKED",
        }

        action_code = action_map.get(reason, "OTP_FAILED")

        # Metadata específica del fallo OTP
        metadata = {
            "user_id": user.user_id,
            "otp_verified": False,
            "otp_reason": reason,
            "attempts_count": attempts_count,
            "user_email": user.email,
            "ip_address": ip,
            "user_agent": user_agent,
        }

        # Generación de hash del payload
        payload_str = json.dumps(metadata, sort_keys=True)
        payload_hash = hashlib.sha256(payload_str.encode()).hexdigest()

        # Resolución del término de acción
        action_term_id = self._get_action_term_id(db, action_code=action_code)

        # Construcción del log de auditoría
        log = AuditLog(
            actor_id=user.user_id,
            action_code=action_code,
            action_term_id=action_term_id,
            outcome="failed",
            target_json=metadata,
            actor_ip=ip,
            module_code="MFA_MANAGEMENT",
            project_id=project.af_project_id,
            payload_hash=payload_hash,
            device_info={"user_agent": user_agent} if user_agent else None,
        )

        # Se agrega a la sesión (commit externo)
        db.add(log)
