from datetime import datetime, timedelta, timezone
from uuid import UUID
from sqlalchemy.orm import Session

from app.models.af_otp_codes import AfOtpCode
from app.utils.otp import hash_otp_code


class OtpRepository:
    """
    Repositorio encargado de la gestión de códigos OTP (One-Time Password).

    Responsabilidades:
    - Invalidar OTPs activos
    - Obtener el último OTP generado
    - Limitar generación por ventana de tiempo
    - Crear nuevos OTPs de forma segura (hash)
    """

    def inv_active_otps(self, db: Session, user_id, purpose: str):
        """
        Invalida todos los OTP activos de un usuario para un propósito específico.

        Se consideran activos aquellos que:
        - No han sido usados
        - No han expirado

        La invalidación se realiza forzando la expiración inmediata.

        :param db: Sesión activa de base de datos
        :param user_id: ID del usuario
        :param purpose: Propósito del OTP (ej: login, reset_password, 2fa)
        """
        db.query(AfOtpCode).filter(
            AfOtpCode.user_id == user_id,
            AfOtpCode.purpose == purpose,
            AfOtpCode.used_at.is_(None),
            AfOtpCode.expires_at > datetime.now(timezone.utc),
        ).update(
            {"expires_at": datetime.now(timezone.utc)},
            synchronize_session=False,
        )

    def get_last_otp(self, db: Session, user_id, purpose: str):
        """
        Obtiene el último OTP generado para un usuario y propósito determinado.

        No valida si el OTP está activo o expirado, solo retorna
        el más reciente por fecha de creación.

        :param db: Sesión activa de base de datos
        :param user_id: ID del usuario
        :param purpose: Propósito del OTP
        :return: Instancia AfOtpCode o None
        """
        return (
            db.query(AfOtpCode)
            .filter(
                AfOtpCode.user_id == user_id,
                AfOtpCode.purpose == purpose,
            )
            .order_by(AfOtpCode.created_at.desc())
            .first()
        )

    def count_recent_otps(
        self,
        db: Session,
        user_id,
        purpose: str,
        minutes: int,
    ) -> int:
        """
        Cuenta cuántos OTPs han sido generados recientemente para un usuario
        dentro de una ventana de tiempo definida.

        Se usa típicamente para:
        - Rate limiting
        - Prevención de abuso
        - Protección contra ataques de fuerza bruta

        :param db: Sesión activa de base de datos
        :param user_id: ID del usuario
        :param purpose: Propósito del OTP
        :param minutes: Ventana de tiempo en minutos
        :return: Cantidad de OTPs generados en el período
        """
        since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        return (
            db.query(AfOtpCode)
            .filter(
                AfOtpCode.user_id == user_id,
                AfOtpCode.purpose == purpose,
                AfOtpCode.created_at >= since,
            )
            .count()
        )

    def create_otp(
        self,
        db: Session,
        *,
        user_id: UUID,
        otp_code: str,
        purpose: str,
        expires_at: datetime,
        ip_address: str,
        user_agent: str,
    ) -> AfOtpCode:
        """
        Crea y persiste un nuevo OTP para un usuario.

        Características de seguridad:
        - El código OTP nunca se guarda en texto plano
        - Se almacena únicamente su hash
        - Se registran IP y User-Agent para auditoría

        :param db: Sesión activa de base de datos
        :param user_id: ID del usuario
        :param otp_code: Código OTP en texto plano (uso temporal)
        :param purpose: Propósito del OTP
        :param expires_at: Fecha/hora de expiración
        :param ip_address: IP desde donde se solicitó el OTP
        :param user_agent: User-Agent del cliente
        :return: Instancia AfOtpCode creada
        """

        otp = AfOtpCode(
            user_id=user_id,
            otp_hash=hash_otp_code(otp_code),
            purpose=purpose,
            expires_at=expires_at,
            used_at=None,
            failed_attempts=0,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        db.add(otp)
        db.flush()  # permite obtener otp_id si se necesita posteriormente
        return otp
