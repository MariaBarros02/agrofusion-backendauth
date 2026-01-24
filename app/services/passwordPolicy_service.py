import re
from fastapi import status
from app.core.errors import auth_error


class PasswordPolicyService:
    """
    Servicio encargado de validar contraseñas según una
    política de seguridad configurable.

    Este servicio no persiste datos ni modifica estado,
    únicamente valida y lanza excepciones en caso de incumplimiento.
    """

    @staticmethod
    def validate_password(password: str, policy) -> None:
        """
        Valida una contraseña contra una política de seguridad.

        La política define reglas como:
        - Longitud mínima y máxima
        - Requisitos de mayúsculas, minúsculas, números
        - Uso obligatorio de caracteres especiales
        - Restricción de caracteres permitidos

        En caso de incumplimiento, se lanza una excepción
        estandarizada mediante `auth_error`.

        :param password: Contraseña en texto plano a validar
        :param policy: Objeto de política de contraseña (ej. PasswordPolicy)
        :raises HTTPException: Si alguna regla no se cumple
        """

        # ---------- LONGITUD MÍNIMA ----------
        if len(password) < policy.min_length:
            raise auth_error(
                "AUTH_PASSWORD_TOO_SHORT",
                status.HTTP_400_BAD_REQUEST
            )

        # ---------- LONGITUD MÁXIMA ----------
        if len(password) > policy.max_length:
            raise auth_error(
                "AUTH_PASSWORD_TOO_LONG",
                status.HTTP_400_BAD_REQUEST
            )

        # ---------- MAYÚSCULAS ----------
        # Verifica al menos una letra mayúscula (A-Z)
        if policy.require_uppercase and not re.search(r"[A-Z]", password):
            raise auth_error(
                "AUTH_PASSWORD_REQUIRE_UPPERCASE",
                status.HTTP_400_BAD_REQUEST,
            )

        # ---------- MINÚSCULAS ----------
        # Verifica al menos una letra minúscula (a-z)
        if policy.require_lowercase and not re.search(r"[a-z]", password):
            raise auth_error(
                "AUTH_PASSWORD_REQUIRE_LOWERCASE",
                status.HTTP_400_BAD_REQUEST,
            )

        # ---------- NÚMEROS ----------
        # Verifica al menos un dígito numérico
        if policy.require_numbers and not re.search(r"\d", password):
            raise auth_error(
                "AUTH_PASSWORD_REQUIRE_NUMBER",
                status.HTTP_400_BAD_REQUEST,
            )

        # ---------- CARACTERES ESPECIALES ----------
        # Verifica la presencia de al menos un carácter especial permitido
        if policy.require_special_chars:
            allowed = re.escape(policy.special_chars_allowed)
            if not re.search(f"[{allowed}]", password):
                raise auth_error(
                    "AUTH_PASSWORD_REQUIRE_SPECIAL_CHAR",
                    status.HTTP_400_BAD_REQUEST
                )

        # ---------- SOLO CARACTERES PERMITIDOS ----------
        # Evita el uso de caracteres no autorizados (espacios, unicode, etc.)
        allowed_chars_regex = rf"^[A-Za-z0-9{re.escape(policy.special_chars_allowed)}]+$"
        if not re.match(allowed_chars_regex, password):
            raise auth_error(
                "AUTH_PASSWORD_INVALID_CHARACTER",
                status.HTTP_400_BAD_REQUEST,
            )
