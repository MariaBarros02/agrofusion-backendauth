import secrets
import string
from passlib.context import CryptContext

# Contexto de hashing seguro usando bcrypt
# Se utiliza para hashear y verificar códigos OTP
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)


def generate_otp_code(length: int = 6) -> str:
    """
    Genera un código OTP numérico aleatorio.

    El código se genera usando el módulo `secrets`, adecuado para
    propósitos criptográficamente seguros.

    :param length: Longitud del código OTP (por defecto 6 dígitos)
    :return: Código OTP en formato string
    """
    # Genera un string compuesto por todas las letras del abecedario y dígitos (0–9)

    alphabet = string.ascii_letters+string.digits
    return "".join(str(secrets.randbelow(alphabet)) for _ in range(length))


def hash_otp_code(code: str) -> str:
    """
    Hashea un código OTP antes de almacenarlo.

    El OTP nunca se guarda en texto plano, solo su hash,
    siguiendo buenas prácticas de seguridad.

    :param code: Código OTP en texto plano
    :return: Hash seguro del OTP
    """
    return pwd_context.hash(code)


def verify_otp_code(code: str, otp_hash: str) -> bool:
    """
    Verifica si un código OTP coincide con su hash almacenado.

    Utiliza comparación segura para prevenir ataques de timing.

    :param code: Código OTP ingresado por el usuario
    :param otp_hash: Hash del OTP almacenado en base de datos
    :return: True si el código es válido, False en caso contrario
    """
    return pwd_context.verify(code, otp_hash)
