import pytest
from types import SimpleNamespace
from fastapi import HTTPException

from app.services.passwordPolicy_service import PasswordPolicyService


@pytest.fixture
def policy():
    """
    Política de contraseña realista y estricta
    """
    return SimpleNamespace(
        min_length=8,
        max_length=32,
        require_uppercase=True,
        require_lowercase=True,
        require_numbers=True,
        require_special_chars=True,
        special_chars_allowed="!@#$%^&*",
    )


# ======================================================
# CASO OK
# ======================================================
def test_validate_password_success(policy):
    password = "Password1!"

    # No debe lanzar excepción
    PasswordPolicyService.validate_password(password, policy)


# ======================================================
# ERRORES DE LONGITUD
# ======================================================
def test_password_too_short(policy):
    with pytest.raises(HTTPException) as exc:
        PasswordPolicyService.validate_password("Pw1!", policy)

    assert "TOO_SHORT" in exc.value.detail["code"]


def test_password_too_long(policy):
    password = "A1!" + "a" * 40

    with pytest.raises(HTTPException) as exc:
        PasswordPolicyService.validate_password(password, policy)

    assert "TOO_LONG" in exc.value.detail["code"]


# ======================================================
# REGLAS DE COMPLEJIDAD
# ======================================================
def test_password_requires_uppercase(policy):
    with pytest.raises(HTTPException) as exc:
        PasswordPolicyService.validate_password("password1!", policy)

    assert "REQUIRE_UPPERCASE" in exc.value.detail["code"]


def test_password_requires_lowercase(policy):
    with pytest.raises(HTTPException) as exc:
        PasswordPolicyService.validate_password("PASSWORD1!", policy)

    assert "REQUIRE_LOWERCASE" in exc.value.detail["code"]


def test_password_requires_number(policy):
    with pytest.raises(HTTPException) as exc:
        PasswordPolicyService.validate_password("Password!", policy)

    assert "REQUIRE_NUMBER" in exc.value.detail["code"]


def test_password_requires_special_char(policy):
    with pytest.raises(HTTPException) as exc:
        PasswordPolicyService.validate_password("Password1", policy)

    assert "REQUIRE_SPECIAL_CHAR" in exc.value.detail["code"]


# ======================================================
# CARACTERES INVÁLIDOS
# ======================================================
def test_password_invalid_character(policy):
    # espacio no permitido
    with pytest.raises(HTTPException) as exc:
        PasswordPolicyService.validate_password("Password 1!", policy)

    assert "INVALID_CHARACTER" in exc.value.detail["code"]
