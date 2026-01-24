# tests/test_auth.py

def test_login_success(client):
    payload = {
        "email": "alejab2302@gmail.com",
        "password": "Password.123"
    }

    response = client.post("/auth/login", json=payload)

    assert response.status_code == 200
    assert "access_token" in response.json()


def test_login_invalid_password(client):
    payload = {
        "email": "alejab2302@gmail.com",
        "password": "password_mal"
    }

    response = client.post("/auth/login", json=payload)
    assert response.status_code == 401


def test_verify_otp_invalid(client):
    payload = {
        "otp_code": "000000",
        "email": "agrofusion2025@gmail.com"
    }

    response = client.post("/auth/verify-otp", json=payload)
    assert response.status_code in (400, 423, 401)

def test_logout_without_auth(client):
    response = client.post("/auth/logout")
    assert response.status_code == 401


def test_request_reset_password_user_not_found(client):
    payload = {
        "email": "noexiste@dominio.com",
        "tokens": {
        "additionalProp1": "string",
        "additionalProp2": "string",
        "additionalProp3": "string"
        }
    }

    response = client.post("/auth/request-reset-password", json=payload)
    assert response.status_code in (404, 401)


def test_reset_password_invalid_token(client):
    payload = {
        "new_password": "NuevaPass123!",
        "confirm_password": "NuevaPass123!"
    }

    response = client.post("/auth/reset-password/token_invalido", json=payload)
    assert response.status_code in (400, 401, 410)


def test_get_external_projects(client):
    response = client.get("/auth/external-projects")

    assert response.status_code == 200
    assert isinstance(response.json(), list)
