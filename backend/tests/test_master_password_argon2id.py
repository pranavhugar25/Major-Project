import inspect
import os
import time
import uuid

import pytest

from app import create_app
from models.database import User, db
from utils.crypto import (
    ARGON2ID_ITERATIONS,
    generate_salt,
    hash_password,
    verify_password_with_algorithm,
)


@pytest.fixture
def app():
    os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
    test_app = create_app(testing=True)
    test_app.config['TESTING'] = True
    return test_app


@pytest.fixture
def client(app):
    with app.test_client() as test_client:
        yield test_client


def _unique_username() -> str:
    return f"argon2id-{uuid.uuid4().hex[:12]}@example.com"


def test_argon2id_class_available():
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

    assert Argon2id is not None


def test_hash_and_verify_use_argon2id_for_new_hashes():
    salt = generate_salt()
    password = "CorrectHorseBatteryStaple!234"

    hashed = hash_password(password, salt)

    is_valid, algorithm = verify_password_with_algorithm(password, salt, hashed)
    assert is_valid is True
    assert algorithm == 'argon2id'

    wrong_valid, wrong_algorithm = verify_password_with_algorithm("wrong-password", salt, hashed)
    assert wrong_valid is False
    assert wrong_algorithm is None


def test_hash_runtime_is_non_trivial():
    salt = generate_salt()

    start = time.perf_counter()
    hash_password("runtime-check-password", salt)
    elapsed = time.perf_counter() - start

    # Real Argon2id hashing should not be effectively instant.
    assert elapsed > 0.01


def test_register_persists_non_plaintext_hash(client, app):
    password = "VeryStrongPassword!123"
    username = _unique_username()

    response = client.post(
        '/api/auth/register',
        json={
            'username': username,
            'masterPassword': password,
        },
    )

    assert response.status_code == 201

    with app.app_context():
        user = User.query.filter_by(username=username).first()
        assert user is not None
        assert user.master_password_hash
        assert user.master_password_hash != password
        assert user.salt

        is_valid, algorithm = verify_password_with_algorithm(
            password,
            user.salt,
            user.master_password_hash,
        )
        assert is_valid is True
        assert algorithm == 'argon2id'


def test_login_uses_classical_path_when_spake2_not_present(client, app):
    password = "StrongLoginPassword!345"
    username = _unique_username()

    register_response = client.post(
        '/api/auth/register',
        json={
            'username': username,
            'masterPassword': password,
        },
    )
    assert register_response.status_code == 201

    with app.app_context():
        user = User.query.filter_by(username=username).first()
        user.spake2_verifier = None
        user.spake2_salt = None
        db.session.commit()

    login_response = client.post(
        '/api/auth/login',
        json={
            'username': username,
            'masterPassword': password,
        },
    )
    assert login_response.status_code == 200
    assert login_response.get_json()['success'] is True


def test_login_fails_when_verifier_fails_and_spake2_missing(client, app, monkeypatch):
    import routes.auth as auth_routes

    password = "VerifierFailurePassword!567"
    username = _unique_username()

    register_response = client.post(
        '/api/auth/register',
        json={
            'username': username,
            'masterPassword': password,
        },
    )
    assert register_response.status_code == 201

    with app.app_context():
        user = User.query.filter_by(username=username).first()
        user.spake2_verifier = None
        user.spake2_salt = None
        db.session.commit()

    monkeypatch.setattr(auth_routes, 'verify_password_with_algorithm', lambda *_args, **_kwargs: (False, None))

    login_response = client.post(
        '/api/auth/login',
        json={
            'username': username,
            'masterPassword': password,
        },
    )
    assert login_response.status_code == 401
    assert login_response.get_json()['success'] is False


def test_crypto_verifier_guard_patterns():
    source = inspect.getsource(verify_password_with_algorithm)

    assert 'secrets.compare_digest' in source
    assert "return True, 'argon2id'" in source
    assert "return True, 'pbkdf2'" in source
    assert "return False, None" in source
    assert ARGON2ID_ITERATIONS >= 3
