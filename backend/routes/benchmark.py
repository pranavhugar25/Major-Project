"""
Benchmark routes for research comparison of auth and transport protocol variants.

These endpoints are benchmark-only and do not alter the main application protocol
configured for registration/login and transport operations.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import statistics
import time
from typing import Callable, Dict, List

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import Blueprint, jsonify, request

from models.database import User
from routes.auth import AUTH_PROTOCOL_MAIN, _load_auth_verifier
from utils.auth import require_auth
from utils.transport import DEFAULT_TRANSPORT_PROTOCOL
from utils.crypto import generate_kyber_keypair, kyber_decapsulate, kyber_encapsulate

benchmark_bp = Blueprint("benchmark", __name__, url_prefix="/api/benchmark")

OPAQUE_BASELINE_SIM = "opaque_baseline_sim"
CPACE_OQUAKE_PLUS_EXPERIMENTAL_SIM = "cpace_oquake_plus_experimental_sim"

BENCHMARK_AUTH_VARIANTS = (
    "main_split_verifier",
    OPAQUE_BASELINE_SIM,
    CPACE_OQUAKE_PLUS_EXPERIMENTAL_SIM,
)
BENCHMARK_TRANSPORT_VARIANTS = (
    "main_hybrid_pqc",
    "classical_ecdh_sim",
)

DEFAULT_BENCH_ITERATIONS = int(os.environ.get("BENCHMARK_ITERATIONS", "3"))
MAX_BENCH_ITERATIONS = 20
DEFAULT_BENCH_PAYLOAD_SIZE = int(os.environ.get("BENCHMARK_PAYLOAD_SIZE", "1024"))
MAX_BENCH_PAYLOAD_SIZE = 32768

OPAQUE_BASELINE_CONTEXT = b"opaque-baseline-sim-v1"
CPACE_OQUAKE_PLUS_CONTEXT = b"cpace-oquake-plus-sim-v1"
TRANSPORT_CLASSICAL_CONTEXT = b"transport-classical-sim-v1"
TRANSPORT_HYBRID_CONTEXT = b"transport-hybrid-pqc-sim-v1"


def _stats_from_samples(samples_ms: List[float]) -> Dict[str, float]:
    ordered = sorted(samples_ms)
    p95_index = max(0, min(len(ordered) - 1, int(round((len(ordered) - 1) * 0.95))))
    return {
        "iterations": len(samples_ms),
        "avgMs": round(statistics.fmean(samples_ms), 3),
        "minMs": round(ordered[0], 3),
        "maxMs": round(ordered[-1], 3),
        "p95Ms": round(ordered[p95_index], 3),
    }


def _run_timed_benchmark(action: Callable[[], None], iterations: int) -> Dict[str, float]:
    samples: List[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        action()
        samples.append((time.perf_counter() - start) * 1000.0)
    return _stats_from_samples(samples)


def _parse_benchmark_input(data: Dict[str, object]) -> tuple[int, int]:
    iterations = int(data.get("iterations") or DEFAULT_BENCH_ITERATIONS)
    payload_size = int(data.get("payloadSize") or DEFAULT_BENCH_PAYLOAD_SIZE)
    if iterations < 1 or iterations > MAX_BENCH_ITERATIONS:
        raise ValueError(f"Iterations must be between 1 and {MAX_BENCH_ITERATIONS}")
    if payload_size < 128 or payload_size > MAX_BENCH_PAYLOAD_SIZE:
        raise ValueError(f"Payload size must be between 128 and {MAX_BENCH_PAYLOAD_SIZE} bytes")
    return iterations, payload_size


def _hkdf_derive(shared_secret: bytes, context: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context)
    return hkdf.derive(shared_secret)


def _auth_main_action(verifier_bytes: bytes) -> None:
    challenge = secrets.token_bytes(32)
    client_proof = hmac.new(verifier_bytes, challenge, hashlib.sha256).digest()
    server_expected = hmac.new(verifier_bytes, challenge, hashlib.sha256).digest()
    if not secrets.compare_digest(client_proof, server_expected):
        raise RuntimeError("Main auth benchmark verification failed")


def _auth_opaque_baseline_action(verifier_bytes: bytes) -> None:
    challenge = secrets.token_bytes(32)
    server_secret = hashlib.sha256(OPAQUE_BASELINE_CONTEXT + verifier_bytes).digest()
    oprf_output = hmac.new(server_secret, verifier_bytes + challenge, hashlib.sha256).digest()
    session_key = hashlib.sha256(oprf_output + verifier_bytes).digest()
    client_proof = hmac.new(session_key, challenge, hashlib.sha256).digest()
    server_expected = hmac.new(session_key, challenge, hashlib.sha256).digest()
    if not secrets.compare_digest(client_proof, server_expected):
        raise RuntimeError("OPAQUE baseline simulation verification failed")


def _auth_cpace_oquake_plus_action(verifier_bytes: bytes) -> None:
    pqc_public_key, pqc_private_key = generate_kyber_keypair()
    pqc_ciphertext, shared_secret_enc = kyber_encapsulate(pqc_public_key)
    shared_secret_dec = kyber_decapsulate(pqc_ciphertext, pqc_private_key)
    if shared_secret_enc != shared_secret_dec:
        raise RuntimeError("PQC shared secret mismatch in experimental auth benchmark")

    client_ecdh_private = ec.generate_private_key(ec.SECP256R1())
    server_ecdh_private = ec.generate_private_key(ec.SECP256R1())
    client_shared = client_ecdh_private.exchange(ec.ECDH(), server_ecdh_private.public_key())
    server_shared = server_ecdh_private.exchange(ec.ECDH(), client_ecdh_private.public_key())
    if client_shared != server_shared:
        raise RuntimeError("ECDH shared secret mismatch in experimental auth benchmark")

    pqc_shared_bytes = base64.b64decode(shared_secret_dec.encode("utf-8"), validate=True)
    handshake_key = _hkdf_derive(
        pqc_shared_bytes + client_shared + verifier_bytes,
        CPACE_OQUAKE_PLUS_CONTEXT,
    )
    challenge = secrets.token_bytes(32)
    client_proof = hmac.new(handshake_key, challenge, hashlib.sha256).digest()
    server_expected = hmac.new(handshake_key, challenge, hashlib.sha256).digest()
    if not secrets.compare_digest(client_proof, server_expected):
        raise RuntimeError("Experimental auth simulation verification failed")


def _transport_hybrid_action(payload: bytes) -> None:
    pqc_public_key, pqc_private_key = generate_kyber_keypair()
    pqc_ciphertext, shared_secret_enc = kyber_encapsulate(pqc_public_key)
    shared_secret_dec = kyber_decapsulate(pqc_ciphertext, pqc_private_key)
    if shared_secret_enc != shared_secret_dec:
        raise RuntimeError("PQC shared secret mismatch in hybrid transport benchmark")

    client_ecdh_private = ec.generate_private_key(ec.SECP256R1())
    server_ecdh_private = ec.generate_private_key(ec.SECP256R1())
    client_shared = client_ecdh_private.exchange(ec.ECDH(), server_ecdh_private.public_key())
    server_shared = server_ecdh_private.exchange(ec.ECDH(), client_ecdh_private.public_key())
    if client_shared != server_shared:
        raise RuntimeError("ECDH shared secret mismatch in hybrid transport benchmark")

    pqc_shared_bytes = base64.b64decode(shared_secret_dec.encode("utf-8"), validate=True)
    session_key = _hkdf_derive(pqc_shared_bytes + client_shared, TRANSPORT_HYBRID_CONTEXT)
    iv = secrets.token_bytes(12)
    ciphertext = AESGCM(session_key).encrypt(iv, payload, None)
    plaintext = AESGCM(session_key).decrypt(iv, ciphertext, None)
    if plaintext != payload:
        raise RuntimeError("Hybrid transport payload integrity check failed")


def _transport_classical_action(payload: bytes) -> None:
    client_ecdh_private = ec.generate_private_key(ec.SECP256R1())
    server_ecdh_private = ec.generate_private_key(ec.SECP256R1())
    client_shared = client_ecdh_private.exchange(ec.ECDH(), server_ecdh_private.public_key())
    server_shared = server_ecdh_private.exchange(ec.ECDH(), client_ecdh_private.public_key())
    if client_shared != server_shared:
        raise RuntimeError("ECDH shared secret mismatch in classical transport benchmark")

    session_key = _hkdf_derive(client_shared, TRANSPORT_CLASSICAL_CONTEXT)
    iv = secrets.token_bytes(12)
    ciphertext = AESGCM(session_key).encrypt(iv, payload, None)
    plaintext = AESGCM(session_key).decrypt(iv, ciphertext, None)
    if plaintext != payload:
        raise RuntimeError("Classical transport payload integrity check failed")


def _benchmark_entry(protocol: str, label: str, runner: Callable[[], Dict[str, float]]) -> Dict[str, object]:
    try:
        stats = runner()
        return {
            "protocol": protocol,
            "label": label,
            "status": "ok",
            **stats,
        }
    except Exception as exc:
        return {
            "protocol": protocol,
            "label": label,
            "status": "error",
            "error": str(exc),
        }


@benchmark_bp.route("/protocols", methods=["GET"])
@require_auth
def get_benchmark_protocols():
    return (
        jsonify(
            {
                "success": True,
                "main": {
                    "authProtocol": AUTH_PROTOCOL_MAIN,
                    "transportProtocol": DEFAULT_TRANSPORT_PROTOCOL,
                },
                "benchmarkOnly": {
                    "authProtocols": list(BENCHMARK_AUTH_VARIANTS),
                    "transportProtocols": list(BENCHMARK_TRANSPORT_VARIANTS),
                },
            }
        ),
        200,
    )


@benchmark_bp.route("/run", methods=["POST"])
@require_auth
def run_benchmarks():
    try:
        data = request.get_json(silent=True) or {}
        iterations, payload_size = _parse_benchmark_input(data)
        user = User.query.filter_by(user_id=str(request.user_id)).first()
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404

        verifier_b64 = _load_auth_verifier(user.master_password_hash)
        verifier_bytes = base64.b64decode(verifier_b64.encode("utf-8"), validate=True)
        payload = secrets.token_bytes(payload_size)

        auth_results = [
            _benchmark_entry(
                "main_split_verifier",
                "Main Auth (split verifier)",
                lambda: _run_timed_benchmark(lambda: _auth_main_action(verifier_bytes), iterations),
            ),
            _benchmark_entry(
                OPAQUE_BASELINE_SIM,
                "Baseline OPAQUE (simulation)",
                lambda: _run_timed_benchmark(lambda: _auth_opaque_baseline_action(verifier_bytes), iterations),
            ),
            _benchmark_entry(
                CPACE_OQUAKE_PLUS_EXPERIMENTAL_SIM,
                "Experimental CPaceOQUAKE+ (simulation)",
                lambda: _run_timed_benchmark(lambda: _auth_cpace_oquake_plus_action(verifier_bytes), iterations),
            ),
        ]

        transport_results = [
            _benchmark_entry(
                "main_hybrid_pqc",
                "Main Hybrid PQC Transport",
                lambda: _run_timed_benchmark(lambda: _transport_hybrid_action(payload), iterations),
            ),
            _benchmark_entry(
                "classical_ecdh_sim",
                "Classical ECDH Transport (simulation)",
                lambda: _run_timed_benchmark(lambda: _transport_classical_action(payload), iterations),
            ),
        ]

        return (
            jsonify(
                {
                    "success": True,
                    "main": {
                        "authProtocol": AUTH_PROTOCOL_MAIN,
                        "transportProtocol": DEFAULT_TRANSPORT_PROTOCOL,
                    },
                    "iterations": iterations,
                    "payloadSize": payload_size,
                    "authResults": auth_results,
                    "transportResults": transport_results,
                    "generatedAt": int(time.time()),
                }
            ),
            200,
        )
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"success": False, "error": f"Benchmark execution failed: {exc}"}), 500
