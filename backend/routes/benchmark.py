"""
Benchmark API Routes
Performance comparison between PQC and Classical cryptography
"""
from flask import Blueprint, jsonify, request
import time
import statistics
from utils.pqc import PQCKeyManager, PQCUnavailableError

benchmark_bp = Blueprint('benchmark', __name__)

# Classical ECC implementation using cryptography library (X25519)
try:
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import serialization
    CLASSICAL_AVAILABLE = True
except ImportError:
    CLASSICAL_AVAILABLE = False


def _run_pqc_benchmark(iterations=10):
    """Run PQC benchmarks using liboqs"""
    if not PQCKeyManager.is_available():
        raise PQCUnavailableError("liboqs is not available")
    
    # Key Generation benchmark
    key_gen_times = []
    for _ in range(iterations):
        start = time.perf_counter()
        public_key, private_key = PQCKeyManager.generate_kyber_keypair()
        end = time.perf_counter()
        key_gen_times.append((end - start) * 1000)  # Convert to ms
    
    # Encapsulation benchmark
    encaps_times = []
    for _ in range(iterations):
        public_key, private_key = PQCKeyManager.generate_kyber_keypair()
        start = time.perf_counter()
        ciphertext, shared_secret = PQCKeyManager.encapsulate(public_key)
        end = time.perf_counter()
        encaps_times.append((end - start) * 1000)
    
    # Decapsulation benchmark
    decap_times = []
    for _ in range(iterations):
        public_key, private_key = PQCKeyManager.generate_kyber_keypair()
        ciphertext, _ = PQCKeyManager.encapsulate(public_key)
        start = time.perf_counter()
        _ = PQCKeyManager.decapsulate(ciphertext, private_key)
        end = time.perf_counter()
        decap_times.append((end - start) * 1000)
    
    return {
        "key_generation": {
            "mean": statistics.mean(key_gen_times),
            "median": statistics.median(key_gen_times),
            "stdev": statistics.stdev(key_gen_times) if len(key_gen_times) > 1 else 0,
            "min": min(key_gen_times),
            "max": max(key_gen_times),
            "iterations": iterations
        },
        "encapsulation": {
            "mean": statistics.mean(encaps_times),
            "median": statistics.median(encaps_times),
            "stdev": statistics.stdev(encaps_times) if len(encaps_times) > 1 else 0,
            "min": min(encaps_times),
            "max": max(encaps_times),
            "iterations": iterations
        },
        "decapsulation": {
            "mean": statistics.mean(decap_times),
            "median": statistics.median(decap_times),
            "stdev": statistics.stdev(decap_times) if len(decap_times) > 1 else 0,
            "min": min(decap_times),
            "max": max(decap_times),
            "iterations": iterations
        },
        "key_sizes": {
            "public_key": len(public_key),
            "private_key": len(private_key),
            "ciphertext": len(ciphertext)
        }
    }


def _run_classical_benchmark(iterations=10):
    """Run Classical ECC (X25519) benchmarks - modern standard for key exchange"""
    if not CLASSICAL_AVAILABLE:
        raise Exception("cryptography library is not available")
    
    # Key Generation benchmark (X25519)
    key_gen_times = []
    for _ in range(iterations):
        start = time.perf_counter()
        private_key = x25519.X25519PrivateKey.generate()
        end = time.perf_counter()
        key_gen_times.append((end - start) * 1000)
    
    # Key Exchange benchmark (ECDH)
    exchange_times = []
    for _ in range(iterations):
        # Generate both sides of the key exchange
        alice_private = x25519.X25519PrivateKey.generate()
        bob_private = x25519.X25519PrivateKey.generate()
        
        alice_public = alice_private.public_key()
        bob_public = bob_private.public_key()
        
        start = time.perf_counter()
        # Both derive the same shared secret
        alice_shared = alice_private.exchange(bob_public)
        bob_shared = bob_private.exchange(alice_public)
        end = time.perf_counter()
        exchange_times.append((end - start) * 1000)
    
    # Get public key sizes
    test_private = x25519.X25519PrivateKey.generate()
    test_public = test_private.public_key()
    public_key_bytes = test_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    private_key_bytes = test_private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    return {
        "key_generation": {
            "mean": statistics.mean(key_gen_times),
            "median": statistics.median(key_gen_times),
            "stdev": statistics.stdev(key_gen_times) if len(key_gen_times) > 1 else 0,
            "min": min(key_gen_times),
            "max": max(key_gen_times),
            "iterations": iterations
        },
        "key_exchange": {
            "mean": statistics.mean(exchange_times),
            "median": statistics.median(exchange_times),
            "stdev": statistics.stdev(exchange_times) if len(exchange_times) > 1 else 0,
            "min": min(exchange_times),
            "max": max(exchange_times),
            "iterations": iterations
        },
        "key_sizes": {
            "public_key": len(public_key_bytes),
            "private_key": len(private_key_bytes),
            "shared_secret": 32  # X25519 always produces 32-byte shared secret
        }
    }


@benchmark_bp.route('/api/benchmark/run', methods=['POST'])
def run_benchmark():
    """
    Run cryptography benchmark comparison
    
    Request body (optional):
        iterations: int - Number of iterations per test (default: 10)
    
    Returns:
        JSON with benchmark results for PQC and Classical
    """
    data = request.get_json() or {}
    iterations = min(data.get('iterations', 10), 50)  # Cap at 50 iterations
    
    results = {
        "iterations": iterations,
        "pqc": None,
        "classical": None,
        "pqc_available": PQCKeyManager.is_available(),
        "classical_available": CLASSICAL_AVAILABLE
    }
    
    # Run PQC benchmark if available
    if PQCKeyManager.is_available():
        try:
            results["pqc"] = _run_pqc_benchmark(iterations)
            results["pqc"]["algorithm"] = "ML-KEM-1024"
        except Exception as e:
            results["pqc_error"] = str(e)
    else:
        results["pqc_error"] = "liboqs not available"
    
    # Run Classical benchmark if available
    if CLASSICAL_AVAILABLE:
        try:
            results["classical"] = _run_classical_benchmark(iterations)
            results["classical"]["algorithm"] = "X25519 (ECC)"
        except Exception as e:
            results["classical_error"] = str(e)
    else:
        results["classical_error"] = "pycryptodome not available"
    
    return jsonify({
        "success": True,
        "results": results
    }), 200


@benchmark_bp.route('/api/benchmark/status', methods=['GET'])
def benchmark_status():
    """
    Check benchmark availability
    
    Returns:
        JSON with status of PQC and Classical benchmark capabilities
    """
    return jsonify({
        "success": True,
        "pqc_available": PQCKeyManager.is_available(),
        "classical_available": CLASSICAL_AVAILABLE,
        "algorithms": {
            "pqc": "ML-KEM-1024" if PQCKeyManager.is_available() else None,
            "classical": "X25519 (ECC)" if CLASSICAL_AVAILABLE else None
        }
    }), 200
