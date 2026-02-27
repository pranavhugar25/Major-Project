"""
Benchmark API Routes
Performance comparison between PQC and Classical cryptography
"""
from flask import Blueprint, jsonify, request
import time
import statistics
from utils.pqc import PQCKeyManager, PQCUnavailableError

benchmark_bp = Blueprint('benchmark', __name__)

# Classical RSA implementation using pycryptodome
try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
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
    """Run Classical RSA benchmarks"""
    if not CLASSICAL_AVAILABLE:
        raise Exception("pycryptodome is not available")
    
    # Key Generation benchmark
    key_gen_times = []
    for _ in range(iterations):
        start = time.perf_counter()
        key = RSA.generate(4096)
        end = time.perf_counter()
        key_gen_times.append((end - start) * 1000)
    
    # Encryption benchmark (using public key)
    encrypt_times = []
    for _ in range(iterations):
        key = RSA.generate(4096)
        cipher = PKCS1_OAEP.new(key.publickey())
        message = b"test message" * 20  # ~240 bytes
        start = time.perf_counter()
        ciphertext = cipher.encrypt(message)
        end = time.perf_counter()
        encrypt_times.append((end - start) * 1000)
    
    # Decryption benchmark (using private key)
    decrypt_times = []
    for _ in range(iterations):
        key = RSA.generate(4096)
        cipher = PKCS1_OAEP.new(key.publickey())
        message = b"test message" * 20
        ciphertext = cipher.encrypt(message)
        decipher = PKCS1_OAEP.new(key)
        start = time.perf_counter()
        _ = decipher.decrypt(ciphertext)
        end = time.perf_counter()
        decrypt_times.append((end - start) * 1000)
    
    return {
        "key_generation": {
            "mean": statistics.mean(key_gen_times),
            "median": statistics.median(key_gen_times),
            "stdev": statistics.stdev(key_gen_times) if len(key_gen_times) > 1 else 0,
            "min": min(key_gen_times),
            "max": max(key_gen_times),
            "iterations": iterations
        },
        "encryption": {
            "mean": statistics.mean(encrypt_times),
            "median": statistics.median(encrypt_times),
            "stdev": statistics.stdev(encrypt_times) if len(encrypt_times) > 1 else 0,
            "min": min(encrypt_times),
            "max": max(encrypt_times),
            "iterations": iterations
        },
        "decryption": {
            "mean": statistics.mean(decrypt_times),
            "median": statistics.median(decrypt_times),
            "stdev": statistics.stdev(decrypt_times) if len(decrypt_times) > 1 else 0,
            "min": min(decrypt_times),
            "max": max(decrypt_times),
            "iterations": iterations
        },
        "key_sizes": {
            "public_key": (key.n.bit_length() // 8) + 4,  # Approximate size
            "private_key": (key.n.bit_length() // 8) + 4,
            "ciphertext": len(ciphertext)
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
            results["classical"]["algorithm"] = "RSA-4096"
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
            "classical": "RSA-4096" if CLASSICAL_AVAILABLE else None
        }
    }), 200
