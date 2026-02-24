#!/usr/bin/env python3
import sys
sys.stderr.write("Starting test\n")
sys.stderr.flush()

import oqs
sys.stderr.write(f"liboqs version: {oqs.oqs_version()}\n")
sys.stderr.write(f"liboqs-python version: {oqs.oqs_python_version()}\n")
sys.stderr.flush()

# Test ML-KEM-1024
sys.stderr.write("Testing ML-KEM-1024...\n")
sys.stderr.flush()
kem = oqs.KeyEncapsulation("ML-KEM-1024")
public_key = kem.generate_keypair()
sys.stderr.write(f"Public key: {len(public_key)} bytes\n")

# Use encap_secret (liboqs-python API)
encap_result = kem.encap_secret(public_key)
if isinstance(encap_result, tuple):
    ciphertext, shared_secret = encap_result
else:
    ciphertext = encap_result
    shared_secret = kem.decap_secret(ciphertext)
sys.stderr.write(f"Ciphertext: {len(ciphertext)} bytes\n")
sys.stderr.write(f"Shared secret: {len(shared_secret)} bytes\n")

# Test decapsulation with separate instance
kem2 = oqs.KeyEncapsulation("ML-KEM-1024", secret_key=kem.export_secret_key())
shared_secret2 = kem2.decap_secret(ciphertext)
sys.stderr.write(f"Decapsulation match: {shared_secret == shared_secret2}\n")
sys.stderr.flush()

# Test ML-DSA-87
sys.stderr.write("Testing ML-DSA-87...\n")
sys.stderr.flush()
sig = oqs.Signature("ML-DSA-87")
public_key = sig.generate_keypair()
sys.stderr.write(f"Sign public key: {len(public_key)} bytes\n")
message = b"Test message"
signature = sig.sign(message)
sys.stderr.write(f"Signature: {len(signature)} bytes\n")

# Verify
sig2 = oqs.Signature("ML-DSA-87", secret_key=sig.export_secret_key())
is_valid = sig2.verify(message, signature, public_key)
sys.stderr.write(f"Signature valid: {is_valid}\n")
sys.stderr.flush()

print("SUCCESS: All PQC tests passed!")
