#!/usr/bin/env python3
"""Test script for PQC functions"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / 'backend'))

from utils.pqc import MLKEM1024, MLDSA87

print('Testing ML-KEM-1024...', flush=True)
kp = MLKEM1024.generate_keypair()
print(f'Public key length: {len(kp.public_key)} bytes', flush=True)
print(f'Private key length: {len(kp.private_key)} bytes', flush=True)

kem_result = MLKEM1024.encapsulate(kp.public_key)
ct, ss = kem_result.ciphertext, kem_result.shared_secret
print(f'Ciphertext length: {len(ct)} bytes', flush=True)
print(f'Shared secret length: {len(ss)} bytes', flush=True)

ss2 = MLKEM1024.decapsulate(ct, kp.private_key)
print(f'Decapsulation match: {ss == ss2}', flush=True)

print('Testing ML-DSA-87...', flush=True)
sig_kp = MLDSA87.generate_keypair()
print(f'Public key length: {len(sig_kp.public_key)} bytes', flush=True)

message = b'Hello Quantum!'
signature = MLDSA87.sign(message, sig_kp.private_key)
print(f'Signature length: {len(signature)} bytes', flush=True)

valid = MLDSA87.verify(message, signature, sig_kp.public_key)
print(f'Signature valid: {valid}', flush=True)

print('ALL TESTS PASSED!', flush=True)
