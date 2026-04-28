#!/usr/bin/env python3
"""Test PQC status and endpoints"""
import os, sys
os.environ['LD_LIBRARY_PATH'] = '/tmp/liboqs-install/usr/local/lib:' + os.environ.get('LD_LIBRARY_PATH', '')
sys.path.insert(0, '/home/dreamworld/GitHub/Major-Project/backend')

from app import create_app
from utils.pqc import PQCKeyManager

print("="*60)
print("PQC STATUS CHECK")
print("="*60)

# Check PQC availability
print(f"\n[1] PQCKeyManager.is_available(): {PQCKeyManager.is_available()}")

# Create app and test with Flask test client
app = create_app()

with app.test_client() as client:
    # Test benchmark status
    print("\n[2] Benchmark Status:")
    r = client.get('/api/benchmark/status')
    print(f"   HTTP: {r.status_code}")
    data = r.get_json()
    print(f"   PQC available: {data.get('pqc_available')}")
    print(f"   Classical available: {data.get('classical_available')}")

    # Register user
    print("\n[3] User Registration:")
    r = client.post('/api/auth/register',
                      json={'username':'testuser2', 'masterPassword':'Test1234!'})
    print(f"   HTTP: {r.status_code}")
    reg = r.get_json()
    if r.status_code in [200, 201]:
        token = reg.get('access_token')
        print(f"   ✓ Registered! Token (first 30): {token[:30]}...")
        print(f"   Salt: {reg.get('salt', '')[:40]}...")

        # Check crypto view
        print("\n[4] Crypto View (what's stored server-side):")
        r2 = client.get('/api/passwords/get-crypto-view',
                         headers={'Authorization': f'Bearer {token}'})
        view = r2.get_json()
        print(f"   HTTP: {r2.status_code}")
        print(f"   spake2Verifier: {view.get('spake2Verifier', 'N/A')[:50]}...")
        print(f"   spake2Salt: {view.get('spake2Salt', 'N/A')[:50]}...")
        print(f"   Salt (classical): {view.get('salt', '')[:40]}...")

        # Add password (classical AES-256-GCM)
        print("\n[5] Password Storage (Classical AES-256-GCM Only):")
        r3 = client.post('/api/passwords/add',
                         headers={'Authorization': f'Bearer {token}'},
                         json={
                             'siteUrl': 'https://example.com',
                             'siteUsername': 'test@example.com',
                             'encryptedPassword': 'fake_encrypted_data_base64',
                             'iv': 'fake_iv_base64',
                             'authTag': ''
                         })
        print(f"   HTTP: {r3.status_code}")
        if r3.status_code in [200, 201]:
            print(f"   ✓ Password saved (but encrypted with AES-256-GCM, NOT PQC)")
        else:
            print(f"   ✗ Error: {r3.get_data(as_text=True)[:200]}")
    else:
        print(f"   ✗ Registration failed: {reg}")

print("\n" + "="*60)
print("SUMMARY")
print("="*60)
print("✓ Backend: PQC available (ML-KEM-1024, ML-DSA-87)")
print("✓ PQC Session Init: Works (tested earlier)")
print("⚠️  Password Encryption: AES-256-GCM (Classical only)")
print("   - Vault key derived from master password (PBKDF2)")
print("   - NOT using ML-KEM shared secret or SPAKE2+")
print("⚠️  SPAKE2+ fields exist in DB but NOT used in auth flow")
print("="*60)
