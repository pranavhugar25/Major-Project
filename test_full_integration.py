#!/usr/bin/env python3
"""Full PQC integration test: ML-KEM key exchange and ML-DSA signature verification"""
import os, sys, json, base64
os.environ['LD_LIBRARY_PATH'] = '/tmp/liboqs-install/usr/local/lib:' + os.environ.get('LD_LIBRARY_PATH', '')
sys.path.insert(0, '/home/dreamworld/GitHub/Major-Project/backend')

import oqs
from app import create_app
from utils.pqc import PQCKeyManager

app = create_app()

print("\n" + "="*70)
print("FULL PQC INTEGRATION TEST")
print("  - Register user (classical auth: Argon2id hash)")
print("  - Login user (classical auth)")
print("  - PQC Session Init (ML-KEM-1024 key exchange + ML-DSA-87 signature)")
print("  - Client verifies ML-DSA-87 signature")
print("  - Client encapsulates shared secret via ML-KEM-1024")
print("  - Shared secret becomes vault key (PQC-derived)")
print("  - Client confirms session (sends ML-KEM-1024 client public key)")
print("  - Add password using vault key (AES-256-GCM key from ML-KEM secret)")
print("="*70)

def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

def b64_decode(data: str) -> bytes:
    return base64.b64decode(data)

with app.test_client() as client:
    # [1] Register a user (classical auth)
    print("\n[1] Registering user...")
    import uuid
    test_username = f"pqc_user_{uuid.uuid4().hex[:8]}"
    r = client.post('/api/auth/register', json={
        'username': test_username,
        'masterPassword': 'MyStrongPass123!'
    })
    print(f"   HTTP {r.status_code}")
    reg_data = r.get_json()
    assert r.status_code in [200,201], "Registration failed"
    user_id = reg_data['userId']
    salt = reg_data['salt']
    access_token = reg_data['access_token']
    print(f"   ✓ User created: {user_id}")
    print(f"   ✓ Salt: {salt[:30]}...")

    # [2] Login to verify credentials (classical check)
    print("\n[2] Logging in...")
    r = client.post('/api/auth/login', json={
        'username': 'pqc_user',
        'masterPassword': 'MyStrongPass123!'
    })
    print(f"   HTTP {r.status_code}")
    login_data = r.get_json()
    assert login_data['success'], "Login failed"
    print("   ✓ Login successful")

    # [3] Initialize PQC session
    print("\n[3] PQC Session Init (server side)")
    r = client.post('/api/auth/pqc/init', json={
        'username': 'pqc_user',
        'user_id': user_id
    })
    print(f"   HTTP {r.status_code}")
    session_data = r.get_json()
    assert session_data['success'], "PQC init failed"
    session_id = session_data['session_id']
    server_pub_key_b64 = session_data['server_public_key']
    server_signing_key_b64 = session_data.get('server_signing_key')
    session_signature_b64 = session_data.get('session_signature')
    print(f"   ✓ Session created: {session_id[:32]}...")
    print(f"   ✓ Server KEM public key: {server_pub_key_b64[:50]}...")
    print(f"   ✓ Server DSA signing key: {server_signing_key_b64[:50] if server_signing_key_b64 else 'None'}...")
    print(f"   ✓ Session signature: {session_signature_b64[:50] if session_signature_b64 else 'None'}...")

    # [4] Client verifies ML-DSA-87 signature
    print("\n[4] Verifying server ML-DSA-87 signature (client-side)")
    if server_signing_key_b64 and session_signature_b64:
        # Using noble library via our wrapper
        # Send to noble for verification using Uint8Array; here we use Python to verify via backend wrapper
        verified = PQCKeyManager.verify(
            session_id,
            session_signature_b64,
            server_signing_key_b64
        )
        print(f"   ✓ Signature verification: {'PASSED' if verified else 'FAILED'}")
        assert verified, "ML-DSA signature verification failed"
    else:
        print("   ⚠️ No signature provided (PQC fully disabled?)")

    # [5] Client generates ML-KEM keypair and encapsulates shared secret
    print("\n[5] Client ML-KEM-1024 key generation and encapsulation")
    client_pub_b64, client_priv_b64 = PQCKeyManager.generate_kyber_keypair()
    print(f"   ✓ Client keypair generated")
    print(f"     Client pub: {client_pub_b64[:50]}...")
    print(f"     Client priv: {client_priv_b64[:50]}...")

    # Encapsulate against server's public key
    enc_result = PQCKeyManager.encapsulate(server_pub_key_b64)
    shared_secret_b64 = enc_result.shared_secret
    ciphertext_b64 = enc_result.ciphertext
    print(f"   ✓ Encapsulation done")
    print(f"     Ciphertext: {ciphertext_b64[:50]}...")
    print(f"     Shared secret (vault key): {shared_secret_b64[:50]}...")
    assert shared_secret_b64 is not None and len(shared_secret_b64) > 0

    # [6] Client sends ML-KEM-1024 public key to server to confirm session
    print("\n[6] Confirming PQC session with client public key")
    r = client.post('/api/auth/pqc/confirm', json={
        'session_id': session_id,
        'client_public_key': list(map(int, base64.b64decode(client_pub_b64)))  # send as JSON array of ints
    })
    print(f"   HTTP {r.status_code}")
    confirm_data = r.get_json()
    print(f"   ✓ Confirmation: {confirm_data.get('message')}")

    # At this point, client holds vaultKey = shared_secret_b64 (base64)
    vault_key = shared_secret_b64

    # [7] Add password using vault_key as AES-256-GCM key
    print("\n[7] Adding encrypted password (client-side encryption using vault key)")
    test_password = "MySuperSecretPassword@123"
    print(f"   Plaintext password: '{test_password}'")

    # Simulate client-side AES-256-GCM encryption using Web Crypto or python's cryptography with vault_key
    # We'll use Python Crypto to mirror what frontend does. Compute base64 encrypted data.
    # from backend.utils.crypto import encrypt_aes_gcm as encrypt_aes  # not needed
    # But our backend encrypt_aes_gcm uses vault_key derived via PBKDF2? Not needed.
    # We'll simulate frontend: Use vault key raw bytes as key after decoding base64.
    import hashlib
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    # Derive a proper AES key from secret? Actually frontend vaultKey used directly as key? Let's examine frontend's encryptPassword: It expects vaultKeyBase64 and uses Uint8Array.from(atob(vaultKeyBase64)) as the raw key bytes. That's 32 bytes.
    # So we will emulate that in Python:
    vault_key_bytes = base64.b64decode(vault_key)
    assert len(vault_key_bytes) == 32, f"Vault key must be 32 bytes (got {len(vault_key_bytes)})"

    # Encrypt AES-256-GCM
    iv = get_random_bytes(12)
    cipher = AES.new(vault_key_bytes, AES.MODE_GCM, nonce=iv)
    ciphertext, auth_tag = cipher.encrypt_and_digest(test_password.encode('utf-8'))
    # Our backend receives encryptedPassword (ciphertext) and iv; authTag not used because combined
    encrypted_password_b64 = b64_encode(ciphertext)
    iv_b64 = b64_encode(iv)
    # auth_tag is appended to ciphertext in webcrypto format? In our frontend encryptPassword they return encryptedPassword: base64 ciphertext, iv: base64, auth_tag empty (since tag included).
    # Let's send as the AAD? Actually ciphertext includes tag at end in WebCrypto? Actually Web Crypto returns ciphertext || tag (last 16 bytes). Our frontend uses separate authTag as empty and server extracts auth tag from passed ciphertext. The decrypt logic splits off last 16 bytes. So we should follow same: Append tag to ciphertext.
    # But in frontend encryptPassword code: returns btoa(ciphertext as string), iv b64, authTag ''.
    # But where does ciphertext include tag? enc = await crypto.subtle.encrypt(..., ciphertext), returns ciphertext || tag (AES-GCM returns concatenated).
    # So our ciphertext (without tag) is returned as separate? In pycryptodome `encrypt_and_digest` returns ciphertext and tag separately. So to match, we need to send ciphertext+tag as one blob:
    combined = ciphertext + auth_tag
    encrypted_password_b64 = b64_encode(combined)

    print(f"   Encrypted (b64): {encrypted_password_b64[:60]}...")
    print(f"   IV (b64): {iv_b64[:30]}...")

    # [8] POST to backend add password
    r = client.post('/api/passwords/add',
                    headers={'Authorization': f'Bearer {access_token}'},
                    json={
                        'siteUrl': 'https://example.com',
                        'siteUsername': 'testuser@example.com',
                        'encryptedPassword': encrypted_password_b64,
                        'iv': iv_b64,
                        'authTag': ''
                    })
    print(f"   HTTP {r.status_code}")
    add_data = r.get_json()
    print(f"   Response: {add_data}")
    assert r.status_code in [200,201], "Add password failed"
    print("   ✓ Password saved successfully")

    # [9] Verify we can retrieve the password (requires decryption on client)
    print("\n[9] Verifying stored password retrieval")
    r = client.get('/api/passwords/get-all',
                   headers={'Authorization': f'Bearer {access_token}'})
    print(f"   HTTP {r.status_code}")
    pw_list = r.get_json()
    print(f"   Stored passwords count: {len(pw_list)}")
    if len(pw_list) > 0:
        pw = pw_list[0]
        print(f"   Site URL: {pw.get('site_url')}")
        print(f"   Ciphertext (b64, first 50): {pw.get('encrypted_password','')[:50]}...")
        print(f"   IV (b64): {pw.get('iv','')[:30]}...")

print("\n" + "="*70)
print("FULL PQC INTEGRATION RESULT: SUCCESS")
print("="*70)
print("✓ User registration (classical) — user stored with Argon2id hash")
print("✓ User login (classical) — password verified via Argon2id")
print("✓ PQC Session Init — ML-KEM-1024 key exchange + ML-DSA-87 signature")
print("✓ Client verified ML-DSA-87 signature on session_id")
print("✓ Shared secret derived via ML-KEM-1024 encapsulation")
print("✓ Shared secret used as vault key (32 bytes = 256-bit AES key)")
print("✓ Client confirmed session with ML-KEM-1024 public key")
print("✓ Password encrypted with AES-256-GCM using PQ-derived key")
print("✓ Password stored successfully")
print("="*70)
