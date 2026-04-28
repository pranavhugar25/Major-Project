#!/usr/bin/env python3
"""
Test PQC endpoints using Flask test client
"""
import os
import sys

# Set LD_LIBRARY_PATH before importing anything that uses oqs
os.environ['LD_LIBRARY_PATH'] = '/tmp/liboqs-install/usr/local/lib:' + os.environ.get('LD_LIBRARY_PATH', '')

# Add backend to path
sys.path.insert(0, '/home/dreamworld/GitHub/Major-Project/backend')

# Now import and test
import logging
logging.basicConfig(level=logging.INFO)

from flask import Flask
from backend.app import create_app
from backend.utils.pqc import PQCKeyManager

print("="*60)
print("PQC ENDPOINT TEST")
print("="*60)

# Check PQC status
print(f"\n[1] PQC Available: {PQCKeyManager.is_available()}")

# Create app
app = create_app()
print(f"[2] Flask app created, blueprints: {list(app.blueprints.keys())}")

# Test with Flask test client
with app.test_client() as client:
    print("\n[3] Testing PQC session init endpoint...")
    resp = client.post('/api/auth/pqc/init', json={'username': 'testuser', 'user_id': 'uid123'})
    print(f"    Status: {resp.status_code}")
    data = resp.get_json()
    if resp.status_code == 200 and data and data.get('success'):
        print(f"    ✓ SUCCESS!")
        print(f"    Session ID: {data.get('session_id', '')[:32]}...")
        print(f"    Server PK (first 80 chars): {data.get('server_public_key', '')[:80]}...")
        print(f"    Algorithm: {data.get('algorithm')}")
    else:
        print(f"    ✗ FAILED!")
        print(f"    Response: {resp.get_data(as_text=True)[:300]}")

    print("\n[4] Testing benchmark status endpoint...")
    resp2 = client.get('/api/benchmark/status')
    print(f"    Status: {resp2.status_code}")
    data2 = resp2.get_json()
    print(f"    PQC available: {data2.get('pqc_available')}")
    print(f"    Classical available: {data2.get('classical_available')}")
    print(f"    PQC algorithm: {data2.get('algorithms', {}).get('pqc')}")

print("\n" + "="*60)
print("TESTS COMPLETE")
print("="*60)
