import os

import pytest

from app import create_app


@pytest.fixture
def client():
    os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
    app = create_app(testing=True)
    app.config['TESTING'] = True
    with app.test_client() as test_client:
        yield test_client


def test_benchmark_status_endpoint(client):
    response = client.get('/api/benchmark/status')
    assert response.status_code == 200

    body = response.get_json()
    assert body['success'] is True
    assert 'pqc_available' in body
    assert 'classical_available' in body
    assert 'algorithms' in body


def test_benchmark_run_returns_dynamic_and_static_metrics(client):
    response = client.post('/api/benchmark/run', json={'iterations': 3, 'mutualAuthIterations': 3})
    assert response.status_code == 200

    body = response.get_json()
    assert body['success'] is True

    results = body['results']
    assert results['iterations'] == 3
    assert results['dynamic_metrics_source'] == 'Measured from runtime execution path'
    assert results['static_metrics_source'] == 'Curated static benchmark constants'

    assert 'static_metrics' in results
    assert 'pqc' in results['static_metrics']
    assert 'classical' in results['static_metrics']

    assert 'resource_metrics' in results
    assert 'request_wall_time_ms' in results['resource_metrics']
    assert 'request_cpu_time_ms' in results['resource_metrics']
    assert 'request_cpu_utilization_percent' in results['resource_metrics']


def test_benchmark_uses_real_runtime_path_metrics(client):
    response = client.post('/api/benchmark/run', json={'iterations': 3, 'mutualAuthIterations': 3})
    body = response.get_json()
    results = body['results']

    if results.get('classical'):
        assert results['classical']['key_generation']['mean'] > 0
        assert results['classical']['key_exchange']['mean'] > 0
        assert results['classical']['signature_generation']['mean'] > 0
        assert results['classical']['signature_verification']['mean'] > 0
        assert results['classical']['key_storage']['write_ms'] >= 0
        assert results['classical']['key_storage']['read_ms'] >= 0

    if results.get('pqc'):
        assert results['pqc']['key_generation']['mean'] > 0
        assert results['pqc']['encapsulation']['mean'] > 0
        assert results['pqc']['decapsulation']['mean'] > 0
        assert results['pqc']['signature_generation']['mean'] > 0
        assert results['pqc']['signature_verification']['mean'] > 0
        assert results['pqc']['key_storage']['write_ms'] >= 0
        assert results['pqc']['key_storage']['read_ms'] >= 0

    # Mutual-auth timing should be present as metric or explicit error
    assert ('mutual_authentication' in results) or ('mutual_authentication_error' in results)

    # Placeholder/synthetic frontend fields are intentionally absent from backend schema
    assert 'fallback' not in results
