import React, { useEffect, useMemo, useState } from 'react';
import { benchmarkAPI } from '../utils/api';
import '../styles/Benchmark.css';

function pickBest(results) {
  const successful = (results || []).filter((row) => row.status === 'ok');
  if (!successful.length) {
    return null;
  }
  return successful.reduce((best, current) => {
    if (!best || current.avgMs < best.avgMs) {
      return current;
    }
    return best;
  }, null);
}

function Benchmark() {
  const [protocolConfig, setProtocolConfig] = useState(null);
  const [iterations, setIterations] = useState(3);
  const [payloadSize, setPayloadSize] = useState(1024);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [results, setResults] = useState(null);

  useEffect(() => {
    const loadProtocols = async () => {
      try {
        const response = await benchmarkAPI.getProtocols();
        if (response.success) {
          setProtocolConfig(response);
        } else {
          setError(response.error || 'Failed to load protocol configuration');
        }
      } catch (err) {
        setError(err.response?.data?.error || 'Failed to load protocol configuration');
      }
    };
    loadProtocols();
  }, []);

  const bestAuth = useMemo(() => pickBest(results?.authResults), [results]);
  const bestTransport = useMemo(() => pickBest(results?.transportResults), [results]);

  const runBenchmarks = async () => {
    setError('');
    setLoading(true);
    try {
      const response = await benchmarkAPI.run({
        iterations,
        payloadSize
      });
      if (response.success) {
        setResults(response);
      } else {
        setError(response.error || 'Benchmark execution failed');
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Benchmark execution failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="benchmark-container">
      <div className="content-header">
        <h1>Benchmark</h1>
        <p className="subtitle">
          Compare main protocol configuration against research benchmark variants
        </p>
      </div>

      <div className="benchmark-controls">
        <div className="control-group">
          <label htmlFor="bench-iterations">Iterations</label>
          <input
            id="bench-iterations"
            type="number"
            min="1"
            max="20"
            value={iterations}
            onChange={(e) => setIterations(Number(e.target.value || 1))}
          />
        </div>
        <div className="control-group">
          <label htmlFor="bench-payload">Payload Size (bytes)</label>
          <input
            id="bench-payload"
            type="number"
            min="128"
            max="32768"
            step="128"
            value={payloadSize}
            onChange={(e) => setPayloadSize(Number(e.target.value || 128))}
          />
        </div>
        <button
          className="run-benchmark-button"
          onClick={runBenchmarks}
          disabled={loading}
          data-testid="run-benchmarks"
        >
          {loading ? 'Running...' : 'Run Benchmarks'}
        </button>
      </div>

      {protocolConfig && (
        <div className="protocol-summary" data-testid="protocol-summary">
          <p><strong>Main Auth Protocol:</strong> {protocolConfig.main?.authProtocol}</p>
          <p><strong>Main Transport Protocol:</strong> {protocolConfig.main?.transportProtocol}</p>
        </div>
      )}

      {error && (
        <div className="error-message" data-testid="benchmark-error">
          {error}
        </div>
      )}

      {results && (
        <div className="benchmark-results">
          <div className="result-card">
            <h2>Auth Protocol Comparison</h2>
            {bestAuth && (
              <p className="best-result" data-testid="best-auth">
                Best: {bestAuth.label} ({bestAuth.avgMs} ms avg)
              </p>
            )}
            <table>
              <thead>
                <tr>
                  <th>Protocol</th>
                  <th>Status</th>
                  <th>Avg (ms)</th>
                  <th>P95 (ms)</th>
                </tr>
              </thead>
              <tbody>
                {(results.authResults || []).map((row) => (
                  <tr key={row.protocol} data-testid={`auth-row-${row.protocol}`}>
                    <td>{row.label}</td>
                    <td>{row.status}</td>
                    <td>{row.status === 'ok' ? row.avgMs : '-'}</td>
                    <td>{row.status === 'ok' ? row.p95Ms : '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="result-card">
            <h2>Transport Protocol Comparison</h2>
            {bestTransport && (
              <p className="best-result" data-testid="best-transport">
                Best: {bestTransport.label} ({bestTransport.avgMs} ms avg)
              </p>
            )}
            <table>
              <thead>
                <tr>
                  <th>Protocol</th>
                  <th>Status</th>
                  <th>Avg (ms)</th>
                  <th>P95 (ms)</th>
                </tr>
              </thead>
              <tbody>
                {(results.transportResults || []).map((row) => (
                  <tr key={row.protocol} data-testid={`transport-row-${row.protocol}`}>
                    <td>{row.label}</td>
                    <td>{row.status}</td>
                    <td>{row.status === 'ok' ? row.avgMs : '-'}</td>
                    <td>{row.status === 'ok' ? row.p95Ms : '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

export default Benchmark;
