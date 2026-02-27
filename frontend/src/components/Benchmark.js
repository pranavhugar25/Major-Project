/**
 * Benchmark Component
 * Demonstrates PQC vs Classical cryptography performance comparison
 * Actually runs benchmarks against the backend
 */
import React, { useState, useEffect } from 'react';
import { benchmarkAPI } from '../utils/api';
import '../styles/Benchmark.css';

// Fallback placeholder data for when backend is unavailable
const PLACEHOLDER_DATA = {
  pqc: {
    name: 'ML-KEM-1024',
    keyGenTime: 0.45, // milliseconds
    encapsulationTime: 0.12, // milliseconds
    publicKeySize: 1568, // bytes
    ciphertextSize: 1568, // bytes
    secretKeySize: 3168, // bytes
  },
  classical: {
    name: 'RSA-4096',
    keyGenTime: 1250, // milliseconds (significantly slower)
    encapsulationTime: 45, // milliseconds (for encryption/decryption)
    publicKeySize: 512, // bytes
    ciphertextSize: 512, // bytes
    secretKeySize: 512, // bytes
  }
};

function Benchmark() {
  const [benchmarkStatus, setBenchmarkStatus] = useState({
    pqcAvailable: false,
    classicalAvailable: false,
    loading: true
  });
  const [isRunning, setIsRunning] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);

  // Check benchmark availability on mount
  useEffect(() => {
    checkBenchmarkStatus();
  }, []);

  const checkBenchmarkStatus = async () => {
    try {
      const response = await benchmarkAPI.getStatus();
      if (response.success) {
        setBenchmarkStatus({
          pqcAvailable: response.pqc_available,
          classicalAvailable: response.classical_available,
          loading: false
        });
      }
    } catch (err) {
      console.error('Failed to check benchmark status:', err);
      setBenchmarkStatus({
        pqcAvailable: false,
        classicalAvailable: false,
        loading: false
      });
    }
  };

  const runBenchmark = async () => {
    setIsRunning(true);
    setError(null);
    
    try {
      const response = await benchmarkAPI.runBenchmark(10);
      
      if (response.success && response.results) {
        const data = response.results;
        
        // Transform backend results into frontend format
        const transformedResults = {
          pqc: null,
          classical: null,
          timestamp: new Date().toISOString(),
          iterations: data.iterations,
          pqcError: data.pqc_error,
          classicalError: data.classical_error
        };
        
        if (data.pqc && !data.pqc_error) {
          transformedResults.pqc = {
            name: data.pqc.algorithm || 'ML-KEM-1024',
            keyGenTime: data.pqc.key_generation.mean,
            encapsulationTime: data.pqc.encapsulation.mean,
            decapsulationTime: data.pqc.decapsulation.mean,
            publicKeySize: data.pqc.key_sizes.public_key,
            secretKeySize: data.pqc.key_sizes.private_key,
            ciphertextSize: data.pqc.key_sizes.ciphertext,
            keyGenStdev: data.pqc.key_generation.stdev,
            encapsStdev: data.pqc.encapsulation.stdev
          };
        }
        
        if (data.classical && !data.classical_error) {
          transformedResults.classical = {
            name: data.classical.algorithm || 'RSA-4096',
            keyGenTime: data.classical.key_generation.mean,
            encryptionTime: data.classical.encryption.mean,
            decryptionTime: data.classical.decryption.mean,
            publicKeySize: data.classical.key_sizes.public_key,
            secretKeySize: data.classical.key_sizes.private_key,
            ciphertextSize: data.classical.key_sizes.ciphertext,
            keyGenStdev: data.classical.key_generation.stdev,
            encryptStdev: data.classical.encryption.stdev
          };
        }
        
        // If neither PQC nor Classical is available, use placeholder data
        if (!transformedResults.pqc && !transformedResults.classical) {
          transformedResults.pqc = { ...PLACEHOLDER_DATA.pqc };
          transformedResults.classical = { ...PLACEHOLDER_DATA.classical };
          setError('Both PQC and Classical backends unavailable - showing estimated values');
        }
        
        setResults(transformedResults);
      } else {
        setError(response.error || 'Benchmark failed');
      }
    } catch (err) {
      console.error('Benchmark error:', err);
      setError('Failed to run benchmark: ' + (err.message || 'Unknown error'));
      // Fall back to placeholder data
      setResults({
        pqc: { ...PLACEHOLDER_DATA.pqc },
        classical: { ...PLACEHOLDER_DATA.classical },
        timestamp: new Date().toISOString(),
        fallback: true
      });
    }
    
    setIsRunning(false);
  };

  const formatTime = (ms) => {
    if (ms === undefined || ms === null) return 'N/A';
    if (ms < 1) {
      return `${(ms * 1000).toFixed(2)} μs`;
    }
    return `${ms.toFixed(2)} ms`;
  };

  const formatSize = (bytes) => {
    if (bytes === undefined || bytes === null) return 'N/A';
    if (bytes >= 1024) {
      return `${(bytes / 1024).toFixed(2)} KB`;
    }
    return `${bytes} B`;
  };

  // Calculate bar widths (as percentage of max value)
  const getBarWidth = (value, maxValue) => {
    if (value === undefined || value === null || maxValue === undefined || maxValue === null) return 5;
    return Math.max(5, (value / maxValue) * 100);
  };

  const getMaxTime = () => {
    if (!results) return 1;
    const pqcTime = results.pqc?.keyGenTime || 1;
    const classicalTime = results.classical?.keyGenTime || 1;
    return Math.max(pqcTime, classicalTime);
  };

  const getMaxEncapsTime = () => {
    if (!results) return 1;
    const pqcTime = results.pqc?.encapsulationTime || results.pqc?.decapsulationTime || 1;
    const classicalTime = results.classical?.encryptionTime || results.classical?.decryptionTime || 1;
    return Math.max(pqcTime, classicalTime);
  };

  const getMaxKeySize = () => {
    if (!results) return 1;
    const pqcSize = results.pqc?.publicKeySize || results.pqc?.secretKeySize || 1;
    return Math.max(pqcSize, 512);
  };

  // Determine liboqs status for display
  const getLiboqsStatus = () => {
    if (benchmarkStatus.loading) return 'loading';
    if (benchmarkStatus.pqcAvailable || benchmarkStatus.classicalAvailable) return 'available';
    return 'unavailable';
  };

  const liboqsStatus = getLiboqsStatus();

  return (
    <div className="benchmark-container">
      <div className="content-header">
        <h1>PQC Benchmark</h1>
        <p className="subtitle">
          Compare Post-Quantum Cryptography (ML-KEM-1024) vs Classical (RSA-4096) performance
        </p>
      </div>

      {/* liboqs Status Banner */}
      <div className={`liboqs-status ${liboqsStatus}`}>
        <span className="status-icon">
          {liboqsStatus === 'loading' && '⏳'}
          {liboqsStatus === 'available' && '✅'}
          {liboqsStatus === 'unavailable' && '⚠️'}
        </span>
        <span className="status-text">
          {liboqsStatus === 'loading' && 'Checking benchmark availability...'}
          {liboqsStatus === 'available' && 
            `PQC: ${benchmarkStatus.pqcAvailable ? '✓' : '✗'} | Classical: ${benchmarkStatus.classicalAvailable ? '✓' : '✗'}`}
          {liboqsStatus === 'unavailable' && 'Backend unavailable - showing estimated values'}
        </span>
      </div>

      {/* Error Message */}
      {error && (
        <div className="error-banner">
          <span className="error-icon">⚠️</span>
          {error}
        </div>
      )}

      {/* Run Benchmark Button */}
      <div className="benchmark-controls">
        <button 
          className="run-benchmark-btn"
          onClick={runBenchmark}
          disabled={isRunning}
        >
          {isRunning ? (
            <>
              <span className="btn-spinner"></span>
              Running Benchmark...
            </>
          ) : (
            <>
              <span className="btn-icon">⚡</span>
              Run Benchmark
            </>
          )}
        </button>
      </div>

      {/* Results Charts */}
      {results && (
        <div className="benchmark-results">
          {/* Key Generation Time Chart */}
          <div className="chart-section">
            <h2>
              <span className="chart-icon">🔑</span>
              Key Generation Time
            </h2>
            <p className="chart-description">Time to generate key pairs (mean of {results.iterations || 10} iterations)</p>
            
            <div className="bar-chart">
              {results.pqc && (
                <div className="bar-row">
                  <div className="bar-label">
                    <span className="algo-name">PQC (ML-KEM-1024)</span>
                    <span className="algo-badge pqc">Post-Quantum</span>
                  </div>
                  <div className="bar-container">
                    <div 
                      className="bar bar-pqc"
                      style={{ width: `${getBarWidth(results.pqc.keyGenTime, getMaxTime())}%` }}
                    >
                      <span className="bar-value">{formatTime(results.pqc.keyGenTime)}</span>
                    </div>
                  </div>
                </div>
              )}
              
              {results.classical && (
                <div className="bar-row">
                  <div className="bar-label">
                    <span className="algo-name">Classical (RSA-4096)</span>
                    <span className="algo-badge classical">Classical</span>
                  </div>
                  <div className="bar-container">
                    <div 
                      className="bar bar-classical"
                      style={{ width: `${getBarWidth(results.classical.keyGenTime, getMaxTime())}%` }}
                    >
                      <span className="bar-value">{formatTime(results.classical.keyGenTime)}</span>
                    </div>
                  </div>
                </div>
              )}
              
              {results.pqcError && (
                <div className="error-note">PQC Error: {results.pqcError}</div>
              )}
              {results.classicalError && (
                <div className="error-note">Classical Error: {results.classicalError}</div>
              )}
            </div>
            
            {results.pqc && results.classical && (
              <div className="speedup-info">
                <span className="speedup-label">PQC Speedup:</span>
                <span className="speedup-value">
                  {(results.classical.keyGenTime / results.pqc.keyGenTime).toFixed(0)}x faster
                </span>
              </div>
            )}
          </div>

          {/* Encapsulation/Encryption Time Chart */}
          <div className="chart-section">
            <h2>
              <span className="chart-icon">🔐</span>
              Encapsulation/Encryption Time
            </h2>
            <p className="chart-description">Time to encapsulate (PQC) or encrypt (Classical)</p>
            
            <div className="bar-chart">
              {results.pqc && (
                <div className="bar-row">
                  <div className="bar-label">
                    <span className="algo-name">PQC (ML-KEM-1024)</span>
                    <span className="algo-badge pqc">Encapsulation</span>
                  </div>
                  <div className="bar-container">
                    <div 
                      className="bar bar-pqc"
                      style={{ width: `${getBarWidth(results.pqc.encapsulationTime || results.pqc.decapsulationTime, getMaxEncapsTime())}%` }}
                    >
                      <span className="bar-value">{formatTime(results.pqc.encapsulationTime || results.pqc.decapsulationTime)}</span>
                    </div>
                  </div>
                </div>
              )}
              
              {results.classical && (
                <div className="bar-row">
                  <div className="bar-label">
                    <span className="algo-name">Classical (RSA-4096)</span>
                    <span className="algo-badge classical">Encryption</span>
                  </div>
                  <div className="bar-container">
                    <div 
                      className="bar bar-classical"
                      style={{ width: `${getBarWidth(results.classical.encryptionTime, getMaxEncapsTime())}%` }}
                    >
                      <span className="bar-value">{formatTime(results.classical.encryptionTime)}</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
            
            {results.pqc && results.classical && (
              <div className="speedup-info">
                <span className="speedup-label">PQC Speedup:</span>
                <span className="speedup-value">
                  {(results.classical.encryptionTime / (results.pqc.encapsulationTime || results.pqc.decapsulationTime)).toFixed(0)}x faster
                </span>
              </div>
            )}
          </div>

          {/* Key Sizes Chart */}
          <div className="chart-section">
            <h2>
              <span className="chart-icon">📊</span>
              Key Sizes
            </h2>
            <p className="chart-description">Size of public and secret keys</p>
            
            <div className="bar-chart">
              <h3 className="chart-subtitle">Public Key</h3>
              {results.pqc && (
                <div className="bar-row">
                  <div className="bar-label">
                    <span className="algo-name">PQC (ML-KEM-1024)</span>
                  </div>
                  <div className="bar-container">
                    <div 
                      className="bar bar-pqc"
                      style={{ width: `${getBarWidth(results.pqc.publicKeySize, getMaxKeySize())}%` }}
                    >
                      <span className="bar-value">{formatSize(results.pqc.publicKeySize)}</span>
                    </div>
                  </div>
                </div>
              )}
              
              {results.classical && (
                <div className="bar-row">
                  <div className="bar-label">
                    <span className="algo-name">Classical (RSA-4096)</span>
                  </div>
                  <div className="bar-container">
                    <div 
                      className="bar bar-classical"
                      style={{ width: `${getBarWidth(results.classical.publicKeySize, getMaxKeySize())}%` }}
                    >
                      <span className="bar-value">{formatSize(results.classical.publicKeySize)}</span>
                    </div>
                  </div>
                </div>
              )}

              <h3 className="chart-subtitle">Secret Key</h3>
              {results.pqc && (
                <div className="bar-row">
                  <div className="bar-label">
                    <span className="algo-name">PQC (ML-KEM-1024)</span>
                  </div>
                  <div className="bar-container">
                    <div 
                      className="bar bar-pqc"
                      style={{ width: `${getBarWidth(results.pqc.secretKeySize, getMaxKeySize())}%` }}
                    >
                      <span className="bar-value">{formatSize(results.pqc.secretKeySize)}</span>
                    </div>
                  </div>
                </div>
              )}
              
              {results.classical && (
                <div className="bar-row">
                  <div className="bar-label">
                    <span className="algo-name">Classical (RSA-4096)</span>
                  </div>
                  <div className="bar-container">
                    <div 
                      className="bar bar-classical"
                      style={{ width: `${getBarWidth(results.classical.secretKeySize, getMaxKeySize())}%` }}
                    >
                      <span className="bar-value">{formatSize(results.classical.secretKeySize)}</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Summary */}
          <div className="benchmark-summary">
            <h2>
              <span className="chart-icon">📋</span>
              Summary
            </h2>
            <div className="summary-grid">
              {results.pqc && (
                <div className="summary-card pqc">
                  <div className="summary-icon">🛡️</div>
                  <h3>ML-KEM-1024 (PQC)</h3>
                  <ul>
                    <li>✓ {formatTime(results.pqc.keyGenTime)} key generation</li>
                    <li>✓ {formatTime(results.pqc.encapsulationTime || results.pqc.decapsulationTime)} encapsulation</li>
                    <li>✓ Quantum-resistant security</li>
                    <li>⚠ Larger key sizes ({formatSize(results.pqc.publicKeySize)} pub / {formatSize(results.pqc.secretKeySize)} priv)</li>
                  </ul>
                </div>
              )}
              
              {results.classical && (
                <div className="summary-card classical">
                  <div className="summary-icon">🔒</div>
                  <h3>RSA-4096 (Classical)</h3>
                  <ul>
                    <li>⚠ {formatTime(results.classical.keyGenTime)} key generation</li>
                    <li>⚠ {formatTime(results.classical.encryptionTime)} encryption</li>
                    <li>✓ Smaller key sizes ({formatSize(results.classical.publicKeySize)} pub / {formatSize(results.classical.secretKeySize)} priv)</li>
                    <li>✗ Vulnerable to quantum attacks</li>
                  </ul>
                </div>
              )}
            </div>
            
            {results.fallback && (
              <div className="fallback-notice">
                <span className="notice-icon">ℹ️</span>
                Showing estimated values. Run the backend with liboqs for actual benchmark results.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Initial State - No Results */}
      {!results && !isRunning && (
        <div className="benchmark-empty">
          <div className="empty-icon">📈</div>
          <h3>Ready to Benchmark</h3>
          <p>Click "Run Benchmark" to compare the performance of PQC vs Classical cryptography</p>
        </div>
      )}
    </div>
  );
}

export default Benchmark;
