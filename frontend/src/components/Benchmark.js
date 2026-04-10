/**
 * Benchmark Component
 * Demonstrates PQC vs Classical cryptography performance comparison
 * Actually runs benchmarks against the backend
 */
import React, { useState, useEffect } from "react";
import { benchmarkAPI } from "../utils/api";
import "../styles/Benchmark.css";

const SCALABILITY_ITERATIONS = [5, 10, 20];

const toNumber = (value) =>
  typeof value === "number" && Number.isFinite(value) ? value : null;

const clampPercent = (value) => {
  if (!Number.isFinite(value)) return 0;
  if (value < 0) return 0;
  if (value > 100) return 100;
  return value;
};

const formatRatio = (value) => {
  if (!Number.isFinite(value) || value === 0) return "N/A";
  if (value >= 1) return `${value.toFixed(2)}x faster`;
  return `${(1 / value).toFixed(2)}x slower`;
};

const buildLinePath = (points, width, height, padding) => {
  if (!points.length) return "";

  const minX = Math.min(...points.map((point) => point.x));
  const maxX = Math.max(...points.map((point) => point.x));
  const minY = 0;
  const maxY = Math.max(...points.map((point) => point.y), 1);

  const drawableWidth = width - padding * 2;
  const drawableHeight = height - padding * 2;

  const mapped = points.map((point) => {
    const xScale = maxX === minX ? 0 : (point.x - minX) / (maxX - minX);
    const yScale = maxY === minY ? 0 : (point.y - minY) / (maxY - minY);
    const x = padding + xScale * drawableWidth;
    const y = height - padding - yScale * drawableHeight;
    return `${x},${y}`;
  });

  return mapped.join(" ");
};

function Benchmark() {
  const [benchmarkStatus, setBenchmarkStatus] = useState({
    pqcAvailable: false,
    classicalAvailable: false,
    loading: true,
  });
  const [isRunning, setIsRunning] = useState(false);
  const [results, setResults] = useState(null);
  const [scalability, setScalability] = useState([]);
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
          loading: false,
        });
      }
    } catch (err) {
      console.error("Failed to check benchmark status:", err);
      setBenchmarkStatus({
        pqcAvailable: false,
        classicalAvailable: false,
        loading: false,
      });
    }
  };

  const runBenchmark = async () => {
    setIsRunning(true);
    setError(null);

    try {
      const mainResponse = await benchmarkAPI.runBenchmark(10);
      if (!mainResponse.success || !mainResponse.results) {
        setError(mainResponse.error || "Analytics run failed");
        setResults(null);
        setScalability([]);
        return;
      }

      const scaleRuns = await Promise.all(
        SCALABILITY_ITERATIONS.map(async (iterations) => {
          const response = await benchmarkAPI.runBenchmark(iterations);
          if (!response.success || !response.results) {
            return null;
          }

          const pqcThroughput = toNumber(
            response.results?.comparative_metrics
              ?.throughput_key_exchanges_per_second?.pqc,
          );
          const classicalThroughput = toNumber(
            response.results?.comparative_metrics
              ?.throughput_key_exchanges_per_second?.classical,
          );

          return {
            iterations,
            pqcThroughput,
            classicalThroughput,
          };
        }),
      );

      setResults(mainResponse.results);
      setScalability(scaleRuns.filter(Boolean));
    } catch (err) {
      setError(`Failed to run analytics: ${err.message || "Unknown error"}`);
      setResults(null);
      setScalability([]);
    }

    setIsRunning(false);
  };

  const formatTime = (ms) => {
    if (ms === undefined || ms === null) return "N/A";
    if (ms < 1) {
      return `${(ms * 1000).toFixed(2)} μs`;
    }
    return `${ms.toFixed(2)} ms`;
  };

  const formatOps = (ops) => {
    if (ops === undefined || ops === null) return "N/A";
    return `${ops.toFixed(2)} /s`;
  };

  const formatPercent = (value) => {
    if (value === undefined || value === null) return "N/A";
    return `${value.toFixed(2)}%`;
  };

  const formatSize = (bytes) => {
    if (bytes === undefined || bytes === null) return "N/A";
    if (bytes >= 1024) {
      return `${(bytes / 1024).toFixed(2)} KB`;
    }
    return `${bytes} B`;
  };

  const getBarWidth = (value, maxValue) => {
    if (
      value === undefined ||
      value === null ||
      maxValue === undefined ||
      maxValue === null ||
      maxValue === 0
    ) {
      return 0;
    }
    return clampPercent((value / maxValue) * 100);
  };

  // Determine liboqs status for display
  const getLiboqsStatus = () => {
    if (benchmarkStatus.loading) return "loading";
    if (benchmarkStatus.pqcAvailable || benchmarkStatus.classicalAvailable)
      return "available";
    return "unavailable";
  };

  const liboqsStatus = getLiboqsStatus();

  const performanceRows = results
    ? [
        {
          label: "Key Generation",
          pqc: toNumber(results?.pqc?.key_generation?.mean),
          classical: toNumber(results?.classical?.key_generation?.mean),
        },
        {
          label: "Encapsulation / Key Exchange",
          pqc: toNumber(results?.pqc?.encapsulation?.mean),
          classical: toNumber(results?.classical?.key_exchange?.mean),
        },
        {
          label: "Decapsulation / Decryption",
          pqc: toNumber(results?.pqc?.decapsulation?.mean),
          classical: toNumber(results?.classical?.key_exchange?.mean),
        },
        {
          label: "Signature Generation",
          pqc: toNumber(results?.pqc?.signature_generation?.mean),
          classical: toNumber(results?.classical?.signature_generation?.mean),
        },
        {
          label: "Signature Verification",
          pqc: toNumber(results?.pqc?.signature_verification?.mean),
          classical: toNumber(results?.classical?.signature_verification?.mean),
        },
        {
          label: "Mutual Authentication",
          pqc: toNumber(results?.mutual_authentication?.mean),
          classical: toNumber(results?.mutual_authentication?.mean),
        },
      ]
    : [];

  const performanceRowsWithScale = performanceRows.map((row) => ({
    ...row,
    rowMax: Math.max(1, row.pqc || 0, row.classical || 0),
  }));

  const staticRows = results?.static_metrics
    ? [
        {
          metric: "Public Key Size",
          pqc: formatSize(results.static_metrics.pqc.public_key_size_bytes),
          classical: formatSize(
            results.static_metrics.classical.public_key_size_bytes,
          ),
        },
        {
          metric: "Private Key Size",
          pqc: formatSize(results.static_metrics.pqc.private_key_size_bytes),
          classical: formatSize(
            results.static_metrics.classical.private_key_size_bytes,
          ),
        },
        {
          metric: "Ciphertext / Encapsulated Size",
          pqc: formatSize(results.static_metrics.pqc.ciphertext_size_bytes),
          classical: formatSize(
            results.static_metrics.classical.ciphertext_size_bytes,
          ),
        },
        {
          metric: "Signature Size",
          pqc: formatSize(results.static_metrics.pqc.signature_size_bytes),
          classical: formatSize(
            results.static_metrics.classical.signature_size_bytes,
          ),
        },
        {
          metric: "Credential / Token Size",
          pqc: formatSize(
            results.static_metrics.pqc.credential_token_size_bytes,
          ),
          classical: formatSize(
            results.static_metrics.classical.credential_token_size_bytes,
          ),
        },
        {
          metric: "NIST Security Level",
          pqc: results.static_metrics.pqc.nist_security_level,
          classical: results.static_metrics.classical.nist_security_level,
        },
        {
          metric: "Core-SVP Hardness (Classical Bits)",
          pqc: results.static_metrics.pqc.core_svp_hardness.classical_bits,
          classical:
            results.static_metrics.classical.core_svp_hardness.classical_bits,
        },
        {
          metric: "Core-SVP Hardness (Quantum Bits)",
          pqc: results.static_metrics.pqc.core_svp_hardness.quantum_bits,
          classical:
            results.static_metrics.classical.core_svp_hardness.quantum_bits,
        },
        {
          metric: "Decapsulation Failure Probability",
          pqc: results.static_metrics.pqc.decapsulation_failure_probability,
          classical:
            results.static_metrics.classical.decapsulation_failure_probability,
        },
        {
          metric: "Countermeasure Overhead",
          pqc: results.static_metrics.pqc.countermeasure_overhead,
          classical: results.static_metrics.classical.countermeasure_overhead,
        },
        {
          metric: "Attack Traces Required",
          pqc: results.static_metrics.pqc.attack_traces_required,
          classical: results.static_metrics.classical.attack_traces_required,
        },
      ]
    : [];

  const keySizePqc = toNumber(results?.pqc?.key_sizes?.public_key) || 0;
  const keySizeClassical =
    toNumber(results?.classical?.key_sizes?.public_key) || 0;
  const keySizeTotal = Math.max(1, keySizePqc + keySizeClassical);
  const keySizePqcPct = (keySizePqc / keySizeTotal) * 100;

  const reqCpu =
    toNumber(results?.resource_metrics?.request_cpu_utilization_percent) || 0;
  const reqMemPeakBytes =
    toNumber(results?.resource_metrics?.request_memory_peak_bytes) || 0;
  const memPqc = toNumber(results?.pqc?.resource_usage?.memory_peak_bytes) || 0;
  const memClassical =
    toNumber(results?.classical?.resource_usage?.memory_peak_bytes) || 0;
  const memTotal = Math.max(1, memPqc + memClassical);
  const requestMemoryPeakDisplay = Math.max(
    reqMemPeakBytes,
    toNumber(results?.resource_metrics?.request_memory_delta_bytes) || 0,
    memPqc,
    memClassical,
    1,
  );

  const scalabilityPqcPoints = scalability
    .filter((point) => point.pqcThroughput)
    .map((point) => ({ x: point.iterations, y: point.pqcThroughput }));
  const scalabilityClassicalPoints = scalability
    .filter((point) => point.classicalThroughput)
    .map((point) => ({ x: point.iterations, y: point.classicalThroughput }));

  const lineWidth = 560;
  const lineHeight = 240;
  const linePadding = 32;
  const pqcLine = buildLinePath(
    scalabilityPqcPoints,
    lineWidth,
    lineHeight,
    linePadding,
  );
  const classicalLine = buildLinePath(
    scalabilityClassicalPoints,
    lineWidth,
    lineHeight,
    linePadding,
  );
  const maxThroughput = Math.max(
    1,
    ...scalability.flatMap((point) => [
      point.pqcThroughput || 0,
      point.classicalThroughput || 0,
    ]),
  );
  const yAxisTicks = [0.25, 0.5, 0.75, 1].map((fraction) => ({
    fraction,
    label: formatOps(maxThroughput * fraction),
  }));

  return (
    <div className="benchmark-container">
      <div className="content-header">
        <h1>Compare Analytics</h1>
        <p className="subtitle">
          Runtime comparison using the existing cryptographic execution path:
          ML-KEM-1024 / ML-DSA-87 vs X25519 / Ed25519.
        </p>
      </div>

      {/* liboqs Status Banner */}
      <div className={`liboqs-status ${liboqsStatus}`}>
        <span className="status-icon">
          {liboqsStatus === "loading" && "⏳"}
          {liboqsStatus === "available" && "✅"}
          {liboqsStatus === "unavailable" && "⚠️"}
        </span>
        <span className="status-text">
          {liboqsStatus === "loading" && "Checking benchmark availability..."}
          {liboqsStatus === "available" &&
            `PQC: ${benchmarkStatus.pqcAvailable ? "✓" : "✗"} | Classical: ${benchmarkStatus.classicalAvailable ? "✓" : "✗"}`}
          {liboqsStatus === "unavailable" && "Benchmark backend unavailable"}
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
              Running Analytics...
            </>
          ) : (
            <>
              <span className="btn-icon">⚡</span>
              Run Analytics
            </>
          )}
        </button>
      </div>

      {/* Results Charts */}
      {results && (
        <div className="benchmark-results">
          <div className="chart-section">
            <h2>
              <span className="chart-icon">🔑</span>
              Performance Metrics (Runtime)
            </h2>
            <p className="chart-description">
              Real timings from backend execution over {results.iterations}{" "}
              iterations.
            </p>

            <div className="bar-chart">
              {performanceRowsWithScale.map((row) => (
                <div className="bar-row" key={row.label}>
                  <div className="performance-metric-header">
                    <span className="algo-name">{row.label}</span>
                    <div className="performance-values">
                      <span className="value-pill pqc">
                        PQC {formatTime(row.pqc)}
                      </span>
                      <span className="value-pill classical">
                        Classical {formatTime(row.classical)}
                      </span>
                    </div>
                  </div>
                  <div className="dual-bar-container">
                    <div className="bar-container">
                      <div
                        className="bar bar-pqc"
                        style={{
                          width: `${Math.max(4, getBarWidth(row.pqc, row.rowMax))}%`,
                        }}
                      />
                    </div>
                    <div className="bar-container">
                      <div
                        className="bar bar-classical"
                        style={{
                          width: `${Math.max(4, getBarWidth(row.classical, row.rowMax))}%`,
                        }}
                      />
                    </div>
                  </div>
                </div>
              ))}

              {results.pqc_error && (
                <div className="error-note">PQC Error: {results.pqc_error}</div>
              )}
              {results.classical_error && (
                <div className="error-note">
                  Classical Error: {results.classical_error}
                </div>
              )}
            </div>
          </div>

          <div className="chart-section">
            <h2>
              <span className="chart-icon">📈</span>
              Scalability (Throughput vs Iterations)
            </h2>
            <p className="chart-description">
              Each point is a real benchmark run at the listed iteration count.
            </p>

            <div className="line-chart-wrap">
              <div className="chart-axis-labels">
                <span className="axis-label y-axis-label">
                  Throughput (ops/sec)
                </span>
                <span className="axis-label x-axis-label">Iterations</span>
              </div>
              <svg
                viewBox={`0 0 ${lineWidth} ${lineHeight}`}
                className="line-chart"
                role="img"
                aria-label="Throughput line chart"
              >
                <rect
                  x="0"
                  y="0"
                  width={lineWidth}
                  height={lineHeight}
                  className="line-grid-bg"
                />
                <line x1={linePadding} y1={linePadding} x2={linePadding} y2={lineHeight - linePadding} className="axis-line" />
                <line x1={linePadding} y1={lineHeight - linePadding} x2={lineWidth - linePadding} y2={lineHeight - linePadding} className="axis-line" />
                {yAxisTicks.map((tick) => {
                  const y = lineHeight - linePadding - (lineHeight - linePadding * 2) * tick.fraction;
                  return (
                    <g key={`y-tick-${tick.fraction}`}>
                      <line x1={linePadding} y1={y} x2={lineWidth - linePadding} y2={y} className="line-grid" />
                      <line x1={linePadding - 4} y1={y} x2={linePadding} y2={y} className="axis-tick" />
                      <text x={linePadding - 8} y={y + 4} textAnchor="end" className="axis-text axis-text-y">
                        {tick.label}
                      </text>
                    </g>
                  );
                })}
                {scalability.map((point) => {
                  const minIteration = Math.min(...scalability.map((item) => item.iterations));
                  const maxIteration = Math.max(...scalability.map((item) => item.iterations));
                  const xScale = maxIteration === minIteration ? 0.5 : (point.iterations - minIteration) / (maxIteration - minIteration);
                  const x = linePadding + xScale * (lineWidth - linePadding * 2);
                  return (
                    <g key={`x-tick-${point.iterations}`}>
                      <line x1={x} y1={lineHeight - linePadding} x2={x} y2={lineHeight - linePadding + 4} className="axis-tick" />
                      <text x={x} y={lineHeight - 6} textAnchor="middle" className="axis-text axis-text-x">
                        {point.iterations}
                      </text>
                    </g>
                  );
                })}
                {pqcLine && <polyline points={pqcLine} className="line-pqc" />}
                {classicalLine && (
                  <polyline points={classicalLine} className="line-classical" />
                )}
              </svg>
              <div className="line-legend">
                <span className="legend-item pqc">PQC throughput</span>
                <span className="legend-item classical">
                  Classical throughput
                </span>
              </div>
            </div>

            <div className="throughput-grid">
              {scalability.map((point) => (
                <div key={`tp-${point.iterations}`} className="throughput-card">
                  <h4>{point.iterations} Iterations</h4>
                  <div>PQC: {formatOps(point.pqcThroughput)}</div>
                  <div>Classical: {formatOps(point.classicalThroughput)}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="chart-section">
            <h2>
              <span className="chart-icon">🍩</span>
              Size and Resource Doughnut Views
            </h2>
            <p className="chart-description">
              Visual split for key-size and memory pressure metrics.
            </p>

            <div className="doughnut-grid">
              <div className="doughnut-card">
                <h3>Public Key Size Share</h3>
                <div
                  className="doughnut"
                  style={{
                    background: `conic-gradient(var(--color-secondary) 0 ${keySizePqcPct}%, var(--color-text-muted) ${keySizePqcPct}% 100%)`,
                  }}
                >
                  <span>{keySizePqcPct.toFixed(1)}%</span>
                </div>
                <p>
                  PQC: {formatSize(keySizePqc)} | Classical:{" "}
                  {formatSize(keySizeClassical)}
                </p>
              </div>

              <div className="doughnut-card">
                <h3>Request CPU Utilization</h3>
                <div
                  className="doughnut"
                  style={{
                    background: `conic-gradient(var(--color-primary) 0 ${clampPercent(reqCpu)}%, var(--color-bg-elevated) ${clampPercent(reqCpu)}% 100%)`,
                  }}
                >
                  <span>{formatPercent(reqCpu)}</span>
                </div>
                <p>Peak request memory: {formatSize(requestMemoryPeakDisplay)}</p>
              </div>

              <div className="doughnut-card">
                <h3>Algorithm Memory Peak Share</h3>
                <div
                  className="doughnut"
                  style={{
                    background: `conic-gradient(var(--color-secondary) 0 ${(memPqc / memTotal) * 100}%, var(--color-text-muted) ${(memPqc / memTotal) * 100}% 100%)`,
                  }}
                >
                  <span>{((memPqc / memTotal) * 100 || 0).toFixed(1)}%</span>
                </div>
                <p>
                  PQC: {formatSize(memPqc)} | Classical:{" "}
                  {formatSize(memClassical)}
                </p>
              </div>
            </div>
          </div>

          <div className="chart-section">
            <h2>
              <span className="chart-icon">📋</span>
              Static Security Metrics
            </h2>
            <p className="chart-description">
              Curated static values used for the security and size comparison
              model.
            </p>

            <div className="comparison-table-wrap">
              <table className="comparison-table">
                <thead>
                  <tr>
                    <th>Metric</th>
                    <th>PQC</th>
                    <th>Classical</th>
                  </tr>
                </thead>
                <tbody>
                  {staticRows.map((row) => (
                    <tr key={row.metric}>
                      <td>{row.metric}</td>
                      <td>{row.pqc}</td>
                      <td>{row.classical}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="benchmark-summary">
            <h2>
              <span className="chart-icon">🧮</span>
              Comparison Cards
            </h2>
            <div className="summary-grid">
              <div className="summary-card pqc">
                <div className="summary-icon">⚡</div>
                <h3>Throughput</h3>
                <ul>
                  <li>
                    PQC key exchanges:{" "}
                    {formatOps(
                      results?.comparative_metrics
                        ?.throughput_key_exchanges_per_second?.pqc,
                    )}
                  </li>
                  <li>
                    Classical key exchanges:{" "}
                    {formatOps(
                      results?.comparative_metrics
                        ?.throughput_key_exchanges_per_second?.classical,
                    )}
                  </li>
                  <li>
                    Mutual auth mean:{" "}
                    {formatTime(results?.mutual_authentication?.mean)}
                  </li>
                </ul>
              </div>

              <div className="summary-card classical">
                <div className="summary-icon">⏱</div>
                <h3>Latency Reduction</h3>
                <ul>
                  <li>
                    Keygen:{" "}
                    {formatPercent(
                      results?.comparative_metrics
                        ?.latency_reduction_percent_classical_vs_pqc_keygen,
                    )}
                  </li>
                  <li>
                    Key exchange:{" "}
                    {formatPercent(
                      results?.comparative_metrics
                        ?.latency_reduction_percent_classical_vs_pqc_key_exchange,
                    )}
                  </li>
                  <li>
                    Speedup ratio:{" "}
                    {formatRatio(
                      results?.comparative_metrics
                        ?.key_exchange_speedup_ratio_classical_over_pqc,
                    )}
                  </li>
                </ul>
              </div>

              <div className="summary-card">
                <div className="summary-icon">💾</div>
                <h3>Key Storage IO</h3>
                <ul>
                  <li>
                    PQC write/read:{" "}
                    {formatTime(results?.pqc?.key_storage?.write_ms)} /{" "}
                    {formatTime(results?.pqc?.key_storage?.read_ms)}
                  </li>
                  <li>
                    Classical write/read:{" "}
                    {formatTime(results?.classical?.key_storage?.write_ms)} /{" "}
                    {formatTime(results?.classical?.key_storage?.read_ms)}
                  </li>
                  <li>
                    Request memory delta:{" "}
                    {formatSize(
                      results?.resource_metrics?.request_memory_delta_bytes,
                    )}
                  </li>
                </ul>
              </div>

              <div className="summary-card">
                <div className="summary-icon">🔐</div>
                <h3>Signature Runtime</h3>
                <ul>
                  <li>
                    PQC sign/verify:{" "}
                    {formatTime(results?.pqc?.signature_generation?.mean)} /{" "}
                    {formatTime(results?.pqc?.signature_verification?.mean)}
                  </li>
                  <li>
                    Classical sign/verify:{" "}
                    {formatTime(results?.classical?.signature_generation?.mean)}{" "}
                    /{" "}
                    {formatTime(
                      results?.classical?.signature_verification?.mean,
                    )}
                  </li>
                  <li>
                    CPU utilization:{" "}
                    {formatPercent(
                      results?.resource_metrics
                        ?.request_cpu_utilization_percent,
                    )}
                  </li>
                </ul>
              </div>
            </div>

            {results.mutual_authentication_error && (
              <div className="fallback-notice">
                <span className="notice-icon">⚠️</span>
                Mutual authentication metric error:{" "}
                {results.mutual_authentication_error}
              </div>
            )}
          </div>

          {(results.pqc_error || results.classical_error) && (
            <div className="error-banner">
              <span className="error-icon">⚠️</span>
              {results.pqc_error && `PQC: ${results.pqc_error} `}
              {results.classical_error &&
                `Classical: ${results.classical_error}`}
            </div>
          )}
        </div>
      )}

      {/* Initial State - No Results */}
      {!results && !isRunning && (
        <div className="benchmark-empty">
          <div className="empty-icon">📈</div>
          <h3>Ready to Run Analytics</h3>
          <p>
            Click "Run Analytics" to execute the real benchmark path and
            generate runtime metrics.
          </p>
        </div>
      )}

      {/* No synthetic fallback allowed */}
      {!results && error && !isRunning && (
        <div className="fallback-notice">
          <span className="notice-icon">ℹ️</span>
          Only real runtime metrics are displayed. Retry when backend services
          are available.
        </div>
      )}
    </div>
  );
}

export default Benchmark;
