import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import Benchmark from "../Benchmark";
import { benchmarkAPI } from "../../utils/api";

jest.mock("../../utils/api", () => ({
  benchmarkAPI: {
    getStatus: jest.fn(),
    runBenchmark: jest.fn(),
  },
}));

const buildPayload = (iterations) => ({
  success: true,
  results: {
    iterations,
    mutual_auth_iterations: 3,
    pqc_available: true,
    classical_available: true,
    dynamic_metrics_source: "Measured from runtime execution path",
    static_metrics_source: "Curated static benchmark constants",
    pqc: {
      algorithm: "ML-KEM-1024",
      key_generation: { mean: 1.2 },
      encapsulation: { mean: 0.9, throughput_per_second: 1111 },
      decapsulation: { mean: 1.0 },
      signature_generation: { mean: 1.5 },
      signature_verification: { mean: 1.4 },
      key_sizes: { public_key: 1568, private_key: 3168, ciphertext: 1568 },
      key_storage: { write_ms: 0.2, read_ms: 0.1 },
      resource_usage: { memory_peak_bytes: 102400 },
    },
    classical: {
      algorithm: "X25519 (ECC)",
      key_generation: { mean: 0.2 },
      key_exchange: { mean: 0.1, throughput_per_second: 10000 },
      signature_generation: { mean: 0.2 },
      signature_verification: { mean: 0.2 },
      key_sizes: { public_key: 32, private_key: 32, shared_secret: 32 },
      key_storage: { write_ms: 0.1, read_ms: 0.1 },
      resource_usage: { memory_peak_bytes: 20480 },
    },
    mutual_authentication: { mean: 3.3 },
    comparative_metrics: {
      key_exchange_speedup_ratio_classical_over_pqc: 9,
      latency_reduction_percent_classical_vs_pqc_keygen: 80,
      latency_reduction_percent_classical_vs_pqc_key_exchange: 88,
      throughput_key_exchanges_per_second: {
        pqc: 1111,
        classical: 10000,
      },
    },
    resource_metrics: {
      request_wall_time_ms: 60,
      request_cpu_time_ms: 30,
      request_cpu_utilization_percent: 50,
      request_memory_delta_bytes: 8192,
      request_memory_peak_bytes: 122880,
    },
    static_metrics: {
      pqc: {
        public_key_size_bytes: 1568,
        private_key_size_bytes: 3168,
        ciphertext_size_bytes: 1568,
        signature_size_bytes: 4627,
        credential_token_size_bytes: 512,
        nist_security_level: "Level 5",
        core_svp_hardness: { classical_bits: 256, quantum_bits: 233 },
        decapsulation_failure_probability: "2^-174",
        countermeasure_overhead: "~8%",
        attack_traces_required: "Not practical",
      },
      classical: {
        public_key_size_bytes: 32,
        private_key_size_bytes: 32,
        ciphertext_size_bytes: 32,
        signature_size_bytes: 64,
        credential_token_size_bytes: 512,
        nist_security_level: "N/A (pre-PQC)",
        core_svp_hardness: { classical_bits: 128, quantum_bits: 64 },
        decapsulation_failure_probability: "N/A",
        countermeasure_overhead: "~2%",
        attack_traces_required: "Model dependent",
      },
    },
  },
});

describe("Benchmark Compare Analytics", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    benchmarkAPI.getStatus.mockResolvedValue({
      success: true,
      pqc_available: true,
      classical_available: true,
    });
    benchmarkAPI.runBenchmark.mockImplementation((iterations) =>
      Promise.resolve(buildPayload(iterations)),
    );
  });

  test("renders run analytics button", async () => {
    render(<Benchmark />);
    await waitFor(() => {
      expect(screen.getByText("Run Analytics")).not.toBeNull();
    });
  });

  test("runs analytics and renders static metrics table and cards", async () => {
    render(<Benchmark />);

    const button = await screen.findByText("Run Analytics");
    fireEvent.click(button);

    await waitFor(() => {
      expect(screen.getByText("Static Security Metrics")).not.toBeNull();
      expect(screen.getByText("Comparison Cards")).not.toBeNull();
      expect(screen.getByText("Signature Size")).not.toBeNull();
    });

    expect(benchmarkAPI.runBenchmark).toHaveBeenCalled();
  });
});
