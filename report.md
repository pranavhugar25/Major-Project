# Security and Redundancy Audit Report

Date: 2026-02-26  
Scope: Current backend, frontend, Docker deployment artifacts, and architecture/API docs.

## Executive Summary

The implementation has improved in important areas (challenge-response login, active PQC integration, hybrid transport support), but several high-impact security flaws and operational gaps remain.

Most severe issue:
- The server currently stores a verifier that is effectively the same key used to decrypt the vault payloads. A DB leak can enable direct account impersonation and offline vault decryption.

## Findings (Priority Order)

## 1) Critical: Stored verifier is equivalent to vault decryption key
Evidence:
- `frontend/src/components/Register.js:44` derives `passwordVerifier` via `deriveVaultKey`.
- `backend/routes/auth.py:229` stores `master_password_hash=password_verifier`.
- `backend/routes/auth.py:395` uses stored verifier directly for login proof verification.
- `frontend/src/utils/crypto.js:58` defines `deriveVaultKey` used for vault encryption/decryption key material.

Impact:
- Database compromise can allow direct login proof generation (no password cracking required).
- Same leaked verifier can decrypt stored vault ciphertexts offline.
- Zero-knowledge claim is effectively broken.

Recommendation:
- Replace current verifier scheme with a real PAKE/SRP/OPAQUE-like design where server-stored material is not a reusable authenticator and not a vault key equivalent.
- Split authentication secret from vault encryption key derivation path.

## 2) Critical: Auth tokens and CSRF token stored in `sessionStorage`
Evidence:
- `frontend/src/utils/api.js:310`
- `frontend/src/utils/api.js:317`
- `frontend/src/utils/api.js:320`
- `frontend/src/utils/api.js:220`

Impact:
- Any successful XSS can steal bearer/refresh/CSRF tokens and fully hijack sessions.

Recommendation:
- Move to `httpOnly`, `Secure`, `SameSite=Strict` cookies for auth.
- Keep CSRF double-submit/anti-CSRF token strategy for state-changing endpoints.

## 3) High: Production compose does not provide HTTPS termination and exposes backend directly
Evidence:
- `docker-compose.prod.yml:12` (`8080:80`)
- `docker-compose.prod.yml:13` (`5001:5000`)
- `Dockerfile:85` nginx listens on port 80 only.
- `Dockerfile:90` proxies to backend over local HTTP.

Impact:
- If deployed as-is, traffic is not TLS-protected at edge.
- Direct backend port exposure bypasses intended reverse-proxy boundary.

Recommendation:
- Enforce TLS termination (443) with real cert management at edge.
- Remove public backend port mapping in production deployment.
- Keep backend reachable only on private network.

## 4) High: Security-critical state is memory-only (non-persistent, non-shared)
Evidence:
- `backend/utils/auth.py:26` in-memory token blacklist.
- `backend/routes/auth.py:43` in-memory failed-login tracker.
- `backend/routes/auth.py:44` in-memory login challenges.
- `backend/utils/transport.py:40` in-memory transport sessions.
- `backend/app.py:114` rate-limiter defaults to memory storage.
- `docker-compose.yml:18` and `docker-compose.prod.yml:18` set `RATELIMIT_STORAGE_URL=memory://`.

Impact:
- Restart clears revocations/challenges/locks/sessions.
- Horizontal scaling breaks correctness and security controls.

Recommendation:
- Move to Redis or another shared durable store for blacklist, rate-limit, lock/challenge/session state.

## 5) High: Hybrid transport is optional for password routes (downgrade path)
Evidence:
- `backend/routes/passwords.py:150`
- `backend/routes/passwords.py:151`
- `backend/routes/passwords.py:152` (accepts plaintext JSON body when `transport` envelope absent).

Impact:
- Clients can bypass hybrid transport mechanism and still call password APIs.
- Claimed transport-hardening is not enforced.

Recommendation:
- Enforce transport envelope on all protected password routes, or add strict policy flag and reject non-enveloped requests.

## 6) High: Weak default `SECRET_KEY` in development compose
Evidence:
- `docker-compose.yml:16` uses fallback `change-this-secret-key-in-prod`.

Impact:
- Predictable signing key risks forged JWTs in misconfigured environments.
- Increases chance of accidental insecure deployment.

Recommendation:
- Remove insecure default.
- Fail-fast when `SECRET_KEY` is missing/weak.

## 7) Medium: Username/account enumeration still possible
Evidence:
- `backend/routes/auth.py:224` registration returns explicit duplicate username message.
- `backend/routes/auth.py:305` and `backend/routes/auth.py:307` login challenge behavior differs for unknown user.

Impact:
- Attackers can enumerate valid accounts and focus credential attacks.

Recommendation:
- Normalize auth error responses and timing.
- For registration, consider generic response with out-of-band verification flow.

## 8) Medium: No anti-replay controls for transport envelopes
Evidence:
- `backend/utils/transport.py:163` decrypts envelope without message nonce tracking.
- `backend/utils/transport.py:189` encrypts payloads but no monotonic counter/replay cache.

Impact:
- Captured encrypted requests could be replayed within session lifetime.

Recommendation:
- Add per-session sequence numbers or nonce replay cache with rejection on duplicates.

## 9) Medium: PQC envelope wrapping key is derived directly from app `SECRET_KEY`
Evidence:
- `backend/utils/pqc_envelope.py:49`
- `backend/utils/pqc_envelope.py:50`
- `backend/utils/pqc_envelope.py:51`

Impact:
- Key separation and rotation strategy is weak.
- Rotating app secret can make historical envelope data undecryptable unless migration process exists.

Recommendation:
- Use dedicated key-management for envelope wrapping keys (KMS/HSM/rotatable key IDs).
- Store key version metadata on each envelope.

## 10) Medium: Frontend response security headers are not explicitly configured in shipped nginx config
Evidence:
- `Dockerfile:85` nginx server block lacks explicit CSP/XFO/Referrer-Policy headers for frontend pages.

Impact:
- Increases XSS/UXSS blast radius, especially while auth tokens live in `sessionStorage`.

Recommendation:
- Add strict frontend CSP and related headers at nginx layer.
- Pair with token-storage hardening (Finding #2).

## 11) Low: Frontend CRA toolchain has high deprecation/vulnerability noise; remediation is likely breaking
Evidence:
- `frontend/package.json:13` pins `react-scripts` to `5.0.1`.
- `frontend/package-lock.json:13715` shows the same legacy CRA toolchain root.
- Docker audit run (`docker compose run --rm frontend npm audit --omit=dev`, 2026-02-26) reports transitive vulnerabilities tied largely to CRA dependencies (`10 high`, `4 moderate`, `1 low`).
- Build output also includes non-security lint warnings in hooks:
  - `frontend/src/components/CryptoView.js:14`
  - `frontend/src/components/Dashboard.js:44`
  - `frontend/src/components/StoredPasswords.js:18`

Impact:
- Security review signal is noisy due to stale transitive dependencies.
- Quick fixes like `npm audit fix --force` can introduce breaking changes.
- Operational risk is currently lower because production serves a static build (no exposed dev server), but this remains maintenance debt.

Recommendation:
- Treat as planned modernization work, not hotfix: migrate from CRA (`react-scripts`) to a maintained bundler (e.g., Vite) in a dedicated branch.
- Fix hook warnings as non-breaking hygiene in the current codebase.
- Re-run Docker-based `npm audit` and build validation after migration.

## Redundancies and Complexity Hotspots

1. Multiple transport/data protection layers overlap:
- Client vault AES (`frontend/src/utils/crypto.js`)
- Hybrid transport AES envelope (`frontend/src/utils/api.js`, `backend/utils/transport.py`)
- Server-side PQC envelope at rest (`backend/utils/pqc_envelope.py`)

This can be valid defense-in-depth, but increases complexity and bug surface. Policy boundaries are now documented, but enforcement and simplification decisions are still pending.

2. CSRF enforcement with bearer-token auth:
- CSRF on bearer-token APIs can be redundant if cookies are not auth carrier.
- Current setup mixes bearer + CSRF token while keeping tokens in JS storage.

## Recommended Remediation Plan

## Immediate (P0)
- Replace verifier scheme with real PAKE/SRP/OPAQUE-style authentication.
- Move auth tokens out of `sessionStorage`.
- Enforce TLS in production deployment and remove public backend port exposure.

## Short-term (P1)
- Enforce hybrid transport envelopes for password APIs (or explicitly disable and simplify).
- Move all security state stores to Redis/shared durable storage.
- Add replay protection for transport envelopes.

## Medium-term (P2)
- Introduce proper key management for envelope wrapping keys.
- Plan and execute frontend toolchain migration off `react-scripts` to reduce stale transitive dependency risk.

## Notes

- Findings are based on static analysis of current repository state.
- Dynamic penetration testing and threat-model validation are still recommended before production release.
