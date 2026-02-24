# Multi-stage Dockerfile for PQC Password Manager
# Stage 1: Backend
FROM python:3.10.11-slim AS backend

WORKDIR /app/backend
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies for crypto libraries and liboqs
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    cmake \
    git \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Build and install liboqs 0.14.0 (matches liboqs-python 0.14.1)
RUN git clone --depth 1 --branch 0.14.0 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && cd /tmp/liboqs \
    && cmake -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF . \
    && make -j$(nproc) \
    && make install \
    && ldconfig \
    && rm -rf /tmp/liboqs

# Copy and install Python dependencies (includes liboqs-python)
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source code
COPY backend/ .

# Verify liboqs KEM and signature operations at build time.
RUN python -c "import oqs; kem=oqs.KeyEncapsulation('ML-KEM-1024'); pk=kem.generate_keypair(); out=kem.encap_secret(pk); ct,ss=(out if isinstance(out, tuple) else (out, kem.decap_secret(out))); kem2=oqs.KeyEncapsulation('ML-KEM-1024', secret_key=kem.export_secret_key()); assert kem2.decap_secret(ct)==ss; sig=oqs.Signature('ML-DSA-87'); spk=sig.generate_keypair(); s=sig.sign(b'pqc'); assert oqs.Signature('ML-DSA-87').verify(b'pqc', s, spk)"

# Stage 2: Frontend
FROM node:18-alpine AS frontend

WORKDIR /app/frontend

# Copy frontend source files
COPY frontend/package*.json ./
COPY frontend/public ./public
COPY frontend/src ./src

# Install dependencies (using npm install instead of npm ci for flexibility)
RUN npm install --no-audit --no-fund

# Build the frontend
RUN npm run build

# Stage 3: Production (serving frontend + running backend)
FROM python:3.10.11-slim AS production

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install nginx for serving frontend and system deps for liboqs
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy liboqs shared library from backend stage
COPY --from=backend /usr/local/lib/liboqs.so* /usr/local/lib/
COPY --from=backend /usr/local/include/oqs /usr/local/include/oqs
RUN ldconfig && ln -sf /usr/local/lib/liboqs.so.9 /usr/local/lib/liboqs.so

# Copy built frontend from frontend stage
COPY --from=frontend /app/frontend/build /var/www/html

# Copy backend from backend stage
COPY --from=backend /app/backend /app/backend

# Install backend dependencies (includes liboqs-python)
WORKDIR /app/backend
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Configure nginx
RUN echo 'server { \
    listen 80; \
    server_name localhost; \
    root /var/www/html; \
    index index.html; \
    location /api { \
        proxy_pass http://localhost:5000; \
        proxy_http_version 1.1; \
        proxy_set_header Upgrade $http_upgrade; \
        proxy_set_header Connection "upgrade"; \
        proxy_set_header Host $host; \
        proxy_set_header X-Real-IP $remote_addr; \
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; \
        proxy_set_header X-Forwarded-Proto $scheme; \
    } \
    location / { \
        try_files $uri $uri/ /index.html; \
    } \
}' > /etc/nginx/sites-available/default

# Create startup script
RUN echo '#!/bin/sh\n\
set -e\n\
python /app/backend/app.py &\n\
exec nginx -g \"daemon off;\"\n' > /start.sh && chmod +x /start.sh

# Expose ports
EXPOSE 80

# Start the application
CMD ["/start.sh"]
