# Multi-stage Dockerfile for PQC Password Manager
# Stage 1: Backend
FROM python:3.10.11-slim AS backend

WORKDIR /app/backend

# Install system dependencies for crypto libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source code
COPY backend/ .

# Stage 2: Frontend
FROM node:20-alpine AS frontend

WORKDIR /app/frontend

# Install build tools for native modules
RUN apk add --no-cache python3 make g++

# Copy frontend source files
COPY frontend/package*.json ./
COPY frontend/public ./public
COPY frontend/src ./src
COPY frontend/scripts ./scripts

# Install dependencies (using npm install instead of npm ci for flexibility)
RUN npm install

# Build the frontend
RUN npm run build

# Stage 3: Production (serving frontend + running backend)
FROM python:3.10.11-slim AS production

WORKDIR /app

# Install nginx for serving frontend
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    && rm -rf /var/lib/apt/lists/*

# Copy built frontend from frontend stage
COPY --from=frontend /app/frontend/build /var/www/html

# Copy backend from backend stage
COPY --from=backend /app/backend /app/backend

# Install backend dependencies
WORKDIR /app/backend
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Configure nginx
RUN echo 'server { \
    listen 80; \
    server_name localhost; \
    root /var/www/html; \
    index index.html; \
    \
    # Serve WASM files with correct MIME type \
    types { \
        application/wasm wasm; \
    } \
    \
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
RUN echo '#!/bin/bash\n\
echo "Starting PQC Password Manager..."\n\
echo "Starting Nginx..."\n\
service nginx start\n\
echo "Starting Backend..."\n\
python app.py\n' > /start.sh && chmod +x /start.sh

# Expose ports
EXPOSE 80

# Start the application
CMD ["/start.sh"]
