# Dockerfile for PQC Password Manager Backend
# Used by docker-compose.yml for running backend in Docker

FROM python:3.10.11-slim

WORKDIR /app/backend

# Install system dependencies for crypto libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    git \
    cmake \
    make \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Build and install liboqs from source
RUN git clone --branch main https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs && \
    cd /tmp/liboqs && \
    mkdir build && \
    cd build && \
    CMAKE_C_COMPILER=gcc CMAKE_CXX=g++ cmake -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON .. && \
    make -j4 && \
    make install && \
    ldconfig && \
    cd / && rm -rf /tmp/liboqs

# Copy and install Python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source code
COPY backend/ .

# Expose Flask port
EXPOSE 5000

# Start the Flask application
CMD ["python", "app.py"]
