#!/bin/bash
# Start the PQC Password Manager Backend
# This script sets up the environment and starts the Flask server

set -e

# Color output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting PQC Password Manager Backend...${NC}"

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"

# Check if virtual environment exists
if [ ! -d "$BACKEND_DIR/venv" ]; then
    echo -e "${RED}Error: Virtual environment not found at $BACKEND_DIR/venv${NC}"
    echo "Please run: cd backend && python3 -m venv venv && ./venv/bin/pip install -r requirements.txt"
    exit 1
fi

# Set up library path for liboqs
export LD_LIBRARY_PATH="/tmp/liboqs-install/usr/local/lib:$LD_LIBRARY_PATH"
export PYTHONPATH="$BACKEND_DIR:$PYTHONPATH"

# Check if liboqs library exists
if [ ! -f "/tmp/liboqs-install/usr/local/lib/liboqs.so.0.15.0" ]; then
    echo -e "${RED}Error: liboqs library not found at /tmp/liboqs-install/usr/local/lib/liboqs.so.0.15.0${NC}"
    echo "Please build and install liboqs first:"
    echo "  cd /tmp/liboqs && mkdir -p build && cd build"
    echo "  cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local .."
    echo "  make && make install DESTDIR=/tmp/liboqs-install"
    exit 1
fi

echo -e "${GREEN}✓ Environment configured${NC}"
echo -e "${GREEN}✓ LD_LIBRARY_PATH set: $LD_LIBRARY_PATH${NC}"

# Start backend
cd "$BACKEND_DIR"
echo -e "${YELLOW}Starting Flask server on http://127.0.0.1:5000${NC}"

# Kill any existing backend processes
pkill -f "python.*app.py" 2>/dev/null || true
sleep 1

# Run the backend
"$BACKEND_DIR/venv/bin/python" "$BACKEND_DIR/app.py"
