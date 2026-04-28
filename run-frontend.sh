#!/bin/bash
# Start the PQC Password Manager Frontend
# This script starts the React development server

set -e

# Color output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting PQC Password Manager Frontend...${NC}"

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND_DIR="$SCRIPT_DIR/frontend"

# Check if node_modules exists
if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
    echo -e "${RED}Error: node_modules not found at $FRONTEND_DIR/node_modules${NC}"
    echo "Please run: cd frontend && npm install"
    exit 1
fi

echo -e "${GREEN}✓ Dependencies installed${NC}"

# Start frontend
cd "$FRONTEND_DIR"
echo -e "${YELLOW}Starting React dev server on http://localhost:3000${NC}"
echo -e "${GREEN}Press Ctrl+C to stop${NC}"

# Run the frontend
npm start
