#!/bin/bash
set -e

echo "Starting Build Process..."

# Ensure we are in the project directory
# If running from home, we are already there.

# 1. Install System Dependencies
echo "Installing system dependencies..."
# sudo apt-get update
# sudo apt-get install -y build-essential curl python3 python3-pip

# 2. Install Rust if not present
if ! command -v cargo &> /dev/null; then
    echo "Rust not found. Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "Rust is already installed."
fi

# 3. Build Linux Backend
echo "Building Linux Backend..."
if [ -d "linux-backend" ]; then
    cd linux-backend
    cargo build --release
    cd ..
else
    echo "Error: linux-backend directory not found!"
    exit 1
fi

# 4. Install Python Dependencies
echo "Installing Python dependencies..."
pip3 install click requests || echo "Warning: pip install failed, you might need to use apt or venv."

echo "Build Success! Run 'chmod +x host-bridge/launcher.sh' if needed."
