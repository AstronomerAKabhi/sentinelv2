#!/bin/bash
set -e

echo "Starting Build Process..."

echo "Installing system dependencies..."

if ! command -v cargo &> /dev/null; then
    echo "Rust not found. Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "Rust is already installed."
fi

echo "Building Linux Backend..."
if [ -d "linux-backend" ]; then
    cd linux-backend
    cargo build --release
    cd ..
else
    echo "Error: linux-backend directory not found!"
    exit 1
fi

# Install Tesseract for OCR
if ! command -v tesseract &> /dev/null; then
    echo "Installing Tesseract OCR..."
    sudo apt-get update && sudo apt-get install -y tesseract-ocr
fi

echo "Installing Python dependencies..."
pip3 install click requests playwright pytesseract Pillow google-generativeai --break-system-packages || echo "Warning: pip install failed"

# Install Playwright browsers
echo "Installing Playwright browsers..."
playwright install chromium

echo "Build Success! Run 'chmod +x host-bridge/launcher.sh' if needed."
