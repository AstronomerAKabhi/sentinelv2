#!/bin/bash
echo "Setting up Sentinel CLI Environment..."

# 1. Install Python Dependencies
echo "Installing Python dependencies..."
/opt/homebrew/Caskroom/miniconda/base/bin/pip install click requests

# 2. Build Rust Binary in Lima
echo "Building Rust binary in Lima..."
limactl shell default bash -c "cd sentinel_v2/linux-backend && cargo build --release"

# 3. Set Environment Variables (Ideally these go in .zshrc)
export VT_API_KEY="5544106b4abff975881f81a0ef8c9d547f8fc213b57c73561c9af1679583f3eb"
export HF_TOKEN="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"

echo "Setup Complete!"
