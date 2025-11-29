# Sentinel V2 - Security Analysis Tool

## Overview
Sentinel V2 is a comprehensive security analysis tool that scans URLs and files for potential threats using AI-powered analysis and hardware-level isolation.

## Features

### 🛡️ Multi-Layer Protection
- **URL Scanning**: LLM-powered phishing detection with domain whitelisting
- **File Scanning**: Firecracker microVM isolation for behavioral analysis
- **Threat Scoring**: Risk levels (LOW/MEDIUM/HIGH) with confidence scores
- **Real-time Protection**: Browser extension with automatic scanning

### 🎯 Components
1. **CLI Tool** - Command-line scanner for URLs and files
2. **Chrome Extension** - Real-time browser protection
3. **Rust Backend** - Firecracker-based file analysis
4. **Python Bridge** - Native messaging for extension-backend communication

### 📊 Capabilities
- ✅ Threat scoring (0-100 scale)
- ✅ Risk indicators and detailed analysis
- ✅ Scan history and statistics
- ✅ CSV/JSON export
- ✅ Persistent local logging
- ✅ Warning modals for high-risk threats
- ✅ Dashboard with analytics

## Installation

### Prerequisites
- **Windows 10/11** with WSL2 (Ubuntu)
- **Chrome Browser**
- **Rust** (latest stable)
- **Python 3.8+**
- **Firecracker** (for file scanning)

### Setup Steps

#### 1. Install System Dependencies (WSL)
```bash
wsl
sudo apt-get update
sudo apt-get install -y build-essential curl python3 python3-pip wget
```

#### 2. Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

#### 3. Install Python Dependencies
```bash
cd ~/sentinel_v2
pip3 install click requests
```

#### 4. Build Rust Backend
```bash
cd ~/sentinel_v2/linux-backend
cargo build --release
```

#### 5. Setup Firecracker (Optional - for file scanning)
```bash
cd ~/sentinel_v2/linux-backend
chmod +x firecracker_setup.sh
./firecracker_setup.sh
```

#### 6. Install Chrome Extension
1. Open Chrome: `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select: `C:\Users\YourName\Downloads\sentinel_v2\sentinel_v2\extension`

#### 7. Register Native Messaging Host
Double-click: `sentinel_v2\host-bridge\register_host.reg`

## Usage

### CLI Tool

**Scan URL:**
```powershell
.\sentinel.bat scan-url "https://example.com"
```

**Scan File:**
```powershell
.\sentinel.bat scan-file "/mnt/c/Users/YourName/file.exe"
```

### Chrome Extension
1. Click Sentinel V2 icon in toolbar
2. Enter URL or file path
3. Click "Scan URL" or "Scan File"
4. View results in popup
5. Click "View Dashboard" for history

## Configuration

### API Keys (Optional)
Set in `host-bridge/bridge.py`:
- `HF_TOKEN` - Hugging Face API token
- `VT_API_KEY` - VirusTotal API key

### Log Location
- **WSL**: `~/sentinel_v2/logs/scan_history.json`
- **Windows**: `\\wsl$\Ubuntu\home\{user}\sentinel_v2\logs\scan_history.json`

## Architecture

```
sentinel_v2/
├── cli_app/          # Python CLI application
│   ├── sentinel.py   # Main CLI script
│   └── log_manager.py # File logging
├── linux-backend/    # Rust backend
│   └── src/main.rs   # Firecracker integration
├── host-bridge/      # Native messaging bridge
│   ├── bridge.py     # Python bridge script
│   └── launcher.bat  # Windows launcher
├── extension/        # Chrome extension
│   ├── popup.html    # Extension popup
│   ├── dashboard.html # Dashboard UI
│   └── warning.html  # Threat warning modal
└── logs/            # Scan logs (auto-generated)
```

## Security Features

### Isolation Methods
1. **LLM Analysis** - AI-powered URL threat detection
2. **Pattern Matching** - Keyword and TLD analysis
3. **Firecracker MicroVM** - Hardware-isolated file execution
4. **Domain Whitelist** - Trusted site verification

### Threat Detection
- Phishing URL patterns
- Suspicious file extensions
- Malicious behavior analysis
- Double extension detection

## Troubleshooting

### Extension not connecting
```powershell
# Re-register native host
reg import sentinel_v2\host-bridge\register_host.reg
```

### Firecracker permission denied
```bash
# Add user to kvm group
sudo usermod -aG kvm $USER
# Restart WSL
wsl --shutdown
```

### Logs not saving
```bash
# Create logs directory
mkdir -p ~/sentinel_v2/logs
```

## Export Options

### Dashboard Export
- **CSV**: Spreadsheet-compatible format
- **JSON**: Full data with statistics

### File Locations
- Scans: `chrome.storage.local`
- Logs: `~/sentinel_v2/logs/scan_history.json`

## Development

### Running Tests
```bash
# Test URL scan
.\sentinel.bat scan-url "https://google.com"

# Test file scan
.\sentinel.bat scan-file "/home/user/testfile"
```

### Rebuilding Backend
```bash
wsl
cd ~/sentinel_v2/linux-backend
cargo build --release
```

## License
MIT License

## Contributors
Sentinel V2 Development Team

## Support
For issues and feature requests, please open an issue on GitHub.

---

**⚠️ Disclaimer**: This tool is for security research and analysis. Always exercise caution when analyzing potentially malicious content.
