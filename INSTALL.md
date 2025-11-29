# Sentinel V2 Installation

Follow these exact steps to deploy the system.

## 1. Rust Build (Guest VM)
Build the backend binary inside the Lima VM.
```bash
limactl shell default
cd sentinel_v2/linux-backend
cargo build --release
exit
```

## 2. Permissions (Host)
Make the bridge scripts executable on your Mac.
```bash
chmod +x ~/sentinel_v2/host-bridge/launcher.sh ~/sentinel_v2/host-bridge/bridge.py
```

## 3. Manifest Install (Host)
Register the Native Messaging Host with Chrome.
```bash
sudo mkdir -p "/Library/Application Support/Google/Chrome/NativeMessagingHosts/"
sudo cp ~/sentinel_v2/host-bridge/com.sentinel.host.json "/Library/Application Support/Google/Chrome/NativeMessagingHosts/"
```

## 4. Extension Setup
1. Open Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (top right).
3. Click **Load unpacked**.
4. Select the directory: `~/sentinel_v2/extension`.
5. Copy the generated **Extension ID** (e.g., `abcdef...`).
6. **Edit the installed manifest file**:
   ```bash
   sudo nano "/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.sentinel.host.json"
   ```
7. Replace `CHROME_EXTENSION_ID_HERE` with your copied ID.
   Example: `"chrome-extension://abcdef.../"`
8. Save (`Ctrl+O`, `Enter`) and Exit (`Ctrl+X`).

## 5. Launch
1. Open a terminal and run the launcher to verify it hangs (waiting for input):
   ```bash
   ~/sentinel_v2/host-bridge/launcher.sh
   ```
   (Press `Ctrl+C` to stop).
2. **Refresh** the Sentinel V2 extension in `chrome://extensions`.
3. Open the extension popup and click **Initiate Scan**.
