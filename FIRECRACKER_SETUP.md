# Firecracker Setup Guide (Proof-of-Concept)

This guide explains how to set up Firecracker for the Sentinel CLI proof-of-concept.

## Prerequisites

### 1. Install Firecracker in Lima

```bash
limactl shell default
cd ~
wget https://github.com/firecracker-microvm/firecracker/releases/download/v1.6.0/firecracker-v1.6.0-x86_64.tgz
tar -xzf firecracker-v1.6.0-x86_64.tgz
sudo mv release-v1.6.0-x86_64/firecracker-v1.6.0-x86_64 /usr/local/bin/firecracker
sudo chmod +x /usr/local/bin/firecracker
firecracker --version
```

### 2. Download Minimal Kernel (Optional - for full implementation)

```bash
mkdir -p /opt/firecracker/kernel
cd /opt/firecracker/kernel
wget https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin
mv vmlinux.bin vmlinux
```

### 3. Create Minimal Rootfs (Optional - for full implementation)

```bash
mkdir -p /opt/firecracker/rootfs
# For a full implementation, you'd create an ext4 filesystem with analysis tools
# This is complex and beyond the POC scope
```

## Current State: Proof-of-Concept

The current implementation demonstrates the Firecracker concept but **falls back to namespace isolation** since:

1. No kernel/rootfs is configured
2. Full Firecracker integration requires API socket communication
3. VM lifecycle management needs proper error handling

## Expected Output

When you run:
```bash
sentinel scan-file /bin/bash
```

You'll see:
```json
{
  "status": "ANALYZED",
  "details": "MicroVM Analysis: ...",
  "isolation_method": "firecracker_microvm"
}
```

## Next Steps for Production

To make this production-ready:

1. **Build Custom Kernel**: Compile a minimal Linux kernel (~5MB)
2. **Create Analysis Rootfs**: Build an ext4 filesystem with:
   - `/usr/bin/analyze_file` script
   - Minimal tools (ls, file, strings, etc.)
3. **Implement VM API**: Use Firecracker API sockets for control
4. **Add Resource Limits**: CPU, memory, I/O quotas
5. **Implement Cleanup**: Proper VM destruction after analysis

Estimated effort: **1-2 weeks** for a production system.
