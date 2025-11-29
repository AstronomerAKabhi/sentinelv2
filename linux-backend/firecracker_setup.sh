#!/bin/bash
# Firecracker Assets Setup Script - Working Version
# Creates minimal Alpine Linux rootfs and downloads compatible kernel

set -e

ASSETS_DIR="$HOME/sentinel_v2/firecracker-assets"
ALPINE_VERSION="3.19"
ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/releases/x86_64/alpine-minirootfs-${ALPINE_VERSION}.0-x86_64.tar.gz"
FIRECRACKER_VERSION="v1.7.0"
FIRECRACKER_URL="https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-x86_64.tgz"

echo "Setting up Firecracker assets..."

# Install Firecracker Binary
if ! command -v firecracker &> /dev/null; then
    echo "Installing Firecracker..."
    wget -q -O /tmp/firecracker.tgz "$FIRECRACKER_URL"
    tar -xzf /tmp/firecracker.tgz -C /tmp
    mv /tmp/release-${FIRECRACKER_VERSION}-x86_64/firecracker-${FIRECRACKER_VERSION}-x86_64 /usr/local/bin/firecracker
    chmod +x /usr/local/bin/firecracker
    rm -rf /tmp/firecracker.tgz /tmp/release-${FIRECRACKER_VERSION}-x86_64
else
    echo "Firecracker binary already installed."
fi

# Create assets directory
mkdir -p "$ASSETS_DIR"

# Download and create Alpine rootfs
if [ ! -f "$ASSETS_DIR/rootfs.ext4" ]; then
    echo "Creating Alpine Linux rootfs..."
    
    # Download Alpine minirootfs
    wget -O /tmp/alpine-minirootfs.tar.gz "$ALPINE_URL"
    
    # Create 100MB ext4 filesystem
    dd if=/dev/zero of="$ASSETS_DIR/rootfs.ext4" bs=1M count=100
    mkfs.ext4 -F "$ASSETS_DIR/rootfs.ext4"
    
    # Mount and extract Alpine
    mkdir -p /tmp/rootfs_mount
    sudo mount "$ASSETS_DIR/rootfs.ext4" /tmp/rootfs_mount
    sudo tar -xzf /tmp/alpine-minirootfs.tar.gz -C /tmp/rootfs_mount
    
    # Create init script
    sudo tee /tmp/rootfs_mount/init > /dev/null << 'EOF'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
echo "Sentinel Firecracker MicroVM - File Analysis Complete"
echo "Target file would be analyzed here"
poweroff -f
EOF
    sudo chmod +x /tmp/rootfs_mount/init
    
    # Unmount
    sudo umount /tmp/rootfs_mount
    rm -rf /tmp/rootfs_mount /tmp/alpine-minirootfs.tar.gz
    
    chmod 666 "$ASSETS_DIR/rootfs.ext4"
    echo "Rootfs created: $(ls -lh $ASSETS_DIR/rootfs.ext4)"
else
    echo "Rootfs already exists"
fi

# Use the kernel we already have or download a minimal one
# Use the kernel we already have or download a minimal one
if [ ! -f "$ASSETS_DIR/vmlinux" ] || [ "$(cat $ASSETS_DIR/vmlinux)" == "KERNEL_NEEDED" ]; then
    echo "Downloading Firecracker kernel..."
    wget -q -O "$ASSETS_DIR/vmlinux" "https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/vmlinux-5.10.186"
    chmod 644 "$ASSETS_DIR/vmlinux"
fi

echo "Firecracker assets ready at $ASSETS_DIR"
ls -lh "$ASSETS_DIR"
