# SMB Mount Command Quick Reference

## Basic Syntax
```bash
sudo mount -t cifs //SERVER/SHARE /mnt/MOUNTPOINT -o OPTIONS
```

## Common Mount Commands

### 1. Basic Authentication
```bash
sudo mount -t cifs //192.168.1.100/SharedDocs /mnt/share \
  -o username=jdoe,password=SecurePass123
```

### 2. Domain Authentication
```bash
sudo mount -t cifs //fileserver.corp.local/HR /mnt/hr \
  -o username=admin,password=P@ssw0rd,domain=CORP
```

### 3. Read-Only Mount (Recommended for Security Scans)
```bash
sudo mount -t cifs //192.168.1.100/Finance /mnt/finance \
  -o username=auditor,password=AuditPass,ro
```

### 4. Specify SMB Version
```bash
sudo mount -t cifs //server/share /mnt/share \
  -o username=user,password=pass,vers=3.0
```

### 5. Using Credentials File (Most Secure)
```bash
# Create credentials file
cat > ~/.smbcreds << EOF
username=admin
password=MyPassword123
domain=CORP
EOF
chmod 600 ~/.smbcreds

# Mount using credentials file
sudo mount -t cifs //server/share /mnt/share -o credentials=/home/USERNAME/.smbcreds
```

### 6. Set File Permissions
```bash
sudo mount -t cifs //server/share /mnt/share \
  -o username=user,password=pass,uid=1000,gid=1000,file_mode=0644,dir_mode=0755
```

### 7. Old SMB1 Protocol (Legacy Systems)
```bash
sudo mount -t cifs //oldserver/share /mnt/share \
  -o username=user,password=pass,vers=1.0,sec=ntlm
```

## Common Options Reference

| Option | Description | Example Values |
|--------|-------------|----------------|
| `username=` | Username for authentication | `admin`, `jdoe` |
| `password=` | Password (use credentials file for security) | `MyPass123` |
| `domain=` | Windows domain name | `CORP`, `EXAMPLE` |
| `uid=` | Linux user ID for file ownership | `1000` (use `id -u` to find) |
| `gid=` | Linux group ID for file ownership | `1000` (use `id -g` to find) |
| `ro` | Mount read-only | Just use `ro` |
| `rw` | Mount read-write (default) | Just use `rw` |
| `vers=` | SMB protocol version | `1.0`, `2.0`, `2.1`, `3.0`, `3.1.1` |
| `sec=` | Security mode | `ntlm`, `ntlmv2`, `ntlmssp`, `krb5` |
| `file_mode=` | Permissions for files | `0644`, `0600` |
| `dir_mode=` | Permissions for directories | `0755`, `0700` |
| `iocharset=` | Character set | `utf8` |
| `noperm` | Don't check permissions | Just use `noperm` |
| `credentials=` | Path to credentials file | `/home/user/.smbcreds` |

## SMB Version Reference

| Version | Description | Use Case |
|---------|-------------|----------|
| `vers=1.0` | SMB1/CIFS (legacy, insecure) | Old Windows XP/2003 servers |
| `vers=2.0` | SMB2 | Windows Vista/Server 2008 |
| `vers=2.1` | SMB2.1 | Windows 7/Server 2008 R2 |
| `vers=3.0` | SMB3 (recommended) | Windows 8/Server 2012+ |
| `vers=3.1.1` | SMB3.1.1 (most secure) | Windows 10/Server 2016+ |

## Complete Workflow

### Step 1: Create Mount Point
```bash
sudo mkdir -p /mnt/share
```

### Step 2: Mount the Share
```bash
sudo mount -t cifs //server/share /mnt/share -o username=user,password=pass
```

### Step 3: Verify Mount
```bash
# Check if mounted
mount | grep cifs

# List contents
ls -la /mnt/share

# Check disk usage
df -h /mnt/share
```

### Step 4: Use the Share
```bash
# Scan with sensitive_scanner
python3 sensitive_scanner.py /mnt/share -o scan_results

# Or access normally
cd /mnt/share
cat some_file.txt
```

### Step 5: Unmount
```bash
# Basic unmount
sudo umount /mnt/share

# Force unmount (if busy)
sudo umount -f /mnt/share

# Lazy unmount (if force fails)
sudo umount -l /mnt/share
```

## Troubleshooting Mount Issues

### Check If Share Exists
```bash
# Using smbclient
smbclient -L //server -U username

# Using nmap
nmap -p 445,139 server
```

### View Mount Options
```bash
# See current mounts
mount | grep cifs

# See detailed mount options
cat /proc/mounts | grep cifs
```

### Test Credentials
```bash
smbclient //server/share -U username
# Enter password when prompted
# If successful, you'll get smb: \> prompt
```

### Common Errors and Solutions

**Error: "mount error(13): Permission denied"**
- Wrong username or password
- Account doesn't have access to share
- Try adding `domain=` option

**Error: "mount error(2): No such file or directory"**
- Mount point doesn't exist - run `sudo mkdir -p /mnt/share`
- Share name is wrong - verify with `smbclient -L //server -U user`

**Error: "mount error(112): Host is down"**
- Server unreachable - check with `ping server`
- SMB ports blocked - check with `nmap -p 445,139 server`

**Error: "mount error(5): Input/output error"**
- SMB version mismatch - try `vers=3.0` or `vers=2.1`
- Try different security mode: `sec=ntlmssp`

**Error: "mount error(95): Operation not supported"**
- SMB1 disabled on server - try `vers=2.0` or higher
- Client doesn't support requested version

## Security Best Practices

### 1. Use Credentials File Instead of Command Line
```bash
# BAD - password visible in process list
sudo mount -t cifs //server/share /mnt/share -o username=admin,password=Secret123

# GOOD - use credentials file
echo "username=admin" > ~/.smbcreds
echo "password=Secret123" >> ~/.smbcreds
chmod 600 ~/.smbcreds
sudo mount -t cifs //server/share /mnt/share -o credentials=~/.smbcreds
```

### 2. Mount Read-Only When Possible
```bash
# For security scans, always use ro
sudo mount -t cifs //server/share /mnt/share -o username=user,password=pass,ro
```

### 3. Set Restrictive Permissions
```bash
# Make files owned by your user, not root
sudo mount -t cifs //server/share /mnt/share \
  -o username=user,password=pass,uid=$(id -u),gid=$(id -g)
```

### 4. Use Latest SMB Version
```bash
# Prefer SMB3
sudo mount -t cifs //server/share /mnt/share \
  -o username=user,password=pass,vers=3.0,sec=ntlmssp
```

### 5. Clean Up After Scanning
```bash
# Unmount immediately after scan
sudo umount /mnt/share

# Remove credentials file
shred -vfz ~/.smbcreds
```

## Automated Mounting Script

```bash
#!/bin/bash
# auto_mount_scan.sh - Mount, scan, and unmount

SERVER="192.168.1.100"
SHARE="HR"
MOUNT_POINT="/mnt/$SHARE"
USERNAME="auditor"
PASSWORD="AuditPass"

# Create mount point
sudo mkdir -p "$MOUNT_POINT"

# Mount
echo "Mounting //$SERVER/$SHARE..."
sudo mount -t cifs "//$SERVER/$SHARE" "$MOUNT_POINT" \
  -o username="$USERNAME",password="$PASSWORD",ro,vers=3.0

# Verify mount
if mount | grep -q "$MOUNT_POINT"; then
    echo "✓ Mount successful"
    
    # Run scanner
    python3 sensitive_scanner.py "$MOUNT_POINT" -o "results_$SHARE"
    
    # Unmount
    echo "Unmounting..."
    sudo umount "$MOUNT_POINT"
    echo "✓ Complete"
else
    echo "✗ Mount failed"
    exit 1
fi
```

## Persistent Mounts (fstab)

For permanent mounts (not recommended for security scans):

### 1. Create credentials file
```bash
sudo nano /etc/samba/credentials
```

Content:
```
username=user
password=pass
domain=CORP
```

Protect it:
```bash
sudo chmod 600 /etc/samba/credentials
```

### 2. Add to /etc/fstab
```bash
sudo nano /etc/fstab
```

Add line:
```
//server/share  /mnt/share  cifs  credentials=/etc/samba/credentials,vers=3.0,ro  0  0
```

### 3. Mount all fstab entries
```bash
sudo mount -a
```

## Testing Connection Without Mounting

```bash
# Test with smbclient
smbclient //server/share -U username

# List shares
smbclient -L //server -U username

# Non-interactive test
smbclient //server/share -U username%password -c "ls"
```

## Getting Share Information

```bash
# List all shares on server
smbclient -L //server -U username

# Get detailed share info
smbmap -H server -u username -p password

# Check permissions
smbmap -H server -u username -p password -r
```
