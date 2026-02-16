# SMB Share Sensitive File Scanner

A Python tool for scanning **mounted** SMB shares to identify files containing sensitive information such as passwords, API keys, private keys, connection strings, and other credentials. Features real-time progress tracking and comprehensive reporting.

## Overview

This scanner works on **already-mounted** SMB shares, making it ideal for security assessments where you have legitimate access to network shares. It identifies sensitive files both by filename patterns and by scanning file content for secrets.

## Features

- 🔍 **Dual Detection**: Identifies sensitive files by both filename patterns and content analysis
- 📊 **Real-time Progress**: Live progress bar showing files scanned and data processed
- 🎯 **Smart Filtering**: Focuses on text-based files likely to contain credentials
- 📁 **Comprehensive Patterns**: Detects passwords, API keys, tokens, database connections, private keys, and more
- 📄 **Multiple Reports**: Generates summary, CSV, and categorized text files
- 🎨 **Color-coded Output**: Easy-to-read terminal output with status indicators
- ⚡ **Fast Scanning**: Efficiently processes large directory structures
- 🚫 **Size Limits**: Skips files larger than 10MB to prevent slowdowns

## Requirements

- Python 3.6 or higher
- Linux system with CIFS/SMB mounting capability
- Valid credentials for the target SMB share
- `mount.cifs` utility (usually pre-installed)

## Installation

### 1. Install Dependencies

```bash
# Install Python (if not already installed)
sudo apt-get update
sudo apt-get install python3

# Install CIFS utilities for mounting SMB shares
sudo apt-get install cifs-utils

# No additional Python packages required - uses only standard library!
```

### 2. Download the Scanner

```bash
# Make the script executable
chmod +x sensitive_scanner.py
```

## Usage

### Step 1: Mount the SMB Share

Before scanning, you need to mount the SMB share to your local filesystem.

#### Basic Mount Commands

```bash
# Create a mount point
sudo mkdir -p /mnt/share

# Mount with username and password
sudo mount -t cifs //SERVER/SHARE /mnt/share -o username=USER,password=PASS

# Mount with domain credentials
sudo mount -t cifs //SERVER/SHARE /mnt/share -o username=USER,password=PASS,domain=DOMAIN
```

#### Mount Command Options

| Option | Description | Example |
|--------|-------------|---------|
| `username=` | Username for authentication | `username=admin` |
| `password=` | Password for authentication | `password=MyPass123` |
| `domain=` | Domain name (for AD environments) | `domain=CORP` |
| `uid=` | User ID for file ownership | `uid=1000` |
| `gid=` | Group ID for file ownership | `gid=1000` |
| `ro` | Mount read-only (safer) | `ro` |
| `vers=` | SMB protocol version | `vers=3.0` |
| `sec=` | Security mode | `sec=ntlmssp` |

#### Complete Mount Examples

**Example 1: Basic mount with credentials**
```bash
sudo mount -t cifs //192.168.1.100/SharedDocs /mnt/share \
  -o username=jdoe,password=SecurePass123
```

**Example 2: Domain environment mount**
```bash
sudo mount -t cifs //fileserver.corp.local/HR /mnt/hr \
  -o username=admin,password=P@ssw0rd,domain=CORP
```

**Example 3: Read-only mount (safer for security assessments)**
```bash
sudo mount -t cifs //192.168.1.100/Finance /mnt/finance \
  -o username=auditor,password=AuditPass,ro
```

**Example 4: Mount with specific SMB version**
```bash
sudo mount -t cifs //server/share /mnt/share \
  -o username=user,password=pass,vers=3.0,sec=ntlmssp
```

**Example 5: Using credentials file (more secure)**
```bash
# Create credentials file
echo "username=admin" > ~/.smbcreds
echo "password=MyPassword123" >> ~/.smbcreds
echo "domain=CORP" >> ~/.smbcreds
chmod 600 ~/.smbcreds

# Mount using credentials file
sudo mount -t cifs //server/share /mnt/share -o credentials=~/.smbcreds
```

### Step 2: Run the Scanner

```bash
# Basic scan
python3 sensitive_scanner.py /mnt/share

# Specify output directory
python3 sensitive_scanner.py /mnt/share -o hr_scan_results

# Limit recursion depth
python3 sensitive_scanner.py /mnt/share --max-depth 5

# Scan multiple shares
python3 sensitive_scanner.py /mnt/hr
python3 sensitive_scanner.py /mnt/finance -o finance_results
python3 sensitive_scanner.py /mnt/it -o it_results
```

### Step 3: Review Results

Results are saved in timestamped directories (or your specified output directory):

```
scan_results_20240216_143022/
├── summary.txt                 # Overall statistics
├── high_value_files.txt        # KeePass, SSH keys, certificates, etc.
├── sensitive_content.txt       # Files with passwords, API keys, etc.
├── interesting_filenames.txt   # Files with suspicious names
└── all_findings.csv           # CSV for sorting/filtering
```

### Step 4: Unmount the Share

```bash
# Unmount when done
sudo umount /mnt/share
```

## Command Line Options

```
usage: sensitive_scanner.py [-h] [-o OUTPUT] [--max-depth MAX_DEPTH] mount_point

positional arguments:
  mount_point           Path to mounted share (e.g., /mnt/share)

optional arguments:
  -h, --help            Show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output directory for results (default: auto-generated)
  --max-depth MAX_DEPTH
                        Maximum directory depth to scan (default: 10)
```

## What It Detects

### High-Value Files (by filename)

| Category | Patterns |
|----------|----------|
| **Password Databases** | `.kdbx`, `.kdb`, KeePass, LastPass, 1Password files |
| **SSH Keys** | `id_rsa`, `id_dsa`, `id_ecdsa`, `.pem`, `.key`, `.ppk` |
| **Certificates** | `.pfx`, `.p12`, `.crt`, `.cer` |
| **Config Files** | `web.config`, `app.config`, `.env`, `appsettings.json` |
| **RDP Files** | `.rdp` (Remote Desktop connections) |
| **VPN Files** | `.ovpn`, VPN config files |
| **Backups** | `.bak`, `.backup`, `.old`, `.sql` |

### Sensitive Content (by pattern matching)

| Category | Examples |
|----------|----------|
| **Passwords** | `password=`, `pwd=`, `passwd=` |
| **API Keys** | `api_key=`, `apikey=`, `api_secret=` |
| **Tokens** | `token=`, `auth_token=`, `access_token=` |
| **Database Connections** | Connection strings, JDBC URLs, MongoDB URIs |
| **AWS Keys** | `AKIA...`, `aws_access_key_id=`, `aws_secret_access_key=` |
| **Private Keys** | `-----BEGIN PRIVATE KEY-----` |
| **Email Addresses** | `user@example.com` |
| **IP Addresses** | `192.168.1.1` |
| **SSNs** | `123-45-6789` |
| **Credit Cards** | Visa, MasterCard, AmEx patterns |

### Interesting Filenames (by keywords)

Files containing: `password`, `passwd`, `pwd`, `credential`, `secret`, `private`, `confidential`, `admin`, `root`, `backup`, `dump`, `export`, `api_key`, `apikey`, `token`, `vpn`, `ssh`, `key`, `cert`, `certificate`

## Output Files Explained

### summary.txt
Overall statistics and findings count by category
```
Sensitive File Scan Results
======================================================================

Scan Location: /mnt/hr
Scan Time: 2024-02-16 14:30:22

Statistics:
  Files Scanned: 1,847
  Directories Scanned: 234
  Data Scanned: 145.3 MB
  Sensitive Files: 23
  High-Value Files: 8
  Errors: 2

Findings by Category:
  High-Value File: 8
  Sensitive Content: 15
  Interesting Filename: 12
```

### high_value_files.txt
Critical files like password databases, SSH keys, certificates
```
Category: SSH Keys
File: /mnt/hr/IT/backups/server_backup/id_rsa
Reason: Matched pattern: ^id_rsa$
----------------------------------------------------------------------

Category: Password Databases
File: /mnt/hr/managers/passwords.kdbx
Reason: Matched pattern: \.kdbx$
```

### sensitive_content.txt
Files containing passwords, API keys, and other secrets
```
======================================================================
FILE: /mnt/hr/config/database.yml
======================================================================

  Category: Passwords
  Line: 12
  Match: password=Admin123!
  Context: production:
    host: db.corp.local
    password=Admin123!
    database: hrdb
  --------------------------------------------------------------------

  Category: Database Connections
  Line: 15
  Match: mysql://root:pass@localhost/hrdb
  Context: backup_connection: mysql://root:pass@localhost/hrdb
```

### interesting_filenames.txt
Files with suspicious or interesting names
```
/mnt/hr/docs/admin_passwords.txt
  Keyword: password

/mnt/hr/IT/vpn_config.conf
  Keyword: vpn
```

### all_findings.csv
All findings in CSV format for easy filtering/sorting in Excel
```csv
Type,Category,File,Details
"High-Value File","SSH Keys","/mnt/hr/IT/id_rsa","Matched pattern: ^id_rsa$"
"Sensitive Content","Passwords","/mnt/hr/config/app.config","Line 45: password=Secret123"
```

## Complete Workflow Example

### Scenario: Scanning HR department share

```bash
# 1. Create mount point
sudo mkdir -p /mnt/hr

# 2. Mount the share
sudo mount -t cifs //fileserver/HR /mnt/hr \
  -o username=auditor,password=AuditPass2024,domain=CORP,ro

# 3. Verify mount
ls /mnt/hr

# 4. Run the scanner
python3 sensitive_scanner.py /mnt/hr -o hr_audit_2024

# 5. Review results
cat hr_audit_2024/summary.txt
cat hr_audit_2024/high_value_files.txt

# 6. Open CSV in Excel for detailed analysis
libreoffice hr_audit_2024/all_findings.csv

# 7. Unmount when done
sudo umount /mnt/hr
```

## Troubleshooting

### Mount Issues

**Problem: "mount error(13): Permission denied"**
```bash
# Solution: Verify credentials
sudo mount -t cifs //server/share /mnt/share \
  -o username=USER,password=PASS,domain=DOMAIN
```

**Problem: "mount error(2): No such file or directory"**
```bash
# Solution: Create mount point first
sudo mkdir -p /mnt/share
```

**Problem: "mount error(112): Host is down"**
```bash
# Solution: Verify server is reachable
ping server
# Check SMB ports
nmap -p 445,139 server
```

**Problem: "mount error(5): Input/output error"**
```bash
# Solution: Try specifying SMB version
sudo mount -t cifs //server/share /mnt/share \
  -o username=USER,password=PASS,vers=3.0
```

### Scanner Issues

**Problem: "Error: Mount point does not exist"**
```bash
# Solution: Verify the mount point exists
ls -la /mnt/share
```

**Problem: Scanner is slow**
```bash
# Solution: Reduce max depth or skip large directories
python3 sensitive_scanner.py /mnt/share --max-depth 5
```

**Problem: Permission denied on certain files**
```bash
# Normal - scanner will skip these and continue
# Check summary.txt for error count
```

## Security Considerations

### Legal and Ethical Use
- ⚠️ **Only scan shares you own or have explicit permission to audit**
- This tool is for authorized security assessments and compliance audits
- Unauthorized access is illegal

### Best Practices

1. **Use read-only mounts** when possible:
   ```bash
   sudo mount -t cifs //server/share /mnt/share -o username=user,password=pass,ro
   ```

2. **Protect credentials file**:
   ```bash
   chmod 600 ~/.smbcreds
   ```

3. **Run as non-root** (after mounting):
   ```bash
   # Mount as root
   sudo mount -t cifs //server/share /mnt/share -o username=user,password=pass,uid=1000
   
   # Scan as regular user
   python3 sensitive_scanner.py /mnt/share
   ```

4. **Secure scan results**:
   ```bash
   chmod 700 scan_results_*
   ```

5. **Clean up after scanning**:
   ```bash
   # Unmount
   sudo umount /mnt/share
   
   # Securely delete results if needed
   shred -vfz -n 3 scan_results_*/sensitive_content.txt
   ```

### Operational Security

- Scanner generates **file access logs** on the server
- Mount operations are **logged in system logs**
- Consider scanning during **maintenance windows**
- Use **service accounts** rather than personal credentials
- **Document all scanning activity** for compliance

## Performance Tips

1. **Limit recursion depth** for faster scans:
   ```bash
   python3 sensitive_scanner.py /mnt/share --max-depth 5
   ```

2. **Scan specific subdirectories**:
   ```bash
   python3 sensitive_scanner.py /mnt/share/configs
   ```

3. **Use SSD for mount point** if possible

4. **Scan during off-hours** to reduce network impact

## Advanced Usage

### Scanning Multiple Shares Sequentially

```bash
#!/bin/bash
# scan_all_shares.sh

SHARES=("HR" "Finance" "IT" "Legal")
SERVER="fileserver.corp.local"
USERNAME="auditor"
PASSWORD="AuditPass"

for SHARE in "${SHARES[@]}"; do
    echo "Scanning $SHARE..."
    
    # Create mount point
    sudo mkdir -p "/mnt/$SHARE"
    
    # Mount
    sudo mount -t cifs "//$SERVER/$SHARE" "/mnt/$SHARE" \
        -o username=$USERNAME,password=$PASSWORD,ro
    
    # Scan
    python3 sensitive_scanner.py "/mnt/$SHARE" -o "results_$SHARE"
    
    # Unmount
    sudo umount "/mnt/$SHARE"
done

echo "All scans complete!"
```

### Filtering CSV Results

```bash
# Find all password files
grep "Password" scan_results_*/all_findings.csv

# Find all .env files with secrets
grep "\.env" scan_results_*/all_findings.csv

# Count findings by type
cut -d',' -f1 scan_results_*/all_findings.csv | sort | uniq -c
```

## Customization

The scanner can be customized by editing `sensitive_scanner.py`:

### Add Custom Patterns

```python
# Around line 119 in setup_patterns()
self.content_patterns = {
    'Custom Secrets': [
        (r'my_app_key\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', re.IGNORECASE),
    ],
    # ... existing patterns
}
```

### Add File Extensions

```python
# Around line 168
self.scannable_extensions = {
    '.txt', '.log', '.myext',  # Add your extension
    # ... existing extensions
}
```

### Adjust File Size Limit

```python
# Around line 178
self.max_file_size = 50 * 1024 * 1024  # 50 MB instead of 10 MB
```

## Comparison to Other Tools

| Feature | This Tool | smbmap | enum4linux |
|---------|-----------|--------|------------|
| Requires mounting | ✅ Yes | ❌ No | ❌ No |
| Content scanning | ✅ Yes | ⚠️ Limited | ❌ No |
| Real-time progress | ✅ Yes | ❌ No | ❌ No |
| Multiple report formats | ✅ Yes | ⚠️ Limited | ⚠️ Limited |
| Customizable patterns | ✅ Easy | ❌ No | ❌ No |
| Cross-platform | ⚠️ Linux only | ✅ Yes | ✅ Yes |

## License

This tool is provided for educational and authorized security testing purposes only.

## Support

For issues or questions:
1. Check the Troubleshooting section
2. Review the output in `summary.txt`
3. Check system logs: `dmesg | tail` and `/var/log/syslog`
