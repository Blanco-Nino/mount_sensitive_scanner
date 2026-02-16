#!/usr/bin/env python3
"""
SMB Share Sensitive File Scanner
Scans mounted shares for passwords, credentials, and sensitive data
Shows real-time progress and detailed findings
"""

import os
import re
import sys
import time
import mimetypes
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import threading
from concurrent.futures import ThreadPoolExecutor

class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[1;37m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class SensitiveScanner:
    def __init__(self, mount_point, output_dir=None):
        self.mount_point = Path(mount_point)
        self.output_dir = Path(output_dir) if output_dir else Path(f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.output_dir.mkdir(exist_ok=True)
        
        # Statistics
        self.stats = {
            'files_scanned': 0,
            'dirs_scanned': 0,
            'bytes_scanned': 0,
            'sensitive_files': 0,
            'high_value_files': 0,
            'errors': 0
        }
        
        # Results
        self.findings = defaultdict(list)
        
        # Patterns for sensitive data
        self.setup_patterns()
        
        # Lock for thread-safe updates
        self.lock = threading.Lock()
        
        # Status display
        self.last_update = time.time()
        
        # Progress bar (set during scan)
        self.total_bytes = 0
        self.total_files = 0
        
    def _get_total_size(self, max_depth=10, use_threading=True):
        """Pre-scan directory to get total file count and total bytes for progress bar.
        Uses os.scandir() for faster traversal and optional threading for parallel stat calls.
        """
        total_files = 0
        total_bytes = 0
        
        def scan_directory(path, current_depth=0):
            """Recursively scan directory using os.scandir() for better performance."""
            nonlocal total_files, total_bytes
            
            if current_depth > max_depth:
                return
            
            try:
                with os.scandir(path) as entries:
                    # Collect files and subdirs
                    files_to_stat = []
                    subdirs = []
                    
                    for entry in entries:
                        if entry.is_file(follow_symlinks=False):
                            files_to_stat.append(entry)
                        elif entry.is_dir(follow_symlinks=False):
                            subdirs.append((entry.path, current_depth + 1))
                    
                    # Stat files (can be parallelized)
                    if use_threading and len(files_to_stat) > 10:
                        # Use threading for directories with many files
                        def stat_file(entry):
                            try:
                                stat_info = entry.stat(follow_symlinks=False)
                                return 1, stat_info.st_size
                            except (OSError, PermissionError):
                                return 0, 0
                        
                        with ThreadPoolExecutor(max_workers=min(8, len(files_to_stat))) as executor:
                            results = executor.map(stat_file, files_to_stat)
                            for count, size in results:
                                total_files += count
                                total_bytes += size
                    else:
                        # Sequential for small directories
                        for entry in files_to_stat:
                            try:
                                stat_info = entry.stat(follow_symlinks=False)
                                total_files += 1
                                total_bytes += stat_info.st_size
                            except (OSError, PermissionError):
                                pass
                    
                    # Recurse into subdirectories
                    for subdir_path, next_depth in subdirs:
                        scan_directory(subdir_path, next_depth)
                        
            except (PermissionError, OSError):
                pass
        
        scan_directory(str(self.mount_point))
        return total_files, total_bytes
        
    def setup_patterns(self):
        """Define patterns for sensitive data detection"""
        
        # High-value filename patterns (automatically flagged)
        self.high_value_filenames = {
            'Password Databases': [
                r'\.kdbx$', r'\.kdb$', r'keepass', r'lastpass', r'1password'
            ],
            'SSH Keys': [
                r'^id_rsa$', r'^id_dsa$', r'^id_ecdsa$', r'^id_ed25519$',
                r'\.pem$', r'\.key$', r'\.ppk$', r'private.*key'
            ],
            'Certificate Files': [
                r'\.pfx$', r'\.p12$', r'\.crt$', r'\.cer$'
            ],
            'Config Files': [
                r'web\.config$', r'app\.config$', r'database\.yml$',
                r'\.env$', r'\.env\..*$', r'appsettings\.json$',
                r'connectionstrings\.config$', r'settings\.xml$'
            ],
            'RDP Files': [
                r'\.rdp$'
            ],
            'VPN Files': [
                r'\.ovpn$', r'\.conf$'
            ],
            'Backup Files': [
                r'\.bak$', r'\.backup$', r'\.old$', r'\.sql$'
            ]
        }
        
        # Keywords in filenames
        self.filename_keywords = [
            'password', 'passwd', 'pwd', 'credential', 'secret',
            'private', 'confidential', 'admin', 'root', 'backup',
            'dump', 'export', 'api_key', 'apikey', 'token',
            'vpn', 'ssh', 'key', 'cert', 'certificate'
        ]
        
        # Content patterns (regex)
        self.content_patterns = {
            'Passwords': [
                (r'password\s*[=:]\s*["\']?([^"\'\s]{4,})["\']?', re.IGNORECASE),
                (r'passwd\s*[=:]\s*["\']?([^"\'\s]{4,})["\']?', re.IGNORECASE),
                (r'pwd\s*[=:]\s*["\']?([^"\'\s]{4,})["\']?', re.IGNORECASE),
                (r'pass\s*[=:]\s*["\']?([^"\'\s]{4,})["\']?', re.IGNORECASE),
            ],
            'API Keys': [
                (r'api[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', re.IGNORECASE),
                (r'apikey\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', re.IGNORECASE),
                (r'api[_-]?secret\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', re.IGNORECASE),
            ],
            'Tokens': [
                (r'token\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,})["\']?', re.IGNORECASE),
                (r'auth[_-]?token\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,})["\']?', re.IGNORECASE),
                (r'access[_-]?token\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,})["\']?', re.IGNORECASE),
            ],
            'Database Connections': [
                (r'connection\s*string\s*[=:]\s*["\']?([^"\']{10,})["\']?', re.IGNORECASE),
                (r'connectionstring\s*[=:]\s*["\']?([^"\']{10,})["\']?', re.IGNORECASE),
                (r'jdbc:[^"\'\s]+', re.IGNORECASE),
                (r'mongodb://[^\s"\']+', re.IGNORECASE),
                (r'mysql://[^\s"\']+', re.IGNORECASE),
                (r'postgresql://[^\s"\']+', re.IGNORECASE),
            ],
            'AWS Keys': [
                (r'AKIA[0-9A-Z]{16}', 0),  # AWS Access Key
                (r'aws_access_key_id\s*[=:]\s*["\']?([A-Z0-9]{20})["\']?', re.IGNORECASE),
                (r'aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', re.IGNORECASE),
            ],
            'Private Keys': [
                (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 0),
            ],
            'Email Addresses': [
                (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 0),
            ],
            'IP Addresses': [
                (r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', 0),
            ],
            'Social Security Numbers': [
                (r'\b\d{3}-\d{2}-\d{4}\b', 0),
                (r'\bSSN\s*[=:]\s*\d{3}-?\d{2}-?\d{4}\b', re.IGNORECASE),
            ],
            'Credit Cards': [
                (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b', 0),
            ],
        }
        
        # File extensions to scan content
        self.scannable_extensions = {
            '.txt', '.log', '.ini', '.conf', '.config', '.xml', '.json', '.yml', '.yaml',
            '.properties', '.env', '.sql', '.sh', '.bat', '.ps1', '.cmd',
            '.py', '.js', '.java', '.cs', '.php', '.rb', '.go', '.cpp', '.c', '.h',
            '.html', '.htm', '.asp', '.aspx', '.jsp',
            '.cfg', '.cnf', '.conf', '.settings', '.prefs',
            '.bak', '.backup', '.old'
        }
        
        # Max file size to scan (10 MB)
        self.max_file_size = 10 * 1024 * 1024
    
    def is_text_file(self, filepath):
        """Check if file is likely text"""
        ext = filepath.suffix.lower()
        if ext in self.scannable_extensions:
            return True
        
        # Try to detect by MIME type
        mime, _ = mimetypes.guess_type(str(filepath))
        if mime and mime.startswith('text/'):
            return True
        
        return False
    
    def check_filename(self, filepath):
        """Check if filename matches sensitive patterns"""
        filename = filepath.name.lower()
        findings = []
        
        # Check high-value patterns
        for category, patterns in self.high_value_filenames.items():
            for pattern in patterns:
                if re.search(pattern, filename, re.IGNORECASE):
                    findings.append({
                        'type': 'High-Value File',
                        'category': category,
                        'pattern': pattern,
                        'file': str(filepath),
                        'reason': f'Filename matches {category} pattern'
                    })
                    with self.lock:
                        self.stats['high_value_files'] += 1
        
        # Check filename keywords
        for keyword in self.filename_keywords:
            if keyword in filename:
                findings.append({
                    'type': 'Interesting Filename',
                    'category': 'Keyword Match',
                    'keyword': keyword,
                    'file': str(filepath),
                    'reason': f'Filename contains "{keyword}"'
                })
        
        return findings
    
    def scan_file_content(self, filepath):
        """Scan file content for sensitive data"""
        findings = []
        
        # Check file size
        try:
            file_size = filepath.stat().st_size
            if file_size > self.max_file_size:
                return []  # Skip large files
            
            if file_size == 0:
                return []  # Skip empty files
        except:
            return []
        
        # Read file content
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(100000)  # Read first 100KB
        except Exception as e:
            return []
        
        # Search for patterns
        for category, patterns in self.content_patterns.items():
            for pattern, flags in patterns:
                try:
                    matches = re.finditer(pattern, content, flags)
                    for match in matches:
                        # Limit matches per category per file
                        category_matches = [f for f in findings if f['category'] == category]
                        if len(category_matches) >= 5:
                            break
                        
                        # Get context (line containing match)
                        match_pos = match.start()
                        line_start = content.rfind('\n', 0, match_pos) + 1
                        line_end = content.find('\n', match_pos)
                        if line_end == -1:
                            line_end = len(content)
                        context = content[line_start:line_end].strip()
                        
                        # Truncate context if too long
                        if len(context) > 200:
                            context = context[:200] + "..."
                        
                        findings.append({
                            'type': 'Sensitive Content',
                            'category': category,
                            'file': str(filepath),
                            'match': match.group(0)[:100],  # Truncate match
                            'context': context,
                            'line': content[:match_pos].count('\n') + 1
                        })
                        
                        with self.lock:
                            self.stats['sensitive_files'] += 1
                except Exception as e:
                    pass
        
        return findings
    
    def _progress_bar(self):
        """Build progress bar string from bytes_scanned / total_bytes."""
        bar_width = 30
        if self.total_bytes <= 0:
            bar = "-" * bar_width
            return f"[{Colors.CYAN}{bar}{Colors.RESET}] 0.0% (0.0 / 0.0 MB)"
        pct = min(100.0, 100.0 * self.stats['bytes_scanned'] / self.total_bytes)
        filled = int(bar_width * pct / 100)
        bar = "=" * filled + "-" * (bar_width - filled)
        scanned_mb = self.stats['bytes_scanned'] / (1024 * 1024)
        total_mb = self.total_bytes / (1024 * 1024)
        return (
            f"[{Colors.GREEN}{bar[:filled]}{Colors.RESET}{Colors.CYAN}{bar[filled:]}{Colors.RESET}] "
            f"{pct:5.1f}% ({scanned_mb:.1f} / {total_mb:.1f} MB)"
        )
    
    def update_status(self, current_file=""):
        """Update status display"""
        now = time.time()
        if now - self.last_update < 0.5:  # Update every 0.5 seconds
            return
        
        self.last_update = now
        
        # Calculate stats
        mb_scanned = self.stats['bytes_scanned'] / (1024 * 1024)
        
        # Progress bar (overall)
        progress = self._progress_bar()
        
        # Print status
        status = (
            f"\r{Colors.CYAN}[SCANNING]{Colors.RESET} "
            f"{progress} | "
            f"Files: {Colors.YELLOW}{self.stats['files_scanned']}{Colors.RESET}/{self.total_files} | "
            f"Sensitive: {Colors.RED}{self.stats['sensitive_files']}{Colors.RESET} | "
            f"High-Value: {Colors.GREEN}{self.stats['high_value_files']}{Colors.RESET}"
        )
        
        if current_file:
            # Truncate long filenames
            if len(current_file) > 50:
                current_file = "..." + current_file[-47:]
            status += f" | {Colors.BLUE}{current_file}{Colors.RESET}"
        
        sys.stdout.write(status)
        sys.stdout.flush()
    
    def scan_directory(self, max_depth=10):
        """Recursively scan directory"""
        print(f"{Colors.BOLD}Starting scan of: {self.mount_point}{Colors.RESET}\n")
        
        # Pre-scan to get total size for progress bar
        print(f"{Colors.CYAN}[*] Calculating total size...{Colors.RESET}")
        self.total_files, self.total_bytes = self._get_total_size(max_depth)
        total_mb = self.total_bytes / (1024 * 1024)
        print(f"{Colors.CYAN}[*] Found {self.total_files} files ({total_mb:.1f} MB). Starting scan.{Colors.RESET}\n")
        
        for root, dirs, files in os.walk(self.mount_point):
            # Check depth
            depth = str(root).count(os.sep) - str(self.mount_point).count(os.sep)
            if depth > max_depth:
                dirs.clear()  # Don't recurse deeper
                continue
            
            with self.lock:
                self.stats['dirs_scanned'] += 1
            
            # Scan files in directory
            for filename in files:
                filepath = Path(root) / filename
                
                try:
                    # Update stats
                    with self.lock:
                        self.stats['files_scanned'] += 1
                        try:
                            self.stats['bytes_scanned'] += filepath.stat().st_size
                        except:
                            pass
                    
                    # Update status display
                    self.update_status(filename)
                    
                    # Check filename
                    filename_findings = self.check_filename(filepath)
                    for finding in filename_findings:
                        self.findings[finding['type']].append(finding)
                    
                    # Check content if text file
                    if self.is_text_file(filepath):
                        content_findings = self.scan_file_content(filepath)
                        for finding in content_findings:
                            self.findings[finding['type']].append(finding)
                
                except Exception as e:
                    with self.lock:
                        self.stats['errors'] += 1
        
        # Clear status line
        sys.stdout.write('\r' + ' ' * 150 + '\r')
        sys.stdout.flush()
    
    def save_results(self):
        """Save results to files"""
        print(f"\n{Colors.CYAN}[*] Saving results to: {self.output_dir}/{Colors.RESET}")
        
        # Summary file
        with open(self.output_dir / 'summary.txt', 'w') as f:
            f.write(f"Sensitive File Scan Results\n")
            f.write(f"{'='*70}\n\n")
            f.write(f"Scan Location: {self.mount_point}\n")
            f.write(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"Statistics:\n")
            f.write(f"  Files Scanned: {self.stats['files_scanned']}\n")
            f.write(f"  Directories Scanned: {self.stats['dirs_scanned']}\n")
            f.write(f"  Data Scanned: {self.stats['bytes_scanned'] / (1024*1024):.1f} MB\n")
            f.write(f"  Sensitive Files: {self.stats['sensitive_files']}\n")
            f.write(f"  High-Value Files: {self.stats['high_value_files']}\n")
            f.write(f"  Errors: {self.stats['errors']}\n\n")
            
            f.write(f"Findings by Category:\n")
            for finding_type, items in self.findings.items():
                f.write(f"  {finding_type}: {len(items)}\n")
        
        # High-value files
        if 'High-Value File' in self.findings:
            with open(self.output_dir / 'high_value_files.txt', 'w') as f:
                f.write(f"High-Value Files Found\n")
                f.write(f"{'='*70}\n\n")
                for item in self.findings['High-Value File']:
                    f.write(f"Category: {item['category']}\n")
                    f.write(f"File: {item['file']}\n")
                    f.write(f"Reason: {item['reason']}\n")
                    f.write(f"{'-'*70}\n\n")
        
        # Sensitive content
        if 'Sensitive Content' in self.findings:
            with open(self.output_dir / 'sensitive_content.txt', 'w') as f:
                f.write(f"Files with Sensitive Content\n")
                f.write(f"{'='*70}\n\n")
                
                # Group by file
                by_file = defaultdict(list)
                for item in self.findings['Sensitive Content']:
                    by_file[item['file']].append(item)
                
                for filepath, items in sorted(by_file.items()):
                    f.write(f"\n{'='*70}\n")
                    f.write(f"FILE: {filepath}\n")
                    f.write(f"{'='*70}\n\n")
                    
                    for item in items:
                        f.write(f"  Category: {item['category']}\n")
                        f.write(f"  Line: {item['line']}\n")
                        f.write(f"  Match: {item['match']}\n")
                        f.write(f"  Context: {item['context']}\n")
                        f.write(f"  {'-'*68}\n\n")
        
        # Interesting filenames
        if 'Interesting Filename' in self.findings:
            with open(self.output_dir / 'interesting_filenames.txt', 'w') as f:
                f.write(f"Interesting Filenames\n")
                f.write(f"{'='*70}\n\n")
                for item in self.findings['Interesting Filename']:
                    f.write(f"{item['file']}\n")
                    f.write(f"  Keyword: {item['keyword']}\n\n")
        
        # Create CSV for easy sorting/filtering
        with open(self.output_dir / 'all_findings.csv', 'w') as f:
            f.write("Type,Category,File,Details\n")
            for finding_type, items in self.findings.items():
                for item in items:
                    file_path = item.get('file', '')
                    category = item.get('category', '')
                    
                    if finding_type == 'Sensitive Content':
                        details = f"Line {item['line']}: {item['match']}"
                    elif finding_type == 'High-Value File':
                        details = item['reason']
                    else:
                        details = item.get('keyword', '')
                    
                    # Escape quotes in CSV
                    details = details.replace('"', '""')
                    f.write(f'"{finding_type}","{category}","{file_path}","{details}"\n')
    
    def print_summary(self):
        """Print summary to console"""
        print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}Scan Complete!{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.CYAN}Statistics:{Colors.RESET}")
        print(f"  Files Scanned: {Colors.YELLOW}{self.stats['files_scanned']}{Colors.RESET}")
        print(f"  Directories: {Colors.YELLOW}{self.stats['dirs_scanned']}{Colors.RESET}")
        print(f"  Data Scanned: {Colors.YELLOW}{self.stats['bytes_scanned'] / (1024*1024):.1f} MB{Colors.RESET}")
        print(f"  Sensitive Files: {Colors.RED}{self.stats['sensitive_files']}{Colors.RESET}")
        print(f"  High-Value Files: {Colors.GREEN}{self.stats['high_value_files']}{Colors.RESET}")
        print(f"  Errors: {Colors.YELLOW}{self.stats['errors']}{Colors.RESET}\n")
        
        print(f"{Colors.CYAN}Findings:{Colors.RESET}")
        for finding_type, items in sorted(self.findings.items()):
            print(f"  {finding_type}: {Colors.YELLOW}{len(items)}{Colors.RESET}")
        
        print(f"\n{Colors.CYAN}Results saved to: {Colors.YELLOW}{self.output_dir}/{Colors.RESET}\n")
        
        # Show top findings
        if 'High-Value File' in self.findings:
            print(f"{Colors.RED}{Colors.BOLD}🔥 HIGH-VALUE FILES (Top 10):{Colors.RESET}")
            for item in self.findings['High-Value File'][:10]:
                print(f"  {Colors.GREEN}[{item['category']}]{Colors.RESET} {item['file']}")
            print()
        
        if 'Sensitive Content' in self.findings:
            print(f"{Colors.RED}{Colors.BOLD}🔐 SENSITIVE CONTENT (Top 10 files):{Colors.RESET}")
            # Group by file
            by_file = defaultdict(list)
            for item in self.findings['Sensitive Content']:
                by_file[item['file']].append(item['category'])
            
            for filepath, categories in sorted(by_file.items())[:10]:
                unique_cats = set(categories)
                cats_str = ", ".join(unique_cats)
                print(f"  {Colors.YELLOW}{filepath}{Colors.RESET}")
                print(f"    Categories: {cats_str}")
            print()


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Scan mounted SMB share for sensitive files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s /mnt/share
  %(prog)s /mnt/share -o results_hr
  %(prog)s /mnt/share --max-depth 5
  
After mounting a share:
  mount -t cifs //172.23.8.198/hr /mnt/hr -o username=user,password=pass
  %(prog)s /mnt/hr
        '''
    )
    
    parser.add_argument('mount_point', help='Path to mounted share')
    parser.add_argument('-o', '--output', help='Output directory for results')
    parser.add_argument('--max-depth', type=int, default=10, 
                       help='Maximum directory depth to scan (default: 10)')
    
    args = parser.parse_args()
    
    # Validate mount point
    mount_point = Path(args.mount_point)
    if not mount_point.exists():
        print(f"{Colors.RED}Error: Mount point does not exist: {mount_point}{Colors.RESET}")
        sys.exit(1)
    
    if not mount_point.is_dir():
        print(f"{Colors.RED}Error: Not a directory: {mount_point}{Colors.RESET}")
        sys.exit(1)
    
    # Create scanner
    scanner = SensitiveScanner(mount_point, args.output)
    
    # Run scan
    try:
        scanner.scan_directory(max_depth=args.max_depth)
        scanner.save_results()
        scanner.print_summary()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Scan interrupted by user{Colors.RESET}")
        print(f"{Colors.CYAN}Saving partial results...{Colors.RESET}")
        scanner.save_results()
        scanner.print_summary()
    except Exception as e:
        print(f"\n{Colors.RED}Error during scan: {e}{Colors.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
