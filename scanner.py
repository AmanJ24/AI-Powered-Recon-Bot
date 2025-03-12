#!/usr/bin/env python3
import json
import argparse
import subprocess
import time
import os
import sys
import shutil
import socket
import ipaddress
from importlib import util
import traceback
from typing import Dict, List, Any, Optional, Tuple, Union
from pathlib import Path

# Initialize dependency check results
DEPENDENCIES = {
    "requests": False,
    "matplotlib": False,
    "python-nmap": False,
    "openai": False,
    "sublist3r": False,
}

# Default command timeout (seconds)
CMD_TIMEOUT = 300

# Function to print colored messages
def print_info(message: str) -> None:
    print(f"\033[94m[INFO]\033[0m {message}")

def print_success(message: str) -> None:
    print(f"\033[92m[+]\033[0m {message}")

def print_warning(message: str) -> None:
    print(f"\033[93m[!]\033[0m {message}")

def print_error(message: str) -> None:
    print(f"\033[91m[ERROR]\033[0m {message}")

def print_progress(message: str) -> None:
    print_success(message)
    time.sleep(0.5)  # Less sleep for better user experience

# Function to find an executable in PATH and common installation locations
def find_executable(executable_name: str) -> Optional[str]:
    """
    Find an executable by checking:
    1. System PATH (using shutil.which)
    2. Common installation locations
    
    Returns the path to the executable if found, None otherwise.
    """
    # First, check in the system PATH
    executable_path = shutil.which(executable_name)
    if executable_path:
        return executable_path
    
    # Common installation locations to check
    common_locations = [
        Path.home() / ".local" / "bin",          # ~/.local/bin
        Path("/usr/local/bin"),                  # /usr/local/bin
        Path.home() / "bin",                     # ~/bin
        Path("/opt/local/bin"),                  # /opt/local/bin
        Path("/usr/bin"),                        # /usr/bin
        Path.home() / "go" / "bin",              # ~/go/bin (for Go-based tools)
        Path(os.getcwd())                        # Current directory
    ]
    
    # Check each location
    for location in common_locations:
        executable_path = location / executable_name
        if executable_path.exists() and os.access(executable_path, os.X_OK):
            return str(executable_path)
    
    # If not found anywhere
    return None

# Check for required dependencies
def check_dependencies() -> None:
    # Check for requests
    try:
        import requests
        DEPENDENCIES["requests"] = True
        print_success("requests module is installed.")
    except ImportError:
        print_error("requests module is not installed. Install it with: pip install requests")

    # Check for matplotlib
    try:
        import matplotlib.pyplot as plt
        DEPENDENCIES["matplotlib"] = True
        print_success("matplotlib module is installed.")
    except ImportError:
        print_warning("matplotlib module is not installed. Visualization features will be disabled.")
        print_info("To install matplotlib: pip install matplotlib")

    # Check for python-nmap
    try:
        import nmap
        DEPENDENCIES["python-nmap"] = True
        print_success("python-nmap module is installed.")
    except ImportError:
        print_warning("python-nmap module is not installed. Port scanning features will be disabled.")
        print_info("To install python-nmap: pip install python-nmap")

    # Check for OpenAI
    try:
        import openai
        DEPENDENCIES["openai"] = True
        print_success("openai module is installed.")
    except ImportError:
        print_warning("openai module is not installed. AI analysis features will be disabled.")
        print_info("To install openai: pip install openai")

    # Check for sublist3r (optional)
    try:
        import sublist3r
        DEPENDENCIES["sublist3r"] = True
        print_success("sublist3r module is installed.")
    except ImportError:
        print_warning("sublist3r module is not installed. Subdomain enumeration will use alternative methods.")
        print_info("To install sublist3r: pip install sublist3r")

    # Check for command-line tools
    for cmd in ["sqlmap", "nikto"]:
        if shutil.which(cmd):
            print_success(f"{cmd} is installed.")
        else:
            print_warning(f"{cmd} is not installed or not in PATH. Related features will be disabled.")

    # Check for subzy (optional)
    if find_executable("subzy"):
        print_success("subzy is installed.")
    else:
        print_warning("subzy is not installed. Subdomain takeover checks will be disabled.")

# Load config for API keys
def load_config() -> Tuple[str, str, str]:
    try:
        from config import VIRUSTOTAL_API_KEY, SHODAN_API_KEY, OPENAI_API_KEY
        print_success("API keys loaded from config file")
        return VIRUSTOTAL_API_KEY, SHODAN_API_KEY, OPENAI_API_KEY
    except ImportError:
        # If config file doesn't exist, create it with empty keys
        print_warning("config.py not found. Creating a template config file...")
        with open("config.py", "w") as config_file:
            config_file.write("""# API Configuration File
# Replace with your actual API keys

VIRUSTOTAL_API_KEY = ""
SHODAN_API_KEY = ""
OPENAI_API_KEY = ""
""")
        print_warning("Please edit config.py with your API keys before running the script again.")
        return "", "", ""


# Function to get subdomains using either sublist3r or manual methods
def get_subdomains(domain: str) -> List[str]:
    print_progress(f"Enumerating subdomains for {domain}...")
    subdomains = []
    
    # Try using sublist3r if installed
    try:
        import sublist3r
        print_info("Using sublist3r for subdomain enumeration")
        
        # Initial attempt with all engines
        try:
            print_info("Running sublist3r with all search engines...")
            subdomains = sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
            print_success(f"Found {len(subdomains)} subdomains with sublist3r (all engines)")
            return subdomains
        except IndexError as e:
            print_error(f"IndexError in sublist3r (likely CSRF token extraction failure): {str(e)}")
        print_info("Retrying sublist3r with reduced engines...")
        
        # Retry with specific engines that might be more reliable
        reliable_engines = ['baidu', 'yahoo', 'google', 'bing', 'ask', 'netcraft', 'dnsdumpster', 'virustotal']
        
        # Try with each reliable engine individually to avoid failures
        all_found_subdomains = set()
        for engine in reliable_engines:
            try:
                print_info(f"Trying sublist3r with engine: {engine}")
                engine_subdomains = sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=[engine])
                if engine_subdomains:
                    print_info(f"Found {len(engine_subdomains)} subdomains with engine {engine}")
                    all_found_subdomains.update(engine_subdomains)
            except Exception as inner_e:
                print_warning(f"Error with {engine} engine: {str(inner_e)}")
                
        if all_found_subdomains:
            subdomains = list(all_found_subdomains)
            print_success(f"Found {len(subdomains)} subdomains with sublist3r (reduced engines)")
            return subdomains
        else:
            print_error("Failed with all sublist3r engines")
            print_info("Falling back to alternative methods...")
                
    except Exception as e:
        print_error(f"Error using sublist3r: {str(e)}")
        print_info("Falling back to alternative methods...")
    
    # Alternative method using DNS records
    try:
        # First attempt: Basic DNS A record lookup
        print_info("Using DNS lookup for subdomain enumeration")
        common_subdomains = [
            # Standard subdomains
            "www", "mail", "ftp", "webmail", "login", "admin", "test", "dev", "api", "blog", 
            "shop", "app", "mobile", "m", "secure", "vpn", "remote", "portal", "cdn", "images", 
            "docs", 
            # Additional common subdomains (at least 30 more)
            "staging", "beta", "alpha", "demo", "sandbox", "auth", "account", "accounts", "billing",
            "store", "download", "downloads", "upload", "media", "video", "videos", "static", "assets",
            "content", "support", "help", "faq", "kb", "wiki", "status", "dashboard", "analytics",
            "metrics", "monitor", "monitoring", "internal", "admin", "administrator", "web", "server",
            "ns1", "ns2", "smtp", "mx", "email", "cloud", "git", "gitlab", "jenkins", "ci", "jira",
            "confluence", "signup", "login", "auth", "sso", "adfs", "ldap", "corp", "intranet", "extranet"
        ]
        
        for sub in common_subdomains:
            try:
                host = f"{sub}.{domain}"
                ip = socket.gethostbyname(host)
                subdomains.append(host)
                print_info(f"Found subdomain: {host} ({ip})")
            except socket.error:
                pass
                
        # Second attempt: If requests is available, try certificate transparency logs
        # Second attempt: If requests is available, try certificate transparency logs and other sources
        if DEPENDENCIES["requests"]:
            print_info("Checking certificate transparency logs and other sources for subdomains")
            import requests
            
            # Create a session for better performance with multiple requests
            session = requests.Session()
            session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})
            
            # List of sources to try
            # List of sources to try
            sources = [
                # 1. crt.sh (Certificate Transparency)
                {
                    "name": "crt.sh",
                    "url": f"https://crt.sh/?q=%.{domain}&output=json",
                    "parser": lambda data: [item.get('name_value', '').lower() for item in data if isinstance(item, dict)]
                },
                # 2. SecurityTrails
                {
                    "name": "SecurityTrails",
                    "url": f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                    "headers": {"apikey": "YOUR_API_KEY"},  # Replace with config.SECURITYTRAILS_API_KEY if available
                    "parser": lambda data: [f"{subdomain}.{domain}" for subdomain in data.get('subdomains', [])]
                },
                # 3. Censys (public interface access)
                {
                    "name": "Censys",
                    "url": f"https://search.censys.io/api/v2/hosts/search",
                    "params": {"q": domain, "per_page": 100},
                    "headers": {"Accept": "application/json"},
                    "parser": lambda data: [result.get('name', '') for result in data.get('result', {}).get('hits', []) if result.get('name', '').endswith(domain)]
                }
            ]
                
            try:
                # Try each source
                for source in sources:
                    try:
                        print_info(f"Checking {source['name']} for subdomains")
                        
                        # Skip SecurityTrails if no API key
                        if source['name'] == "SecurityTrails" and source['headers']['apikey'] == "YOUR_API_KEY":
                            try:
                                from config import SECURITYTRAILS_API_KEY
                                source['headers']['apikey'] = SECURITYTRAILS_API_KEY
                            except (ImportError, AttributeError):
                                print_warning(f"Skipping {source['name']} (no API key)")
                                continue
                        
                        # Make the request
                        if 'params' in source:
                            response = session.get(source['url'], headers=source.get('headers', {}), params=source['params'], timeout=15)
                        else:
                            response = session.get(source['url'], headers=source.get('headers', {}), timeout=15)
                        
                        if response.status_code == 200:
                            try:
                                data = response.json()
                                found_subdomains = source['parser'](data)
                                
                                # Add to main list if not already present
                                for name in found_subdomains:
                                    if name and name.endswith(f".{domain}") and name not in subdomains:
                                        subdomains.append(name)
                                        print_info(f"Found subdomain from {source['name']}: {name}")
                                
                                print_success(f"Found {len(found_subdomains)} potential subdomains from {source['name']}")
                            except json.JSONDecodeError:
                                print_warning(f"Could not parse {source['name']} response")
                            except Exception as e:
                                print_warning(f"Error processing {source['name']} data: {str(e)}")
                        elif response.status_code == 401:
                            print_warning(f"{source['name']} requires authentication or API key")
                        else:
                            print_warning(f"{source['name']} returned status code: {response.status_code}")
                    except Exception as e:
                        print_warning(f"Error checking {source['name']}: {str(e)}")
            except Exception as e:
                print_warning(f"Error checking certificate transparency: {str(e)}")
            
            # Third attempt: DNS brute force with wordlist
            try:
                print_info("Performing DNS brute force subdomain discovery")
                # Option to use a custom wordlist file
                wordlist_file = os.environ.get('SUBDOMAIN_WORDLIST', '')
                use_custom_wordlist = os.path.exists(wordlist_file)
                
                # Create a wordlist from either file or common subdomains
                wordlist = []
                
                if use_custom_wordlist:
                    print_info(f"Using custom wordlist from {wordlist_file}")
                    try:
                        with open(wordlist_file, 'r') as f:
                            wordlist = [line.strip() for line in f if line.strip()]
                        print_info(f"Loaded {len(wordlist)} subdomains from wordlist")
                    except Exception as e:
                        print_warning(f"Error loading wordlist: {str(e)}")
                        use_custom_wordlist = False
                
                # Use the common subdomains list if no custom wordlist
                if not use_custom_wordlist:
                    print_info("Using built-in wordlist for brute forcing")
                    wordlist = common_subdomains
                
                # Limit for demonstration purposes (remove or increase in production)
                max_brute_force = 100  # Safety limit
                if len(wordlist) > max_brute_force:
                    print_warning(f"Limiting brute force to {max_brute_force} entries for performance")
                    wordlist = wordlist[:max_brute_force]
                
                # Ask for confirmation if wordlist is large
                if len(wordlist) > 50:
                    print_warning(f"About to perform DNS lookups for {len(wordlist)} potential subdomains")
                    should_continue = get_user_confirmation("Continue with brute force?")
                    if not should_continue:
                        print_info("DNS brute force skipped by user")
                        wordlist = []
                
                # Perform the brute force
                brute_force_found = 0
                for word in wordlist:
                    try:
                        subdomain = f"{word}.{domain}"
                        if subdomain not in subdomains:  # Skip if already found
                            ip = socket.gethostbyname(subdomain)
                            subdomains.append(subdomain)
                            brute_force_found += 1
                            print_info(f"Brute force found: {subdomain} ({ip})")
                    except socket.error:
                        pass  # Subdomain doesn't resolve
                
                print_success(f"DNS brute force found {brute_force_found} additional subdomains")
            
            except Exception as e:
                print_warning(f"Error during DNS brute force: {str(e)}")
    except Exception as e:
        print_error(f"Error enumerating subdomains: {str(e)}")
    
    # Remove duplicates and sort
    subdomains = sorted(list(set(subdomains)))
    print_success(f"Found {len(subdomains)} subdomains in total")
    return subdomains


# Function to scan ports using nmap
def scan_ports(target: str, scan_intensity: str = 'normal', version_detection: bool = True) -> Dict[int, Dict[str, str]]:
    if not DEPENDENCIES["python-nmap"]:
        print_warning("python-nmap is not installed. Skipping port scan.")
        return {}
    
    print_progress(f"Scanning ports on {target}...")
    try:
        import nmap
        scanner = nmap.PortScanner()
        
        # Check if target is valid
        try:
            socket.gethostbyname(target)  # Validate domain/IP
        except socket.gaierror:
            print_error(f"Invalid target: {target}")
            return {}
        
        # Top 100 common ports to scan (based on nmap's common ports)
        top_ports = "21,22,23,25,26,53,80,81,110,111,113,135,139,143,179,199,443,445,465,514,515,548,554,587,646,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49153,49154,49155,49156,49157,50000,50999,51511,54321,65535"
        
        # Set scan intensity
        scan_speed = '-T2'  # Default (safe) scan speed
        if scan_intensity == 'low':
            scan_speed = '-T1'
            print_info("Using low intensity scan (slower but stealthier)")
        elif scan_intensity == 'normal':
            scan_speed = '-T3'
            print_info("Using normal intensity scan")
        elif scan_intensity == 'aggressive':
            scan_speed = '-T4'
            print_info("Using aggressive scan (faster but noisier)")
        elif scan_intensity == 'insane':
            scan_speed = '-T5'
            print_warning("Using maximum intensity scan (very noisy, might be detected)")
        
        # Build arguments
        arguments = f"{scan_speed}"
        
        # Add version detection if requested
        if version_detection:
            arguments += " -sV"
            print_info("Service version detection enabled")
        
        print_info(f"Scanning top 100 ports (this may take a while)...")
        print_info(f"Using scan arguments: {arguments}")
        
        # Run the scan
        scanner.scan(target, top_ports, arguments=arguments)
        
        open_ports = {}
        if target in scanner.all_hosts():
            for proto in scanner[target].all_protocols():
                ports = sorted(scanner[target][proto].keys())
                for port in ports:
                    state = scanner[target][proto][port]['state']
                    if state == 'open':
                        service_info = {
                            'name': scanner[target][proto][port].get('name', 'unknown'),
                            'product': scanner[target][proto][port].get('product', ''),
                            'version': scanner[target][proto][port].get('version', ''),
                            'extrainfo': scanner[target][proto][port].get('extrainfo', ''),
                            'state': state
                        }
                        
                        open_ports[port] = service_info
                        
                        # Create a formatted service string
                        service_str = service_info['name']
                        if service_info['product']:
                            service_str += f" ({service_info['product']}"
                            if service_info['version']:
                                service_str += f" {service_info['version']}"
                            if service_info['extrainfo']:
                                service_str += f", {service_info['extrainfo']}"
                            service_str += ")"
                            
                        print_info(f"Port {port}/{proto}: {service_str}")
        
        print_success(f"Found {len(open_ports)} open ports")
        return open_ports
    
    except Exception as e:
        print_error(f"Error during port scanning: {str(e)}")
        traceback.print_exc()
        return {}


# Function to check for SQL injection vulnerabilities
def check_sql_injection(target: str) -> Dict[str, Any]:
    print_progress(f"Checking for SQL injection vulnerabilities on {target}...")
    results = {"vulnerable": False, "details": []}
    
    # Check if sqlmap is available
    if not shutil.which("sqlmap"):
        print_warning("sqlmap is not installed. Skipping SQL injection check.")
        return results
    
    try:
        # Prepare the command
        cmd = ["sqlmap", "-u", f"{target}", "--batch", "--level=1", "--risk=1", "--output-dir=sqlmap_output"]
        
        print_info(f"Running sqlmap with command: {' '.join(cmd)}")
        
        # Run sqlmap with timeout
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=CMD_TIMEOUT
        )
        
        # Parse the output
        output = process.stdout
        
        # Check if vulnerabilities were found
        if "is vulnerable" in output:
            results["vulnerable"] = True
            vulnerable_params = []
            for line in output.split('\n'):
                if "Parameter:" in line and "is vulnerable" in line:
                    vulnerable_params.append(line.strip())
            
            results["details"] = vulnerable_params
            print_success(f"SQL injection vulnerabilities found: {len(vulnerable_params)}")
        else:
            print_info("No SQL injection vulnerabilities detected")
        
        return results
    
    except subprocess.TimeoutExpired:
        print_warning(f"SQL injection check timed out after {CMD_TIMEOUT} seconds")
        return {"vulnerable": False, "details": ["Check timed out"]}
    
    except Exception as e:
        print_error(f"Error during SQL injection check: {str(e)}")
        return {"vulnerable": False, "details": [str(e)]}


# Function to scan for web vulnerabilities using nikto
def scan_web_vulnerabilities(target: str) -> Dict[str, Any]:
    print_progress(f"Scanning for web vulnerabilities on {target}...")
    results = {"vulnerable": False, "details": []}
    
    # Check if nikto is available
    if not shutil.which("nikto"):
        print_warning("nikto is not installed. Skipping web vulnerability scan.")
        return results
    
    try:
        # Prepare the command
        cmd = ["nikto", "-h", target, "-Format", "txt"]
        
        print_info(f"Running nikto with command: {' '.join(cmd)}")
        
        # Run nikto with timeout
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=CMD_TIMEOUT
        )
        
        # Parse the output
        output = process.stdout
        vulnerabilities = []
        
        for line in output.split('\n'):
            # Filter for relevant vulnerability information
            if "+ " in line and ("OSVDB-" in line or "warning" in line.lower() or "vulnerability" in line.lower()):
                vulnerabilities.append(line.strip())
        
        if vulnerabilities:
            results["vulnerable"] = True
            results["details"] = vulnerabilities
            print_success(f"Found {len(vulnerabilities)} potential vulnerabilities")
        else:
            print_info("No web vulnerabilities detected")
        
        return results
    
    except subprocess.TimeoutExpired:
        print_warning(f"Web vulnerability scan timed out after {CMD_TIMEOUT} seconds")
        return {"vulnerable": False, "details": ["Check timed out"]}
    
    except Exception as e:
        print_error(f"Error during web vulnerability scan: {str(e)}")
        return {"vulnerable": False, "details": [str(e)]}


# Function to check for subdomain takeover vulnerabilities
def check_subdomain_takeover(subdomains: List[str]) -> Dict[str, Any]:
    print_progress("Checking for subdomain takeover vulnerabilities...")
    results = {"vulnerable": False, "details": []}
    
    # Check if subzy is available
    if not find_executable("subzy"):
        print_warning("subzy is not installed. Skipping subdomain takeover check.")
        return results

    if not subdomains:
        print_warning("No subdomains provided. Skipping subdomain takeover check.")
        return results
    
    try:
        # Create a temporary file with the list of subdomains
        with open("temp_subdomains.txt", "w") as f:
            for subdomain in subdomains:
                f.write(f"{subdomain}\n")
        
        # Prepare the command
        subzy_path = find_executable("subzy")
        cmd = [subzy_path, "run", "--targets", "temp_subdomains.txt", "--concurrency", "10"]
        
        print_info(f"Running subzy with command: {' '.join(cmd)}")
        
        # Run subzy with timeout
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=CMD_TIMEOUT
        )
        
        # Parse the output
        output = process.stdout
        vulnerable_subdomains = []
        
        for line in output.split('\n'):
            if "[Vulnerable]" in line:
                vulnerable_subdomains.append(line.strip())
        
        # Clean up temporary file
        if os.path.exists("temp_subdomains.txt"):
            os.remove("temp_subdomains.txt")
        
        if vulnerable_subdomains:
            results["vulnerable"] = True
            results["details"] = vulnerable_subdomains
            print_success(f"Found {len(vulnerable_subdomains)} vulnerable subdomains")
        else:
            print_info("No subdomain takeover vulnerabilities detected")
        
        return results
    
    except subprocess.TimeoutExpired:
        print_warning(f"Subdomain takeover check timed out after {CMD_TIMEOUT} seconds")
        # Clean up temporary file if it exists
        if os.path.exists("temp_subdomains.txt"):
            os.remove("temp_subdomains.txt")
        return {"vulnerable": False, "details": ["Check timed out"]}
    
    except Exception as e:
        print_error(f"Error during subdomain takeover check: {str(e)}")
        # Clean up temporary file if it exists
        if os.path.exists("temp_subdomains.txt"):
            os.remove("temp_subdomains.txt")
        return {"vulnerable": False, "details": [str(e)]}


# Function to check for CORS misconfigurations
def check_cors_misconfig(target: str) -> Dict[str, Any]:
    print_progress(f"Checking for CORS misconfigurations on {target}...")
    results = {"vulnerable": False, "details": []}
    
    if not DEPENDENCIES["requests"]:
        print_warning("requests module is not installed. Skipping CORS misconfiguration check.")
        return results
    
    try:
        import requests
        
        # Normalize the target URL
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        # List of test origins to check
        test_origins = [
            "https://evil.com",               # Different domain
            "https://attacker.evil.com",      # Subdomain of evil.com
            "null",                           # Special null origin
            f"https://{target}.evil.com",     # Target as subdomain of evil.com
            "https://evil.com:123",           # Different port
            f"https://{target}evil.com",      # Target prepended to evil.com
            "*"                               # Wildcard (very bad practice)
        ]
        
        vulnerable_origins = []
        
        # Create a session for better performance
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        print_info(f"Testing {len(test_origins)} different origin headers...")
        
        for origin in test_origins:
            try:
                # Set the Origin header for this request
                session.headers.update({'Origin': origin})
                
                # Make the request to the target
                response = session.get(target, timeout=10)
                
                # Check if Access-Control-Allow-Origin header is present
                acao_header = response.headers.get('Access-Control-Allow-Origin')
                if acao_header:
                    # Check if the header reflects our malicious origin
                    if acao_header == origin or acao_header == '*':
                        credentials_allowed = 'Access-Control-Allow-Credentials' in response.headers and response.headers['Access-Control-Allow-Credentials'].lower() == 'true'
                        
                        vulnerability = {
                            "origin": origin,
                            "allowed": acao_header,
                            "credentials_allowed": credentials_allowed
                        }
                        
                        vulnerable_origins.append(vulnerability)
                        
                        severity = "High" if credentials_allowed else "Medium"
                        print_warning(f"CORS misconfiguration found (Severity: {severity}):")
                        print_warning(f"  Origin: {origin}")
                        print_warning(f"  Reflected in Access-Control-Allow-Origin: {acao_header}")
                        if credentials_allowed:
                            print_warning("  Credentials allowed: Yes (This is particularly dangerous)")
                            
            except Exception as e:
                print_warning(f"Error testing origin {origin}: {str(e)}")
        
        if vulnerable_origins:
            results["vulnerable"] = True
            results["details"] = vulnerable_origins
            print_success(f"Found {len(vulnerable_origins)} CORS misconfigurations")
        else:
            print_info("No CORS misconfigurations detected")
        
        return results
    
    except Exception as e:
        print_error(f"Error during CORS misconfiguration check: {str(e)}")
        return results


# Function to check for missing security headers
def check_security_headers(target: str) -> Dict[str, Any]:
    print_progress(f"Checking for missing security headers on {target}...")
    results = {"vulnerable": False, "details": []}
    
    if not DEPENDENCIES["requests"]:
        print_warning("requests module is not installed. Skipping security headers check.")
        return results
    
    try:
        import requests
        
        # Normalize the target URL
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        # List of important security headers to check
        security_headers = {
            "Strict-Transport-Security": {
                "description": "HTTP Strict Transport Security (HSTS) enforces secure (HTTPS) connections to the server",
                "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'"
            },
            "Content-Security-Policy": {
                "description": "Content Security Policy (CSP) helps prevent XSS and data injection attacks",
                "recommendation": "Implement a Content-Security-Policy suited to your website's needs"
            },
            "X-Content-Type-Options": {
                "description": "Prevents browsers from MIME-sniffing a response from the declared content-type",
                "recommendation": "Add 'X-Content-Type-Options: nosniff'"
            },
            "X-Frame-Options": {
                "description": "Provides clickjacking protection by not allowing the browser to render the page in a frame",
                "recommendation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'"
            },
            "X-XSS-Protection": {
                "description": "Enables cross-site scripting filtering in some browsers",
                "recommendation": "Add 'X-XSS-Protection: 1; mode=block'"
            },
            "Referrer-Policy": {
                "description": "Controls how much referrer information should be included with requests",
                "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'"
            },
            "Permissions-Policy": {
                "description": "Controls which browser features and APIs can be used (formerly Feature-Policy)",
                "recommendation": "Implement a Permissions-Policy that restricts unnecessary features"
            }
        }
        
        # Make the request
        response = requests.get(target, timeout=10)
        
        # Check which headers are missing
        missing_headers = []
        
        for header, info in security_headers.items():
            # Check for alternative header names for some policies
            present = False
            
            # Direct match
            if header in response.headers:
                present = True
            
            # Handle alternative header names (e.g., Feature-Policy as alternative to Permissions-Policy)
            if header == "Permissions-Policy" and "Feature-Policy" in response.headers:
                present = True
            
            if not present:
                missing_headers.append({
                    "header": header,
                    "description": info["description"],
                    "recommendation": info["recommendation"]
                })
                print_warning(f"Missing security header: {header}")
                print_info(f"  Description: {info['description']}")
                print_info(f"  Recommendation: {info['recommendation']}")
        
        # Add results
        if missing_headers:
            results["vulnerable"] = True
            results["details"] = missing_headers
            print_success(f"Found {len(missing_headers)} missing security headers")
        else:
            print_info("All important security headers are present")
        
        # Also include the headers that are present for reference
        results["present_headers"] = dict(response.headers)
        
        return results
    
    except Exception as e:
        print_error(f"Error during security headers check: {str(e)}")
        return results


# Function to check for open DNS resolvers
def check_open_dns_resolver(target: str) -> Dict[str, Any]:
    print_progress(f"Checking if {target} is an open DNS resolver...")
    results = {"vulnerable": False, "details": []}
    
    try:
        import socket
        import random
        import struct
        
        # Try to get the IP address if a domain is provided
        try:
            # If target is already an IP, this will raise an exception
            ipaddress.ip_address(target)
            target_ip = target
        except ValueError:
            # Try to resolve the domain to an IP
            try:
                target_ip = socket.gethostbyname(target)
                print_info(f"Resolved {target} to IP: {target_ip}")
            except socket.gaierror:
                print_error(f"Could not resolve domain {target} to IP address")
                return results
        
        # Create a UDP socket to send DNS queries
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)  # Set a timeout for responses
        
        # Function to create a DNS query packet
        def create_dns_query(domain, record_type=1):  # Type 1 = A record
            transaction_id = random.randint(0, 65535)
            
            # Header section
            header = struct.pack(">HHHHHH", 
                transaction_id,  # Transaction ID
                0x0100,          # Flags (standard query)
                0x0001,          # Questions: 1
                0x0000,          # Answer RRs: 0
                0x0000,          # Authority RRs: 0
                0x0000           # Additional RRs: 0
            )
            
            # Encode domain name properly
            domain_parts = domain.split('.')
            encoded_domain = b""
            
            for part in domain_parts:
                length = len(part)
                encoded_domain += struct.pack("B", length) + part.encode()
            
            encoded_domain += b"\x00"  # Terminating null byte
            
            # Question section
            question = encoded_domain + struct.pack(">HH", record_type, 0x0001)  # Type A, Class IN
            
            return header + question
        
        # List of domains to test that the DNS server shouldn't be authoritative for
        test_domains = [
            "google.com",
            "facebook.com",
            "example.org",
            "nonexistent-domain-for-testing-123456.com"
        ]
        
        # Test each domain
        successful_resolutions = []
        
        for domain in test_domains:
            query = create_dns_query(domain)
            
            try:
                # Send the query
                print_info(f"Testing resolution of {domain}...")
                sock.sendto(query, (target_ip, 53))
                
                # Try to receive a response
                response, _ = sock.recvfrom(1024)
                
                # If we get here, we received a response
                # Check if it's a proper DNS response by examining the header
                if len(response) >= 12:  # DNS header is 12 bytes
                    # Extract transaction ID and flags
                    transaction_id, flags = struct.unpack(">HH", response[:4])
                    
                    # Check if it's a response (QR bit set) and not an error
                    is_response = (flags & 0x8000) != 0
                    rcode = flags & 0x000F  # Response code
                    
                    if is_response and rcode == 0:  # NOERROR response code
                        successful_resolutions.append(domain)
                        print_warning(f"Server resolved {domain} - Potentially an open resolver")
            
            except socket.timeout:
                print_info(f"No response for {domain} (timeout)")
                continue
            except Exception as inner_e:
                print_warning(f"Error testing {domain}: {str(inner_e)}")
                continue
        
        # Close the socket
        sock.close()
        
        # Determine if the server is an open resolver
        if successful_resolutions:
            results["vulnerable"] = True
            results["details"] = successful_resolutions
            print_success(f"Found evidence of open DNS resolver - resolved {len(successful_resolutions)} non-authoritative domains")
        else:
            print_info("No evidence of open DNS resolver found")
        
        return results
    
    except Exception as e:
        print_error(f"Error during open DNS resolver check: {str(e)}")
        return results


# Function to get information from VirusTotal
def get_virustotal_info(domain: str, api_key: str) -> Dict[str, Any]:
    print_progress(f"Getting VirusTotal information for {domain}...")
    results = {"available": False, "data": {}}
    
    if not api_key:
        print_warning("VirusTotal API key not provided. Skipping VirusTotal check.")
        return results
    
    if not DEPENDENCIES["requests"]:
        print_warning("requests module is not installed. Skipping VirusTotal check.")
        return results
    
    try:
        import requests
        
        # API endpoint
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        
        # Headers with API key
        headers = {
            "x-apikey": api_key
        }
        
        # Make the request
        response = requests.get(url, headers=headers, timeout=30)
        
        # Check response
        if response.status_code == 200:
            data = response.json()
            results["available"] = True
            
            # Extract relevant information
            attributes = data.get("data", {}).get("attributes", {})
            
            # Domain creation date
            if "creation_date" in attributes:
                results["data"]["creation_date"] = attributes["creation_date"]
            
            # Last update date
            if "last_update_date" in attributes:
                results["data"]["last_update_date"] = attributes["last_update_date"]
            
            # Reputation
            if "reputation" in attributes:
                results["data"]["reputation"] = attributes["reputation"]
            
            # Last analysis stats
            if "last_analysis_stats" in attributes:
                results["data"]["analysis_stats"] = attributes["last_analysis_stats"]
            
            print_success("Successfully retrieved VirusTotal information")
        elif response.status_code == 401:
            print_error("Invalid VirusTotal API key")
        else:
            print_warning(f"VirusTotal API returned status code: {response.status_code}")
        
        return results
    
    except Exception as e:
        print_error(f"Error getting VirusTotal information: {str(e)}")
        return results


# Function to get information from Shodan
def get_shodan_info(domain: str, api_key: str) -> Dict[str, Any]:
    print_progress(f"Getting Shodan information for {domain}...")
    results = {"available": False, "data": {}}
    
    if not api_key:
        print_warning("Shodan API key not provided. Skipping Shodan check.")
        return results
    
    if not DEPENDENCIES["requests"]:
        print_warning("requests module is not installed. Skipping Shodan check.")
        return results
    
    try:
        import requests
        
        # First try to resolve the domain to IP
        try:
            ip = socket.gethostbyname(domain)
            print_info(f"Resolved {domain} to IP: {ip}")
        except socket.gaierror:
            print_error(f"Could not resolve domain {domain} to IP address")
            return results
        
        # API endpoint for host information
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        
        # Make the request
        response = requests.get(url, timeout=30)
        
        # Check response
        if response.status_code == 200:
            data = response.json()
            results["available"] = True
            
            # Extract relevant information
            if "ports" in data:
                results["data"]["open_ports"] = data["ports"]
            
            if "hostnames" in data:
                results["data"]["hostnames"] = data["hostnames"]
            
            if "country_name" in data:
                results["data"]["country"] = data["country_name"]
            
            if "os" in data:
                results["data"]["os"] = data["os"]
            
            if "vulns" in data:
                results["data"]["vulnerabilities"] = data["vulns"]
            
            if "data" in data:
                # Extract services information from first few banners
                services = []
                for i, service in enumerate(data["data"]):
                    if i >= 5:  # Limit to first 5 services for brevity
                        break
                    service_info = {
                        "port": service.get("port"),
                        "transport": service.get("transport"),
                        "product": service.get("product", ""),
                        "version": service.get("version", "")
                    }
                    services.append(service_info)
                results["data"]["services"] = services
            
            print_success("Successfully retrieved Shodan information")
        elif response.status_code == 401:
            print_error("Invalid Shodan API key")
        elif response.status_code == 404:
            print_warning(f"No Shodan information found for IP {ip}")
        else:
            print_warning(f"Shodan API returned status code: {response.status_code}")
        
        return results
    
    except Exception as e:
        print_error(f"Error getting Shodan information: {str(e)}")
        return results


# Function to generate visualization
def generate_visualization(results: Dict[str, Any], target: str) -> bool:
    print_progress(f"Generating visualization for {target}...")
    
    if not DEPENDENCIES["matplotlib"]:
        print_warning("matplotlib module is not installed. Skipping visualization.")
        return False
    
    try:
        import matplotlib.pyplot as plt
        
        # Create a figure with subplots
        fig, axs = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle(f"Security Scan Results for {target}", fontsize=16)
        
        # 1. Port Distribution - Top left subplot
        ports = results.get("open_ports", {})
        if ports:
            port_names = [f"{port}/{ports[port]}" for port in ports]
            axs[0, 0].bar(port_names, [1] * len(ports), color='skyblue')
            axs[0, 0].set_title("Open Ports")
            axs[0, 0].set_xticklabels(port_names, rotation=45, ha="right")
            axs[0, 0].set_ylabel("Status (Open)")
        else:
            axs[0, 0].text(0.5, 0.5, "No port data available", 
                          horizontalalignment='center', verticalalignment='center',
                          transform=axs[0, 0].transAxes)
        
        # 2. Vulnerability Distribution - Top right subplot
        vuln_data = []
        vuln_labels = []
        
        # SQL injection
        if results.get("sql_injection", {}).get("vulnerable", False):
            vuln_data.append(len(results["sql_injection"]["details"]))
            vuln_labels.append("SQL Injection")
        
        # Web vulnerabilities
        if results.get("web_vulnerabilities", {}).get("vulnerable", False):
            vuln_data.append(len(results["web_vulnerabilities"]["details"]))
            vuln_labels.append("Web Vulnerabilities")
        
        # Subdomain takeover
        if results.get("subdomain_takeover", {}).get("vulnerable", False):
            vuln_data.append(len(results["subdomain_takeover"]["details"]))
            vuln_labels.append("Subdomain Takeover")
        
        # Shodan vulnerabilities
        if results.get("shodan", {}).get("available", False) and "vulnerabilities" in results["shodan"]["data"]:
            vuln_data.append(len(results["shodan"]["data"]["vulnerabilities"]))
            vuln_labels.append("Known CVEs")
        
        if vuln_data:
            axs[0, 1].pie(vuln_data, labels=vuln_labels, autopct='%1.1f%%', startangle=90)
            axs[0, 1].set_title("Vulnerability Distribution")
        else:
            axs[0, 1].text(0.5, 0.5, "No vulnerability data available", 
                          horizontalalignment='center', verticalalignment='center',
                          transform=axs[0, 1].transAxes)
        
        # 3. Subdomain Count - Bottom left subplot
        subdomains = results.get("subdomains", [])
        if subdomains:
            axs[1, 0].bar(["Subdomains"], [len(subdomains)], color='lightgreen')
            axs[1, 0].set_title(f"Subdomain Count: {len(subdomains)}")
            axs[1, 0].set_ylabel("Count")
        else:
            axs[1, 0].text(0.5, 0.5, "No subdomain data available", 
                          horizontalalignment='center', verticalalignment='center',
                          transform=axs[1, 0].transAxes)
        
        # 4. VirusTotal reputation - Bottom right subplot
        if results.get("virustotal", {}).get("available", False) and "analysis_stats" in results["virustotal"]["data"]:
            stats = results["virustotal"]["data"]["analysis_stats"]
            labels = ["Malicious", "Suspicious", "Harmless", "Undetected"]
            values = [
                stats.get("malicious", 0),
                stats.get("suspicious", 0),
                stats.get("harmless", 0),
                stats.get("undetected", 0)
            ]
            
            axs[1, 1].pie(values, labels=labels, autopct='%1.1f%%', startangle=90)
            axs[1, 1].set_title("VirusTotal Analysis Results")
        else:
            axs[1, 1].text(0.5, 0.5, "No VirusTotal data available", 
                          horizontalalignment='center', verticalalignment='center',
                          transform=axs[1, 1].transAxes)
        
        # Adjust layout and save
        plt.tight_layout(rect=[0, 0, 1, 0.96])
        filename = f"{target}_scan_results.png"
        plt.savefig(filename)
        plt.close()
        
        print_success(f"Visualization saved as {filename}")
        return True
    
    except Exception as e:
        print_error(f"Error generating visualization: {str(e)}")
        traceback.print_exc()
        return False


# Function to analyze results with OpenAI
def analyze_with_ai(results: Dict[str, Any], target: str, api_key: str) -> Dict[str, Any]:
    print_progress(f"Analyzing scan results with AI for {target}...")
    analysis_result = {"available": False, "analysis": ""}
    
    if not api_key:
        print_warning("OpenAI API key not provided. Skipping AI analysis.")
        return analysis_result
    
    if not DEPENDENCIES["openai"]:
        print_warning("openai module is not installed. Skipping AI analysis.")
        return analysis_result
    
    try:
        import openai
        
        # Set API key
        openai.api_key = api_key
        
        # Prepare a summary of findings to send to the API
        summary = f"Target: {target}\n\n"
        
        # Add subdomain information
        subdomains = results.get("subdomains", [])
        summary += f"Subdomains found: {len(subdomains)}\n"
        if subdomains and len(subdomains) <= 10:
            summary += "List of subdomains: " + ", ".join(subdomains) + "\n"
        
        # Add port information
        ports = results.get("open_ports", {})
        summary += f"Open ports found: {len(ports)}\n"
        if ports:
            port_str = ", ".join([f"{port}/{ports[port]}" for port in ports])
            summary += f"Open ports: {port_str}\n"
        
        # Add vulnerability information
        has_vulnerabilities = False
        
        if results.get("sql_injection", {}).get("vulnerable", False):
            has_vulnerabilities = True
            summary += f"SQL Injection vulnerabilities found: {len(results['sql_injection']['details'])}\n"
        
        if results.get("web_vulnerabilities", {}).get("vulnerable", False):
            has_vulnerabilities = True
            summary += f"Web vulnerabilities found: {len(results['web_vulnerabilities']['details'])}\n"
            if len(results['web_vulnerabilities']['details']) <= 5:
                summary += "Examples: " + "\n".join(results['web_vulnerabilities']['details'][:5]) + "\n"
        
        if results.get("subdomain_takeover", {}).get("vulnerable", False):
            has_vulnerabilities = True
            summary += f"Subdomain takeover vulnerabilities found: {len(results['subdomain_takeover']['details'])}\n"
        
        if results.get("shodan", {}).get("available", False) and "vulnerabilities" in results["shodan"]["data"]:
            has_vulnerabilities = True
            summary += f"Known CVEs from Shodan: {len(results['shodan']['data']['vulnerabilities'])}\n"
        
        if not has_vulnerabilities:
            summary += "No vulnerabilities were detected.\n"
        
        # Add VirusTotal information
        if results.get("virustotal", {}).get("available", False) and "analysis_stats" in results["virustotal"]["data"]:
            stats = results["virustotal"]["data"]["analysis_stats"]
            summary += f"VirusTotal analysis: Malicious: {stats.get('malicious', 0)}, Suspicious: {stats.get('suspicious', 0)}, Harmless: {stats.get('harmless', 0)}\n"
        
        # Create the prompt for the AI
        prompt = f"""
        Analyze the following security scan results and provide:
        1. A summary of the most critical findings
        2. The potential impact of the vulnerabilities
        3. Recommendations for fixing the issues
        4. An overall security rating (Low, Medium, High risk)

        Scan Results:
        {summary}
        """
        
        # Call the OpenAI API with the current client version
        client = openai.OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert analyzing scan results."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=1000,
            temperature=0.5
        )
        
        # Get the AI analysis
        ai_analysis = response.choices[0].message.content
        
        analysis_result["available"] = True
        analysis_result["analysis"] = ai_analysis
        
        print_success("AI analysis completed successfully")
        return analysis_result
    
    except Exception as e:
        print_error(f"Error during AI analysis: {str(e)}")
        traceback.print_exc()
        analysis_result["analysis"] = f"Error during analysis: {str(e)}"
        return analysis_result


# Function to get user confirmation
def get_user_confirmation(message: str, default: str = "y") -> bool:
    valid_responses = {"y": True, "n": False}
    prompt = f"{message} [Y/n]: " if default.lower() == "y" else f"{message} [y/N]: "
    
    while True:
        response = input(prompt).strip().lower()
        if response == "":
            return valid_responses[default.lower()]
        elif response in valid_responses:
            return valid_responses[response]
        else:
            print_warning("Please enter 'y' or 'n'")

# Function to save scan configuration
def save_scan_config(config: Dict[str, bool], filename: str = "scan_config.json") -> bool:
    try:
        with open(filename, "w") as f:
            json.dump(config, f, indent=4)
        print_success(f"Scan configuration saved to {filename}")
        return True
    except Exception as e:
        print_error(f"Error saving scan configuration: {str(e)}")
        return False

# Function to load scan configuration
def load_scan_config(filename: str = "scan_config.json") -> Dict[str, bool]:
    default_config = {
        "do_subdomain": True,
        "do_port": True,
        "do_vuln": True,
        "do_api": True,
        "do_ai": True,
        "do_viz": True
    }
    
    if not os.path.exists(filename):
        return default_config
    
    try:
        with open(filename, "r") as f:
            config = json.load(f)
        print_success(f"Loaded scan configuration from {filename}")
        return config
    except Exception as e:
        print_error(f"Error loading scan configuration: {str(e)}")
        return default_config

# Main function
def main():
    # Parse command line arguments (only target and output)
    parser = argparse.ArgumentParser(description="Security Scanner Tool")
    parser.add_argument("target", help="Target domain or IP address to scan")
    parser.add_argument("--output", help="Output file for JSON results")
    parser.add_argument("--config", help="Use a saved scan configuration file")
    args = parser.parse_args()
    
    # Initialize scan configuration
    if args.config and os.path.exists(args.config):
        scan_config = load_scan_config(args.config)
    else:
        scan_config = {
            "do_subdomain": None,
            "do_port": None,
            "do_vuln": None,
            "do_api": None,
            "do_ai": None,
            "do_viz": None
        }
    
    # Welcome message
    print("\n" + "="*50)
    print("Security Scanner Tool")
    print("="*50 + "\n")
    
    # Check dependencies
    check_dependencies()
    
    # Load API keys
    virustotal_api_key, shodan_api_key, openai_api_key = load_config()
    
    # Prepare results dictionary
    results = {
        "target": args.target,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "subdomains": [],
        "open_ports": {},
        "sql_injection": {},
        "web_vulnerabilities": {},
        "subdomain_takeover": {},
        "virustotal": {},
        "shodan": {},
        "ai_analysis": {}
    }
    
    # Ask the user about scan configuration
    print("\n" + "="*50)
    print("INTERACTIVE SCAN CONFIGURATION")
    print("="*50)
    
    try:
        # Step 1: Ask about subdomain enumeration
        print("\n⬤ Subdomain Enumeration")
        print("   Discovers all subdomains associated with the target domain")
        print("   This helps in identifying the attack surface and potential entry points")
        if scan_config["do_subdomain"] is None:
            scan_config["do_subdomain"] = get_user_confirmation("Do you want to enumerate subdomains?")
        
        if scan_config["do_subdomain"]:
            subdomains = get_subdomains(args.target)
            results["subdomains"] = subdomains
        else:
            print_info("Subdomain enumeration skipped")
        
        # Step 2: Ask about port scanning
        print("\n⬤ Port Scanning")
        print("   Identifies open ports and services running on the target")
        print("   This helps in determining potential vulnerabilities based on exposed services")
        if scan_config["do_port"] is None:
            scan_config["do_port"] = get_user_confirmation("Do you want to scan for open ports?")
        
        if scan_config["do_port"]:
            open_ports = scan_ports(args.target)
            results["open_ports"] = open_ports
        else:
            print_info("Port scanning skipped")
        
        # Step 3: Ask about vulnerability checks
        print("\n⬤ Vulnerability Scanning")
        print("   Checks for SQL injection, web vulnerabilities, and subdomain takeover issues")
        print("   This identifies exploitable security weaknesses in the target")
        if scan_config["do_vuln"] is None:
            scan_config["do_vuln"] = get_user_confirmation("Do you want to scan for vulnerabilities?")
        
        if scan_config["do_vuln"]:
            # Web path for target
            web_target = f"http://{args.target}"
            if 80 not in results["open_ports"] and 443 in results["open_ports"]:
                web_target = f"https://{args.target}"
            
            # SQL injection check
            if get_user_confirmation("   - Do you want to check for SQL injection vulnerabilities?"):
                results["sql_injection"] = check_sql_injection(web_target)
            else:
                print_info("SQL injection check skipped")
            
            # Web vulnerabilities check
            if get_user_confirmation("   - Do you want to scan for web vulnerabilities?"):
                results["web_vulnerabilities"] = scan_web_vulnerabilities(web_target)
            else:
                print_info("Web vulnerability scan skipped")
            
            # Subdomain takeover check (only if subdomains were enumerated)
            if scan_config["do_subdomain"] and results["subdomains"]:
                if get_user_confirmation("   - Do you want to check for subdomain takeover vulnerabilities?"):
                    results["subdomain_takeover"] = check_subdomain_takeover(results["subdomains"])
                else:
                    print_info("Subdomain takeover check skipped")
            else:
                print_info("Subdomain takeover check skipped (no subdomains)")
        else:
            print_info("Vulnerability scanning skipped")
        
        # Step 4: Ask about API-based checks
        print("\n⬤ API-Based Intelligence Gathering")
        print("   Uses VirusTotal and Shodan to gather additional security information")
        print("   This provides reputation data and known vulnerabilities from external sources")
        if scan_config["do_api"] is None:
            scan_config["do_api"] = get_user_confirmation("Do you want to perform API-based checks?")
        
        if scan_config["do_api"]:
            # VirusTotal check
            if virustotal_api_key:
                if get_user_confirmation("   - Do you want to check VirusTotal for information?"):
                    results["virustotal"] = get_virustotal_info(args.target, virustotal_api_key)
                else:
                    print_info("VirusTotal check skipped")
            else:
                print_warning("VirusTotal check skipped (no API key)")
            
            # Shodan check
            if shodan_api_key:
                if get_user_confirmation("   - Do you want to check Shodan for information?"):
                    results["shodan"] = get_shodan_info(args.target, shodan_api_key)
                else:
                    print_info("Shodan check skipped")
            else:
                print_warning("Shodan check skipped (no API key)")
        else:
            print_info("API-based checks skipped")
        
        # Step 5: Ask about AI analysis
        print("\n⬤ AI Security Analysis")
        print("   Uses OpenAI to analyze scan results and provide security recommendations")
        print("   This gives expert insights and actionable remediation steps")
        if scan_config["do_ai"] is None:
            scan_config["do_ai"] = get_user_confirmation("Do you want to perform AI analysis of the results?")
        
        if scan_config["do_ai"]:
            if openai_api_key:
                results["ai_analysis"] = analyze_with_ai(results, args.target, openai_api_key)
            else:
                print_warning("AI analysis skipped (no OpenAI API key)")
        else:
            print_info("AI analysis skipped")
        
        # Step 6: Ask about visualization
        print("\n⬤ Results Visualization")
        print("   Generates graphical charts summarizing the scan findings")
        print("   This helps in understanding the security posture at a glance")
        if scan_config["do_viz"] is None:
            scan_config["do_viz"] = get_user_confirmation("Do you want to generate a visualization of the results?")
        
        visualization_generated = False
        if scan_config["do_viz"]:
            visualization_generated = generate_visualization(results, args.target)
        else:
            print_info("Visualization generation skipped")
        
        # Step 7: Save results to JSON file
        output_file = args.output if args.output else f"{args.target}_scan_results.json"
        try:
            with open(output_file, "w") as f:
                json.dump(results, f, indent=4, default=str)
            print_success(f"Results saved to {output_file}")
        except Exception as e:
            print_error(f"Error saving results to file: {str(e)}")
        
        # Step 8: Display summary
        print("\n" + "="*50)
        print("SCAN SUMMARY")
        print("="*50)
        print(f"Target: {args.target}")
        print(f"Timestamp: {results['timestamp']}")
        print("-"*50)
        
        # Subdomain summary
        print(f"Subdomains Found: {len(results.get('subdomains', []))}")
        
        # Open ports summary
        print(f"Open Ports Found: {len(results.get('open_ports', {}))}")
        if results.get('open_ports'):
            port_services = [f"{port}/{results['open_ports'][port]}" for port in results['open_ports']]
            print(f"  - Services: {', '.join(port_services[:5])}" + (" and more..." if len(port_services) > 5 else ""))
        
        # Vulnerabilities summary
        vuln_count = 0
        if results.get("sql_injection", {}).get("vulnerable", False):
            vuln_count += len(results["sql_injection"]["details"])
        if results.get("web_vulnerabilities", {}).get("vulnerable", False):
            vuln_count += len(results["web_vulnerabilities"]["details"])
        if results.get("subdomain_takeover", {}).get("vulnerable", False):
            vuln_count += len(results["subdomain_takeover"]["details"])
        print(f"Vulnerabilities Found: {vuln_count}")
        
        # API results summary
        if results.get("virustotal", {}).get("available", False):
            print("VirusTotal Data: Available")
            if "analysis_stats" in results["virustotal"]["data"]:
                stats = results["virustotal"]["data"]["analysis_stats"]
                malicious = stats.get("malicious", 0)
                if malicious > 0:
                    print(f"  - Warning: {malicious} malicious reports detected!")
        
        if results.get("shodan", {}).get("available", False):
            print("Shodan Data: Available")
            if "vulnerabilities" in results["shodan"]["data"]:
                vuln_count = len(results["shodan"]["data"]["vulnerabilities"])
                if vuln_count > 0:
                    print(f"  - Warning: {vuln_count} CVEs detected!")
        
        # AI analysis summary
        if results.get("ai_analysis", {}).get("available", False):
            print("AI Analysis: Available")
            print("Review the full output file for detailed AI recommendations.")
        
        # Output files
        print("-"*50)
        print(f"Results JSON file: {output_file}")
        if visualization_generated:
            print(f"Visualization image: {args.target}_scan_results.png")
        
        print("="*50)
        print("Scan completed successfully!")
        
        # Ask if user wants to save the scan configuration
        if get_user_confirmation("\nDo you want to save your scan configuration for future use?"):
            config_filename = input("Enter filename to save configuration [scan_config.json]: ").strip()
            if not config_filename:
                config_filename = "scan_config.json"
            save_scan_config(scan_config, config_filename)
            print_info(f"You can use this configuration in future scans with: python3 scanner.py {args.target} --config {config_filename}")
        
    except KeyboardInterrupt:
        print_warning("\nScan interrupted by user. Saving partial results...")
        # Save partial results
        if args.output:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=4, default=str)
            print_info(f"Partial results saved to {args.output}")
        sys.exit(1)
    
    except Exception as e:
        print_error(f"Error during scan: {str(e)}")
        traceback.print_exc()
        sys.exit(1)

# Run the main function if the script is run directly
if __name__ == "__main__":
    main()
