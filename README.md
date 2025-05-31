# BadAuth0

BadAuth0 is a security testing tool designed to identify vulnerabilities in Auth0 account creation endpoints. It tests for unauthenticated account creation and misconfigurations in Auth0 implementations.

## Features

- Tests for unauthenticated account creation vulnerabilities
- Identifies misconfigured Auth0 endpoints
- Supports single email and bulk email list testing
- Generates detailed output reports
- Configurable output directory

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/OctaYus/BadAuth0.git
   ```

2. Navigate to the project directory:
   ```bash
   cd BadAuth0
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Basic command structure:
```bash
python main.py -d <domain> [-e <email> | -l <email_list>] [-o <output_dir>] [-v]
```

### Required Arguments:
- `-d`, `--domain`: Target domain (e.g., example.com)

### Target Selection (use one):
- `-e`, `--email`: Single email address to test
- `-l`, `--list`: File containing list of email addresses to test

### Optional Arguments:
- `-o`, `--output`: Custom output directory (default: ./output)
- `-v`, `--verbose`: Enable verbose output for debugging

### Examples:

1. Test single email address:
   ```bash
   python main.py -d example.com -e test@example.com
   ```

2. Test list of email addresses:
   ```bash
   python main.py -d example.com -l emails.txt -o results
   ```

3. Test with verbose output:
   ```bash
   python main.py -d example.com -l emails.txt -v
   ```

## Output

The tool generates:
- Credentials file containing successful account creations
- Status reports for each attempt
- Verbose debugging information when enabled

All output is saved in the specified directory (default: ./output)

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
