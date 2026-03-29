# BadAuth0

BadAuth0 is a security testing tool designed to identify vulnerabilities in Auth0 account creation endpoints. It tests for unauthenticated account creation and misconfigurations in Auth0 implementations.

## Features

- Tests for unauthenticated account creation vulnerabilities
- Identifies misconfigured Auth0 endpoints
- Bulk domain list testing
- Verbose mode for detailed output
- Results saved to a configurable output directory

## Installation

### go install (recommended)

```bash
go install github.com/OctaYus/BadAuth0@latest
```

Then run it as:
```bash
BadAuth0 -l domains.txt -e test@example.com
```

### Build from source

```bash
git clone https://github.com/OctaYus/BadAuth0.git
cd BadAuth0
go build -o badauth0 .
```

## Usage

```bash
BadAuth0 -l <domains_file> -e <email> [-o <output_dir>] [-v]
```

### Arguments

| Flag | Description | Required |
|------|-------------|----------|
| `-l` | File containing list of target domains | Yes |
| `-e` | Test email address for account creation | Yes |
| `-o` | Output directory (default: `./output`) | No |
| `-v` | Enable verbose output | No |

### Examples

Test a list of domains:
```bash
BadAuth0 -l domains.txt -e test@example.com
```

With custom output directory and verbose mode:
```bash
BadAuth0 -l domains.txt -e test@example.com -o results -v
```

## Output

Results are saved in the output directory (default: `./output`):
- `vulnerable_domains.txt` — domains where account creation succeeded, with credentials used

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
