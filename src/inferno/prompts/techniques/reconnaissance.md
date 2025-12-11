# Passive Reconnaissance

Gather information without directly interacting with the target.

## OSINT Sources
- DNS records (dig, nslookup, host)
- WHOIS information
- Certificate transparency logs
- Search engine results
- Cached pages and archives
- Social media and public profiles

## DNS Enumeration
```bash
# Basic DNS lookup
dig {target} ANY
dig {target} AXFR  # Zone transfer attempt

# Subdomain enumeration
# Use tools like subfinder, amass (if available)
```

## Information to Gather
- IP addresses and ranges
- Subdomains
- Email addresses
- Technology stack clues
- Employee information
- Related domains

---

# Active Reconnaissance

Direct interaction with the target to gather information.

## Network Scanning (Use Tool Search for nmap_scan)
The **nmap_scan** tool wrapper provides structured scanning:
- Quick scan: `scan_type: "quick"` - Common ports only
- Service scan: `scan_type: "service"` - Version detection
- Full scan: `scan_type: "full"` - All 65535 ports

Or use shell directly:
```bash
# Quick scan for common ports
nmap -sV -sC -T4 -p 21,22,23,25,53,80,443,445,3306,3389,8080 {target}

# Full TCP scan
nmap -sV -sC -p- -T4 {target}

# UDP scan (slow but important)
nmap -sU -T4 --top-ports 100 {target}
```

## Service-Specific Enumeration
After discovering services, test for:
- Default credentials (use **hydra** tool wrapper)
- Anonymous access
- Version-specific vulnerabilities

## Key Information
- Open ports and services
- Service versions
- Operating system fingerprint
- Network topology
- Firewall detection

---

# Service Enumeration

Deep enumeration of discovered services.

## Common Services

### SSH (22)
- Banner grabbing
- Supported authentication methods
- Version vulnerabilities
- **Credential testing**: Use **hydra** with `protocol: "ssh"`

### HTTP/HTTPS (80/443)
- Technology fingerprinting (whatweb)
- Directory enumeration (**gobuster**)
- Virtual host discovery
- SSL/TLS analysis (sslscan, testssl)
- **Form auth testing**: Use **hydra** with `protocol: "http-post-form"`

### SMB (445)
- Share enumeration (smbclient, enum4linux)
- Null session testing
- Version detection (EternalBlue check)
- **Credential testing**: Use **hydra** with `protocol: "smb"`

### Database Ports
- MySQL (3306): Version, auth methods → **hydra** `protocol: "mysql"`
- PostgreSQL (5432): Version, auth → **hydra** `protocol: "postgres"`
- MSSQL (1433): Version, config → **hydra** `protocol: "mssql"`
- MongoDB (27017): Auth bypass check
- Redis (6379): Auth check → **hydra** `protocol: "redis"`

### FTP (21)
- Anonymous access (try user: anonymous, pass: anonymous)
- Version vulnerabilities
- Writable directories
- **Credential testing**: Use **hydra** with `protocol: "ftp"`

## Credential Attack Strategy
Use **hydra** tool wrapper (Tool Search) for brute-forcing:
- Start with common credentials first
- Use `passwords-common` wordlist preset for quick tests
- Increase threads carefully to avoid lockouts
- Set `wait_time` parameter to avoid detection

---

# Web Application Enumeration

Detailed enumeration of web applications.

## Technology Stack
```bash
# Identify technologies
whatweb {target}
curl -I {target}  # Headers analysis
```

## Directory/File Discovery (Use Tool Search for gobuster)
The **gobuster** tool wrapper auto-resolves wordlists:
- Use preset: `wordlist: "common"` or `wordlist: "big"`
- Add extensions: `extensions: ["php", "txt", "html", "bak"]`
- Wordlists are found automatically (SecLists, brew, apt locations)

Or use shell directly:
```bash
gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak
```

## Key Files to Check
- robots.txt, sitemap.xml
- **.git/ directory** → Use **git_dumper** tool if exposed!
- .env, .htaccess files
- backup files (.bak, .old, .swp, ~)
- config files (config.php, settings.py, etc.)

## Git Repository Exposure
If /.git/HEAD returns content (ref: refs/heads/...), use:
- **git_dumper** tool (built-in, no installation needed)
- Downloads objects, reconstructs repository
- May reveal source code, credentials, history

## API Discovery (ALWAYS USE FUZZING - MANDATORY)

**RULE: Never manually guess API endpoints. Always fuzz first.**

### Inferno Bundled Wordlists (ALWAYS AVAILABLE)
- `wordlists/api-endpoints.txt` - API paths (users, auth, admin, graphql, etc.)
- `wordlists/common-dirs.txt` - Common directories and files
- `wordlists/parameters.txt` - URL/POST parameter names

### Primary Tool: ffuf (fastest)
```bash
# Basic API endpoint fuzzing (use Inferno's bundled wordlist)
ffuf -u http://{target}/FUZZ -w wordlists/api-endpoints.txt -mc all -fc 404

# Fuzz under /api/ path
ffuf -u http://{target}/api/FUZZ -w wordlists/api-endpoints.txt -mc all -fc 404

# Version-aware API fuzzing
ffuf -u http://{target}/api/v1/FUZZ -w wordlists/api-endpoints.txt -mc all -fc 404
ffuf -u http://{target}/api/v2/FUZZ -w wordlists/api-endpoints.txt -mc all -fc 404
ffuf -u http://{target}/v1/FUZZ -w wordlists/api-endpoints.txt -mc all -fc 404

# Directory fuzzing
ffuf -u http://{target}/FUZZ -w wordlists/common-dirs.txt -mc all -fc 404
```

### Alternative: gobuster
```bash
gobuster dir -u http://{target}/api -w wordlists/api-endpoints.txt -t 50
gobuster dir -u http://{target} -w wordlists/common-dirs.txt -t 50
```

### API Documentation Endpoints (Check These)
```bash
# Fuzz for API docs (these are in api-endpoints.txt but double-check)
for doc in swagger.json openapi.json api-docs swagger-ui.html graphql graphiql redoc; do
  curl -s -o /dev/null -w "%{http_code} $doc\n" http://{target}/$doc
done
```

### GraphQL Discovery
```bash
# Check for GraphQL endpoint
curl -X POST http://{target}/graphql -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}'
```

### Parameter Fuzzing on Discovered Endpoints
```bash
# Fuzz GET parameters (use Inferno's bundled wordlist)
ffuf -u "http://{target}/api/users?FUZZ=1" -w wordlists/parameters.txt -mc all -fc 404

# Fuzz JSON body keys
ffuf -u http://{target}/api/login -X POST -H "Content-Type: application/json" -d '{"FUZZ":"test"}' -w wordlists/parameters.txt -mc all -fc 404
```

### Fallback Wordlist Locations (if bundled not found)
1. `/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt`
2. `/usr/share/wordlists/dirb/common.txt`
3. `/opt/metasploit-framework/embedded/framework/data/wordlists/common_roots.txt`

## Virtual Host Enumeration
For vhost discovery, use **gobuster** with `mode: "vhost"`:
- Automatically handles DNS resolution via curl --resolve
- No /etc/hosts modification needed