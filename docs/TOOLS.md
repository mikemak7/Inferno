# Security Tools Installation Guide

Complete guide to installing all security tools used by Inferno.

## Table of Contents

- [Quick Start](#quick-start)
- [Installation Methods](#installation-methods)
- [Core Tools](#core-tools)
- [Reconnaissance Tools](#reconnaissance-tools)
- [Web Application Tools](#web-application-tools)
- [Exploitation Tools](#exploitation-tools)
- [Network Tools](#network-tools)
- [Wordlists Setup](#wordlists-setup)
- [Docker-Based Setup](#docker-based-setup)
- [Verification](#verification)

---

## Quick Start

### Option A: Use Kali Docker (Recommended)

Everything pre-installed, no local setup needed:

```bash
# Pull and run Kali with all tools
docker run -it --name inferno-kali kalilinux/kali-rolling /bin/bash

# Inside container, install tools
apt update && apt install -y kali-linux-headless seclists
```

### Option B: Native Installation (macOS)

```bash
# Install Homebrew if needed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install all core tools
brew install nmap masscan gobuster ffuf nikto sqlmap hydra \
    subfinder amass nuclei whatweb sslscan john hashcat \
    netcat socat curl wget jq

# Install Go for additional tools
brew install go
export PATH=$PATH:$(go env GOPATH)/bin

# Install Go-based tools
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/httprobe@latest
go install github.com/lc/gau/v2/cmd/gau@latest
```

### Option C: Native Installation (Ubuntu/Debian)

```bash
sudo apt update && sudo apt install -y \
    nmap masscan gobuster nikto sqlmap hydra \
    amass whatweb sslscan john hashcat \
    netcat-openbsd socat curl wget jq dnsutils whois \
    seclists

# Install Go for additional tools
sudo apt install -y golang
export PATH=$PATH:$(go env GOPATH)/bin

# Install Go-based tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

---

## Installation Methods

| Method | Pros | Cons |
|--------|------|------|
| **Kali Docker** | All tools pre-installed, isolated | Requires Docker, some overhead |
| **Kali VM** | Full environment, GUI available | Heavy, resource intensive |
| **Native (macOS)** | Fast, no overhead | Some tools need workarounds |
| **Native (Linux)** | Best performance | Clutters system |

---

## Core Tools

### Network Scanning

#### nmap (Network Mapper)
```bash
# macOS
brew install nmap

# Ubuntu/Debian
sudo apt install nmap

# Verify
nmap --version
```

**Usage Examples:**
```bash
nmap -sV -sC target.com              # Service detection + scripts
nmap -sS -p- target.com              # SYN scan all ports (needs root)
nmap -sU --top-ports 100 target.com  # UDP scan top 100
nmap --script vuln target.com        # Vulnerability scripts
```

#### masscan (Fast Port Scanner)
```bash
# macOS
brew install masscan

# Ubuntu/Debian
sudo apt install masscan

# Verify
masscan --version
```

**Usage Examples:**
```bash
sudo masscan -p1-65535 target.com --rate=1000  # All ports fast
sudo masscan -p80,443,8080 10.0.0.0/24         # Subnet scan
```

#### rustscan (Modern Port Scanner)
```bash
# macOS
brew install rustscan

# From cargo (any platform)
cargo install rustscan

# Verify
rustscan --version
```

**Usage Examples:**
```bash
rustscan -a target.com -- -sV          # Fast scan + nmap service detection
rustscan -a target.com -p 1-65535      # All ports
```

---

## Reconnaissance Tools

### Subdomain Enumeration

#### subfinder
```bash
# macOS
brew install subfinder

# Go install
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Verify
subfinder -version
```

**Usage:**
```bash
subfinder -d target.com -silent        # Basic enumeration
subfinder -d target.com -all           # All sources
subfinder -d target.com -o subs.txt    # Save to file
```

#### amass
```bash
# macOS
brew install amass

# Ubuntu/Debian
sudo apt install amass

# Verify
amass -version
```

**Usage:**
```bash
amass enum -d target.com               # Passive enumeration
amass enum -d target.com -active       # Active (more intrusive)
amass intel -whois -d target.com       # WHOIS intelligence
```

#### assetfinder
```bash
# Go install
go install github.com/tomnomnom/assetfinder@latest

# Verify
assetfinder --help
```

**Usage:**
```bash
assetfinder target.com                 # Find related domains
assetfinder --subs-only target.com     # Only subdomains
```

### Web Fingerprinting

#### whatweb
```bash
# macOS
brew install whatweb

# Ubuntu/Debian
sudo apt install whatweb

# Verify
whatweb --version
```

**Usage:**
```bash
whatweb target.com                     # Basic fingerprint
whatweb -a 3 target.com                # Aggressive
whatweb -v target.com                  # Verbose output
```

#### httpx
```bash
# Go install
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Verify
httpx -version
```

**Usage:**
```bash
echo "target.com" | httpx              # Probe HTTP/HTTPS
cat urls.txt | httpx -status-code      # Check status codes
cat subs.txt | httpx -title -tech      # Title + tech detection
```

---

## Web Application Tools

### Directory/File Discovery

#### gobuster
```bash
# macOS
brew install gobuster

# Ubuntu/Debian
sudo apt install gobuster

# Go install
go install github.com/OJ/gobuster/v3@latest

# Verify
gobuster version
```

**Usage:**
```bash
gobuster dir -u http://target.com -w wordlist.txt                    # Dir brute
gobuster dns -d target.com -w subdomains.txt                         # DNS brute
gobuster vhost -u http://target.com -w vhosts.txt                    # Vhost brute
gobuster dir -u http://target.com -w wordlist.txt -x php,txt,html    # Extensions
```

#### ffuf (Fuzz Faster U Fool)
```bash
# macOS
brew install ffuf

# Go install
go install github.com/ffuf/ffuf/v2@latest

# Verify
ffuf -V
```

**Usage:**
```bash
ffuf -u http://target.com/FUZZ -w wordlist.txt                       # Dir fuzz
ffuf -u http://target.com/FUZZ -w wordlist.txt -mc 200,301,302       # Filter codes
ffuf -u "http://target.com/api?FUZZ=test" -w params.txt              # Param fuzz
ffuf -u http://target.com/ -H "Host: FUZZ.target.com" -w subs.txt    # Vhost fuzz
```

#### dirsearch
```bash
# pip install
pip install dirsearch

# Or clone
git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch && pip install -r requirements.txt

# Verify
dirsearch --version
```

**Usage:**
```bash
dirsearch -u http://target.com                                       # Default scan
dirsearch -u http://target.com -e php,asp,html                       # Extensions
dirsearch -u http://target.com -w custom-wordlist.txt                # Custom wordlist
```

### Vulnerability Scanning

#### nikto
```bash
# macOS
brew install nikto

# Ubuntu/Debian
sudo apt install nikto

# Verify
nikto -Version
```

**Usage:**
```bash
nikto -h target.com                    # Basic scan
nikto -h target.com -Tuning x          # All tuning options
nikto -h target.com -ssl               # HTTPS
nikto -h target.com -o report.html     # HTML report
```

#### nuclei
```bash
# macOS
brew install nuclei

# Go install
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Verify
nuclei -version

# Update templates
nuclei -ut
```

**Usage:**
```bash
nuclei -u http://target.com                                          # All templates
nuclei -u http://target.com -t cves/                                 # CVE templates only
nuclei -u http://target.com -severity critical,high                  # High severity
nuclei -l urls.txt -t exposures/                                     # Multiple targets
```

#### wpscan (WordPress Scanner)
```bash
# macOS
brew install wpscan

# Ruby gem
gem install wpscan

# Docker
docker pull wpscanteam/wpscan

# Verify
wpscan --version
```

**Usage:**
```bash
wpscan --url http://target.com                                       # Basic scan
wpscan --url http://target.com --enumerate u,p,t                     # Users, plugins, themes
wpscan --url http://target.com --api-token YOUR_TOKEN                # Vulnerability data
```

### SQL Injection

#### sqlmap
```bash
# macOS
brew install sqlmap

# Ubuntu/Debian
sudo apt install sqlmap

# pip
pip install sqlmap

# Verify
sqlmap --version
```

**Usage:**
```bash
sqlmap -u "http://target.com/page?id=1" --batch                      # Auto SQLi
sqlmap -u "http://target.com/page?id=1" --dbs                        # Enumerate DBs
sqlmap -u "http://target.com/page?id=1" -D dbname --tables           # Enumerate tables
sqlmap -u "http://target.com/page?id=1" -D db -T users --dump        # Dump table
sqlmap -u "http://target.com/page?id=1" --os-shell                   # OS shell
sqlmap -r request.txt --batch                                        # From Burp request
```

---

## Exploitation Tools

### Password Attacks

#### hydra
```bash
# macOS
brew install hydra

# Ubuntu/Debian
sudo apt install hydra

# Verify
hydra -V
```

**Usage:**
```bash
hydra -l admin -P passwords.txt target.com ssh                       # SSH brute
hydra -l admin -P passwords.txt target.com http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
hydra -L users.txt -P passwords.txt target.com ftp                   # FTP brute
hydra -l admin -P passwords.txt target.com mysql                     # MySQL brute
```

#### john (John the Ripper)
```bash
# macOS
brew install john

# Ubuntu/Debian
sudo apt install john

# Verify
john --version
```

**Usage:**
```bash
john --wordlist=rockyou.txt hashes.txt                               # Dictionary attack
john --format=raw-md5 hashes.txt                                     # Specify format
john --show hashes.txt                                               # Show cracked
```

#### hashcat
```bash
# macOS
brew install hashcat

# Ubuntu/Debian
sudo apt install hashcat

# Verify
hashcat --version
```

**Usage:**
```bash
hashcat -m 0 hashes.txt rockyou.txt                                  # MD5 dictionary
hashcat -m 1000 hashes.txt rockyou.txt                               # NTLM
hashcat -m 1800 hashes.txt rockyou.txt                               # sha512crypt
hashcat -a 3 -m 0 hashes.txt ?a?a?a?a?a?a                            # Brute force
```

### Exploitation Frameworks

#### searchsploit (Exploit-DB)
```bash
# Kali (pre-installed)
searchsploit --help

# Other Linux
sudo apt install exploitdb

# macOS
brew install exploitdb

# Verify
searchsploit --version
```

**Usage:**
```bash
searchsploit apache 2.4                                              # Search exploits
searchsploit -m 12345                                                # Copy exploit locally
searchsploit -x 12345                                                # View exploit
searchsploit --cve CVE-2021-44228                                    # Search by CVE
```

#### Metasploit Framework
```bash
# Kali (pre-installed)
msfconsole

# macOS
brew install --cask metasploit

# Other Linux (official installer)
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall

# Verify
msfconsole -v
```

---

## Network Tools

#### netcat (nc)
```bash
# macOS (pre-installed, or)
brew install netcat

# Ubuntu/Debian
sudo apt install netcat-openbsd

# Verify
nc -h
```

**Usage:**
```bash
nc -lvnp 4444                          # Listen for reverse shell
nc target.com 80                       # Connect to port
nc -zv target.com 1-1000               # Port scan
```

#### socat
```bash
# macOS
brew install socat

# Ubuntu/Debian
sudo apt install socat

# Verify
socat -V
```

**Usage:**
```bash
socat TCP-LISTEN:4444,fork STDOUT      # Listen
socat - TCP:target.com:80              # Connect
socat TCP-LISTEN:8080,fork TCP:target.com:80  # Port forward
```

---

## Wordlists Setup

### Rockyou.txt (Password Cracking)

The famous 14 million password wordlist. Essential for password cracking and brute forcing.

**macOS:**
```bash
# Download to ~/wordlists
mkdir -p ~/wordlists
curl -L https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -o ~/wordlists/rockyou.txt

# Or via wget
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -P ~/wordlists/
```

**Linux (Kali/Ubuntu):**
```bash
# Kali - already installed, just decompress
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# Ubuntu - install wordlists package
sudo apt install wordlists
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

**Docker (Inferno container):**
```bash
# Already available at:
/usr/share/wordlists/rockyou.txt
/rockyou.txt  # symlink for convenience
```

**Verify:**
```bash
wc -l ~/wordlists/rockyou.txt  # Should show ~14 million lines
head -20 ~/wordlists/rockyou.txt
```

### SecLists (Essential)

```bash
# Clone SecLists
git clone https://github.com/danielmiessler/SecLists.git ~/SecLists

# Or shallow clone (faster, less disk)
git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/SecLists

# Ubuntu/Debian
sudo apt install seclists
# Installed to /usr/share/seclists/
```

### Key Wordlists

| Wordlist | Path | Purpose |
|----------|------|---------|
| common.txt | `SecLists/Discovery/Web-Content/common.txt` | Quick directory scan |
| directory-list-2.3-medium.txt | `SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt` | Thorough directory scan |
| api-endpoints.txt | `SecLists/Discovery/Web-Content/api/api-endpoints-res.txt` | API endpoint discovery |
| subdomains-top1million-5000.txt | `SecLists/Discovery/DNS/subdomains-top1million-5000.txt` | Subdomain brute |
| burp-parameter-names.txt | `SecLists/Discovery/Web-Content/burp-parameter-names.txt` | Parameter fuzzing |
| rockyou.txt | `/usr/share/wordlists/rockyou.txt` (Kali) | Password cracking |
| 10k-most-common.txt | `SecLists/Passwords/Common-Credentials/10k-most-common.txt` | Quick password spray |

### Wordlist Locations by Platform

| Platform | Default Path |
|----------|--------------|
| Kali Linux | `/usr/share/wordlists/`, `/usr/share/seclists/` |
| Ubuntu (apt) | `/usr/share/seclists/` |
| macOS (manual) | `~/SecLists/` |
| Docker | `/wordlists/`, `/usr/share/seclists/` |

---

## Docker-Based Setup

### Kali Docker (All Tools)

```bash
# Pull Kali rolling
docker pull kalilinux/kali-rolling

# Run interactive
docker run -it --name inferno-kali kalilinux/kali-rolling /bin/bash

# Inside container
apt update
apt install -y kali-linux-headless seclists

# Start container later
docker start -i inferno-kali
```

### Custom Dockerfile

Create `Dockerfile.tools`:

```dockerfile
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Fix GPG keys
RUN apt-get update --allow-insecure-repositories && \
    apt-get install -y --allow-unauthenticated kali-archive-keyring

# Install tools
RUN apt-get update && apt-get install -y \
    kali-linux-headless \
    seclists \
    exploitdb \
    && apt-get clean

# Install Go tools
RUN apt-get install -y golang && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest

ENV PATH="${PATH}:/root/go/bin"

WORKDIR /workspace
```

Build and run:
```bash
docker build -t inferno-tools -f Dockerfile.tools .
docker run -it --rm -v $(pwd):/workspace inferno-tools
```

---

## Verification

### Check All Tools Script

Save as `check-tools.sh`:

```bash
#!/bin/bash

tools=(
    "nmap:nmap --version"
    "masscan:masscan --version"
    "gobuster:gobuster version"
    "ffuf:ffuf -V"
    "nikto:nikto -Version"
    "sqlmap:sqlmap --version"
    "nuclei:nuclei -version"
    "subfinder:subfinder -version"
    "amass:amass -version"
    "hydra:hydra -V"
    "john:john --version"
    "searchsploit:searchsploit --version"
    "nc:nc -h 2>&1 | head -1"
    "curl:curl --version | head -1"
    "wget:wget --version | head -1"
)

echo "=== Security Tools Check ==="
echo ""

for entry in "${tools[@]}"; do
    tool="${entry%%:*}"
    cmd="${entry##*:}"

    if command -v "$tool" &> /dev/null; then
        version=$($cmd 2>&1 | head -1)
        echo "✓ $tool: $version"
    else
        echo "✗ $tool: NOT INSTALLED"
    fi
done

echo ""
echo "=== Wordlists Check ==="

wordlist_paths=(
    "/usr/share/seclists"
    "/usr/share/wordlists"
    "$HOME/SecLists"
)

for path in "${wordlist_paths[@]}"; do
    if [ -d "$path" ]; then
        count=$(find "$path" -type f -name "*.txt" 2>/dev/null | wc -l)
        echo "✓ $path: $count wordlist files"
    else
        echo "✗ $path: NOT FOUND"
    fi
done
```

Run it:
```bash
chmod +x check-tools.sh
./check-tools.sh
```

### Quick Verification Commands

```bash
# Network tools
nmap --version && echo "nmap OK"
masscan --version && echo "masscan OK"

# Web tools
gobuster version && echo "gobuster OK"
ffuf -V && echo "ffuf OK"
nikto -Version && echo "nikto OK"

# Exploitation
sqlmap --version && echo "sqlmap OK"
searchsploit --version && echo "searchsploit OK"
hydra -V && echo "hydra OK"

# Wordlists
ls /usr/share/seclists/Discovery/Web-Content/common.txt && echo "SecLists OK"
```

---

## Troubleshooting

### Tool Not Found

```bash
# Check if in PATH
which nmap
echo $PATH

# Reinstall
brew reinstall nmap          # macOS
sudo apt install --reinstall nmap  # Ubuntu
```

### Permission Denied

```bash
# Some tools need root
sudo nmap -sS target.com
sudo masscan -p1-65535 target.com --rate=1000
```

### Go Tools Not Found

```bash
# Add Go bin to PATH
export PATH=$PATH:$(go env GOPATH)/bin

# Add to ~/.bashrc or ~/.zshrc
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

### Docker Permission Denied

```bash
# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

---

## Next Steps

- [Installation Guide](INSTALL.md)
- [Authentication Setup](AUTHENTICATION.md)
- [Usage Guide](USAGE.md)
