<context_network_security>
## Network Security Assessment

### Reconnaissance

1. **Host Discovery**
   - Ping sweep
   - ARP scan
   - DNS enumeration

2. **Port Scanning**
   - TCP full scan
   - UDP important ports
   - Service version detection

3. **Service Fingerprinting**
   - Banner grabbing
   - Protocol detection
   - Version identification

### Common Services

| Port | Service | Tests |
|------|---------|-------|
| 21 | FTP | Anonymous access, version CVEs |
| 22 | SSH | Weak creds, version CVEs |
| 23 | Telnet | Default creds, sniffing |
| 25 | SMTP | Relay, user enum |
| 53 | DNS | Zone transfer, cache poison |
| 80/443 | HTTP/S | Web app testing |
| 110/143 | POP/IMAP | Weak creds |
| 139/445 | SMB | Null sessions, CVEs |
| 3306 | MySQL | Weak creds, remote access |
| 3389 | RDP | Weak creds, BlueKeep |
| 5432 | PostgreSQL | Weak creds, remote access |
| 5900 | VNC | No auth, weak password |
| 6379 | Redis | No auth, RCE |
| 27017 | MongoDB | No auth, exposure |

### Network Attack Vectors

**SMB Attacks**:
```
- Null session enumeration
- Share enumeration
- EternalBlue (MS17-010)
- Password spraying
```

**SSH Attacks**:
```
- Password brute force
- Key-based auth bypass
- Version-specific CVEs
- Weak key detection
```

**Database Attacks**:
```
- Default credentials
- Remote code execution
- Data exfiltration
- Privilege escalation
```

### Scanning Commands

**Nmap**:
```bash
# Quick scan
nmap -sV -sC -O target

# Full TCP
nmap -p- -sV target

# UDP
nmap -sU --top-ports 100 target

# Aggressive
nmap -A -T4 target
```

**Service-Specific**:
```bash
# SMB
smbclient -L //target -N
enum4linux target

# SSH
hydra -l root -P wordlist.txt ssh://target

# FTP
ftp target (try anonymous)

# SNMP
snmpwalk -c public target
```

### Credential Attacks

**Default Credentials by Service**:
| Service | Common Creds |
|---------|--------------|
| SSH | root:root, admin:admin |
| MySQL | root:(blank), root:root |
| PostgreSQL | postgres:postgres |
| Redis | (no auth default) |
| MongoDB | (no auth default) |
| Tomcat | admin:admin, tomcat:tomcat |

### Post-Exploitation Network

After gaining access:
1. Identify network segments
2. Scan for internal services
3. Check for trust relationships
4. Look for shared credentials
5. Identify high-value targets
</context_network_security>
