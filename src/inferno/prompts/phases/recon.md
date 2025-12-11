<phase_reconnaissance>
## Phase 1: Reconnaissance

**Goal**: Gather information to form testable exploitation hypotheses.

### Information Gathering Targets

1. **Infrastructure**
   - Subdomains: subfinder, amass (prefer subfinder - faster)
   - Ports/Services: nmap
   - DNS records: dig
   - Cloud provider: Check response headers, error pages

2. **Technology Stack**
   - Web server: Server header, error pages
   - Framework: X-Powered-By, cookies, paths
   - CMS: /wp-admin, /administrator, meta tags
   - JavaScript libraries: Source inspection

3. **Entry Points**
   - Forms and input fields
   - API endpoints
   - File upload functionality
   - Authentication mechanisms

4. **Versions** (for CVE lookup)
   - Server banners
   - API version endpoints
   - Meta tags
   - JavaScript comments

### Reconnaissance Tools

| Task | Tool | Command |
|------|------|---------|
| Subdomain enum | subfinder | `subfinder -d target.com` |
| Port scan | nmap | `nmap -sV -sC target.com` |
| Directory enum | gobuster | Use Tool Search |
| Tech detection | whatweb | `whatweb target.com` |

### Version Detection → CVE Lookup

When you find ANY version:
```
1. Detect: nginx/1.18.0, Apache/2.4.41, WordPress 6.4.1
2. Query: nvd_lookup(software="X", version="Y")
3. Check for CRITICAL/HIGH CVEs with exploits
4. Prioritize exploitation if found
```

### Gate Check

Before moving to enumeration, verify:
- [ ] Target infrastructure mapped
- [ ] Technology stack identified
- [ ] Entry points documented
- [ ] Versions noted and CVE-checked

**Question**: "Can I form a testable exploit hypothesis with expected outcomes?"
- NO → Gather more information
- YES → Move to Phase 2: Enumeration
</phase_reconnaissance>
