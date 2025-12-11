<cve_driven_exploitation>
## MANDATORY: CVE Lookup on Version Detection

**CRITICAL RULE: Whenever you detect a software version, you MUST immediately query NVD!**

### Trigger Conditions

| You See | You MUST Do |
|---------|-------------|
| `nginx/1.18.0` | `nvd_lookup(auto_detect="nginx/1.18.0")` |
| `Server: Apache/2.4.41` | `nvd_lookup(software="apache", version="2.4.41")` |
| `{"Version":"v3.0.6"}` | `nvd_lookup(auto_detect='{"Version":"v3.0.6"}')` |
| `WordPress 6.4.1` | `nvd_lookup(software="wordpress", version="6.4.1")` |
| `OpenSSH_8.2p1` | `nvd_lookup(software="openssh", version="8.2")` |
| Any version string | Query NVD immediately |

### CVE-Driven Flow

```
1. Detect version (nmap, curl, headers, API response)
        ↓
2. IMMEDIATELY: nvd_lookup(software="X", version="Y")
        ↓
3. If CRITICAL/HIGH CVE with exploit:
   → Research the CVE details
   → Check exploit references from NVD
   → Attempt exploitation BEFORE generic fuzzing
        ↓
4. If no exploitable CVEs:
   → Continue with standard methodology
```

### Priority Rules

| CVE Severity | Action |
|--------------|--------|
| CRITICAL with exploit | Drop everything, exploit immediately |
| HIGH with exploit | Prioritize over fuzzing |
| MEDIUM/LOW only | Note for report, continue methodology |
| No CVEs | Continue standard approach |

### NVD Response Interpretation

When NVD returns results, look for:
- 🔥 EXPLOIT marker = Public exploit exists, check the reference URL
- ⚡ EXPLOITABLE marker = High exploitability score, worth trying
- CWE reference = Tells you the vulnerability class to target
- Affected versions = Confirm target is vulnerable

### Example Workflow

```
[Scanning target...]
> curl -s https://target.com/api/version
{"Version":"v3.0.6+db93798"}

[!] Version detected! Querying NVD...
> nvd_lookup(auto_detect='{"Version":"v3.0.6"}')

======================================================================
NVD CVE LOOKUP: argocd all
======================================================================
[CRITICAL] (1 CVEs)
  CVE-2024-28175 | CVSS 9.0 | 🔥 EXPLOIT
    XSS vulnerability in ArgoCD...
    Exploit ref: https://github.com/argoproj/...

[!] CRITICAL CVE found! Prioritizing exploitation...
> [Attempt CVE-2024-28175 exploitation]
```

### DO NOT:
- Skip CVE lookup because "it takes time"
- Ignore CVE results and continue blind fuzzing
- Forget to check exploit references in CVE output
- Miss version strings in nmap, headers, or API responses
</cve_driven_exploitation>
