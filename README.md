# Security Checks Documentation

This document provides detailed technical information about each security check performed by the AD Security Audit tool, including the underlying vulnerabilities, detection methods, and risk assessments.

## Table of Contents

1. [Old Password Detection](#old-password-detection)
2. [Kerberoasting Vulnerability Assessment](#kerberoasting-vulnerability-assessment)
3. [Privileged Group Auditing](#privileged-group-auditing)
4. [LDAP NULL Bind Testing](#ldap-null-bind-testing)
5. [Password Exposure in Descriptions](#password-exposure-in-descriptions)
6. [SYSVOL Password Analysis](#sysvol-password-analysis)

---

## Old Password Detection

### Overview
Identifies user accounts with passwords that exceed the configured age threshold, indicating potential security risks from stale or compromised credentials.

### Technical Details

#### LDAP Query
```powershell
Get-ADUser -Filter {Enabled -eq $true} -Properties PasswordLastSet, PasswordNeverExpires, LastLogonDate
```

#### Detection Logic
- Filters enabled user accounts only
- Excludes accounts with `PasswordNeverExpires` set to true
- Compares `PasswordLastSet` attribute against threshold date
- Sorts results by password age (oldest first)

#### Risk Assessment
| Risk Level | Criteria | Impact |
|------------|----------|--------|
| **Critical** | Password >180 days old | High likelihood of compromise |
| **High** | Password >120 days old | Increased vulnerability window |
| **Medium** | Password >90 days old | Standard policy violation |
| **Low** | Password >60 days old | Early warning indicator |

### Security Implications

**Attack Vectors:**
- Password spraying attacks against old passwords
- Credential stuffing using leaked password databases
- Social engineering targeting users with old passwords
- Brute force attacks with higher success probability

**Business Impact:**
- Unauthorized access to user accounts
- Lateral movement within the network
- Data exfiltration or destruction
- Compliance violations (SOX, HIPAA, PCI-DSS)

### Remediation Priority
🔴 **High Priority** - Passwords >120 days should be reset immediately

---

## Kerberoasting Vulnerability Assessment

### Overview
Detects service accounts configured with Service Principal Names (SPNs) that are vulnerable to Kerberoasting attacks, where attackers can extract and crack service account passwords offline.

### Technical Details

#### LDAP Query
```powershell
Get-ADUser -Filter {ServicePrincipalName -ne $null} -Properties ServicePrincipalName, PasswordLastSet, Enabled
```

#### Detection Logic
- Identifies all user accounts with SPNs configured
- Checks if accounts are enabled
- Analyzes password age for enabled service accounts
- Lists all SPNs associated with each account

#### Vulnerability Scoring
| Score | Criteria | Risk Level |
|-------|----------|------------|
| **10** | Enabled + Password never set | Critical |
| **9** | Enabled + Password >365 days | Critical |
| **8** | Enabled + Password >180 days | High |
| **6** | Enabled + Password >90 days | Medium |
| **3** | Disabled account with SPN | Low |

### Attack Methodology

**Kerberoasting Process:**
1. **Discovery**: Attacker enumerates SPNs using tools like `setspn` or `PowerView`
2. **Request**: Requests Kerberos service tickets (TGS) for identified SPNs
3. **Extraction**: Extracts encrypted password hash from TGS tickets
4. **Cracking**: Performs offline password cracking using tools like Hashcat
5. **Access**: Uses cracked credentials for lateral movement

**Common Tools:**
- Rubeus
- Invoke-Kerberoast
- GetUserSPNs.py (Impacket)
- Hashcat for offline cracking

### Security Implications

**Attack Scenarios:**
- Service account compromise leading to application access
- Database server compromise via SQL service accounts
- File server access through backup service accounts
- Web application compromise via IIS service accounts

**Detection Challenges:**
- Kerberos ticket requests appear legitimate
- No authentication failures generated
- Difficult to distinguish from normal service requests

### Remediation Priority
🔴 **Critical Priority** - All enabled service accounts with SPNs require immediate attention

---

## Privileged Group Auditing

### Overview
Reviews membership in high-privilege Active Directory groups to identify excessive access rights and potential security risks from over-privileged accounts.

### Technical Details

#### Monitored Groups
```powershell
$privilegedGroups = @(
    'Domain Admins',        # Full domain control
    'Enterprise Admins',    # Forest-wide control
    'Schema Admins',        # Schema modification rights
    'Administrators',       # Local admin on DCs
    'Account Operators',    # User/group management
    'Server Operators',     # Server management
    'Print Operators',      # Print server management
    'Backup Operators'      # Backup/restore rights
)
```

#### Analysis Criteria
- Member count exceeding configured threshold
- Enabled vs disabled account status
- Last logon date analysis
- Nested group membership evaluation

#### Risk Matrix
| Group | Max Recommended | Typical Risk |
|-------|-----------------|--------------|
| Domain Admins | 2-3 | Critical |
| Enterprise Admins | 1-2 | Critical |
| Schema Admins | 1 | High |
| Administrators | 3-5 | High |
| Account Operators | 5-10 | Medium |
| Server Operators | 5-10 | Medium |

### Security Implications

**Over-Privileged Risks:**
- Increased attack surface for privilege escalation
- Higher likelihood of insider threats
- Difficulty in access control management
- Compliance violations

**Attack Scenarios:**
- Compromise of over-privileged service accounts
- Insider threat with excessive permissions
- Credential theft targeting high-value accounts
- Lateral movement using privileged credentials

### Remediation Priority
🟡 **Medium Priority** - Review and reduce membership systematically

---

## LDAP NULL Bind Testing

### Overview
Tests for the ability to perform anonymous LDAP binds against domain controllers, which can expose directory information to unauthenticated users.

### Technical Details

#### Test Methodology
```powershell
$ldapPath = "LDAP://$env:USERDNSDOMAIN"
$anonymousEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
$schemaContext = $anonymousEntry.SchemaEntry
```

#### Detection Logic
- Creates DirectoryEntry without credentials
- Attempts to access schema information
- Tests read access to directory objects
- Evaluates anonymous query capabilities

#### Vulnerability Assessment
| Access Level | Risk | Impact |
|--------------|------|--------|
| Full Directory Read | Critical | Complete information disclosure |
| Schema Access Only | High | Structure enumeration possible |
| Limited Object Access | Medium | Partial information disclosure |
| No Anonymous Access | Secure | Proper configuration |

### Security Implications

**Information Disclosure:**
- User account enumeration
- Group membership discovery
- Organizational unit structure
- Computer account information
- Service account identification

**Attack Enhancement:**
- Reconnaissance for targeted attacks
- Username harvesting for password spraying
- Service discovery for lateral movement
- Infrastructure mapping

### Remediation Priority
🟡 **Medium Priority** - Disable unless specifically required for applications

---

## Password Exposure in Descriptions

### Overview
Scans Active Directory user description fields for potential password exposure using advanced pattern matching to identify various password formats and obfuscation attempts.

### Technical Details

#### Pattern Detection
```regex
# Standard formats
(?i)password\s*[:=]\s*\S+
(?i)pwd\s*[:=]\s*\S+
(?i)pass\s*[:=]\s*\S+

# Obfuscated formats
(?i)p@ssw[0o]rd\s*[:=]\s*\S+

# Complex passwords
\b[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,}\b(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])
```

#### Analysis Process
1. Retrieve all enabled users with populated descriptions
2. Apply pattern matching against description content
3. Score matches based on complexity and format
4. Generate detailed findings with context

#### Risk Classification
| Pattern Type | Risk Level | Example |
|--------------|------------|---------|
| Explicit Password | Critical | "password=MyPass123" |
| Common Abbreviations | High | "pwd: TempPassword" |
| Obfuscated Text | Medium | "p@ssw0rd = SecretValue" |
| Complex Strings | Low | Random character sequences |

### Security Implications

**Immediate Risks:**
- Direct credential exposure
- Password pattern analysis
- Dictionary attack vectors
- Social engineering intelligence

**Compliance Issues:**
- Data protection violations
- Audit finding escalation  
- Regulatory non-compliance
- Policy violation documentation

### Remediation Priority
🔴 **Critical Priority** - Immediate removal and password reset required

---

## SYSVOL Password Analysis

### Overview
Searches SYSVOL files for hardcoded passwords, credentials, and sensitive information that could be exploited by attackers with domain access.

### Technical Details

#### Scan Parameters
```powershell
$fileExtensions = @('*.xml', '*.txt', '*.ini', '*.cfg', '*.conf', '*.bat', '*.cmd', '*.ps1', '*.vbs')
$passwordPatterns = @('password', 'pwd', 'pass', 'cpassword')
```

#### File Analysis Process
1. Enumerate SYSVOL share structure
2. Filter files by extension and accessibility
3. Content analysis using pattern matching
4. Context extraction around matches
5. Risk assessment based on file type and content

#### Common Findings
| File Type | Risk Level | Common Content |
|-----------|------------|----------------|
| Group Policy XML | Critical | Encrypted passwords (reversible) |
