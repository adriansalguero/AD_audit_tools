# AD_audit_tools

# Invoke-ADSecurityAudit.ps1

## Overview

The `Invoke-ADSecurityAudit.ps1` script is a comprehensive Active Directory security assessment tool that identifies common misconfigurations and vulnerabilities that could lead to domain compromise.

## Synopsis

```powershell
Invoke-ADSecurityAudit.ps1 
    [-CheckType <String[]>] 
    [-PasswordAge <Int32>] 
    [-PrivilegedGroupThreshold <Int32>] 
    [-OutputPath <String>] 
    [-Interactive] 
    [-ShowProgress]
```

## Description

This script performs six critical security checks against Active Directory environments:

1. **Old Password Detection** - Identifies accounts with passwords exceeding age thresholds
2. **Kerberoasting Vulnerability Assessment** - Detects service accounts susceptible to Kerberoasting attacks
3. **Privileged Group Auditing** - Reviews membership in high-privilege Active Directory groups
4. **LDAP NULL Bind Testing** - Checks for anonymous LDAP access vulnerabilities
5. **Password Exposure in Descriptions** - Scans user description fields for exposed credentials
6. **SYSVOL Password Analysis** - Searches SYSVOL files for hardcoded passwords

## Parameters

### CheckType
- **Type**: String[]
- **Default**: All
- **Valid Values**: All, OldPasswords, Kerberoasting, PrivilegedGroups, LDAPNullBind, PasswordsInDescription, PasswordsInSYSVOL
- **Description**: Specifies which security checks to perform

### PasswordAge
- **Type**: Int32
- **Default**: 90
- **Range**: 1-365
- **Description**: Password age threshold in days for old password detection

### PrivilegedGroupThreshold
- **Type**: Int32
- **Default**: 5
- **Range**: 1-50
- **Description**: Maximum number of members allowed in privileged groups before flagging

### OutputPath
- **Type**: String
- **Default**: None
- **Description**: File path to save audit results in JSON format
- **Validation**: Parent directory must exist

### Interactive
- **Type**: Switch
- **Default**: False
- **Description**: Enables interactive mode with user prompts for each check

### ShowProgress
- **Type**: Switch
- **Default**: True
- **Description**: Controls display of progress bars during execution

## Examples

### Example 1: Basic Audit
```powershell
.\Invoke-ADSecurityAudit.ps1
```
Runs all security checks with default parameters in non-interactive mode.

### Example 2: Targeted Assessment
```powershell
.\Invoke-ADSecurityAudit.ps1 -CheckType OldPasswords,Kerberoasting -PasswordAge 120
```
Performs only password age and Kerberoasting checks with a 120-day password threshold.

### Example 3: Interactive Mode with Export
```powershell
.\Invoke-ADSecurityAudit.ps1 -Interactive -OutputPath "C:\Audit\AD-Security-Report.json" -Verbose
```
Runs in interactive mode, saves results to JSON, and provides verbose output.

### Example 4: Privileged Group Focus
```powershell
.\Invoke-ADSecurityAudit.ps1 -CheckType PrivilegedGroups -PrivilegedGroupThreshold 3
```
Audits only privileged groups with a stricter threshold of 3 members maximum.

### Example 5: Password Security Assessment
```powershell
.\Invoke-ADSecurityAudit.ps1 -CheckType OldPasswords,PasswordsInDescription,PasswordsInSYSVOL -PasswordAge 60
```
Focuses on password-related security issues with a 60-day age threshold.

## Detailed Check Descriptions

### Old Password Check
- **Purpose**: Identifies accounts with passwords older than the specified threshold
- **Risk**: Old passwords are more likely to be compromised or weak
- **Output**: List of accounts with password age and last logon information
- **Remediation**: Implement password expiration policies and user education

### Kerberoasting Vulnerability Check
- **Purpose**: Detects service accounts with Service Principal Names (SPNs)
- **Risk**: These accounts are vulnerable to Kerberoasting attacks
- **Output**: Service accounts with SPNs, password ages, and enabled status
- **Remediation**: Use managed service accounts (MSAs) and strong passwords

### Privileged Group Check
- **Purpose**: Audits membership in high-privilege Active Directory groups
- **Risk**: Excessive privileged access increases attack surface
- **Output**: Group membership counts and member details
- **Remediation**: Implement least privilege access and regular access reviews

### LDAP NULL Bind Check
- **Purpose**: Tests for anonymous LDAP access capabilities
- **Risk**: Anonymous access can expose directory information
- **Output**: Whether anonymous LDAP binding is enabled
- **Remediation**: Disable anonymous LDAP access in domain controller settings

### Passwords in Description Check
- **Purpose**: Scans user description fields for potential password exposure
- **Risk**: Plaintext passwords in descriptions pose immediate security risk
- **Output**: Users with suspicious description content
- **Remediation**: Remove passwords from descriptions and educate users

### SYSVOL Password Check
- **Purpose**: Searches SYSVOL files for hardcoded passwords
- **Risk**: Scripts and configurations may contain embedded credentials
- **Output**: Files containing potential password references
- **Remediation**: Remove hardcoded credentials and use secure alternatives

## Output Format

### Console Output
The script provides color-coded console output:
- **Green [+]**: Successful checks or secure configurations
- **Yellow [!]**: Warnings or potential issues
- **Red [-]**: Failed checks or security vulnerabilities
- **Cyan [=]**: Section headers and summary information
- **White [*]**: General information

### JSON Export Format
When using `-OutputPath`, results are saved in structured JSON format:

```json
{
  "Timestamp": "2025-06-10 14:30:15",
  "Domain": "contoso.com",
  "ExecutedBy": "security.admin",
  "Parameters": {
    "CheckType": ["All"],
    "PasswordAge": 90,
    "PrivilegedGroupThreshold": 5,
    "Interactive": false
  },
  "Results": {
    "OldPasswords": {
      "Status": "Fail",
      "Message": "Found 12 accounts with passwords older than 90 days",
      "Details": [...],
      "Timestamp": "2025-06-10 14:30:45"
    }
  },
  "Summary": {
    "TotalChecks": 6,
    "PassedChecks": 2,
    "FailedChecks": 3,
    "Warnings": 1,
    "ExecutionTime": "00:02:34.156"
  }
}
```

## Requirements

### System Requirements
- **Operating System**: Windows 10/11, Windows Server 2016+
- **PowerShell**: Version 5.1 or higher (PowerShell 7+ recommended)
- **Modules**: Active Directory PowerShell module
- **Network**: Connectivity to domain controllers

### Permissions Required
- **Minimum**: Domain User account
- **Recommended**: Account with the following delegated permissions:
  - Read all user objects and properties
  - Read group membership
  - Access to SYSVOL share
  - LDAP query permissions

### Installation Prerequisites
```powershell
# Install Active Directory module (if not already installed)
Install-WindowsFeature -Name RSAT-AD-PowerShell

# Or on Windows 10/11
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

## Performance Considerations

### Large Environments
For environments with >10,000 users:
- Use specific check types rather than "All"
- Disable progress bars with `-ShowProgress:$false`
- Run during off-peak hours
- Consider running from a domain controller for better performance

### Memory Usage
- Script uses minimal memory footprint
- Large result sets are processed incrementally
- JSON export may require additional memory for serialization

### Network Impact
- Uses efficient LDAP queries with appropriate filters
- Minimal network traffic for most checks
- SYSVOL check generates more network I/O

## Error Handling

The script implements comprehensive error handling:
- **Module Import Errors**: Script exits gracefully if AD module unavailable
- **Permission Errors**: Individual check failures don't stop other checks
- **Network Errors**: Timeout and retry logic for network operations
- **File Access Errors**: Proper handling of inaccessible SYSVOL files

## Security Considerations

### Data Sensitivity
- Script output may contain sensitive information
- JSON exports should be stored securely
- Consider redacting sensitive details in shared reports

### Execution Security
- Script follows PowerShell security best practices
- No credential handling or storage
- Uses read-only operations where possible
- Validates all user inputs

## Troubleshooting

### Common Issues

**"Access Denied" Errors**
```
Cause: Insufficient permissions to read AD objects
Solution: Verify account has Domain User privileges minimum
```

**"Module Not Found" Errors**
```
Cause: Active Directory PowerShell module not installed
Solution: Install RSAT tools or AD management features
```

**SYSVOL Access Issues**
```
Cause: Network connectivity or share permission issues
Solution: Verify SYSVOL share accessibility and permissions
```

**Performance Issues**
```
Cause: Large environment or network latency
Solution: Use targeted checks and disable progress indicators
```

### Debug Information
Enable debug output for troubleshooting:
```powershell
.\Invoke-ADSecurityAudit.ps1 -Debug -Verbose
```

## Version History

- **v2.0.0**: Complete rewrite with enhanced features and professional output
- **v1.0.0**: Initial version with basic security checks

## Related Files

- `SECURITY_CHECKS.md`: Detailed technical information about each security check
- `REMEDIATION_GUIDE.md`: Step-by-step remediation procedures
- `examples/`: Sample usage scenarios and output examples
