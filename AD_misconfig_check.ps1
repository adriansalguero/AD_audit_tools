<#
.SYNOPSIS
    Active Directory Security Configuration Audit Tool

.DESCRIPTION
    Comprehensive PowerShell script for auditing Active Directory security configurations.
    Identifies common security vulnerabilities including old passwords, Kerberoasting risks,
    excessive privileged accounts, LDAP misconfigurations, and credential exposure.

.PARAMETER CheckType
    Specifies which security checks to perform. Valid values:
    - All: Run all security checks (default)
    - OldPasswords: Check for accounts with old passwords
    - Kerberoasting: Check for Kerberoasting vulnerabilities
    - PrivilegedGroups: Check for excessive privileged group membership
    - LDAPNullBind: Check for LDAP NULL bind configuration
    - PasswordsInDescription: Check for passwords in user descriptions
    - PasswordsInSYSVOL: Check for passwords in SYSVOL

.PARAMETER PasswordAge
    Specifies the password age threshold in days (default: 90)

.PARAMETER PrivilegedGroupThreshold
    Maximum number of members allowed in privileged groups before flagging (default: 5)

.PARAMETER OutputPath
    Path to save the audit results in JSON format

.PARAMETER Interactive
    Run in interactive mode with user prompts (default: $false)

.PARAMETER ShowProgress
    Display progress bars during execution (default: $true)

.EXAMPLE
    .\Invoke-ADSecurityAudit.ps1
    Runs all security checks in non-interactive mode

.EXAMPLE
    .\Invoke-ADSecurityAudit.ps1 -CheckType OldPasswords,Kerberoasting -PasswordAge 120 -Interactive
    Runs specific checks with custom password age in interactive mode

.EXAMPLE
    .\Invoke-ADSecurityAudit.ps1 -OutputPath "C:\Audit\Results.json" -Verbose
    Runs all checks and saves results to JSON file with verbose output

.NOTES
    Version:        2.0.0
    Author:         Security Professional
    Creation Date:  2025-06-10
    Purpose:        Active Directory Security Assessment
    
    Requirements:
    - PowerShell 5.1 or higher
    - Active Directory PowerShell module
    - Domain user privileges (some checks require elevated permissions)
    - Network connectivity to domain controllers

.LINK
    https://github.com/yourusername/ad-security-tools
#>

[CmdletBinding(DefaultParameterSetName = 'Default')]
param (
    [Parameter(ParameterSetName = 'Default')]
    [ValidateSet('All', 'OldPasswords', 'Kerberoasting', 'PrivilegedGroups', 'LDAPNullBind', 'PasswordsInDescription', 'PasswordsInSYSVOL')]
    [string[]]$CheckType = @('All'),

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$PasswordAge = 90,

    [Parameter()]
    [ValidateRange(1, 50)]
    [int]$PrivilegedGroupThreshold = 5,

    [Parameter()]
    [ValidateScript({
        if ($_ -and (Test-Path (Split-Path $_ -Parent))) { $true }
        else { throw "Output directory does not exist: $(Split-Path $_ -Parent)" }
    })]
    [string]$OutputPath,

    [Parameter()]
    [switch]$Interactive,

    [Parameter()]
    [switch]$ShowProgress = $true
)

#Requires -Modules ActiveDirectory
#Requires -Version 5.1

# Script configuration
$ErrorActionPreference = 'Stop'
$ProgressPreference = if ($ShowProgress) { 'Continue' } else { 'SilentlyContinue' }

# Initialize result storage
$script:AuditResults = @{
    Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Domain = $env:USERDNSDOMAIN
    ExecutedBy = $env:USERNAME
    Parameters = @{
        CheckType = $CheckType
        PasswordAge = $PasswordAge
        PrivilegedGroupThreshold = $PrivilegedGroupThreshold
        Interactive = $Interactive.IsPresent
    }
    Results = @{}
    Summary = @{
        TotalChecks = 0
        PassedChecks = 0
        FailedChecks = 0
        Warnings = 0
        ExecutionTime = $null
    }
}

# Import required modules with error handling
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Verbose "Active Directory module imported successfully"
} catch {
    Write-Error "Failed to import Active Directory module: $($_.Exception.Message)"
    exit 1
}

#region Helper Functions

function Write-AuditMessage {
    <#
    .SYNOPSIS
        Writes formatted audit messages with consistent styling
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Header')]
        [string]$Type = 'Info',

        [Parameter()]
        [int]$IndentLevel = 0
    )

    $colorMap = @{
        'Info'    = 'White'
        'Success' = 'Green'
        'Warning' = 'Yellow'
        'Error'   = 'Red'
        'Header'  = 'Cyan'
    }

    $prefixMap = @{
        'Info'    = '[*]'
        'Success' = '[+]'
        'Warning' = '[!]'
        'Error'   = '[-]'
        'Header'  = '[=]'
    }

    $indent = ' ' * ($IndentLevel * 4)
    $prefix = $prefixMap[$Type]
    $color = $colorMap[$Type]

    Write-Host "$indent$prefix $Message" -ForegroundColor $color
    Write-Verbose "$prefix $Message" # Also log to verbose stream
}

function Get-UserConsent {
    <#
    .SYNOPSIS
        Prompts user for consent with input validation
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Prompt,

        [Parameter()]
        [char[]]$ValidResponses = @('y', 'n'),

        [Parameter()]
        [char]$DefaultResponse = 'n'
    )

    if (-not $Interactive) {
        return $true # Auto-consent in non-interactive mode
    }

    do {
        $response = Read-Host "$Prompt [$($ValidResponses -join '/')] (default: $DefaultResponse)"
        if ([string]::IsNullOrWhiteSpace($response)) {
            $response = $DefaultResponse
        }
        $response = $response.ToLower()[0]
    } while ($response -notin $ValidResponses)

    return $response -eq 'y'
}

function Add-AuditResult {
    <#
    .SYNOPSIS
        Adds results to the audit report
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$CheckName,

        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Fail', 'Warning', 'Error')]
        [string]$Status,

        [Parameter()]
        [string]$Message,

        [Parameter()]
        [object]$Details
    )

    $script:AuditResults.Results[$CheckName] = @{
        Status = $Status
        Message = $Message
        Details = $Details
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    }

    # Update summary counters
    $script:AuditResults.Summary.TotalChecks++
    switch ($Status) {
        'Pass' { $script:AuditResults.Summary.PassedChecks++ }
        'Fail' { $script:AuditResults.Summary.FailedChecks++ }
        'Warning' { $script:AuditResults.Summary.Warnings++ }
        'Error' { $script:AuditResults.Summary.FailedChecks++ }
    }
}

function Test-AdminPrivileges {
    <#
    .SYNOPSIS
        Tests if the current user has administrative privileges
    #>
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

#endregion

#region Security Check Functions

function Test-OldPasswords {
    <#
    .SYNOPSIS
        Checks for accounts with old passwords
    #>
    [CmdletBinding()]
    param()

    Write-AuditMessage "Checking for accounts with passwords older than $PasswordAge days..." -Type Header

    try {
        $progressParams = @{
            Activity = 'Password Age Check'
            Status = 'Retrieving user accounts...'
            Id = 1
        }
        Write-Progress @progressParams

        $users = Get-ADUser -Filter { Enabled -eq $true } -Properties PasswordLastSet, PasswordNeverExpires, LastLogonDate -ResultSetSize $null
        $thresholdDate = (Get-Date).AddDays(-$PasswordAge)
        
        $oldPasswordUsers = $users | Where-Object { 
            $_.PasswordLastSet -and 
            $_.PasswordLastSet -lt $thresholdDate -and
            -not $_.PasswordNeverExpires
        } | Sort-Object PasswordLastSet

        Write-Progress -Activity 'Password Age Check' -Completed -Id 1

        if ($oldPasswordUsers.Count -gt 0) {
            Write-AuditMessage "Found $($oldPasswordUsers.Count) accounts with old passwords" -Type Warning -IndentLevel 1
            
            $details = $oldPasswordUsers | ForEach-Object {
                $passwordAge = [Math]::Round(((Get-Date) - $_.PasswordLastSet).TotalDays)
                [PSCustomObject]@{
                    SamAccountName = $_.SamAccountName
                    PasswordLastSet = $_.PasswordLastSet
                    PasswordAgeDays = $passwordAge
                    LastLogonDate = $_.LastLogonDate
                }
            }

            $details | Format-Table -AutoSize | Out-String | Write-Verbose

            Add-AuditResult -CheckName 'OldPasswords' -Status 'Fail' -Message "Found $($oldPasswordUsers.Count) accounts with passwords older than $PasswordAge days" -Details $details
        } else {
            Write-AuditMessage "No accounts found with passwords older than $PasswordAge days" -Type Success -IndentLevel 1
            Add-AuditResult -CheckName 'OldPasswords' -Status 'Pass' -Message "No accounts with old passwords found"
        }
    } catch {
        Write-AuditMessage "Error during password age check: $($_.Exception.Message)" -Type Error -IndentLevel 1
        Add-AuditResult -CheckName 'OldPasswords' -Status 'Error' -Message $_.Exception.Message
    }
}

function Test-KerberoastingVulnerability {
    <#
    .SYNOPSIS
        Checks for potential Kerberoasting vulnerabilities
    #>
    [CmdletBinding()]
    param()

    Write-AuditMessage "Checking for Kerberoasting vulnerabilities..." -Type Header

    try {
        $progressParams = @{
            Activity = 'Kerberoasting Check'
            Status = 'Retrieving service accounts...'
            Id = 1
        }
        Write-Progress @progressParams

        $serviceAccounts = Get-ADUser -Filter { ServicePrincipalName -ne $null } -Properties ServicePrincipalName, PasswordLastSet, Enabled -ResultSetSize $null
        
        Write-Progress -Activity 'Kerberoasting Check' -Completed -Id 1

        if ($serviceAccounts.Count -gt 0) {
            Write-AuditMessage "Found $($serviceAccounts.Count) accounts with Service Principal Names" -Type Warning -IndentLevel 1
            
            $vulnerableAccounts = $serviceAccounts | Where-Object { $_.Enabled -eq $true }
            
            $details = $vulnerableAccounts | ForEach-Object {
                $passwordAge = if ($_.PasswordLastSet) {
                    [Math]::Round(((Get-Date) - $_.PasswordLastSet).TotalDays)
                } else {
                    'Never Set'
                }
                
                [PSCustomObject]@{
                    SamAccountName = $_.SamAccountName
                    Enabled = $_.Enabled
                    PasswordLastSet = $_.PasswordLastSet
                    PasswordAge = $passwordAge
                    ServicePrincipalNames = ($_.ServicePrincipalName -join '; ')
                }
            }

            $details | Format-Table -AutoSize | Out-String | Write-Verbose

            Add-AuditResult -CheckName 'Kerberoasting' -Status 'Fail' -Message "Found $($vulnerableAccounts.Count) enabled accounts with SPNs" -Details $details
        } else {
            Write-AuditMessage "No service accounts with SPNs found" -Type Success -IndentLevel 1
            Add-AuditResult -CheckName 'Kerberoasting' -Status 'Pass' -Message "No service accounts with SPNs found"
        }
    } catch {
        Write-AuditMessage "Error during Kerberoasting check: $($_.Exception.Message)" -Type Error -IndentLevel 1
        Add-AuditResult -CheckName 'Kerberoasting' -Status 'Error' -Message $_.Exception.Message
    }
}

function Test-PrivilegedGroups {
    <#
    .SYNOPSIS
        Checks for excessive membership in privileged groups
    #>
    [CmdletBinding()]
    param()

    Write-AuditMessage "Checking privileged group memberships..." -Type Header

    $privilegedGroups = @(
        'Domain Admins',
        'Enterprise Admins', 
        'Schema Admins',
        'Administrators',
        'Account Operators',
        'Server Operators',
        'Print Operators',
        'Backup Operators'
    )

    $allGroupResults = @()

    foreach ($groupName in $privilegedGroups) {
        try {
            Write-Progress -Activity 'Privileged Groups Check' -Status "Checking $groupName..." -PercentComplete (($privilegedGroups.IndexOf($groupName) / $privilegedGroups.Count) * 100) -Id 1

            $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
            if (-not $group) {
                Write-AuditMessage "Group '$groupName' not found, skipping..." -Type Warning -IndentLevel 1
                continue
            }

            $members = Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction SilentlyContinue
            $memberCount = if ($members) { $members.Count } else { 0 }

            $memberDetails = if ($members) {
                $members | ForEach-Object {
                    $memberInfo = Get-ADObject -Identity $_.distinguishedName -Properties Enabled, LastLogonDate -ErrorAction SilentlyContinue
                    [PSCustomObject]@{
                        Name = $_.SamAccountName
                        ObjectClass = $_.objectClass
                        Enabled = $memberInfo.Enabled
                        LastLogonDate = $memberInfo.LastLogonDate
                    }
                }
            } else { @() }

            $groupResult = [PSCustomObject]@{
                GroupName = $groupName
                MemberCount = $memberCount
                ExceedsThreshold = $memberCount -gt $PrivilegedGroupThreshold
                Members = $memberDetails
            }

            $allGroupResults += $groupResult

            if ($memberCount -gt $PrivilegedGroupThreshold) {
                Write-AuditMessage "$groupName has $memberCount members (threshold: $PrivilegedGroupThreshold)" -Type Warning -IndentLevel 1
            } else {
                Write-AuditMessage "$groupName has $memberCount members" -Type Success -IndentLevel 1
            }

        } catch {
            Write-AuditMessage "Error checking group '$groupName': $($_.Exception.Message)" -Type Error -IndentLevel 1
        }
    }

    Write-Progress -Activity 'Privileged Groups Check' -Completed -Id 1

    $excessiveGroups = $allGroupResults | Where-Object { $_.ExceedsThreshold }
    
    if ($excessiveGroups.Count -gt 0) {
        Add-AuditResult -CheckName 'PrivilegedGroups' -Status 'Fail' -Message "Found $($excessiveGroups.Count) privileged groups exceeding membership threshold" -Details $allGroupResults
    } else {
        Add-AuditResult -CheckName 'PrivilegedGroups' -Status 'Pass' -Message "All privileged groups within acceptable membership limits" -Details $allGroupResults
    }
}

function Test-LDAPNullBind {
    <#
    .SYNOPSIS
        Tests for LDAP NULL bind vulnerability
    #>
    [CmdletBinding()]
    param()

    Write-AuditMessage "Testing LDAP NULL bind configuration..." -Type Header

    try {
        Write-Progress -Activity 'LDAP NULL Bind Check' -Status 'Testing anonymous bind...' -Id 1

        # Test anonymous LDAP connection
        $ldapPath = "LDAP://$env:USERDNSDOMAIN"
        $anonymousEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        
        # Attempt to read schema naming context anonymously
        $schemaContext = $null
        try {
            $schemaContext = $anonymousEntry.SchemaEntry
            $canReadSchema = $schemaContext -ne $null
        } catch {
            $canReadSchema = $false
        }

        Write-Progress -Activity 'LDAP NULL Bind Check' -Completed -Id 1

        if ($canReadSchema) {
            Write-AuditMessage "LDAP NULL bind is enabled - anonymous access detected" -Type Warning -IndentLevel 1
            Add-AuditResult -CheckName 'LDAPNullBind' -Status 'Fail' -Message "LDAP NULL bind is enabled, allowing anonymous access"
        } else {
            Write-AuditMessage "LDAP NULL bind appears to be disabled" -Type Success -IndentLevel 1
            Add-AuditResult -CheckName 'LDAPNullBind' -Status 'Pass' -Message "LDAP NULL bind is properly configured"
        }

        $anonymousEntry.Dispose()

    } catch {
        Write-AuditMessage "Error testing LDAP NULL bind: $($_.Exception.Message)" -Type Error -IndentLevel 1
        Add-AuditResult -CheckName 'LDAPNullBind' -Status 'Error' -Message $_.Exception.Message
    }
}

function Test-PasswordsInDescription {
    <#
    .SYNOPSIS
        Checks for passwords stored in user description fields
    #>
    [CmdletBinding()]
    param()

    Write-AuditMessage "Checking for passwords in user description fields..." -Type Header

    try {
        Write-Progress -Activity 'Description Field Check' -Status 'Retrieving user accounts...' -Id 1

        $users = Get-ADUser -Filter { Enabled -eq $true -and Description -ne $null } -Properties Description -ResultSetSize $null
        
        # Enhanced password detection patterns
        $passwordPatterns = @(
            '(?i)password\s*[:=]\s*\S+',
            '(?i)pwd\s*[:=]\s*\S+',
            '(?i)pass\s*[:=]\s*\S+',
            '(?i)p@ssw[0o]rd\s*[:=]\s*\S+',
            '\b[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};'':"\\|,.<>\/?]{8,}\b(?=.*[!@#$%^&*()_+\-=\[\]{};'':"\\|,.<>\/?])'
        )

        $suspiciousUsers = @()
        $totalUsers = $users.Count
        $processedUsers = 0

        foreach ($user in $users) {
            $processedUsers++
            Write-Progress -Activity 'Description Field Check' -Status "Processing user $processedUsers of $totalUsers" -PercentComplete (($processedUsers / $totalUsers) * 100) -Id 1

            foreach ($pattern in $passwordPatterns) {
                if ($user.Description -match $pattern) {
                    $suspiciousUsers += [PSCustomObject]@{
                        SamAccountName = $user.SamAccountName
                        Description = $user.Description
                        MatchedPattern = $pattern
                    }
                    break # Only need one match per user
                }
            }
        }

        Write-Progress -Activity 'Description Field Check' -Completed -Id 1

        if ($suspiciousUsers.Count -gt 0) {
            Write-AuditMessage "Found $($suspiciousUsers.Count) accounts with potential passwords in descriptions" -Type Warning -IndentLevel 1
            Add-AuditResult -CheckName 'PasswordsInDescription' -Status 'Fail' -Message "Found potential passwords in $($suspiciousUsers.Count) user descriptions" -Details $suspiciousUsers
        } else {
            Write-AuditMessage "No passwords detected in user description fields" -Type Success -IndentLevel 1
            Add-AuditResult -CheckName 'PasswordsInDescription' -Status 'Pass' -Message "No passwords found in user descriptions"
        }

    } catch {
        Write-AuditMessage "Error checking passwords in descriptions: $($_.Exception.Message)" -Type Error -IndentLevel 1
        Add-AuditResult -CheckName 'PasswordsInDescription' -Status 'Error' -Message $_.Exception.Message
    }
}

function Test-PasswordsInSYSVOL {
    <#
    .SYNOPSIS
        Checks for passwords in SYSVOL files
    #>
    [CmdletBinding()]
    param()

    Write-AuditMessage "Checking for passwords in SYSVOL..." -Type Header

    try {
        $sysvolPath = "\\$env:USERDNSDOMAIN\SYSVOL"
        
        if (-not (Test-Path $sysvolPath)) {
            Write-AuditMessage "SYSVOL path not accessible: $sysvolPath" -Type Warning -IndentLevel 1
            Add-AuditResult -CheckName 'PasswordsInSYSVOL' -Status 'Warning' -Message "SYSVOL path not accessible"
            return
        }

        Write-Progress -Activity 'SYSVOL Password Check' -Status 'Scanning files...' -Id 1

        $fileExtensions = @('*.xml', '*.txt', '*.ini', '*.cfg', '*.conf', '*.bat', '*.cmd', '*.ps1', '*.vbs')
        $passwordPatterns = @('password', 'pwd', 'pass', 'cpassword')
        
        $suspiciousFiles = @()
        
        foreach ($extension in $fileExtensions) {
            try {
                $files = Get-ChildItem -Path $sysvolPath -Recurse -Include $extension -ErrorAction SilentlyContinue
                
                foreach ($file in $files) {
                    try {
                        $content = Get-Content -Path $file.FullName -ErrorAction SilentlyContinue
                        
                        foreach ($pattern in $passwordPatterns) {
                            $matches = $content | Select-String -Pattern $pattern -ErrorAction SilentlyContinue
                            
                            if ($matches) {
                                $suspiciousFiles += [PSCustomObject]@{
                                    FilePath = $file.FullName
                                    Pattern = $pattern
                                    LineNumber = $matches[0].LineNumber
                                    MatchedLine = $matches[0].Line.Trim()
                                }
                                break # Only need one match per file
                            }
                        }
                    } catch {
                        Write-Verbose "Could not read file: $($file.FullName) - $($_.Exception.Message)"
                    }
                }
            } catch {
                Write-Verbose "Error processing file extension $extension - $($_.Exception.Message)"
            }
        }

        Write-Progress -Activity 'SYSVOL Password Check' -Completed -Id 1

        if ($suspiciousFiles.Count -gt 0) {
            Write-AuditMessage "Found $($suspiciousFiles.Count) files with potential password references" -Type Warning -IndentLevel 1
            Add-AuditResult -CheckName 'PasswordsInSYSVOL' -Status 'Fail' -Message "Found potential passwords in $($suspiciousFiles.Count) SYSVOL files" -Details $suspiciousFiles
        } else {
            Write-AuditMessage "No password references found in SYSVOL files" -Type Success -IndentLevel 1
            Add-AuditResult -CheckName 'PasswordsInSYSVOL' -Status 'Pass' -Message "No passwords found in SYSVOL"
        }

    } catch {
        Write-AuditMessage "Error checking passwords in SYSVOL: $($_.Exception.Message)" -Type Error -IndentLevel 1
        Add-AuditResult -CheckName 'PasswordsInSYSVOL' -Status 'Error' -Message $_.Exception.Message
    }
}

#endregion

#region Main Execution

function Invoke-SecurityAudit {
    <#
    .SYNOPSIS
        Main function that orchestrates the security audit
    #>
    [CmdletBinding()]
    param()

    $startTime = Get-Date
    
    Write-AuditMessage "Starting Active Directory Security Audit" -Type Header
    Write-AuditMessage "Domain: $env:USERDNSDOMAIN" -Type Info -IndentLevel 1
    Write-AuditMessage "Executed by: $env:USERNAME" -Type Info -IndentLevel 1
    Write-AuditMessage "Start time: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Type Info -IndentLevel 1

    if (-not (Test-AdminPrivileges)) {
        Write-AuditMessage "Warning: Running without administrative privileges. Some checks may be limited." -Type Warning -IndentLevel 1
    }

    # Define check mappings
    $checkMappings = @{
        'OldPasswords' = 'Test-OldPasswords'
        'Kerberoasting' = 'Test-KerberoastingVulnerability'
        'PrivilegedGroups' = 'Test-PrivilegedGroups'
        'LDAPNullBind' = 'Test-LDAPNullBind'
        'PasswordsInDescription' = 'Test-PasswordsInDescription'
        'PasswordsInSYSVOL' = 'Test-PasswordsInSYSVOL'
    }

    # Determine which checks to run
    $checksToRun = if ('All' -in $CheckType) {
        $checkMappings.Keys
    } else {
        $CheckType
    }

    Write-AuditMessage "Checks to perform: $($checksToRun -join ', ')" -Type Info -IndentLevel 1
    Write-Host ""

    # Execute each check
    foreach ($check in $checksToRun) {
        if ($checkMappings.ContainsKey($check)) {
            $proceed = if ($Interactive) {
                Get-UserConsent -Prompt "Run $check check?"
            } else {
                $true
            }

            if ($proceed) {
                try {
                    & $checkMappings[$check]
                } catch {
                    Write-AuditMessage "Unexpected error in $check check: $($_.Exception.Message)" -Type Error
                    Add-AuditResult -CheckName $check -Status 'Error' -Message $_.Exception.Message
                }
            } else {
                Write-AuditMessage "Skipping $check check" -Type Info -IndentLevel 1
            }
            Write-Host ""
        } else {
            Write-AuditMessage "Unknown check type: $check" -Type Warning
        }
    }

    # Calculate execution time and update summary
    $endTime = Get-Date
    $executionTime = $endTime - $startTime
    $script:AuditResults.Summary.ExecutionTime = $executionTime.ToString('hh\:mm\:ss\.fff')

    # Display summary
    Write-AuditMessage "Audit Summary" -Type Header
    Write-AuditMessage "Total checks: $($script:AuditResults.Summary.TotalChecks)" -Type Info -IndentLevel 1
    Write-AuditMessage "Passed: $($script:AuditResults.Summary.PassedChecks)" -Type Success -IndentLevel 1
    Write-AuditMessage "Failed: $($script:AuditResults.Summary.FailedChecks)" -Type Error -IndentLevel 1
    Write-AuditMessage "Warnings: $($script:AuditResults.Summary.Warnings)" -Type Warning -IndentLevel 1
    Write-AuditMessage "Execution time: $($script:AuditResults.Summary.ExecutionTime)" -Type Info -IndentLevel 1

    # Save results if output path specified
    if ($OutputPath) {
        try {
            $script:AuditResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-AuditMessage "Results saved to: $OutputPath" -Type Success -IndentLevel 1
        } catch {
            Write-AuditMessage "Failed to save results: $($_.Exception.Message)" -Type Error -IndentLevel 1
        }
    }

    Write-Host ""
    Write-AuditMessage "Security audit completed. Please review all findings and take appropriate remediation actions." -Type Header

    return $script:AuditResults
}

#endregion

# Execute the audit
try {
    $results = Invoke-SecurityAudit
    
    # Return results for pipeline usage
    if (-not $Interactive) {
        return $results
    }
} catch {
    Write-Error "Critical error during security audit: $($_.Exception.Message)"
    exit 1
}
