#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    Audits local privileged group memberships and flags stale accounts.

.DESCRIPTION
    Enumerates members of key local security groups, collects account details
    (type, status, last logon), and exports results to CSV. Accounts that
    haven't logged in within the specified threshold are flagged as stale.

.PARAMETER StaleDays
    Number of days without logon before an account is considered stale.
    Default: 90

.PARAMETER OutputPath
    Path for the CSV output file. Defaults to ./output/PrivilegeAudit_<timestamp>.csv

.EXAMPLE
    .\Invoke-PrivilegeAudit.ps1
    Runs audit with default settings.

.EXAMPLE
    .\Invoke-PrivilegeAudit.ps1 -StaleDays 60 -OutputPath "C:\Reports\audit.csv"
    Runs audit with 60-day stale threshold and custom output path.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 365)]
    [int]$StaleDays = 90,

    [ValidateNotNullOrEmpty()]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Configuration ---
# Groups to audit - add or remove as needed
$TargetGroups = @(
    'Administrators'
    'Remote Desktop Users'
    'Backup Operators'
)

# --- Functions ---

function Get-TargetGroupMembers {
    <#
    .SYNOPSIS
        Retrieves members of a specified local group.
    .PARAMETER GroupName
        Name of the local group to enumerate.
    .OUTPUTS
        Array of member objects with at minimum: Name, PrincipalSource
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$GroupName
    )

    try {
        $null = Get-LocalGroup -Name $GroupName -ErrorAction Stop
    }
    catch {
        Write-Warning "Group '$GroupName' not found on this system. Skipping."
        return @()
    }

    try {
        return @(Get-LocalGroupMember -Name $GroupName -ErrorAction Stop)
    }
    catch {
        # Get-LocalGroupMember has a known issue with orphaned/unresolvable SIDs
        Write-Warning "Could not fully enumerate '$GroupName': $($_.Exception.Message)"
        return @()
    }
}

function Get-MemberDetail {
    <#
    .SYNOPSIS
        Collects detailed information for a single group member.
    .PARAMETER Member
        A member object returned from Get-TargetGroupMembers.
    .PARAMETER GroupName
        The group this member belongs to.
    .PARAMETER StaleDaysThreshold
        Number of days without logon before an account is considered stale.
    .OUTPUTS
        PSCustomObject with: GroupName, Username, AccountType, Enabled, LastLogon, IsStale
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Member,

        [Parameter(Mandatory)]
        [string]$GroupName,

        [Parameter(Mandatory)]
        [int]$StaleDaysThreshold
    )

    $enabled      = $null
    $lastLogon    = $null
    $isStale      = $null
    $lookupFailed = $false

    if ($Member.PrincipalSource -eq 'Local') {
        # Strip the COMPUTERNAME\ prefix to get the bare username for Get-LocalUser
        $localUsername = ($Member.Name -split '\\')[-1]
        try {
            $localUser = Get-LocalUser -Name $localUsername -ErrorAction Stop
            $enabled   = $localUser.Enabled
            $lastLogon = $localUser.LastLogon  # $null means never logged on locally

            $isStale = if ($null -eq $lastLogon) {
                $true  # Never logged on — treat as stale
            } else {
                ((Get-Date) - $lastLogon).Days -gt $StaleDaysThreshold
            }
        }
        catch {
            $lookupFailed = $true
            Write-Warning "Could not retrieve details for local user '$localUsername': $($_.Exception.Message)"
        }
    }
    # Domain/Azure accounts: local machine does not store their enabled status or logon history.
    # Enabled, LastLogon, and IsStale remain $null to signal indeterminate.

    $lastLogonDisplay = if ($null -ne $lastLogon) {
        $lastLogon.ToString('yyyy-MM-dd HH:mm:ss')
    } elseif ($lookupFailed) {
        'N/A (error)'
    } elseif ($Member.PrincipalSource -eq 'Local') {
        'Never'
    } else {
        'N/A (Domain)'
    }

    [PSCustomObject]@{
        GroupName   = $GroupName
        Username    = $Member.Name
        AccountType = $Member.PrincipalSource
        Enabled     = if ($null -ne $enabled) { $enabled } else { 'N/A' }
        LastLogon   = $lastLogonDisplay
        IsStale     = if ($null -ne $isStale) { $isStale } else { 'N/A' }
    }
}

function Write-ColorTable {
    <#
    .SYNOPSIS
        Prints audit results as a color-coded console table.
    .PARAMETER Results
        Array of audit result objects to display.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Results
    )

    $header = '{0,-25} {1,-22} {2,-10} {3,-8} {4,-22} {5}' -f 'Username', 'Group', 'Type', 'Enabled', 'Last Logon', 'Stale'
    $divider = '-' * $header.Length

    Write-Host "`n$header" -ForegroundColor White
    Write-Host $divider -ForegroundColor DarkGray

    foreach ($row in $Results) {
        $line = '{0,-25} {1,-22} {2,-10} {3,-8} {4,-22} {5}' -f `
            $row.Username, $row.GroupName, $row.AccountType, $row.Enabled, $row.LastLogon, $row.IsStale

        $color = if ($row.IsStale -eq $true) {
            'Red'
        } elseif ($row.IsStale -eq $false) {
            'Green'
        } else {
            'DarkGray'  # N/A (domain accounts)
        }

        Write-Host $line -ForegroundColor $color
    }

    Write-Host $divider -ForegroundColor DarkGray
}

function Export-AuditResults {
    <#
    .SYNOPSIS
        Exports audit results to CSV.
    .PARAMETER Results
        Array of audit result objects to export.
    .PARAMETER Path
        File path for the CSV output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Results,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $outputDir = Split-Path -Path $Path -Parent
    if ($outputDir -and (-not (Test-Path -Path $outputDir))) {
        Write-Verbose "Creating output directory: $outputDir"
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }

    $Results | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    Write-Verbose "Results exported to: $Path"
}

# --- Main Execution ---

# 1. Guard: nothing to do if no groups are configured
if ($TargetGroups.Count -eq 0) {
    Write-Warning "No target groups configured. Add group names to `$TargetGroups and re-run."
    return
}

# 2. Set default output path if not provided
$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { $PWD.Path }
if (-not $OutputPath) {
    $timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
    $OutputPath = Join-Path -Path $scriptRoot -ChildPath "output\PrivilegeAudit_$timestamp.csv"
}

# 3. Loop through target groups and collect member details
$allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($group in $TargetGroups) {
    Write-Verbose "Auditing group: $group"
    $members = Get-TargetGroupMembers -GroupName $group

    foreach ($member in $members) {
        $detail = Get-MemberDetail -Member $member -GroupName $group -StaleDaysThreshold $StaleDays
        $allResults.Add($detail)
    }
}

# 4. Export results and print summary
if ($allResults.Count -gt 0) {
    $resultsArray = $allResults.ToArray()
    Export-AuditResults -Results $resultsArray -Path $OutputPath

    # 5. Color-coded console table
    Write-ColorTable -Results $resultsArray

    # 6. Summary block
    $staleCount    = ($resultsArray | Where-Object { $_.IsStale -eq $true }).Count
    $healthyCount  = ($resultsArray | Where-Object { $_.IsStale -eq $false }).Count
    $unknownCount  = ($resultsArray | Where-Object { $_.IsStale -eq 'N/A' }).Count
    $totalCount    = $resultsArray.Count

    Write-Host "`n=== Privilege Audit Summary ===" -ForegroundColor Cyan
    Write-Host "Groups audited   : $($TargetGroups.Count)"
    Write-Host "Accounts found   : $totalCount"
    Write-Host "  Healthy        : $healthyCount" -ForegroundColor Green
    Write-Host "  Stale          : $staleCount"   -ForegroundColor $(if ($staleCount -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  Unknown (domain): $unknownCount" -ForegroundColor DarkGray
    Write-Host "Stale threshold  : $StaleDays days"
    Write-Host "Report saved to  : $OutputPath`n"
}
else {
    Write-Warning "No members found across all target groups. No CSV generated."
}
