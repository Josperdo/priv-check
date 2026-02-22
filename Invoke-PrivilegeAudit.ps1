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

    $enabled   = $null
    $lastLogon = $null
    $isStale   = $null

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
            Write-Warning "Could not retrieve details for local user '$localUsername': $($_.Exception.Message)"
        }
    }
    # Domain/Azure accounts: local machine does not store their enabled status or logon history.
    # Enabled, LastLogon, and IsStale remain $null to signal indeterminate.

    [PSCustomObject]@{
        GroupName   = $GroupName
        Username    = $Member.Name
        AccountType = $Member.PrincipalSource
        Enabled     = if ($null -ne $enabled) { $enabled } else { 'N/A' }
        LastLogon   = if ($null -ne $lastLogon) { $lastLogon.ToString('yyyy-MM-dd HH:mm:ss') } elseif ($Member.PrincipalSource -eq 'Local') { 'Never' } else { 'N/A (Domain)' }
        IsStale     = if ($null -ne $isStale) { $isStale } else { 'N/A' }
    }
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

# 1. Set default output path if not provided
if (-not $OutputPath) {
    $timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
    $OutputPath = Join-Path -Path $PSScriptRoot -ChildPath "output\PrivilegeAudit_$timestamp.csv"
}

# 2. Loop through target groups and collect member details
$allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($group in $TargetGroups) {
    Write-Verbose "Auditing group: $group"
    $members = Get-TargetGroupMembers -GroupName $group

    foreach ($member in $members) {
        $detail = Get-MemberDetail -Member $member -GroupName $group -StaleDaysThreshold $StaleDays
        $allResults.Add($detail)
    }
}

# 3. Export results and print summary
if ($allResults.Count -gt 0) {
    Export-AuditResults -Results $allResults.ToArray() -Path $OutputPath

    # 4. Console summary
    $staleCount = ($allResults | Where-Object { $_.IsStale -eq $true }).Count
    $totalCount = $allResults.Count

    Write-Host "`n=== Privilege Audit Summary ===" -ForegroundColor Cyan
    Write-Host "Groups audited   : $($TargetGroups.Count)"
    Write-Host "Accounts found   : $totalCount"
    Write-Host "Stale accounts   : $staleCount" -ForegroundColor $(if ($staleCount -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "Stale threshold  : $StaleDays days"
    Write-Host "Report saved to  : $OutputPath`n"
}
else {
    Write-Warning "No members found across all target groups. No CSV generated."
}
