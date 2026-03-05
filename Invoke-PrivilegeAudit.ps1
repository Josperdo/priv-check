#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    Audits local privileged group memberships and flags stale accounts.

.DESCRIPTION
    Enumerates members of key local security groups, collects account details
    (type, status, last logon), and exports results to CSV. Optionally generates
    a self-contained HTML report and supports auditing remote machines via WinRM.
    Accounts that haven't logged in within the specified threshold are flagged as stale.

.PARAMETER StaleDays
    Number of days without logon before an account is considered stale.
    Default: 90

.PARAMETER OutputPath
    Path for the CSV output file.
    Defaults to ./output/PrivilegeAudit_<machine>_<timestamp>.csv

.PARAMETER GroupName
    One or more group names to audit. Overrides the default list
    (Administrators, Remote Desktop Users, Backup Operators).

.PARAMETER ComputerName
    Remote machine to audit via WinRM. Omit to audit the local machine.
    The remote session must have administrator rights on the target.

.PARAMETER Credential
    Credential to use when connecting to a remote machine.
    Only applies when -ComputerName is specified.

.PARAMETER HtmlReport
    When specified, generates a self-contained HTML report alongside the CSV.

.EXAMPLE
    .\Invoke-PrivilegeAudit.ps1
    Runs audit with default settings on the local machine.

.EXAMPLE
    .\Invoke-PrivilegeAudit.ps1 -StaleDays 60 -HtmlReport
    Runs audit with a 60-day stale threshold and generates both CSV and HTML output.

.EXAMPLE
    .\Invoke-PrivilegeAudit.ps1 -ComputerName SRV-DC01 -Credential (Get-Credential)
    Audits a remote machine using explicit credentials.

.EXAMPLE
    .\Invoke-PrivilegeAudit.ps1 -GroupName 'Administrators', 'Remote Desktop Users'
    Audits only the specified groups on the local machine.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 365)]
    [int]$StaleDays = 90,

    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [string[]]$GroupName,

    [string]$ComputerName,

    [System.Management.Automation.PSCredential]$Credential,

    [switch]$HtmlReport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Configuration ---
# Default groups - used when -GroupName is not specified
$defaultGroups = @(
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

    $header  = '{0,-25} {1,-22} {2,-10} {3,-8} {4,-22} {5}' -f 'Username', 'Group', 'Type', 'Enabled', 'Last Logon', 'Stale'
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

function Export-HtmlReport {
    <#
    .SYNOPSIS
        Exports audit results as a self-contained HTML report.
    .PARAMETER Results
        Array of audit result objects to include.
    .PARAMETER Path
        File path for the HTML output.
    .PARAMETER TargetName
        Machine name displayed in the report heading.
    .PARAMETER StaleDays
        Stale threshold used for this audit run, shown in the report footer.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Results,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$TargetName,

        [Parameter(Mandatory)]
        [int]$StaleDays
    )

    $staleCount   = ($Results | Where-Object { $_.IsStale -eq $true }).Count
    $healthyCount = ($Results | Where-Object { $_.IsStale -eq $false }).Count
    $unknownCount = ($Results | Where-Object { $_.IsStale -eq 'N/A' }).Count

    $rows = foreach ($row in $Results) {
        $cssClass = if ($row.IsStale -eq $true) { 'stale' } elseif ($row.IsStale -eq $false) { 'healthy' } else { 'unknown' }
        "      <tr class='$cssClass'><td>$($row.Username)</td><td>$($row.GroupName)</td><td>$($row.AccountType)</td><td>$($row.Enabled)</td><td>$($row.LastLogon)</td><td>$($row.IsStale)</td></tr>"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Privilege Audit &mdash; $TargetName</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body    { font-family: 'Segoe UI', Arial, sans-serif; background: #1e1e2e; color: #cdd6f4; padding: 28px; }
    h1      { color: #89dceb; font-size: 1.5rem; margin-bottom: 18px; }
    .summary { display: flex; gap: 24px; margin-bottom: 24px; }
    .stat   { background: #313244; border-radius: 8px; padding: 14px 24px; text-align: center; min-width: 100px; }
    .stat .value { font-size: 2rem; font-weight: 700; }
    .stat .label { font-size: 0.75rem; color: #a6adc8; margin-top: 2px; text-transform: uppercase; letter-spacing: .05em; }
    .s-healthy .value { color: #a6e3a1; }
    .s-stale   .value { color: #f38ba8; }
    .s-unknown .value { color: #6c7086; }
    table   { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
    th      { background: #313244; padding: 10px 14px; text-align: left; color: #89dceb; font-weight: 600; }
    td      { padding: 8px 14px; border-bottom: 1px solid #313244; }
    tr.stale   td { color: #f38ba8; }
    tr.healthy td { color: #a6e3a1; }
    tr.unknown td { color: #6c7086; }
    tr:hover   td { background: #313244; }
    .footer { margin-top: 16px; font-size: 0.75rem; color: #6c7086; }
  </style>
</head>
<body>
  <h1>Privilege Audit &mdash; $TargetName</h1>
  <div class="summary">
    <div class="stat s-healthy"><div class="value">$healthyCount</div><div class="label">Healthy</div></div>
    <div class="stat s-stale"><div class="value">$staleCount</div><div class="label">Stale</div></div>
    <div class="stat s-unknown"><div class="value">$unknownCount</div><div class="label">Unknown</div></div>
  </div>
  <table>
    <thead>
      <tr><th>Username</th><th>Group</th><th>Type</th><th>Enabled</th><th>Last Logon</th><th>Stale</th></tr>
    </thead>
    <tbody>
$($rows -join "`n")
    </tbody>
  </table>
  <p class="footer">Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &bull; Stale threshold: $StaleDays days</p>
</body>
</html>
"@

    $outputDir = Split-Path -Path $Path -Parent
    if ($outputDir -and (-not (Test-Path -Path $outputDir))) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }

    $html | Set-Content -Path $Path -Encoding UTF8
    Write-Verbose "HTML report saved to: $Path"
}

# --- Main Execution ---
# Guard: dot-sourcing this script (e.g., from Pester) loads only the functions above.
if ($MyInvocation.InvocationName -ne '.') {

    # 1. Resolve target groups
    $effectiveGroups = if ($PSBoundParameters.ContainsKey('GroupName')) { $GroupName } else { $defaultGroups }

    # 2. Guard: nothing to audit if group list is empty
    if ($effectiveGroups.Count -eq 0) {
        Write-Warning "No target groups configured. Provide group names via -GroupName or add them to `$defaultGroups."
        return
    }

    # 3. Resolve output paths
    $scriptRoot  = if ($PSScriptRoot) { $PSScriptRoot } else { $PWD.Path }
    $targetLabel = if ($ComputerName) { $ComputerName } else { $env:COMPUTERNAME }
    $timestamp   = Get-Date -Format 'yyyyMMdd_HHmmss'

    if (-not $OutputPath) {
        $OutputPath = Join-Path -Path $scriptRoot -ChildPath "output\PrivilegeAudit_${targetLabel}_$timestamp.csv"
    }
    $htmlPath = [System.IO.Path]::ChangeExtension($OutputPath, '.html')

    # 4. Collect results — local or remote
    if ($ComputerName) {
        Write-Host "Connecting to '$ComputerName'..." -ForegroundColor Cyan

        # Both helper functions are embedded in the scriptblock so they execute in the remote session.
        $remoteScriptBlock = {
            param([string[]]$Groups, [int]$Days)

            function Get-TargetGroupMembers {
                param([Parameter(Mandatory)][string]$GroupName)
                try { $null = Get-LocalGroup -Name $GroupName -ErrorAction Stop }
                catch { Write-Warning "Group '$GroupName' not found. Skipping."; return @() }
                try { return @(Get-LocalGroupMember -Name $GroupName -ErrorAction Stop) }
                catch { Write-Warning "Could not enumerate '$GroupName': $($_.Exception.Message)"; return @() }
            }

            function Get-MemberDetail {
                param($Member, [string]$GroupName, [int]$StaleDaysThreshold)
                $enabled = $null; $lastLogon = $null; $isStale = $null; $lookupFailed = $false
                if ($Member.PrincipalSource -eq 'Local') {
                    $localUsername = ($Member.Name -split '\\')[-1]
                    try {
                        $u = Get-LocalUser -Name $localUsername -ErrorAction Stop
                        $enabled   = $u.Enabled
                        $lastLogon = $u.LastLogon
                        $isStale   = if ($null -eq $lastLogon) { $true } else { ((Get-Date) - $lastLogon).Days -gt $StaleDaysThreshold }
                    }
                    catch { $lookupFailed = $true }
                }
                $lastLogonDisplay = if ($null -ne $lastLogon)                { $lastLogon.ToString('yyyy-MM-dd HH:mm:ss') }
                                    elseif ($lookupFailed)                   { 'N/A (error)' }
                                    elseif ($Member.PrincipalSource -eq 'Local') { 'Never' }
                                    else                                     { 'N/A (Domain)' }
                [PSCustomObject]@{
                    GroupName   = $GroupName
                    Username    = $Member.Name
                    AccountType = $Member.PrincipalSource
                    Enabled     = if ($null -ne $enabled) { $enabled } else { 'N/A' }
                    LastLogon   = $lastLogonDisplay
                    IsStale     = if ($null -ne $isStale) { $isStale } else { 'N/A' }
                }
            }

            $results = [System.Collections.Generic.List[object]]::new()
            foreach ($group in $Groups) {
                foreach ($member in (Get-TargetGroupMembers -GroupName $group)) {
                    $results.Add((Get-MemberDetail -Member $member -GroupName $group -StaleDaysThreshold $Days))
                }
            }
            return $results.ToArray()
        }

        $icmParams = @{
            ComputerName = $ComputerName
            ScriptBlock  = $remoteScriptBlock
            ArgumentList = $effectiveGroups, $StaleDays
            ErrorAction  = 'Stop'
        }
        if ($Credential) { $icmParams['Credential'] = $Credential }

        try {
            $resultsArray = @(Invoke-Command @icmParams)
        }
        catch {
            Write-Error "Failed to connect to '$ComputerName': $($_.Exception.Message)"
            return
        }
    }
    else {
        # Local collection
        $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($group in $effectiveGroups) {
            Write-Verbose "Auditing group: $group"
            foreach ($member in (Get-TargetGroupMembers -GroupName $group)) {
                $allResults.Add((Get-MemberDetail -Member $member -GroupName $group -StaleDaysThreshold $StaleDays))
            }
        }
        $resultsArray = $allResults.ToArray()
    }

    # 5. Export and display
    if ($resultsArray.Count -gt 0) {
        Export-AuditResults -Results $resultsArray -Path $OutputPath

        if ($HtmlReport) {
            Export-HtmlReport -Results $resultsArray -Path $htmlPath -TargetName $targetLabel -StaleDays $StaleDays
        }

        Write-ColorTable -Results $resultsArray

        $staleCount   = ($resultsArray | Where-Object { $_.IsStale -eq $true }).Count
        $healthyCount = ($resultsArray | Where-Object { $_.IsStale -eq $false }).Count
        $unknownCount = ($resultsArray | Where-Object { $_.IsStale -eq 'N/A' }).Count
        $totalCount   = $resultsArray.Count

        Write-Host "`n=== Privilege Audit Summary ===" -ForegroundColor Cyan
        Write-Host "Target machine    : $targetLabel"
        Write-Host "Groups audited    : $($effectiveGroups.Count)"
        Write-Host "Accounts found    : $totalCount"
        Write-Host "  Healthy         : $healthyCount"  -ForegroundColor Green
        Write-Host "  Stale           : $staleCount"    -ForegroundColor $(if ($staleCount -gt 0) { 'Red' } else { 'Green' })
        Write-Host "  Unknown (domain): $unknownCount"  -ForegroundColor DarkGray
        Write-Host "Stale threshold   : $StaleDays days"
        Write-Host "CSV saved to      : $OutputPath"
        if ($HtmlReport) { Write-Host "HTML saved to     : $htmlPath" }
        Write-Host ""
    }
    else {
        Write-Warning "No members found across all target groups. No output generated."
    }
}
