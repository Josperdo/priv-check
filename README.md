# priv-check

A PowerShell script that audits local privileged group memberships on Windows machines. Designed for security analysts who need to quickly identify who has elevated access and flag potentially stale accounts.

## What It Does

- Enumerates members of key local security groups (Administrators, Remote Desktop Users, Backup Operators)
- Captures account details: username, account type (local vs. domain), enabled/disabled status, last logon
- Flags accounts that haven't logged in within a configurable threshold as "stale"
- Prints a color-coded console table (red = stale, green = healthy, gray = domain/unknown)
- Exports results to CSV for reporting and further analysis
- Optionally generates a self-contained HTML report (`-HtmlReport`)
- Supports auditing remote machines via WinRM (`-ComputerName`)

## Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or later
- **Must be run as Administrator** to read local group memberships and account details
- Remote audits require WinRM to be enabled and accessible on the target machine

## Usage

```powershell
# Basic audit with default settings (90-day stale threshold)
.\Invoke-PrivilegeAudit.ps1

# Custom stale threshold with HTML report
.\Invoke-PrivilegeAudit.ps1 -StaleDays 60 -HtmlReport

# Specify a custom output path
.\Invoke-PrivilegeAudit.ps1 -OutputPath "C:\Reports\audit.csv"

# Audit a remote machine
.\Invoke-PrivilegeAudit.ps1 -ComputerName SRV-DC01

# Audit a remote machine with explicit credentials
.\Invoke-PrivilegeAudit.ps1 -ComputerName SRV-DC01 -Credential (Get-Credential)

# Audit only specific groups
.\Invoke-PrivilegeAudit.ps1 -GroupName 'Administrators', 'Remote Desktop Users'
```

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-StaleDays` | `int` | `90` | Days without logon before an account is flagged stale (1–365) |
| `-OutputPath` | `string` | auto | Path for the CSV file. Defaults to `output\PrivilegeAudit_<machine>_<timestamp>.csv` |
| `-GroupName` | `string[]` | built-in list | Override the default groups to audit |
| `-ComputerName` | `string` | local | Remote machine to audit via WinRM |
| `-Credential` | `PSCredential` | current user | Credential for the remote session |
| `-HtmlReport` | `switch` | off | Generate an HTML report alongside the CSV |

## Example Output

Console table (color-coded):

```
Username                  Group                  Type       Enabled  Last Logon             Stale
-------------------------------------------------------------------------------------------------
DESKTOP\Admin             Administrators         Local      True     2025-06-01 08:30:00    True
DESKTOP\jdoe              Administrators         Local      True     2026-02-20 09:15:00    False
DOMAIN\svc-backup         Backup Operators       ActiveDir  N/A      N/A (Domain)           N/A
```

Summary block:

```
=== Privilege Audit Summary ===
Target machine    : DESKTOP-ABC123
Groups audited    : 3
Accounts found    : 3
  Healthy         : 1
  Stale           : 1
  Unknown (domain): 1
Stale threshold   : 90 days
CSV saved to      : C:\...\output\PrivilegeAudit_DESKTOP-ABC123_20260305_143022.csv
```

## Running Tests

Tests require [Pester 5+](https://pester.dev/docs/introduction/installation):

```powershell
Install-Module Pester -MinimumVersion 5.0 -Force

# Run from the repo root (must be elevated)
Invoke-Pester .\tests\Invoke-PrivilegeAudit.Tests.ps1
```

## Project Structure

```
priv-check/
├── Invoke-PrivilegeAudit.ps1   # Main script
├── output/                      # Default CSV/HTML output directory (auto-created)
├── tests/
│   └── Invoke-PrivilegeAudit.Tests.ps1  # Pester unit tests
├── tasks/                       # Development task tracking
└── README.md
```

## Security Considerations

- This script reads local account information and does not modify any system settings
- Requires administrator privileges for complete enumeration — running without elevation may return incomplete results
- Output CSV and HTML files may contain usernames and logon timestamps — handle according to your organization's data handling policies
- No credentials are stored or transmitted; `-Credential` is passed directly to `Invoke-Command`

## Known Limitations

- Local machine scope only by default — use `-ComputerName` for remote targets
- `Get-LocalGroupMember` has a known issue with orphaned SIDs and certain account types — the script handles these gracefully
- Last logon data reflects local logons only, not domain controller logon events
- Domain/Azure account enabled status and logon history are not available from the local machine and show as `N/A`
- Remote audits require WinRM to be configured on the target (`Enable-PSRemoting`)

## License

MIT
