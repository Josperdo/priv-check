# priv-check

A PowerShell script that audits local privileged group memberships on Windows machines. Designed for security analysts who need to quickly identify who has elevated access and flag potentially stale accounts.

## What It Does

- Enumerates members of key local security groups (Administrators, Remote Desktop Users, Backup Operators)
- Captures account details: username, account type (local vs. domain), enabled/disabled status, last logon
- Flags accounts that haven't logged in within a configurable threshold as "stale"
- Exports results to CSV for reporting and further analysis

## Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or later
- **Must be run as Administrator** to read local group memberships and account details

## Usage

```powershell
# Basic audit with default settings (90-day stale threshold)
.\Invoke-PrivilegeAudit.ps1

# Custom stale threshold
.\Invoke-PrivilegeAudit.ps1 -StaleDays 60

# Specify output path
.\Invoke-PrivilegeAudit.ps1 -OutputPath "C:\Reports\audit.csv"
```

## Example Output

| GroupName      | Username       | AccountType | Enabled | LastLogon           | IsStale |
|----------------|----------------|-------------|---------|---------------------|---------|
| Administrators | DESKTOP\Admin  | Local       | True    | 2025-12-01 08:30:00 | True    |
| Administrators | DOMAIN\jsmith  | Domain      | True    | 2026-02-10 14:22:00 | False   |

## Project Structure

```
LocalPrivilegeAuditor/
├── Invoke-PrivilegeAudit.ps1   # Main script
├── output/                      # Default CSV output directory
├── tests/                       # Pester tests
├── tasks/                       # Development task tracking
└── README.md
```

## Security Considerations

- This script reads local account information and does not modify any system settings
- Requires administrator privileges for complete enumeration — running without elevation may return incomplete results
- Output CSV files may contain usernames and logon timestamps — handle according to your organization's data handling policies
- No credentials are stored or transmitted

## Known Limitations

- Local machine scope only (no Active Directory or Azure AD enumeration)
- `Get-LocalGroupMember` has a known issue with orphaned SIDs and certain account types — the script handles these gracefully
- Last logon data reflects local logons only, not domain controller logon events
- Designed with extensibility in mind so AD cmdlets can be swapped in later

## License

MIT
