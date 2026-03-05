# Local Privilege Auditor - Task Tracker

## Current Sprint

- [x] Define function signatures and script structure
- [x] Implement local group enumeration
- [x] Implement member detail collection (type, status, last logon)
- [x] Implement CSV export
- [x] Add stale account flagging
- [x] Add color-coded console table output (red=stale, green=healthy, gray=unknown)
- [x] Testing and edge case handling (empty group config guard, lookup failure display, `$PSScriptRoot` fallback)
- [x] Final code review and cleanup (cache `.ToArray()`, clarify `LastLogon` on lookup error)

## Backlog

- [ ] Add HTML report export option
- [ ] Support auditing remote machines via `-ComputerName`
- [ ] Add `-GroupName` parameter to override default target groups at runtime
- [ ] Pester unit tests for `Get-MemberDetail` logic
