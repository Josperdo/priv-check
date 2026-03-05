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

- [x] Add HTML report export option (`-HtmlReport` switch, dark-themed self-contained HTML)
- [x] Support auditing remote machines via `-ComputerName` (+ optional `-Credential`)
- [x] Add `-GroupName` parameter to override default target groups at runtime
- [x] Pester unit tests for `Get-MemberDetail` and `Get-TargetGroupMembers`
