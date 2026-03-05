#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
.SYNOPSIS
    Pester unit tests for Invoke-PrivilegeAudit.ps1
.NOTES
    Must be run as Administrator (the main script requires elevation).
    Run with: Invoke-Pester .\tests\Invoke-PrivilegeAudit.Tests.ps1
#>

BeforeAll {
    # Dot-sourcing loads only the functions; the main execution block is guarded
    # by the $MyInvocation.InvocationName check and will not run.
    . (Join-Path $PSScriptRoot '..\Invoke-PrivilegeAudit.ps1')
}

# ---------------------------------------------------------------------------
Describe 'Get-MemberDetail' {

    Context 'Local account — never logged on' {
        It 'flags the account as stale and shows Never for LastLogon' {
            $member = [PSCustomObject]@{ Name = 'TESTPC\testuser'; PrincipalSource = 'Local' }
            Mock Get-LocalUser { [PSCustomObject]@{ Enabled = $true; LastLogon = $null } }

            $result = Get-MemberDetail -Member $member -GroupName 'Administrators' -StaleDaysThreshold 90

            $result.IsStale   | Should -Be $true
            $result.LastLogon | Should -Be 'Never'
            $result.Enabled   | Should -Be $true
        }
    }

    Context 'Local account — recently logged on' {
        It 'does not flag the account as stale' {
            $member = [PSCustomObject]@{ Name = 'TESTPC\testuser'; PrincipalSource = 'Local' }
            Mock Get-LocalUser { [PSCustomObject]@{ Enabled = $true; LastLogon = (Get-Date).AddDays(-5) } }

            $result = Get-MemberDetail -Member $member -GroupName 'Administrators' -StaleDaysThreshold 90

            $result.IsStale | Should -Be $false
        }
    }

    Context 'Local account — exceeds stale threshold' {
        It 'flags the account as stale' {
            $member = [PSCustomObject]@{ Name = 'TESTPC\olduser'; PrincipalSource = 'Local' }
            Mock Get-LocalUser { [PSCustomObject]@{ Enabled = $false; LastLogon = (Get-Date).AddDays(-120) } }

            $result = Get-MemberDetail -Member $member -GroupName 'Administrators' -StaleDaysThreshold 90

            $result.IsStale | Should -Be $true
            $result.Enabled | Should -Be $false
        }
    }

    Context 'Local account — exactly at threshold boundary' {
        It 'does not flag an account at exactly the threshold as stale (uses -gt not -ge)' {
            $member = [PSCustomObject]@{ Name = 'TESTPC\borderuser'; PrincipalSource = 'Local' }
            Mock Get-LocalUser { [PSCustomObject]@{ Enabled = $true; LastLogon = (Get-Date).AddDays(-90) } }

            $result = Get-MemberDetail -Member $member -GroupName 'Administrators' -StaleDaysThreshold 90

            $result.IsStale | Should -Be $false
        }
    }

    Context 'Domain account' {
        It 'returns N/A for IsStale, Enabled, and LastLogon' {
            $member = [PSCustomObject]@{ Name = 'DOMAIN\domuser'; PrincipalSource = 'ActiveDirectory' }

            $result = Get-MemberDetail -Member $member -GroupName 'Administrators' -StaleDaysThreshold 90

            $result.IsStale     | Should -Be 'N/A'
            $result.LastLogon   | Should -Be 'N/A (Domain)'
            $result.Enabled     | Should -Be 'N/A'
            $result.AccountType | Should -Be 'ActiveDirectory'
        }
    }

    Context 'Local account — Get-LocalUser lookup failure' {
        It 'handles errors gracefully and returns N/A fields' {
            $member = [PSCustomObject]@{ Name = 'TESTPC\missinguser'; PrincipalSource = 'Local' }
            Mock Get-LocalUser { throw 'User not found' }

            $result = Get-MemberDetail -Member $member -GroupName 'Administrators' -StaleDaysThreshold 90

            $result.IsStale   | Should -Be 'N/A'
            $result.LastLogon | Should -Be 'N/A (error)'
            $result.Enabled   | Should -Be 'N/A'
        }
    }

    Context 'Output object structure' {
        It 'always returns all six expected properties' {
            $member = [PSCustomObject]@{ Name = 'DOMAIN\user'; PrincipalSource = 'ActiveDirectory' }

            $result = Get-MemberDetail -Member $member -GroupName 'TestGroup' -StaleDaysThreshold 90

            $result.PSObject.Properties.Name | Should -Contain 'GroupName'
            $result.PSObject.Properties.Name | Should -Contain 'Username'
            $result.PSObject.Properties.Name | Should -Contain 'AccountType'
            $result.PSObject.Properties.Name | Should -Contain 'Enabled'
            $result.PSObject.Properties.Name | Should -Contain 'LastLogon'
            $result.PSObject.Properties.Name | Should -Contain 'IsStale'
        }

        It 'maps GroupName and Username from the inputs correctly' {
            $member = [PSCustomObject]@{ Name = 'DOMAIN\user'; PrincipalSource = 'ActiveDirectory' }

            $result = Get-MemberDetail -Member $member -GroupName 'TestGroup' -StaleDaysThreshold 90

            $result.GroupName | Should -Be 'TestGroup'
            $result.Username  | Should -Be 'DOMAIN\user'
        }
    }
}

# ---------------------------------------------------------------------------
Describe 'Get-TargetGroupMembers' {

    Context 'Group does not exist' {
        It 'returns an empty array' {
            Mock Get-LocalGroup { throw 'Group not found' }

            $result = Get-TargetGroupMembers -GroupName 'NonExistentGroup'

            $result | Should -HaveCount 0
        }
    }

    Context 'Group exists with members' {
        It 'returns the member objects' {
            Mock Get-LocalGroup { }
            Mock Get-LocalGroupMember {
                @([PSCustomObject]@{ Name = 'TESTPC\Admin'; PrincipalSource = 'Local' })
            }

            $result = Get-TargetGroupMembers -GroupName 'Administrators'

            $result          | Should -HaveCount 1
            $result[0].Name  | Should -Be 'TESTPC\Admin'
        }
    }

    Context 'Group exists but enumeration fails (e.g. orphaned SIDs)' {
        It 'returns an empty array' {
            Mock Get-LocalGroup { }
            Mock Get-LocalGroupMember { throw 'Failed to enumerate members' }

            $result = Get-TargetGroupMembers -GroupName 'Administrators'

            $result | Should -HaveCount 0
        }
    }
}
