<#
.SYNOPSIS
    HVMC Healthcare IAM - Step 8b: process joiner / mover / leaver events from an HR feed (CSV) in Microsoft Entra ID.

.DESCRIPTION
    Horizon Valley Medical Center | Author: Sabitha S Karanavar

    The HR system exports one row per lifecycle event. For each event the script builds a plan from the RBAC v2 matrix,
    shows it, and changes nothing unless -Apply is given. Safe to run again: events already in effect are reported as
    "already done", events with a future date as "not due yet".

      Join   create the account (random password, change forced at first sign-in), set the manager, add the
             department's SG-* groups
      Move   update department, title and manager; remove groups of the old role FIRST, then add the new role's
             groups (no moment with both roles' access - separation of duties)
      Leave  record the leave date now; on or after that date disable sign-in, revoke sessions and remove all SG-*
             groups. Future leave dates are picked up by Invoke-HvmcLeaverCheck.ps1 (daily)

    After changes, application access is synced from groups (step 3 tool). Evidence goes to evidence/ (not in Git).

.EXAMPLE
    ./Invoke-HvmcLifecycle.ps1 -HrFeed hr_feed/hr_feed_2026-11-02.csv            # dry run
    ./Invoke-HvmcLifecycle.ps1 -HrFeed hr_feed/hr_feed_2026-11-02.csv -Apply     # make the changes
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$HrFeed,
    [switch]$Apply,
    [switch]$Interactive,
    [datetime]$Today = (Get-Date).Date
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'HVMC.Lifecycle.psm1') -Force

$required = 'Ticket', 'Event', 'EmployeeId', 'GivenName', 'Surname', 'Department', 'JobTitle', 'ManagerEmployeeId', 'EffectiveDate'
$rows = @(Import-Csv -Path $HrFeed)
$missing = $required | Where-Object { $_ -notin $rows[0].PSObject.Properties.Name }
if ($missing) { throw "HR feed is missing columns: $($missing -join ', ')" }

Connect-HvmcGraph -Interactive:$Interactive
$groups = Get-HvmcSgGroups
$privileged = Get-HvmcPrivilegedIds
$domain = Get-HvmcInitialDomain

function Test-Row($row, $plan) {
    if ($row.EmployeeId -notmatch '^HVMC-(\d{4}|C\d{3})$') { $plan.Status = 'Invalid'; $plan.Message = "bad employee ID '$($row.EmployeeId)'"; return $false }
    if ($row.Event -notin 'Join', 'Move', 'Leave') { $plan.Status = 'Invalid'; $plan.Message = "unknown event '$($row.Event)'"; return $false }
    try { [void][datetime]::ParseExact($row.EffectiveDate, 'yyyy-MM-dd', $null) } catch { $plan.Status = 'Invalid'; $plan.Message = "bad date '$($row.EffectiveDate)'"; return $false }
    if ($row.Event -ne 'Leave') {
        try { $want = Get-HvmcDesiredGroups -Department $row.Department } catch { $plan.Status = 'Invalid'; $plan.Message = $_.Exception.Message; return $false }
        $absent = $want | Where-Object { -not $groups.ContainsKey($_) }
        if ($absent) { $plan.Status = 'Invalid'; $plan.Message = "groups missing in the tenant: $($absent -join ', ')"; return $false }
    }
    return $true
}

$plans = foreach ($row in $rows) {
    $plan = New-HvmcPlan -Ticket $row.Ticket -Event $row.Event -Employee $row.EmployeeId
    if (-not (Test-Row $row $plan)) { $plan; continue }
    $effective = [datetime]::ParseExact($row.EffectiveDate, 'yyyy-MM-dd', $null)
    $user = Get-HvmcUser -EmployeeId $row.EmployeeId
    if ($user) {
        $plan.Employee = "$($user.DisplayName) ($($row.EmployeeId))"
        $plan.UserId = $user.Id
        if ($privileged.Contains($user.Id)) { $plan.Status = 'Invalid'; $plan.Message = 'account holds an admin role - lifecycle tools never change it'; $plan; continue }
    }

    switch ($row.Event) {
        'Join' {
            $plan.Employee = "$($row.GivenName) $($row.Surname) ($($row.EmployeeId))"
            if ($user) { $plan.Status = 'AlreadyDone'; $plan.Message = "account exists ($($user.Department), $($user.JobTitle))"; break }
            if ($effective -gt $Today) { $plan.Status = 'NotDue'; $plan.Message = "starts $($row.EffectiveDate)"; break }
            $mgr = Get-HvmcUser -EmployeeId $row.ManagerEmployeeId
            if (-not $mgr) { $plan.Status = 'Invalid'; $plan.Message = "manager $($row.ManagerEmployeeId) not found"; break }
            $nick = ('{0}.{1}' -f $row.GivenName, $row.Surname).ToLower() -replace '[^a-z0-9.]', ''
            $upn = "$nick@$domain"
            if (Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue) { $plan.Status = 'Invalid'; $plan.Message = "user name $nick is taken"; break }
            $state = @{}
            $body = @{
                accountEnabled = $true; displayName = "$($row.GivenName) $($row.Surname)"; givenName = $row.GivenName; surname = $row.Surname
                mailNickname = $nick; userPrincipalName = $upn; department = $row.Department; jobTitle = $row.JobTitle
                employeeId = $row.EmployeeId; employeeType = 'Employee'; employeeHireDate = "$($row.EffectiveDate)T00:00:00Z"
                companyName = 'Horizon Valley Medical Center'; usageLocation = 'US'
            }
            Add-HvmcStep $plan "create account $nick@<tenant> ($($row.Department), $($row.JobTitle), hire $($row.EffectiveDate); random password, change forced at first sign-in)" {
                $b = $body.Clone(); $b.passwordProfile = @{ forceChangePasswordNextSignIn = $true; password = (New-HvmcPassword) }
                $state.user = New-MgUser -BodyParameter $b
                $plan.UserId = $state.user.Id
            }.GetNewClosure()
            Add-HvmcStep $plan "set manager -> $($mgr.DisplayName)" {
                Set-MgUserManagerByRef -UserId $state.user.Id -BodyParameter @{ '@odata.id' = "https://graph.microsoft.com/v1.0/users/$($mgr.Id)" }
            }.GetNewClosure()
            foreach ($g in Get-HvmcDesiredGroups -Department $row.Department) {
                $gid = $groups[$g]
                Add-HvmcStep $plan "add to $g" { New-MgGroupMember -GroupId $gid -DirectoryObjectId $state.user.Id }.GetNewClosure()
            }
        }
        'Move' {
            if (-not $user) { $plan.Status = 'Invalid'; $plan.Message = 'employee not found'; break }
            if ($effective -gt $Today) { $plan.Status = 'NotDue'; $plan.Message = "moves on $($row.EffectiveDate)"; break }
            $mgr = Get-HvmcUser -EmployeeId $row.ManagerEmployeeId
            if (-not $mgr) { $plan.Status = 'Invalid'; $plan.Message = "manager $($row.ManagerEmployeeId) not found"; break }
            $uid = $user.Id
            $current = @(Get-HvmcUserGroups -UserId $uid)
            $target = @(Get-HvmcDesiredGroups -Department $row.Department)
            $curMgr = try { (Get-MgUserManager -UserId $uid -ErrorAction Stop).Id } catch { $null }
            if ($user.Department -ne $row.Department -or $user.JobTitle -ne $row.JobTitle) {
                $dept = $row.Department; $title = $row.JobTitle
                Add-HvmcStep $plan "department $($user.Department) -> $dept; title $($user.JobTitle) -> $title (employee ID kept)" {
                    Update-MgUser -UserId $uid -Department $dept -JobTitle $title
                }.GetNewClosure()
            }
            if ($curMgr -ne $mgr.Id) {
                Add-HvmcStep $plan "manager -> $($mgr.DisplayName)" {
                    Set-MgUserManagerByRef -UserId $uid -BodyParameter @{ '@odata.id' = "https://graph.microsoft.com/v1.0/users/$($mgr.Id)" }
                }.GetNewClosure()
            }
            foreach ($g in $current | Where-Object { $_ -notin $target }) {
                $gid = $groups[$g]
                Add-HvmcStep $plan "REMOVE from $g (old role)" { Remove-MgGroupMemberDirectoryObjectByRef -GroupId $gid -DirectoryObjectId $uid }.GetNewClosure()
            }
            foreach ($g in $target | Where-Object { $_ -notin $current }) {
                $gid = $groups[$g]
                Add-HvmcStep $plan "add to $g (new role)" { New-MgGroupMember -GroupId $gid -DirectoryObjectId $uid }.GetNewClosure()
            }
            if ($plan.Steps.Count -eq 0) { $plan.Status = 'AlreadyDone'; $plan.Message = "already $($row.Department), $($row.JobTitle)" }
        }
        'Leave' {
            if (-not $user) { $plan.Status = 'Invalid'; $plan.Message = 'employee not found'; break }
            $uid = $user.Id
            $leave = "$($row.EffectiveDate)T23:59:59Z"
            $recorded = if ($user.EmployeeLeaveDateTime) { ([datetime]$user.EmployeeLeaveDateTime).ToUniversalTime().ToString('yyyy-MM-dd') }
            if ($recorded -ne $row.EffectiveDate) {
                Add-HvmcStep $plan "record leave date -> $($row.EffectiveDate) (last working day)" {
                    Update-MgUser -UserId $uid -BodyParameter @{ employeeLeaveDateTime = $leave }
                }.GetNewClosure()
            }
            if ($effective -gt $Today) {
                $plan.Message = "leaves $($row.EffectiveDate): access stays until then; the daily leaver check removes it"
                if ($plan.Steps.Count -eq 0) { $plan.Status = 'AlreadyDone'; $plan.Message = "leave date $($row.EffectiveDate) already recorded; the daily leaver check removes access" }
                break
            }
            if ($user.AccountEnabled) {
                Add-HvmcStep $plan 'disable sign-in' { Update-MgUser -UserId $uid -AccountEnabled:$false }.GetNewClosure()
                Add-HvmcStep $plan 'revoke all sign-in sessions' { Revoke-MgUserSignInSession -UserId $uid }.GetNewClosure()
            }
            foreach ($g in Get-HvmcUserGroups -UserId $uid) {
                $gid = $groups[$g]
                Add-HvmcStep $plan "REMOVE from $g" { Remove-MgGroupMemberDirectoryObjectByRef -GroupId $gid -DirectoryObjectId $uid }.GetNewClosure()
            }
            if ($plan.Steps.Count -eq 0) { $plan.Status = 'AlreadyDone'; $plan.Message = 'already disabled with no groups' }
        }
    }
    $plan
}

# ---- show the plan
Write-Host ("`n{0}  HR feed {1}  ({2} events, today {3:yyyy-MM-dd})`n" -f ($Apply ? 'APPLY' : 'DRY RUN'), (Split-Path $HrFeed -Leaf), $plans.Count, $Today)
foreach ($p in $plans) {
    Write-Host ("{0}  {1,-5}  {2}  [{3}]{4}" -f $p.Ticket, $p.Event, $p.Employee, $p.Status, ($p.Message ? "  $($p.Message)" : ''))
    $i = 0
    foreach ($s in $p.Steps) { $i++; Write-Host ("      {0,2}. {1}" -f $i, $s.Description) }
}
$work = @($plans | Where-Object { $_.Status -eq 'Due' -and $_.Steps.Count -gt 0 })
Write-Host ("`n{0} event(s) with changes, {1} step(s) in total." -f $work.Count, ($work | ForEach-Object { $_.Steps.Count } | Measure-Object -Sum).Sum)
if (-not $Apply) {
    if ($work) { Write-Host 'Then: sync application access from groups (step 3 tool).' }
    Write-Host 'DRY RUN - nothing was changed. Run again with -Apply to make these changes.'
    return
}

# ---- apply
foreach ($p in $work) { Invoke-HvmcPlan -Plan $p -Apply }
$sync = if ($work) { Invoke-HvmcAppSync } else { 'not needed' }
foreach ($p in $plans) {
    $ok = @($p.Results | Where-Object { $_.result -eq 'ok' }).Count
    Write-Host ("{0}  {1,-12} {2}/{3} steps ok" -f $p.Ticket, $p.Status, $ok, $p.Steps.Count)
}
Write-Host "Application access sync: $sync"
foreach ($p in $plans) { if ($p.UserId -and $p.Status -in 'Done', 'Failed') { $p.After = Get-HvmcUserState -UserId $p.UserId } }
$evidence = Write-HvmcEvidence -Name 'lifecycle_run' -Data ([ordered]@{
    run = 'HVMC lifecycle automation (Step 8b)'; mode = 'apply'; hrFeed = (Split-Path $HrFeed -Leaf); today = $Today.ToString('yyyy-MM-dd')
    executedBy = 'IAM administrator (Sabitha S Karanavar)'; appSync = "$sync"
    events = @($plans | ForEach-Object { [ordered]@{ ticket = $_.Ticket; event = $_.Event; employee = $_.Employee; status = $_.Status
        message = $_.Message; plannedSteps = @($_.Steps.Description); results = $_.Results; before = $_.Before; after = $_.After } })
})
Write-Host "Evidence: $evidence"
