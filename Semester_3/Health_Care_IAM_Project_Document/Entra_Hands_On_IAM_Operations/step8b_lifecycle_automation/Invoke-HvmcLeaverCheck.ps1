<#
.SYNOPSIS
    HVMC Healthcare IAM - Step 8b: daily leaver check in Microsoft Entra ID.

.DESCRIPTION
    Horizon Valley Medical Center | Author: Sabitha S Karanavar

    Runs once a day as a safety net behind the HR feed. It reads every account's leave date (employeeLeaveDateTime)
    and finds:
      ACTION  leave date passed, account still enabled          -> disable, revoke sessions, remove SG-* groups
      ACTION  leave date passed, disabled but still in groups   -> remove SG-* groups ("disabled is not deprovisioned")
      NOTICE  leave date within the next 14 days                -> heads-up for the manager or sponsor
      WARNING enabled contractor with no end date               -> contractors must have an end date (policy R06)
    Changes nothing unless -Apply is given. Accounts holding an Entra ID admin role are never touched.

.EXAMPLE
    ./Invoke-HvmcLeaverCheck.ps1            # dry run (report only)
    ./Invoke-HvmcLeaverCheck.ps1 -Apply     # deprovision the due leavers
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Interactive,
    [int]$NoticeDays = 14,
    [datetime]$Now = (Get-Date).ToUniversalTime()
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'HVMC.Lifecycle.psm1') -Force
$Now = $Now.ToUniversalTime()

Connect-HvmcGraph -Interactive:$Interactive
$groups = Get-HvmcSgGroups
$privileged = Get-HvmcPrivilegedIds
$users = @(Get-MgUser -All -Property id, displayName, employeeId, employeeType, accountEnabled, employeeLeaveDateTime, department)

$plans = [System.Collections.Generic.List[object]]::new()
$findings = [System.Collections.Generic.List[object]]::new()
foreach ($u in $users | Sort-Object DisplayName) {
    if ($privileged.Contains($u.Id)) { continue }
    $leave = if ($u.EmployeeLeaveDateTime) { ([datetime]$u.EmployeeLeaveDateTime).ToUniversalTime() }
    $who = "$($u.DisplayName) ($($u.EmployeeId ?? 'no ID'))"
    if ($leave -and $leave -le $Now) {
        $uid = $u.Id
        $member = @(Get-HvmcUserGroups -UserId $uid)
        if (-not $u.AccountEnabled -and -not $member) { continue }            # fully deprovisioned - nothing to do
        $plan = New-HvmcPlan -Ticket 'HVMC-LVC' -Event 'Leave' -Employee $who
        $plan.UserId = $uid
        $plan.Message = "leave date $($leave.ToString('yyyy-MM-dd')) has passed"
        if ($u.AccountEnabled) {
            Add-HvmcStep $plan 'disable sign-in' { Update-MgUser -UserId $uid -AccountEnabled:$false }.GetNewClosure()
            Add-HvmcStep $plan 'revoke all sign-in sessions' { Revoke-MgUserSignInSession -UserId $uid }.GetNewClosure()
        } else {
            $plan.Message += '; account disabled but still in groups'
        }
        foreach ($g in $member) {
            $gid = $groups[$g]
            Add-HvmcStep $plan "REMOVE from $g" { Remove-MgGroupMemberDirectoryObjectByRef -GroupId $gid -DirectoryObjectId $uid }.GetNewClosure()
        }
        $plans.Add($plan)
        $findings.Add([ordered]@{ level = 'ACTION'; user = $who; detail = $plan.Message })
    } elseif ($leave -and $leave -le $Now.AddDays($NoticeDays)) {
        $findings.Add([ordered]@{ level = 'NOTICE'; user = $who
                                  detail = "leaves $($leave.ToString('yyyy-MM-dd')) ($([math]::Ceiling(($leave - $Now).TotalDays)) days) - tell the manager/sponsor; access is removed automatically" })
    }
    if ($u.EmployeeType -eq 'Contractor' -and $u.AccountEnabled -and -not $leave) {
        $findings.Add([ordered]@{ level = 'WARNING'; user = $who; detail = 'enabled contractor with no end date (policy: contractors must expire)' })
    }
}

Write-Host ("`n{0}  Daily leaver check  {1:yyyy-MM-dd HH:mm} UTC  ({2} accounts checked, {3} admin accounts skipped)`n" -f `
    ($Apply ? 'APPLY' : 'DRY RUN'), $Now, $users.Count, $privileged.Count)
if (-not $findings.Count) { Write-Host 'No leavers due, none upcoming, no contractor without an end date.' }
foreach ($f in $findings) { Write-Host ("{0,-8} {1,-34} {2}" -f $f.level, $f.user, $f.detail) }
foreach ($p in $plans) {
    Write-Host "`n  $($p.Employee):"
    $i = 0; foreach ($s in $p.Steps) { $i++; Write-Host ("      {0,2}. {1}" -f $i, $s.Description) }
}

if (-not $Apply) {
    Write-Host "`nDRY RUN - nothing was changed.$(if ($plans.Count) { ' Run with -Apply to deprovision the leavers above.' })"
    return
}
foreach ($p in $plans) { Invoke-HvmcPlan -Plan $p -Apply }
$sync = if ($plans.Count) { Invoke-HvmcAppSync } else { 'not needed' }
foreach ($p in $plans) { Write-Host ("{0,-34} {1}  {2}/{3} steps ok" -f $p.Employee, $p.Status, @($p.Results | Where-Object { $_.result -eq 'ok' }).Count, $p.Steps.Count) }
Write-Host "Application access sync: $sync"
foreach ($p in $plans) { if ($p.UserId -and $p.Status -in 'Done', 'Failed') { $p.After = Get-HvmcUserState -UserId $p.UserId } }
$evidence = Write-HvmcEvidence -Name 'leaver_check' -Data ([ordered]@{
    run = 'HVMC daily leaver check (Step 8b)'; mode = 'apply'; checkedAt = $Now.ToString('s') + 'Z'
    accountsChecked = $users.Count; adminAccountsSkipped = $privileged.Count; findings = $findings; appSync = "$sync"
    actions = @($plans | ForEach-Object { [ordered]@{ employee = $_.Employee; status = $_.Status; plannedSteps = @($_.Steps.Description)
        results = $_.Results; before = $_.Before; after = $_.After } })
})
Write-Host "Evidence: $evidence"
