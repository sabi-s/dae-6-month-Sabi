<#
.SYNOPSIS
    HVMC Healthcare IAM - HVMC-IAM-CHG-110: record each employee's hire date (employeeHireDate) from an HR extract.

.DESCRIPTION
    Horizon Valley Medical Center | Author: Sabitha S Karanavar

    The staff accounts were bulk-created without hire dates, so only people who came through the joiner process had one.
    Hire dates are needed for access reviews (how long someone has held access), audits and tenure-based checks.
    The HR extract lists EmployeeId and HireDate. Only EMPTY hire dates are filled - an existing date is never overwritten
    (HR is the source of truth; a conflict is reported for HR to resolve). Accounts with an admin role are never touched.

.EXAMPLE
    ./Set-HvmcHireDates.ps1 -HrExtract hr_feed/hire_dates_2026-11-02.csv            # dry run
    ./Set-HvmcHireDates.ps1 -HrExtract hr_feed/hire_dates_2026-11-02.csv -Apply     # record the dates
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$HrExtract,
    [switch]$Apply,
    [switch]$Interactive
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'HVMC.Lifecycle.psm1') -Force
$Ticket = 'HVMC-IAM-CHG-110'

$rows = @(Import-Csv -Path $HrExtract)
Connect-HvmcGraph -Interactive:$Interactive
$privileged = Get-HvmcPrivilegedIds
$today = (Get-Date).Date

$plans = foreach ($row in $rows) {
    $plan = New-HvmcPlan -Ticket $Ticket -Event 'HireDate' -Employee $row.EmployeeId
    $date = $null
    try { $date = [datetime]::ParseExact($row.HireDate, 'yyyy-MM-dd', $null) } catch { }
    if (-not $date -or $date -gt $today) { $plan.Status = 'Invalid'; $plan.Message = "bad or future hire date '$($row.HireDate)'"; $plan; continue }
    $user = Get-HvmcUser -EmployeeId $row.EmployeeId
    if (-not $user) { $plan.Status = 'Invalid'; $plan.Message = 'employee not found'; $plan; continue }
    $plan.Employee = "$($user.DisplayName) ($($row.EmployeeId))"
    $plan.UserId = $user.Id
    if ($privileged.Contains($user.Id)) { $plan.Status = 'Invalid'; $plan.Message = 'admin account - not changed'; $plan; continue }
    $current = if ($user.EmployeeHireDate) { ([datetime]$user.EmployeeHireDate).ToUniversalTime().ToString('yyyy-MM-dd') }
    if ($current -eq $row.HireDate) { $plan.Status = 'AlreadyDone'; $plan.Message = "hire date $current"; $plan; continue }
    if ($current) { $plan.Status = 'Conflict'; $plan.Message = "has $current, HR extract says $($row.HireDate) - not overwritten, refer to HR"; $plan; continue }
    $uid = $user.Id; $value = "$($row.HireDate)T00:00:00Z"
    Add-HvmcStep $plan "hire date -> $($row.HireDate)" { Update-MgUser -UserId $uid -BodyParameter @{ employeeHireDate = $value } }.GetNewClosure()
    $plan
}

Write-Host ("`n{0}  {1}  hire dates from {2}  ({3} rows)`n" -f ($Apply ? 'APPLY' : 'DRY RUN'), $Ticket, (Split-Path $HrExtract -Leaf), $rows.Count)
foreach ($p in $plans) {
    $what = if ($p.Steps.Count) { $p.Steps[0].Description } else { $p.Message }
    Write-Host ("  {0,-30} [{1}] {2}" -f $p.Employee, $p.Status, $what)
}
$work = @($plans | Where-Object { $_.Status -eq 'Due' -and $_.Steps.Count })
$counts = $plans | Group-Object Status | ForEach-Object { "$($_.Name) $($_.Count)" }
Write-Host "`n$($counts -join ', ')"
if (-not $Apply) { Write-Host 'DRY RUN - nothing was changed. Run again with -Apply to record these dates.'; return }

foreach ($p in $work) { Invoke-HvmcPlan -Plan $p -Apply }
$verified = 0
foreach ($p in $work) {
    $u = Get-HvmcUser -UserId $p.UserId
    $p.After = [ordered]@{ employeeHireDate = if ($u.EmployeeHireDate) { ([datetime]$u.EmployeeHireDate).ToUniversalTime().ToString('yyyy-MM-dd') } }
    if ($p.Status -eq 'Done' -and $p.After.employeeHireDate -eq ($p.Steps[0].Description -replace '^hire date -> ', '')) { $verified++ }
}
Write-Host ("Recorded and re-read: {0}/{1} hire dates match the HR extract." -f $verified, $work.Count)
$evidence = Write-HvmcEvidence -Name 'hire_dates' -Data ([ordered]@{
    ticket = $Ticket; mode = 'apply'; hrExtract = (Split-Path $HrExtract -Leaf); verified = $verified; changed = $work.Count
    note = 'Lab data: hire dates are simulated from a fixed rule (no real HR records).'
    results = @($plans | ForEach-Object { [ordered]@{ employee = $_.Employee; status = $_.Status; message = $_.Message
        step = @($_.Steps.Description); result = $_.Results; after = $_.After } })
})
Write-Host "Evidence: $evidence"
