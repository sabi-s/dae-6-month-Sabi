<#
HVMC Healthcare IAM - Step 8b: shared functions for joiner / mover / leaver automation (Microsoft Graph PowerShell).

Horizon Valley Medical Center | Author: Sabitha S Karanavar

Group membership is derived from the RBAC v2 matrix (config/rbac_matrix.json, exported from step2_rbac_v2/rbac_v2.py);
application access is then synced from groups by step3_enterprise_apps/enterprise_apps.py.
Every action is planned first; nothing changes unless the calling script runs with -Apply.
Accounts holding an Entra ID admin role are never touched.
#>
Set-StrictMode -Version Latest

$script:Here = $PSScriptRoot
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Matrix = Get-Content (Join-Path $PSScriptRoot 'config/rbac_matrix.json') -Raw | ConvertFrom-Json -AsHashtable
$script:UserProps = @('id', 'displayName', 'givenName', 'surname', 'userPrincipalName', 'department', 'jobTitle', 'accountEnabled',
                      'employeeId', 'employeeType', 'employeeHireDate', 'employeeLeaveDateTime')
$script:Scopes = @('User.ReadWrite.All', 'Group.ReadWrite.All', 'Directory.Read.All', 'User-LifeCycleInfo.ReadWrite.All',
                   'User.RevokeSessions.All', 'RoleManagement.Read.Directory')

function Connect-HvmcGraph {
    <# Sign in to Microsoft Graph. Default: reuse the Azure CLI sign-in (no browser). -Interactive: browser sign-in. #>
    [CmdletBinding()]
    param([switch]$Interactive)
    if ($Interactive) {
        Connect-MgGraph -Scopes $script:Scopes -NoWelcome
    } else {
        $az = (Get-Command az -ErrorAction SilentlyContinue)?.Source
        if (-not $az) { $az = Join-Path $HOME '.azure-cli-env/bin/az' }
        $token = & $az account get-access-token --resource-type ms-graph --query accessToken -o tsv 2>$null
        if (-not $token) { throw 'No Azure CLI sign-in found. Run "az login", or use -Interactive.' }
        Connect-MgGraph -AccessToken (ConvertTo-SecureString $token -AsPlainText -Force) -NoWelcome
    }
    $ctx = Get-MgContext
    Write-Host ("Connected to Microsoft Graph ({0})" -f $ctx.AuthType)
}

function Get-HvmcDesiredGroups {
    <# The SG-* groups a department should have, from the RBAC v2 matrix. #>
    param([Parameter(Mandatory)][string]$Department)
    if (-not $script:Matrix.groups.ContainsKey($Department)) { throw "Department '$Department' is not in the RBAC v2 matrix." }
    return [string[]]$script:Matrix.groups[$Department]
}

function Get-HvmcSgGroups {
    <# All SG-* groups in the tenant: name -> id. #>
    $map = @{}
    Get-MgGroup -All -Property id, displayName | Where-Object DisplayName -like 'SG-*' |
        ForEach-Object { $map[$_.DisplayName] = $_.Id }
    return $map
}

function Get-HvmcUser {
    <# Find a user by employee ID (preferred) or by user ID. Returns $null if not found. #>
    param([string]$EmployeeId, [string]$UserId)
    if ($UserId) { return Get-MgUser -UserId $UserId -Property $script:UserProps }
    $found = @(Get-MgUser -Filter "employeeId eq '$($EmployeeId.Replace("'", "''"))'" -Property $script:UserProps `
                          -ConsistencyLevel eventual -CountVariable count)
    if ($found.Count -gt 1) { throw "Employee ID $EmployeeId is used by $($found.Count) accounts - fix the HR data first." }
    return $found | Select-Object -First 1
}

function Get-HvmcUserGroups {
    <# The SG-* groups a user is a direct member of. #>
    param([Parameter(Mandatory)][string]$UserId)
    return @(Get-MgUserMemberOf -UserId $UserId -All |
             Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.group' } |
             ForEach-Object { $_.AdditionalProperties['displayName'] } |
             Where-Object { $_ -like 'SG-*' } | Sort-Object)
}

function Get-HvmcPrivilegedIds {
    <# IDs of every account that holds an Entra ID admin role - these are never changed by the lifecycle tools. #>
    $ids = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($role in Get-MgDirectoryRole -All) {
        Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All | ForEach-Object { [void]$ids.Add($_.Id) }
    }
    return $ids
}

function Get-HvmcInitialDomain {
    return (Get-MgDomain -All | Where-Object IsInitial | Select-Object -First 1).Id
}

function New-HvmcPassword {
    <# Random 24-character password; never printed or stored (the helpdesk issues the first password at hand-over). #>
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%+=?@'.ToCharArray()
    do {
        $pw = -join (1..24 | ForEach-Object { $chars[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($chars.Length)] })
    } until ($pw -cmatch '[a-z]' -and $pw -cmatch '[A-Z]' -and $pw -match '\d' -and $pw -match '[^A-Za-z0-9]')
    return $pw
}

function Get-HvmcUserState {
    <# Snapshot for evidence: account fields, groups, app assignments. #>
    param([Parameter(Mandatory)][string]$UserId)
    $u = Get-HvmcUser -UserId $UserId
    $mgr = try { (Get-MgUserManager -UserId $UserId -ErrorAction Stop).AdditionalProperties['displayName'] } catch { $null }
    $apps = @(Get-MgUserAppRoleAssignment -UserId $UserId -All | ForEach-Object ResourceDisplayName | Sort-Object)
    return [ordered]@{
        displayName = $u.DisplayName; employeeId = $u.EmployeeId; department = $u.Department; jobTitle = $u.JobTitle
        manager = $mgr; accountEnabled = $u.AccountEnabled; employeeLeaveDateTime = $u.EmployeeLeaveDateTime
        groups = @(Get-HvmcUserGroups -UserId $UserId); apps = $apps
    }
}

function New-HvmcPlan {
    param([string]$Ticket, [string]$Event, [string]$Employee)
    return [pscustomobject]@{
        Ticket = $Ticket; Event = $Event; Employee = $Employee; Status = 'Due'; Message = ''
        UserId = $null; Steps = [System.Collections.Generic.List[object]]::new(); Results = @(); Before = $null; After = $null
    }
}

function Add-HvmcStep {
    param([Parameter(Mandatory)]$Plan, [Parameter(Mandatory)][string]$Description, [Parameter(Mandatory)][scriptblock]$Action)
    $Plan.Steps.Add([pscustomobject]@{ Description = $Description; Action = $Action })
}

function Invoke-HvmcPlan {
    <# Run a plan's steps (only with -Apply). Stops the event at the first failure so it is never half-done silently.
       The "after" snapshot is taken by the caller, AFTER the application sync, so it shows the final access. #>
    param([Parameter(Mandatory)]$Plan, [switch]$Apply)
    if (-not $Apply -or $Plan.Status -ne 'Due' -or $Plan.Steps.Count -eq 0) { return }
    if ($Plan.UserId) { $Plan.Before = Get-HvmcUserState -UserId $Plan.UserId }
    $results = @()
    foreach ($step in $Plan.Steps) {
        try {
            $null = & $step.Action
            $results += [ordered]@{ time = (Get-Date).ToUniversalTime().ToString('s') + 'Z'; step = $step.Description; result = 'ok' }
        } catch {
            $results += [ordered]@{ time = (Get-Date).ToUniversalTime().ToString('s') + 'Z'; step = $step.Description; result = 'FAILED'
                                    error = ($_.Exception.Message -split "`n")[0] }
            Write-Warning "$($Plan.Ticket): step failed - $($step.Description): $(($_.Exception.Message -split "`n")[0])"
            $Plan.Status = 'Failed'
            break
        }
    }
    $Plan.Results = $results
    if ($Plan.Status -eq 'Due') { $Plan.Status = 'Done' }
}

function Invoke-HvmcAppSync {
    <# Sync application assignments from groups with the step 3 tool (Entra ID Free cannot assign groups to apps). #>
    $script = Join-Path $script:Root 'step3_enterprise_apps/enterprise_apps.py'
    $out = & python3 $script --apply 2>&1
    return (@($out | Where-Object { $_ -match 'applied|FAILED' }) | Select-Object -Last 1) ?? ($out | Select-Object -Last 1)
}

function Write-HvmcEvidence {
    <# Save the run (plans, steps, results, before/after) as JSON in evidence/ - kept out of Git. No passwords are ever included. #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)]$Data)
    $dir = Join-Path $script:Here 'evidence'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $path = Join-Path $dir ('{0}_{1}.json' -f (Get-Date -Format 'yyyyMMdd_HHmmss'), $Name)
    $Data | ConvertTo-Json -Depth 8 | Set-Content -Path $path -Encoding utf8
    return $path
}

Export-ModuleMember -Function Connect-HvmcGraph, Get-HvmcDesiredGroups, Get-HvmcSgGroups, Get-HvmcUser, Get-HvmcUserGroups,
    Get-HvmcPrivilegedIds, Get-HvmcInitialDomain, New-HvmcPassword, Get-HvmcUserState, New-HvmcPlan, Add-HvmcStep,
    Invoke-HvmcPlan, Invoke-HvmcAppSync, Write-HvmcEvidence
