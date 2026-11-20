<#
.SYNOPSIS
    HVMC Healthcare IAM - Step 10 / Activity 4: MFA support - a user has lost the phone with their Authenticator app.

.DESCRIPTION
    Horizon Valley Medical Center | Author: Sabitha S Karanavar

    Help-desk process for a lost MFA device in Microsoft Entra ID (Free tier):
      Status   read-only: the user's sign-in state, registered methods and recent security-info audit events
      Reset    contain and reset: revoke all sign-in sessions, then remove every MFA method (Authenticator, phone,
               software OATH, FIDO2) so whoever holds the lost phone can no longer approve sign-ins.
               The password and the SSPR email are not touched. Dry run unless -Apply.
               -Apply also needs -VerifiedBy: how the caller's identity was confirmed BEFORE anything is changed
               (help-desk social engineering is a real attack path).
      Verify   after the user has registered the new phone: checks a new method exists, created after the reset,
               and shows the audit trail ("Admin deleted security info" -> "User registered security info").
    Accounts with an Entra ID admin role are refused: admin MFA recovery follows the break-glass process instead.
    Phone numbers are masked in all output and evidence. Evidence JSON goes to evidence/ (kept out of Git).

    Needs a browser sign-in once (scope UserAuthenticationMethod.ReadWrite.All is not in the Azure CLI token).

.EXAMPLE
    ./Invoke-HvmcMfaSupport.ps1 -Action Status
    ./Invoke-HvmcMfaSupport.ps1 -Action Reset                                         # dry run: shows the plan
    ./Invoke-HvmcMfaSupport.ps1 -Action Reset -Apply -VerifiedBy "Call-back to the HR phone number on file"
    ./Invoke-HvmcMfaSupport.ps1 -Action Verify
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Status', 'Reset', 'Verify')][string]$Action,
    [string]$EmployeeId = 'HVMC-1001',
    [string]$Ticket = 'IAM-0004',
    [switch]$Apply,
    [string]$VerifiedBy,
    [switch]$DeviceCode
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../step8b_lifecycle_automation/HVMC.Lifecycle.psm1') -Force
$Evidence = Join-Path $PSScriptRoot 'evidence'
$Scopes = @('User.ReadWrite.All', 'UserAuthenticationMethod.ReadWrite.All', 'AuditLog.Read.All', 'Directory.Read.All',
            'RoleManagement.Read.Directory')

# ---------------------------------------------------------------- helpers
function Connect-MfaGraph {
    $ctx = Get-MgContext
    $missing = if ($ctx) { @($Scopes | Where-Object { $ctx.Scopes -notcontains $_ }) } else { $Scopes }
    if ($missing.Count) {
        if ($DeviceCode) {
            Write-Host 'Sign-in needed. Within 2 minutes: open https://login.microsoft.com/device in a normal browser window,'
            Write-Host '  type the code below, sign in as helpdesk.admin, approve MFA and accept the permissions.'
        } else {
            Write-Host 'Sign-in needed: a browser window opens. Sign in as helpdesk.admin (the help-desk account), approve MFA, accept the'
            Write-Host '  permissions, and keep the tab open until this window continues (use -DeviceCode if no browser opens).'
        }
        # The admin is a personal (gmail) Microsoft account, so the HVMC tenant must be named or the sign-in
        # lands in the wrong directory ("You don't have access to this"). The ID comes from the Azure CLI sign-in.
        $tenant = $env:HVMC_TENANT_ID
        if (-not $tenant) { $tenant = (& az account show --query tenantId -o tsv 2>$null) }
        if (-not $tenant) { throw 'Tenant ID not found - run "az login" first, or set $env:HVMC_TENANT_ID.' }
        $cm = @{ TenantId = $tenant.Trim(); Scopes = $Scopes; NoWelcome = $true }
        if ($DeviceCode) { $cm.UseDeviceCode = $true }
        Connect-MgGraph @cm
    }
    $ctx = Get-MgContext
    if (-not $ctx -or -not $ctx.Account) {
        throw 'Not signed in to Microsoft Graph - the sign-in did not finish. Run the command again and complete the sign-in.'
    }
    $still = @($Scopes | Where-Object { $ctx.Scopes -notcontains $_ })
    if ($still.Count) { throw ('Signed in, but these permissions were not granted: {0}' -f ($still -join ', ')) }
    Write-Host ('Connected to Microsoft Graph as {0}' -f ($ctx.Account -replace '@.*', '@<tenant>'))
}

function Hide-Phone([string]$n) { if ($n.Length -gt 4) { ($n.Substring(0, [Math]::Min(3, $n.Length)) + ' *** *** **' + $n.Substring($n.Length - 2)) } else { '****' } }

$TypeName = @{
    '#microsoft.graph.passwordAuthenticationMethod'                = 'Password'
    '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod'  = 'Microsoft Authenticator'
    '#microsoft.graph.phoneAuthenticationMethod'                   = 'Phone (SMS/voice)'
    '#microsoft.graph.softwareOathAuthenticationMethod'            = 'Software OATH token'
    '#microsoft.graph.fido2AuthenticationMethod'                   = 'FIDO2 security key'
    '#microsoft.graph.emailAuthenticationMethod'                   = 'Email (password reset only)'
    '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' = 'Windows Hello for Business'
    '#microsoft.graph.temporaryAccessPassAuthenticationMethod'     = 'Temporary Access Pass'
}
$MfaTypes = @('#microsoft.graph.microsoftAuthenticatorAuthenticationMethod', '#microsoft.graph.phoneAuthenticationMethod',
              '#microsoft.graph.softwareOathAuthenticationMethod', '#microsoft.graph.fido2AuthenticationMethod')

function Get-Methods([string]$uid) {
    foreach ($m in Get-MgUserAuthenticationMethod -UserId $uid -All) {
        $t = $m.AdditionalProperties['@odata.type']; $p = $m.AdditionalProperties
        $detail = switch ($t) {
            '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' { "device: $($p['displayName'])" }
            '#microsoft.graph.phoneAuthenticationMethod' { "$($p['phoneType']) $(Hide-Phone $p['phoneNumber'])" }
            '#microsoft.graph.fido2AuthenticationMethod' { "$($p['displayName'])" }
            '#microsoft.graph.emailAuthenticationMethod' { 'address on file (not shown)' }
            default { '' }
        }
        $created = if ($p['createdDateTime']) { ([datetime]$p['createdDateTime']).ToUniversalTime() } else { $null }
        [pscustomobject]@{ Id = $m.Id; Type = $t; Name = $TypeName[$t] ?? $t; Detail = $detail; Created = $created
                           IsMfa = $MfaTypes -contains $t }
    }
}

function Get-SecurityAudit([string]$uid, [datetime]$since) {
    $iso = $since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $url = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=targetResources/any(t:t/id eq '$uid') and activityDateTime ge $iso&`$top=50"
    $rows = (Invoke-MgGraphRequest -Method GET -Uri $url).value
    $rows | Sort-Object { [datetime]$_.activityDateTime } | ForEach-Object {
        $by = $_.initiatedBy.user.userPrincipalName ?? $_.initiatedBy.app.displayName ?? 'system'
        [pscustomobject]@{ Time = ([datetime]$_.activityDateTime).ToUniversalTime(); Activity = $_.activityDisplayName
                           Result = $_.result; By = (($by -replace '^.*#EXT#@.*$', 'Global Admin (IAM admin)') -replace '@.*', '@<tenant>') }
    }
}

function Show-Status($user, [datetime]$since) {
    Write-Host ("`n{0}  {1} ({2})  sign-in enabled: {3}" -f $Ticket, $user.DisplayName, $user.EmployeeId, $user.AccountEnabled)
    $methods = @(Get-Methods $user.Id)
    Write-Host ("  Registered methods ({0}):" -f $methods.Count)
    foreach ($m in $methods) {
        Write-Host ("    {0,-28} {1,-30} {2}" -f $m.Name, $m.Detail, ($m.Created ? "added $($m.Created.ToString('yyyy-MM-dd HH:mm')) UTC" : ''))
    }
    $mfa = @($methods | Where-Object IsMfa).Count
    Write-Host ("  MFA methods: {0}{1}" -f $mfa, $(if (-not $mfa) { '  (the user will be asked to register at next sign-in)' }))
    $audit = @(Get-SecurityAudit $user.Id $since)
    Write-Host ("  Audit events since {0:yyyy-MM-dd HH:mm} UTC ({1}):" -f $since.ToUniversalTime(), $audit.Count)
    foreach ($a in $audit) { Write-Host ("    {0:yyyy-MM-dd HH:mm}  {1,-40} {2,-8} by {3}" -f $a.Time, $a.Activity, $a.Result, $a.By) }
    return [ordered]@{ user = "$($user.DisplayName) ($($user.EmployeeId))"; accountEnabled = $user.AccountEnabled
        methods = @($methods | ForEach-Object { [ordered]@{ type = $_.Name; detail = $_.Detail; created = $_.Created } })
        mfaMethods = $mfa; audit = @($audit) }
}

function Save-Evidence([string]$name, $data) {
    New-Item -ItemType Directory -Path $Evidence -Force | Out-Null
    $path = Join-Path $Evidence ('{0}_{1}.json' -f (Get-Date -Format 'yyyyMMdd_HHmmss'), $name)
    $data | ConvertTo-Json -Depth 8 | Set-Content -Path $path -Encoding utf8
    return $path
}

# ---------------------------------------------------------------- main
Connect-MfaGraph
$user = Get-HvmcUser -EmployeeId $EmployeeId
if (-not $user) { throw "No account with employee ID $EmployeeId" }
$user = Get-MgUser -UserId $user.Id -Property id, displayName, employeeId, accountEnabled
if ((Get-HvmcPrivilegedIds).Contains($user.Id)) { throw "$($user.DisplayName) holds an admin role - use the break-glass / admin recovery process, not this script." }

switch ($Action) {
    'Status' {
        $s = Show-Status $user (Get-Date).AddDays(-7)
        Write-Host "`nEvidence: $(Save-Evidence 'mfa_status' ([ordered]@{ ticket = $Ticket; action = 'status'; at = (Get-Date).ToUniversalTime().ToString('s') + 'Z'; state = $s }))"
    }
    'Reset' {
        $before = Show-Status $user (Get-Date).AddDays(-7)
        $remove = @(Get-Methods $user.Id | Where-Object IsMfa)
        Write-Host ("`n{0}  Lost-device reset for {1}" -f ($Apply ? 'APPLY' : 'DRY RUN'), $user.DisplayName)
        Write-Host '   1. revoke all sign-in sessions (refresh tokens on every device, including the lost phone)'
        $i = 1; foreach ($m in $remove) { $i++; Write-Host ("  {0,2}. remove {1} {2}" -f $i, $m.Name, $m.Detail) }
        Write-Host '      (kept: password, and the password-reset email)'
        if (-not $remove.Count) { Write-Host '  No MFA method is registered - register one first (see the guide, step 0).' }
        if (-not $Apply) { Write-Host "`nDRY RUN - nothing was changed. Verify the caller's identity, then run with -Apply -VerifiedBy `"...`"."; return }
        if (-not $VerifiedBy) { throw 'Refused: -VerifiedBy is required with -Apply. Confirm the caller is really the user BEFORE resetting MFA.' }

        $started = (Get-Date).ToUniversalTime(); $results = @()
        Revoke-MgUserSignInSession -UserId $user.Id | Out-Null
        $results += [ordered]@{ time = (Get-Date).ToUniversalTime().ToString('HH:mm:ss'); step = 'revoke all sign-in sessions'; result = 'ok' }
        $pending = [System.Collections.Generic.List[object]]::new($remove)
        foreach ($pass in 1..2) {                       # the default method can only go once the others are gone - retry once
            foreach ($m in @($pending)) {
                try {
                    switch ($m.Type) {
                        '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' { Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $user.Id -MicrosoftAuthenticatorAuthenticationMethodId $m.Id }
                        '#microsoft.graph.phoneAuthenticationMethod' { Remove-MgUserAuthenticationPhoneMethod -UserId $user.Id -PhoneAuthenticationMethodId $m.Id }
                        '#microsoft.graph.softwareOathAuthenticationMethod' { Remove-MgUserAuthenticationSoftwareOathMethod -UserId $user.Id -SoftwareOathAuthenticationMethodId $m.Id }
                        '#microsoft.graph.fido2AuthenticationMethod' { Remove-MgUserAuthenticationFido2Method -UserId $user.Id -Fido2AuthenticationMethodId $m.Id }
                    }
                    $results += [ordered]@{ time = (Get-Date).ToUniversalTime().ToString('HH:mm:ss'); step = "remove $($m.Name) $($m.Detail)"; result = 'ok' }
                    $pending.Remove($m) | Out-Null
                } catch {
                    if ($pass -eq 2) { $results += [ordered]@{ time = (Get-Date).ToUniversalTime().ToString('HH:mm:ss'); step = "remove $($m.Name)"; result = "FAILED: $($_.Exception.Message)" } }
                }
            }
            if (-not $pending.Count) { break }
        }
        foreach ($r in $results) { Write-Host ("  {0}  {1,-60} {2}" -f $r.time, $r.step, $r.result) }
        # Entra replicates the deletion: the method can still be listed for a short time after a successful delete.
        Write-Host '  waiting for Entra ID to show the change (up to 2 minutes)...'
        foreach ($i in 1..24) {
            Start-Sleep -Seconds 5
            if (-not @(Get-Methods $user.Id | Where-Object IsMfa).Count) { break }
        }
        $after = Show-Status $user $started.AddMinutes(-1)
        $failed = @($results | Where-Object { $_.result -ne 'ok' })
        $okAll = -not $failed.Count -and $after.mfaMethods -eq 0
        Write-Host $(if ($okAll) { "`nRESET DONE: sessions revoked and all MFA methods removed. Ask the user to sign in and register the new phone." }
                     elseif ($failed.Count) { "`nRESET INCOMPLETE - see the FAILED lines above." }
                     else { "`nRESET SENT, NOT YET VISIBLE: every step returned ok but the method is still listed. Wait a few minutes and run -Action Status." })
        $ev = Save-Evidence 'mfa_reset' ([ordered]@{ ticket = $Ticket; action = 'reset'; mode = 'apply'; startedAt = $started.ToString('s') + 'Z'
            identityVerifiedBy = $VerifiedBy; results = $results; before = $before; after = $after; complete = $okAll })
        Write-Host "Evidence: $ev"
    }
    'Verify' {
        $last = Get-ChildItem $Evidence -Filter '*_mfa_reset.json' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
        if (-not $last) { throw 'No reset evidence found - run -Action Reset -Apply first.' }
        $reset = Get-Content $last.FullName -Raw | ConvertFrom-Json
        $resetAt = ([datetime]$reset.startedAt).ToUniversalTime()
        $s = Show-Status $user $resetAt.AddMinutes(-1)
        # Old methods removed: the reset saw 0 methods itself, or every step returned ok and a later status check saw 0
        # (Entra can list a deleted method for a short time, so the reset's own re-check may have been too early).
        $laterZero = @(Get-ChildItem $Evidence -Filter '*_mfa_status.json' | ForEach-Object { Get-Content $_.FullName -Raw | ConvertFrom-Json } |
                       Where-Object { ([datetime]$_.at).ToUniversalTime() -gt $resetAt -and $_.state.mfaMethods -eq 0 })
        $removed = [bool]$reset.complete -or (-not @($reset.results | Where-Object { $_.result -ne 'ok' }).Count -and $laterZero.Count -gt 0)
        # New method: Authenticator entries often have no creation date, so also accept "MFA method present now + user
        # registered security info after the reset" (the old one was removed, so any method now is new).
        $mfaNow = @(Get-Methods $user.Id | Where-Object IsMfa)
        $regAfter = [bool]($s.audit | Where-Object { $_.Time -gt $resetAt -and $_.Activity -match 'register.*security info|registered.*authentication method' })
        $newOk = @($mfaNow | Where-Object { $_.Created -and $_.Created -gt $resetAt }).Count -gt 0 -or ($mfaNow.Count -gt 0 -and $removed -and $regAfter)
        $checks = [ordered]@{
            'identity verified before the reset'          = [bool]$reset.identityVerifiedBy
            'old MFA methods removed at reset'            = $removed
            'new MFA method registered after the reset'   = $newOk
            'audit: admin deleted security info'          = [bool]($s.audit | Where-Object { $_.Activity -match 'delete.*security info|delete.*authentication method' })
            'audit: user registered security info'        = [bool]($s.audit | Where-Object { $_.Activity -match 'register.*security info|registered.*authentication method' })
            'account still enabled'                       = [bool]$user.AccountEnabled
        }
        Write-Host ''
        foreach ($k in $checks.Keys) { Write-Host ("  {0}  {1}" -f ($checks[$k] ? 'PASS' : 'FAIL'), $k) }
        $pass = @($checks.Values | Where-Object { $_ }).Count
        Write-Host ("`n{0}/{1} checks passed{2}" -f $pass, $checks.Count, $(if ($pass -lt $checks.Count) { ' - audit events can take up to 15 minutes to appear; run Verify again later' }))
        $ev = Save-Evidence 'mfa_verify' ([ordered]@{ ticket = $Ticket; action = 'verify'; at = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
            resetAt = $reset.startedAt; checks = $checks; state = $s })
        Write-Host "Evidence: $ev"
    }
}
