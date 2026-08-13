#Requires -Version 7.0
<#
.SYNOPSIS
    Deletes all resource groups in the current Azure subscription.

.DESCRIPTION
    Finds all resource groups, kicks off deletion with --no-wait, then polls
    until every group is gone or has errored.

.PARAMETER SubscriptionId
    Optional. Target subscription ID. Defaults to the current az cli context.

.PARAMETER PollIntervalSeconds
    How often (in seconds) to re-check deletion progress. Default: 15.

.EXAMPLE
    .\Clear-Subscription.ps1
    .\Clear-Subscription.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000"
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $SubscriptionId,
    [int]    $PollIntervalSeconds = 15,
    [int]    $MaxRetries = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── 1. Resolve subscription ──────────────────────────────────────────────────
if ($SubscriptionId) {
    az account set --subscription $SubscriptionId
    if ($LASTEXITCODE -ne 0) { throw "Failed to set subscription '$SubscriptionId'." }
}

$sub = az account show --query "{id:id, name:name}" --output json | ConvertFrom-Json
Write-Host ""
Write-Host ("-" * 70) -ForegroundColor Cyan
Write-Host "  Subscription : $($sub.name)" -ForegroundColor Cyan
Write-Host "  ID           : $($sub.id)" -ForegroundColor Cyan
Write-Host ("-" * 70) -ForegroundColor Cyan
Write-Host ""

# ── 2. Find all resource groups ──────────────────────────────────────────────
Write-Host "`nFetching resource groups..." -ForegroundColor Cyan
$groups = az group list --query "[].name" --output json | ConvertFrom-Json

if ($groups.Count -eq 0) {
    Write-Host "No resource groups found. Nothing to do." -ForegroundColor Green
    exit 0
}

Write-Host "Found $($groups.Count) resource group(s):" -ForegroundColor Yellow
$groups | ForEach-Object { Write-Host "  - $_" }

# ── 3. Check for resource locks ──────────────────────────────────────────────
Write-Host "`nChecking for resource locks across all resource groups..." -ForegroundColor Cyan

[array]$allLocks = @(az lock list --query "[].{name:name, level:level, resourceGroup:resourceGroup, id:id}" --output json | ConvertFrom-Json)

# Enrich each lock with scope info by inspecting the resource ID.
# RG lock id:       .../resourceGroups/{rg}/providers/Microsoft.Authorization/locks/{name}
# Resource lock id: .../resourceGroups/{rg}/providers/{ns}/{type}/{resource}/providers/Microsoft.Authorization/locks/{name}
foreach ($lock in $allLocks) {
    # Strip the lock suffix to get the parent path
    $parent = $lock.id -replace '/providers/Microsoft\.Authorization/locks/[^/]+$', ''
    if ($parent -match '/providers/[^/]+/[^/]+/[^/]+$') {
        $lock | Add-Member -NotePropertyName 'scope'    -NotePropertyValue 'Resource'
        $lock | Add-Member -NotePropertyName 'resource' -NotePropertyValue ($parent -split '/')[-1]
    }
    else {
        $lock | Add-Member -NotePropertyName 'scope'    -NotePropertyValue 'ResourceGroup'
        $lock | Add-Member -NotePropertyName 'resource' -NotePropertyValue ''
    }
}

if (@($allLocks).Count -gt 0) {
    Write-Host "`nWARNING: $(@($allLocks).Count) lock(s) found — these will block deletion:" -ForegroundColor Red
    $allLocks | ForEach-Object {
        $target = if ($_.scope -eq 'Resource') { "$($_.resourceGroup)/$($_.resource)" } else { $_.resourceGroup }
        Write-Host ("  [{0}] {1,-20} {2,-12} {3}" -f $_.level, $_.name, $_.scope, $target) -ForegroundColor Red
    }
    Write-Host ""
    $removeLocks = Read-Host "Remove all locks automatically before deleting? (yes/no)"
    if ($removeLocks -eq 'yes') {
        foreach ($lock in $allLocks) {
            if ($PSCmdlet.ShouldProcess("$($lock.resourceGroup)/$($lock.name)", "Remove resource lock")) {
                Write-Host "  Removing lock '$($lock.name)' [$($lock.scope)] from '$($lock.resourceGroup)'..."
                # Use --ids so resource-level locks are resolved correctly regardless of scope
                az lock delete --ids $lock.id
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning "  Failed to remove lock '$($lock.name)' — deletion of '$($lock.resourceGroup)' may fail."
                }
            }
        }
        Write-Host "  All locks removed." -ForegroundColor Green
    }
    else {
        Write-Host "Locks were not removed. Proceeding anyway — affected resource groups will likely fail to delete." -ForegroundColor Yellow
    }
}
else {
    Write-Host "  No locks found." -ForegroundColor Green
}

# ── 4. Safety confirmation ───────────────────────────────────────────────────
$confirm = Read-Host "`nType 'yes' to delete ALL resource groups in this subscription"
if ($confirm -ne 'yes') {
    Write-Host "Aborted." -ForegroundColor Yellow
    exit 0
}

# ── 5. Kick off async deletion ───────────────────────────────────────────────
Write-Host "`nStarting deletion (--no-wait)..." -ForegroundColor Cyan

foreach ($rg in $groups) {
    if ($PSCmdlet.ShouldProcess($rg, "Delete resource group")) {
        Write-Host "  Deleting: $rg"
        $output = az group delete --name $rg --yes --no-wait 2>&1
        if ($LASTEXITCODE -ne 0) {
            $outputStr = $output | Out-String
            if ($outputStr -match 'DenyAssignmentAuthorizationFailed') {
                Write-Warning "  '$rg' has a deny assignment (managed resource group) — will auto-delete with parent"
                $managedRGs[$rg] = $true
            }
            else {
                Write-Warning "  az group delete returned a non-zero exit code for '$rg' — it may still be queued."
            }
        }
    }
}

# ── 6. Poll until all groups are gone ────────────────────────────────────────
Write-Host "`nPolling for completion every $PollIntervalSeconds second(s)...`n" -ForegroundColor Cyan

$retryCounts = @{}
$managedRGs = @{}   # RGs protected by deny assignment (auto-deleted with parent)
# Initialize retry counts for all groups — initial delete counts as attempt 1
foreach ($rg in $groups) {
    $retryCounts[$rg] = 1
}

$deletedLog = [System.Collections.Generic.List[PSCustomObject]]::new()
$previousRemaining = $groups   # seed with all groups so first disappearances are captured
[array]$stuck = @()            # pre-init so summary section is safe if loop exits early
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

do {
    Start-Sleep -Seconds $PollIntervalSeconds

    [array]$remaining = az group list --query "[].{name:name, state:properties.provisioningState}" --output json |
    ConvertFrom-Json

    $elapsed = "{0:mm\:ss}" -f $stopwatch.Elapsed

    # Detect RGs that disappeared since the last poll
    [array]$remainingNames = @($remaining | Select-Object -ExpandProperty name)
    foreach ($prev in $previousRemaining) {
        $prevName = if ($prev -is [string]) { $prev } else { $prev.name }
        if ($prevName -notin $remainingNames) {
            $attempts = if ($retryCounts.ContainsKey($prevName)) { $retryCounts[$prevName] + 1 } else { 1 }
            $deletedLog.Add([PSCustomObject]@{ Name = $prevName; Attempts = $attempts })
        }
    }
    $previousRemaining = $remaining

    if (@($remaining).Count -eq 0) {
        Write-Host "[$elapsed] All resource groups deleted successfully." -ForegroundColor Green
        break
    }

    Write-Host "[$elapsed] $(@($remaining).Count) group(s) still present:"
    foreach ($r in $remaining) {
        $stateColor = switch ($r.state) {
            'Deleting' { 'Yellow' }
            'Failed' { 'Red' }
            default { 'Gray' }
        }
        Write-Host ("  {0,-50} {1}" -f $r.name, $r.state) -ForegroundColor $stateColor
    }

    # Retry any RG that is no longer actively deleting (Failed, Succeeded, or unknown state).
    # ARM sometimes reverts state back to Succeeded on failure rather than showing Failed.
    # Skip managed RGs (protected by deny assignment) — they auto-delete with their parent.
    [array]$notDeleting = @($remaining | Where-Object { $_.state -ne 'Deleting' -and -not $managedRGs[$_.name] })
    foreach ($f in $notDeleting) {
        if (-not $retryCounts.ContainsKey($f.name)) { $retryCounts[$f.name] = 0 }

        if ($retryCounts[$f.name] -ge $MaxRetries) {
            # Already at limit — will be caught in the stuck check below
        }
        else {
            # Increment before ShouldProcess so the counter advances in -WhatIf mode too
            $retryCounts[$f.name]++
            if ($PSCmdlet.ShouldProcess($f.name, "Retry delete resource group (attempt $($retryCounts[$f.name])/$MaxRetries)")) {
                Write-Host "    Re-queuing: $($f.name) [$($f.state)] (attempt $($retryCounts[$f.name])/$MaxRetries)" -ForegroundColor Yellow
                az group delete --name $f.name --yes --no-wait
            }
        }
    }

    # If all remaining non-managed RGs have hit the retry limit, break to avoid infinite loop
    [array]$stuck = @($remaining | Where-Object { -not $managedRGs[$_.name] -and $retryCounts[$_.name] -ge $MaxRetries })
    [array]$managedStill = @($remaining | Where-Object { $managedRGs[$_.name] })
    $nonManagedRemaining = @($remaining).Count - @($managedStill).Count
    if ($nonManagedRemaining -gt 0 -and @($stuck).Count -eq $nonManagedRemaining) {
        break
    }

} while (@($remaining).Count -gt 0)

$stopwatch.Stop()

# ── 7. Final summary ─────────────────────────────────────────────────────────
Write-Host "`n── Deletion Summary ──────────────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host "  Subscription : $($sub.name)" -ForegroundColor Cyan
Write-Host "  ID           : $($sub.id)" -ForegroundColor Cyan
Write-Host ("  {0,-50} {1,-8} {2}" -f 'Resource Group', 'Attempts', 'Status')
Write-Host ("  {0,-50} {1,-8} {2}" -f ('-' * 50), ('-' * 8), ('-' * 6))

$stuckNames = @($stuck | Select-Object -ExpandProperty name)

foreach ($entry in ($deletedLog | Sort-Object Name)) {
    $colour = if ($entry.Attempts -eq 1) { 'Green' } else { 'Yellow' }
    Write-Host ("  {0,-50} {1,-8} {2}" -f $entry.Name, $entry.Attempts, 'Deleted') -ForegroundColor $colour
}

foreach ($m in ($managedRGs.Keys | Sort-Object)) {
    $attempts = if ($retryCounts.ContainsKey($m)) { $retryCounts[$m] } else { '1' }
    Write-Host ("  {0,-50} {1,-8} {2}" -f $m, $attempts, 'MANAGED') -ForegroundColor Cyan
}

foreach ($s in ($stuck | Sort-Object name)) {
    $attempts = if ($retryCounts.ContainsKey($s.name)) { $retryCounts[$s.name] } else { '?' }
    Write-Host ("  {0,-50} {1,-8} {2}" -f $s.name, $attempts, 'STUCK') -ForegroundColor Red
}

Write-Host ""
Write-Host "  Deleted : $($deletedLog.Count)" -ForegroundColor Green
if (@($managedRGs).Count -gt 0) {
    Write-Host "  Managed : $(@($managedRGs).Count)" -ForegroundColor Cyan
}
if (@($stuck).Count -gt 0) {
    Write-Host "  Stuck   : $(@($stuck).Count)" -ForegroundColor Red
}
Write-Host "  Total time: $("{0:mm\:ss}" -f $stopwatch.Elapsed)" -ForegroundColor Cyan
