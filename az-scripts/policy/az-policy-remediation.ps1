#Requires -Modules Az.PolicyInsights, Az.Resources, Az.Accounts

<#
.SYNOPSIS
    Remediates all non-compliant DeployIfNotExists and Modify policy assignments across
    management groups and subscriptions, then reports on outcomes.

.DESCRIPTION
    Phase 1 – Discovery   : Enumerates accessible management groups and subscriptions,
                            or uses the lists you provide.
    Phase 2 – Assessment  : Queries non-compliant policy states and filters to only those
                            with a deployIfNotExists or modify effect that actually have
                            non-compliant resources. Policies with zero non-compliant
                            resources are skipped entirely.
    Phase 3 – Remediation : Starts one remediation task per unique assignment (and per
                            policy definition reference when the assignment targets an
                            initiative / policy set).
    Phase 4 – Monitoring  : Polls each remediation until it reaches a terminal state
                            (Succeeded / Failed / Canceled) or the timeout is reached.
    Phase 5 – Reporting   : Outputs a summary table, a failure detail block, and exports
                            a timestamped Markdown report next to the script.

    IMPORTANT: Remediation tasks are created at the same scope as the assignment
    (management group or subscription), regardless of where the non-compliance was
    discovered. Deduplication by assignment ID + initiative reference ID ensures no
    assignment is remediated twice even when the same assignment appears in both a
    parent management group query and a child subscription query.

.PARAMETER ManagementGroupIds
    One or more management group IDs (short names, e.g. 'mg-platform') to process.
    If omitted, ALL management groups accessible under the current tenant are discovered.
    Pass an empty array @() to skip management group scope entirely.

.PARAMETER SubscriptionIds
    One or more subscription IDs (GUIDs) to process.
    If omitted, ALL enabled subscriptions accessible to the current account are used.
    Pass an empty array @() to skip subscription scope entirely.

.PARAMETER MaxWaitMinutes
    Maximum minutes to wait for all remediations before generating the report.
    Remediations still running at timeout are reported as 'TimedOut'. Default: 60.

.PARAMETER PollIntervalSeconds
    Seconds between remediation status polls during Phase 4. Default: 30.

.PARAMETER Mode
    Execution mode:
    - StartOnly    : Discover and start remediations, save a run file, then exit.
    - StartAndWait : Discover/start and then monitor until completion/timeout.
    - ReportOnly   : Do not start anything; load a previous run file and report status.
    - CancelOnly   : Load a previous run file and stop any active remediations in it.

.PARAMETER MaxRemediations
    Optional cap on how many remediation targets are processed in this run.
    Use this to test with a single remediation before scaling out. Default: 0.

.PARAMETER RunFilePath
    Optional path to a run file (JSON) produced by StartOnly/StartAndWait.
    - In ReportOnly mode: required unless you want to use the newest run file in script folder.
    - In Start modes : optional output path for the run file.

.EXAMPLE
    # Run against everything accessible in the tenant
    .\az-policy-remediation.ps1

.EXAMPLE
    # Target specific management groups and subscriptions
    .\az-policy-remediation.ps1 `
        -ManagementGroupIds 'mg-platform', 'mg-landing-zones' `
        -SubscriptionIds    '00000000-0000-0000-0000-000000000001'

.EXAMPLE
    # Dry-run — show what would be remediated without starting anything
    .\az-policy-remediation.ps1 -WhatIf

.EXAMPLE
    # Skip management group scope, process subscriptions only
    .\az-policy-remediation.ps1 -ManagementGroupIds @()

.EXAMPLE
    # Fast kickoff - no waiting; capture run file for later status reporting
    .\az-policy-remediation.ps1 -Mode StartOnly

.EXAMPLE
    # Later: report statuses/failures from a previous run file
    .\az-policy-remediation.ps1 -Mode ReportOnly -RunFilePath .\policy-remediation-run-20260604-180010.json
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter()]
    [AllowEmptyCollection()]
    [string[]]$ManagementGroupIds,

    [Parameter()]
    [AllowEmptyCollection()]
    [string[]]$SubscriptionIds,

    [Parameter()]
    [ValidateRange(1, 1440)]
    [int]$MaxWaitMinutes = 60,

    [Parameter()]
    [ValidateRange(10, 300)]
    [int]$PollIntervalSeconds = 30,

    [Parameter()]
    [ValidateSet('StartOnly', 'StartAndWait', 'ReportOnly', 'CancelOnly')]
    [string]$Mode = 'StartAndWait',

    [Parameter()]
    [ValidateRange(0, 1000)]
    [int]$MaxRemediations = 0,

    [Parameter()]
    [string]$RunFilePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Effects that support (and require) remediation
$REMEDIABLE_EFFECTS = @('deployIfNotExists', 'modify')

# States from which a remediation will not progress further
$TERMINAL_STATES = @('Succeeded', 'Failed', 'Canceled', 'LaunchFailed')

# ── Helpers ───────────────────────────────────────────────────────────────────

function Write-Section {
    param([string]$Title)
    $line = '─' * 72
    Write-Host "`n$line" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "$line`n" -ForegroundColor Cyan
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )
    $colour = switch ($Level) {
        'SUCCESS' { 'Green' }
        'WARN' { 'Yellow' }
        'ERROR' { 'Red' }
        default { 'White' }
    }
    Write-Host "[$Level] $(Get-Date -Format 'HH:mm:ss')  $Message" -ForegroundColor $colour
}

# Executes a scriptblock with PowerShell progress output disabled.
# This keeps Az cmdlet progress noise out of console while preserving script logs.
function Invoke-WithProgressSuppressed {
    param([scriptblock]$ScriptBlock)

    $previousProgressPreference = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        & $ScriptBlock
    }
    finally {
        $ProgressPreference = $previousProgressPreference
    }
}

# Parses a fully-qualified Policy Assignment resource ID and returns the scope details.
function Resolve-AssignmentScope {
    param([string]$PolicyAssignmentId)

    if ($PolicyAssignmentId -match '^/providers/Microsoft\.Management/managementGroups/([^/]+)/') {
        return [PSCustomObject]@{ Type = 'ManagementGroup'; ManagementGroupId = $Matches[1] }
    }
    if ($PolicyAssignmentId -match '^/subscriptions/([^/]+)/resourceGroups/([^/]+)/') {
        return [PSCustomObject]@{ Type = 'ResourceGroup'; SubscriptionId = $Matches[1]; ResourceGroupName = $Matches[2] }
    }
    if ($PolicyAssignmentId -match '^/subscriptions/([^/]+)/') {
        return [PSCustomObject]@{ Type = 'Subscription'; SubscriptionId = $Matches[1] }
    }
    return [PSCustomObject]@{ Type = 'Unknown' }
}

# Builds a valid remediation name that is unique, lowercase, and ≤ 64 characters.
function New-RemediationName {
    param(
        [string]$AssignmentId,
        [string]$PolicyDefinitionReferenceId = ''
    )
    $timestamp = Get-Date -Format 'yyyyMMddHHmmss'   # 14 chars
    $assignmentName = ($AssignmentId -split '/')[-1]
    $safeName = ($assignmentName -replace '[^a-zA-Z0-9]', '-').ToLower()

    if ($PolicyDefinitionReferenceId) {
        $safeRef = ($PolicyDefinitionReferenceId -replace '[^a-zA-Z0-9]', '-').ToLower()
        $name = "rem-${safeName}-${safeRef}-${timestamp}"
    }
    else {
        $name = "rem-${safeName}-${timestamp}"
    }

    # Trim to 64 chars while keeping the timestamp suffix for uniqueness
    if ($name.Length -gt 64) {
        $overhead = 4 + 1 + $timestamp.Length   # "rem-" + "-" + timestamp
        $allowedLen = 64 - $overhead
        $name = "rem-$($safeName.Substring(0, [Math]::Min($safeName.Length, $allowedLen)))-$timestamp"
    }
    return $name
}

function Resolve-RunFilePath {
    param(
        [string]$InputPath,
        [string]$ExecutionMode
    )

    if ($InputPath) {
        return $InputPath
    }

    if ($ExecutionMode -in @('StartOnly', 'StartAndWait')) {
        return (Join-Path $PSScriptRoot ("policy-remediation-run-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
    }

    $latest = Get-ChildItem -Path $PSScriptRoot -Filter 'policy-remediation-run-*.json' -File |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

    if ($latest) {
        return $latest.FullName
    }

    throw 'No run file found. Provide -RunFilePath or run StartOnly first.'
}

function Get-RemediationCurrentState {
    param([PSCustomObject]$RemediationRecord)

    $getParams = @{ Name = $RemediationRecord.RemediationName; ErrorAction = 'Stop' }
    switch ($RemediationRecord.ScopeType) {
        'ManagementGroup' { $getParams['ManagementGroupName'] = $RemediationRecord.ManagementGroupId }
        'Subscription' { $getParams['SubscriptionId'] = $RemediationRecord.SubscriptionId }
        'ResourceGroup' {
            $getParams['SubscriptionId'] = $RemediationRecord.SubscriptionId
            $getParams['ResourceGroupName'] = $RemediationRecord.ResourceGroupName
        }
    }

    $current = Get-AzPolicyRemediation @getParams
    $deploymentSummary = $null
    if (@($current.PSObject.Properties.Match('DeploymentSummary')).Count -gt 0) {
        $deploymentSummary = $current.DeploymentSummary
    }
    elseif (@($current.PSObject.Properties.Match('DeploymentStatus')).Count -gt 0) {
        $deploymentSummary = $current.DeploymentStatus
    }

    return [PSCustomObject]@{
        ProvisioningState  = $current.ProvisioningState
        ResourcesSucceeded = if ($deploymentSummary) { [int]$deploymentSummary.SuccessfulDeployments } else { 0 }
        ResourcesFailed    = if ($deploymentSummary) { [int]$deploymentSummary.FailedDeployments } else { 0 }
    }
}

function Get-DeploymentFailureReasons {
    param([PSCustomObject]$RemediationRecord)

    $getParams = @{
        Name          = $RemediationRecord.RemediationName
        IncludeDetail = $true
        ErrorAction   = 'Stop'
    }

    switch ($RemediationRecord.ScopeType) {
        'ManagementGroup' { $getParams['ManagementGroupName'] = $RemediationRecord.ManagementGroupId }
        'Subscription' { $getParams['Scope'] = "/subscriptions/$($RemediationRecord.SubscriptionId)" }
        'ResourceGroup' { $getParams['Scope'] = "/subscriptions/$($RemediationRecord.SubscriptionId)/resourceGroups/$($RemediationRecord.ResourceGroupName)" }
    }

    $detail = Get-AzPolicyRemediation @getParams
    $reasons = [System.Collections.Generic.List[string]]::new()
    $deploymentSummary = $null

    if (@($detail.PSObject.Properties.Match('DeploymentSummary')).Count -gt 0) {
        $deploymentSummary = $detail.DeploymentSummary
    }
    elseif (@($detail.PSObject.Properties.Match('DeploymentStatus')).Count -gt 0) {
        $deploymentSummary = $detail.DeploymentStatus
    }

    $deployments = @()
    if (@($detail.PSObject.Properties.Match('Deployments')).Count -gt 0 -and $detail.Deployments) {
        $deployments = @($detail.Deployments)
    }

    if ($deployments.Count -gt 0) {
        foreach ($deployment in $deployments) {
            if ($deployment.Status -ne 'Failed' -and -not $deployment.Error) {
                continue
            }

            $msg = $null
            if ($deployment.Error) {
                if ($deployment.Error.Message) {
                    $msg = $deployment.Error.Message
                }
                elseif ($deployment.Error.Details) {
                    $errorDetails = @($deployment.Error.Details)
                    if ($errorDetails.Count -gt 0) {
                        $firstDetail = $errorDetails | Select-Object -First 1
                        if ($firstDetail.Message) {
                            $msg = $firstDetail.Message
                        }
                        elseif ($firstDetail.PSObject.Properties['Message']) {
                            $msg = [string]$firstDetail.Message
                        }
                    }
                }
                elseif ($deployment.Error.Code) {
                    $msg = [string]$deployment.Error.Code
                }
                else {
                    $msg = ($deployment.Error | ConvertTo-Json -Depth 6 -Compress)
                }
            }

            if (-not $msg -and $deployment.PSObject.Properties['StatusMessage']) {
                $msg = [string]$deployment.StatusMessage
            }

            $resourceRef = if ($deployment.PSObject.Properties['RemediatedResourceId']) { [string]$deployment.RemediatedResourceId } elseif ($deployment.PSObject.Properties['ResourceId']) { [string]$deployment.ResourceId } elseif ($deployment.PSObject.Properties['DeploymentId']) { [string]$deployment.DeploymentId } else { 'unknown-resource' }
            if ($msg) {
                $reasons.Add("$resourceRef => $msg")
            }
        }
    }
    elseif ($deploymentSummary -and $deploymentSummary.FailedDeploymentDetails) {
        foreach ($failed in $deploymentSummary.FailedDeploymentDetails) {
            $msg = $null
            if ($failed.Error) {
                if ($failed.Error.Message) {
                    $msg = $failed.Error.Message
                }
                elseif ($failed.Error.Details) {
                    $errorDetails = @($failed.Error.Details)
                    if ($errorDetails.Count -gt 0) {
                        $firstDetail = $errorDetails | Select-Object -First 1
                        if ($firstDetail.Message) {
                            $msg = $firstDetail.Message
                        }
                        elseif ($firstDetail.PSObject.Properties['Message']) {
                            $msg = [string]$firstDetail.Message
                        }
                    }
                }
                elseif ($failed.Error.Code) {
                    $msg = [string]$failed.Error.Code
                }
                else {
                    $msg = ($failed.Error | ConvertTo-Json -Depth 6 -Compress)
                }
            }
            elseif ($failed.Message) {
                $msg = $failed.Message
            }

            if (-not $msg -and $failed.PSObject.Properties['StatusMessage']) {
                $msg = [string]$failed.StatusMessage
            }

            $resourceRef = if ($failed.PSObject.Properties['ResourceId']) { [string]$failed.ResourceId } elseif ($failed.PSObject.Properties['DeploymentId']) { [string]$failed.DeploymentId } else { 'unknown-resource' }
            if ($msg) {
                $reasons.Add("$resourceRef => $msg")
            }
        }
    }

    return $reasons
}

function Enrich-DeploymentFailureReasons {
    param([System.Collections.Generic.List[PSCustomObject]]$Records)

    $targets = @(
        $Records | Where-Object {
            $_.Status -in @('Failed', 'LaunchFailed', 'TimedOut', 'Canceled') -or $_.ResourcesFailed -gt 0
        }
    )

    if ($targets.Count -eq 0) {
        return
    }

    Write-Section 'Collecting deployment-level failure reasons'
    foreach ($record in $targets) {
        if ($record.Status -eq 'LaunchFailed') {
            continue
        }

        try {
            $reasons = Get-DeploymentFailureReasons -RemediationRecord $record
            if ($reasons.Count -gt 0) {
                $record.DeploymentFailureReasons = @($reasons)
                Write-Log "  Captured $($reasons.Count) deployment failure reason(s) for '$($record.PolicyAssignmentName)'" -Level WARN
            }
        }
        catch {
            $detail = $_.Exception.Message
            if ($record.ErrorDetail) {
                $record.ErrorDetail = "$($record.ErrorDetail); Failure-detail lookup: $detail"
            }
            else {
                $record.ErrorDetail = "Failure-detail lookup: $detail"
            }
            Write-Log "  Could not collect failure details for '$($record.PolicyAssignmentName)': $detail" -Level WARN
        }
    }
}

function Write-RemediationReport {
    param(
        [System.Collections.Generic.List[PSCustomObject]]$Records,
        [string]$ReportPath
    )

    Write-Section 'Phase 5 – Remediation Report'

    $total = $Records.Count
    $succeeded = @($Records | Where-Object { $_.Status -eq 'Succeeded' }).Count
    $failed = @($Records | Where-Object { $_.Status -eq 'Failed' }).Count
    $launchFail = @($Records | Where-Object { $_.Status -eq 'LaunchFailed' }).Count
    $timedOut = @($Records | Where-Object { $_.Status -eq 'TimedOut' }).Count
    $canceled = @($Records | Where-Object { $_.Status -eq 'Canceled' }).Count
    $inProgress = @($Records | Where-Object { $_.Status -in @('Pending', 'Started', 'InProgress', 'Accepted', 'Evaluating') }).Count

    $summaryColour = if ($failed -gt 0 -or $launchFail -gt 0) { 'Red' } elseif ($timedOut -gt 0 -or $inProgress -gt 0) { 'Yellow' } else { 'Green' }

    Write-Host '  ┌─────────────────────────────────────────────┐' -ForegroundColor $summaryColour
    Write-Host "  │  REMEDIATION SUMMARY                        │" -ForegroundColor $summaryColour
    Write-Host '  ├─────────────────────────────────────────────┤' -ForegroundColor $summaryColour
    Write-Host ("  │  Total tracked       : {0,-24}│" -f $total) -ForegroundColor White
    Write-Host ("  │  Succeeded           : {0,-24}│" -f $succeeded) -ForegroundColor $(if ($succeeded -gt 0) { 'Green' } else { 'White' })
    Write-Host ("  │  Failed              : {0,-24}│" -f $failed) -ForegroundColor $(if ($failed -gt 0) { 'Red' } else { 'White' })
    Write-Host ("  │  Launch failed       : {0,-24}│" -f $launchFail) -ForegroundColor $(if ($launchFail -gt 0) { 'Red' } else { 'White' })
    Write-Host ("  │  Timed out           : {0,-24}│" -f $timedOut) -ForegroundColor $(if ($timedOut -gt 0) { 'Yellow' } else { 'White' })
    Write-Host ("  │  Canceled            : {0,-24}│" -f $canceled) -ForegroundColor $(if ($canceled -gt 0) { 'Yellow' } else { 'White' })
    Write-Host ("  │  Still running       : {0,-24}│" -f $inProgress) -ForegroundColor $(if ($inProgress -gt 0) { 'Yellow' } else { 'White' })
    Write-Host '  └─────────────────────────────────────────────┘' -ForegroundColor $summaryColour

    Write-Host ''
    Write-Host '  All Remediations' -ForegroundColor White
    $Records | Sort-Object Status, PolicyAssignmentName |
    Format-Table -AutoSize -Property `
        PolicyAssignmentName,
    PolicyDefinitionAction,
    NonCompliantCount,
    @{ N = 'Succeeded'; E = { $_.ResourcesSucceeded } },
    @{ N = 'Failed'; E = { $_.ResourcesFailed } },
    Status,
    Scope

    $failures = @($Records | Where-Object { $_.Status -in @('Failed', 'LaunchFailed', 'TimedOut') -or $_.ResourcesFailed -gt 0 })

    $mdSummaryRows = [System.Collections.Generic.List[string]]::new()
    $mdFailureRows = [System.Collections.Generic.List[string]]::new()

    foreach ($row in ($Records | Sort-Object Status, PolicyAssignmentName)) {
        $mdSummaryRows.Add(("| {0} | {1} | {2} | {3} | {4} | {5} | {6} |" -f `
                (($row.PolicyAssignmentName -replace '\|', '\\|') -replace "`r|`n", ' '),
                (($row.PolicyDefinitionAction -replace '\|', '\\|') -replace "`r|`n", ' '),
                $row.NonCompliantCount,
                $row.ResourcesSucceeded,
                $row.ResourcesFailed,
                (($row.Status -replace '\|', '\\|') -replace "`r|`n", ' '),
                (($row.Scope -replace '\|', '\\|') -replace "`r|`n", ' ')
            ))
    }

    foreach ($f in $failures) {
        if ($f.DeploymentFailureReasons -and $f.DeploymentFailureReasons.Count -gt 0) {
            foreach ($reason in $f.DeploymentFailureReasons) {
                $mdFailureRows.Add(("| {0} | {1} | {2} | {3} | {4} |" -f `
                        (($f.PolicyAssignmentName -replace '\|', '\\|') -replace "`r|`n", ' '),
                        (($f.Status -replace '\|', '\\|') -replace "`r|`n", ' '),
                        $f.ResourcesFailed,
                        (($f.Scope -replace '\|', '\\|') -replace "`r|`n", ' '),
                        (($reason -replace '\|', '\\|') -replace "`r|`n", ' ')
                    ))
            }
        }
        elseif ($f.ErrorDetail) {
            $mdFailureRows.Add(("| {0} | {1} | {2} | {3} | {4} |" -f `
                    (($f.PolicyAssignmentName -replace '\|', '\\|') -replace "`r|`n", ' '),
                    (($f.Status -replace '\|', '\\|') -replace "`r|`n", ' '),
                    $f.ResourcesFailed,
                    (($f.Scope -replace '\|', '\\|') -replace "`r|`n", ' '),
                    (($f.ErrorDetail -replace '\|', '\\|') -replace "`r|`n", ' ')
                ))
        }
    }
    if ($failures.Count -gt 0) {
        Write-Host ''
        Write-Host '  ── Failure Details ──────────────────────────────────────────────────' -ForegroundColor Red
        foreach ($f in $failures) {
            Write-Host ''
            Write-Host "  Assignment   : $($f.PolicyAssignmentName)" -ForegroundColor Red
            Write-Host "  Effect       : $($f.PolicyDefinitionAction)"
            Write-Host "  Scope        : $($f.Scope)"
            Write-Host "  Status       : $($f.Status)"
            Write-Host "  Non-compliant: $($f.NonCompliantCount) resource(s) identified"
            Write-Host "  Succeeded    : $($f.ResourcesSucceeded)"
            Write-Host "  Failed res   : $($f.ResourcesFailed)"
            if ($f.PolicyDefinitionReferenceId) {
                Write-Host "  Init.Ref ID  : $($f.PolicyDefinitionReferenceId)"
            }
            if ($f.DeploymentFailureReasons) {
                foreach ($reason in $f.DeploymentFailureReasons) {
                    Write-Host "  Deploy Error : $reason" -ForegroundColor DarkRed
                }
            }
            if ($f.ErrorDetail) {
                Write-Host "  Error        : $($f.ErrorDetail)" -ForegroundColor DarkRed
            }
            Write-Host "  Remediation  : $($f.RemediationName)"
            Write-Host "  Assignment ID: $($f.PolicyAssignmentId)"
        }
        Write-Host ''
    }

    $mdLines = [System.Collections.Generic.List[string]]::new()
    $mdLines.Add('# Policy Remediation Report')
    $mdLines.Add('')
    $mdLines.Add(("Generated: {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')))
    $mdLines.Add('')
    $mdLines.Add('## Summary')
    $mdLines.Add('')
    $mdLines.Add(("- Total tracked: {0}" -f $total))
    $mdLines.Add(("- Succeeded: {0}" -f $succeeded))
    $mdLines.Add(("- Failed: {0}" -f $failed))
    $mdLines.Add(("- Launch failed: {0}" -f $launchFail))
    $mdLines.Add(("- Timed out: {0}" -f $timedOut))
    $mdLines.Add(("- Canceled: {0}" -f $canceled))
    $mdLines.Add(("- Still running: {0}" -f $inProgress))
    $mdLines.Add('')
    $mdLines.Add('## All Remediations')
    $mdLines.Add('')
    $mdLines.Add('| Assignment | Effect | NonCompliant | Succeeded | Failed | Status | Scope |')
    $mdLines.Add('|---|---|---:|---:|---:|---|---|')
    foreach ($line in $mdSummaryRows) {
        $mdLines.Add($line)
    }
    $mdLines.Add('')

    if ($mdFailureRows.Count -gt 0) {
        $mdLines.Add('## Failure Details')
        $mdLines.Add('')
        $mdLines.Add('| Assignment | Status | FailedCount | Scope | Reason |')
        $mdLines.Add('|---|---|---:|---|---|')
        foreach ($line in $mdFailureRows) {
            $mdLines.Add($line)
        }
        $mdLines.Add('')
    }

    Set-Content -Path $ReportPath -Value ($mdLines -join "`r`n") -Encoding UTF8
    Write-Log "Full report exported to: $ReportPath" -Level SUCCESS

    if ($failed -gt 0 -or $launchFail -gt 0 -or ($failures | Measure-Object).Count -gt 0) {
        exit 1
    }
    exit 0
}

function Save-RunFile {
    param(
        [System.Collections.Generic.List[PSCustomObject]]$Records,
        [string]$Path
    )

    $payload = [PSCustomObject]@{
        GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        Version        = 1
        Remediations   = $Records
    }

    $json = $payload | ConvertTo-Json -Depth 6
    Set-Content -Path $Path -Value $json -Encoding UTF8
    Write-Log "Run file saved: $Path" -Level SUCCESS
}

function Load-RunFile {
    param([string]$Path)

    if (-not (Test-Path -Path $Path -PathType Leaf)) {
        throw "Run file not found: $Path"
    }

    $payload = Get-Content -Path $Path -Raw | ConvertFrom-Json
    if (-not $payload.Remediations) {
        throw "Run file '$Path' does not contain remediation records."
    }

    $list = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($item in $payload.Remediations) {
        $list.Add([PSCustomObject]$item)
    }
    return $list
}

# ── Phase 0: Pre-flight ───────────────────────────────────────────────────────
Write-Section 'Phase 0 – Pre-flight checks'

try {
    $azContext = Get-AzContext -ErrorAction Stop
    if (-not $azContext) { throw 'No Azure context.' }
    Write-Log "Authenticated as : $($azContext.Account.Id)"
    Write-Log "Tenant           : $($azContext.Tenant.Id)"
    Write-Log "Default sub      : $($azContext.Subscription.Name) ($($azContext.Subscription.Id))"
}
catch {
    Write-Log "Azure authentication check failed: $_" -Level ERROR
    Write-Log 'Run Connect-AzAccount and retry.' -Level ERROR
    exit 1
}

if ($Mode -eq 'CancelOnly') {
    Write-Section 'CancelOnly mode – Stopping active remediations'

    try {
        $resolvedRunPath = Resolve-RunFilePath -InputPath $RunFilePath -ExecutionMode $Mode
        Write-Log "Using run file: $resolvedRunPath"
        $startedRemediations = Load-RunFile -Path $resolvedRunPath
    }
    catch {
        Write-Log "Unable to load run file: $($_.Exception.Message)" -Level ERROR
        exit 1
    }

    foreach ($rem in $startedRemediations) {
        try {
            $current = Get-RemediationCurrentState -RemediationRecord $rem
            $rem.ProvisioningState = $current.ProvisioningState
            $rem.ResourcesSucceeded = $current.ResourcesSucceeded
            $rem.ResourcesFailed = $current.ResourcesFailed
            $rem.Status = $current.ProvisioningState
            if ($current.ProvisioningState -in $TERMINAL_STATES -and -not $rem.EndTime) {
                $rem.EndTime = Get-Date
            }
        }
        catch {
            $rem.ErrorDetail = $_.Exception.Message
            Write-Log "Could not refresh '$($rem.RemediationName)' before cancel: $($_.Exception.Message)" -Level WARN
            continue
        }

        if ($rem.Status -in $TERMINAL_STATES) {
            Write-Log "Skipping '$($rem.RemediationName)' because it is already $($rem.Status)." -Level INFO
            continue
        }

        $stopParams = @{ Name = $rem.RemediationName; ErrorAction = 'Stop' }
        switch ($rem.ScopeType) {
            'ManagementGroup' { $stopParams['ManagementGroupName'] = $rem.ManagementGroupId }
            'Subscription' { $stopParams['Scope'] = "/subscriptions/$($rem.SubscriptionId)" }
            'ResourceGroup' { $stopParams['Scope'] = "/subscriptions/$($rem.SubscriptionId)/resourceGroups/$($rem.ResourceGroupName)" }
        }

        try {
            Invoke-WithProgressSuppressed {
                Stop-AzPolicyRemediation @stopParams | Out-Null
            }
            $rem.ProvisioningState = 'Canceled'
            $rem.Status = 'Canceled'
            $rem.EndTime = Get-Date
            $rem.ErrorDetail = $null
            Write-Log "Canceled remediation '$($rem.RemediationName)'" -Level SUCCESS
        }
        catch {
            $rem.ErrorDetail = $_.Exception.Message
            if (-not $rem.Status) { $rem.Status = 'Unknown' }
            Write-Log "Could not cancel '$($rem.RemediationName)': $($_.Exception.Message)" -Level WARN
        }
    }

    Save-RunFile -Records $startedRemediations -Path $resolvedRunPath
    $reportPath = Join-Path $PSScriptRoot "policy-remediation-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').md"
    Write-RemediationReport -Records $startedRemediations -ReportPath $reportPath
}

# Report-only flow: load prior run file and query current status
if ($Mode -eq 'ReportOnly') {
    Write-Section 'ReportOnly mode – Loading previous remediation run'

    try {
        $resolvedRunPath = Resolve-RunFilePath -InputPath $RunFilePath -ExecutionMode $Mode
        Write-Log "Using run file: $resolvedRunPath"
        $startedRemediations = Load-RunFile -Path $resolvedRunPath
    }
    catch {
        Write-Log "Unable to load run file: $($_.Exception.Message)" -Level ERROR
        exit 1
    }

    Write-Section 'Refreshing remediation statuses'
    foreach ($rem in $startedRemediations) {
        if ($rem.Status -eq 'LaunchFailed') { continue }

        try {
            $current = Get-RemediationCurrentState -RemediationRecord $rem
            $rem.ProvisioningState = $current.ProvisioningState
            $rem.ResourcesSucceeded = $current.ResourcesSucceeded
            $rem.ResourcesFailed = $current.ResourcesFailed
            $rem.Status = $current.ProvisioningState
            if ($current.ProvisioningState -in $TERMINAL_STATES -and -not $rem.EndTime) {
                $rem.EndTime = Get-Date
            }
        }
        catch {
            $rem.ErrorDetail = $_.Exception.Message
            if (-not $rem.Status) { $rem.Status = 'Unknown' }
            Write-Log "Could not refresh '$($rem.RemediationName)': $($_.Exception.Message)" -Level WARN
        }
    }

    Save-RunFile -Records $startedRemediations -Path $resolvedRunPath
    Enrich-DeploymentFailureReasons -Records $startedRemediations
    $reportPath = Join-Path $PSScriptRoot "policy-remediation-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').md"
    Write-RemediationReport -Records $startedRemediations -ReportPath $reportPath
}

# ── Phase 1: Scope discovery ──────────────────────────────────────────────────
Write-Section 'Phase 1 – Scope discovery'

# --- Management groups ---
# If the parameter was not supplied at all, discover all accessible MGs.
# If it was supplied as @(), skip MG scope.
$mgList = @()
if ($PSBoundParameters.ContainsKey('ManagementGroupIds') -and $ManagementGroupIds.Count -eq 0) {
    Write-Log 'Management group scope skipped (empty array provided).' -Level WARN
}
elseif ($PSBoundParameters.ContainsKey('ManagementGroupIds')) {
    foreach ($mgId in $ManagementGroupIds) {
        try {
            $mg = Get-AzManagementGroup -GroupId $mgId -ErrorAction Stop
            $mgList += $mg
            Write-Log "  ✓ Management group resolved: $($mg.DisplayName) ($($mg.Name))"
        }
        catch {
            Write-Log "  Management group '$mgId' not found or not accessible – skipping." -Level WARN
        }
    }
}
else {
    Write-Log 'No management groups specified – discovering all accessible management groups...'
    try {
        $mgList = @(Get-AzManagementGroup -ErrorAction Stop)
        Write-Log "Discovered $($mgList.Count) management group(s)."
    }
    catch {
        Write-Log "Could not enumerate management groups: $_" -Level WARN
    }
}

# --- Subscriptions ---
$subList = @()
if ($PSBoundParameters.ContainsKey('SubscriptionIds') -and $SubscriptionIds.Count -eq 0) {
    Write-Log 'Subscription scope skipped (empty array provided).' -Level WARN
}
elseif ($PSBoundParameters.ContainsKey('SubscriptionIds')) {
    foreach ($subId in $SubscriptionIds) {
        try {
            $sub = Get-AzSubscription -SubscriptionId $subId -ErrorAction Stop
            $subList += $sub
            Write-Log "  ✓ Subscription resolved: $($sub.Name) ($($sub.Id))"
        }
        catch {
            Write-Log "  Subscription '$subId' not found or not accessible – skipping." -Level WARN
        }
    }
}
else {
    Write-Log 'No subscriptions specified – discovering all enabled subscriptions...'
    try {
        $subList = @(Get-AzSubscription -TenantId $azContext.Tenant.Id -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' })
        Write-Log "Discovered $($subList.Count) enabled subscription(s)."
    }
    catch {
        Write-Log "Could not enumerate subscriptions: $_" -Level WARN
    }
}

if ($mgList.Count -eq 0 -and $subList.Count -eq 0) {
    Write-Log 'No accessible management groups or subscriptions to process. Exiting.' -Level ERROR
    exit 1
}

Write-Log "Scopes in scope: $($mgList.Count) management group(s), $($subList.Count) subscription(s)." -Level SUCCESS

# ── Phase 2: Non-compliant DINE/Modify policy assessment ─────────────────────
Write-Section 'Phase 2 – Non-compliant DINE/Modify policy assessment'

Write-Log 'Querying non-compliant policy states (server-side filter: ComplianceState eq NonCompliant).'
Write-Log 'Client-side filter will then isolate deployIfNotExists and modify effects only.'
Write-Log 'Note: only policies with at least one non-compliant resource are queued for remediation.'

# Key = "PolicyAssignmentId|PolicyDefinitionReferenceId"
# Using a hashtable ensures one remediation per unique assignment+reference pair.
$remediationMap = [System.Collections.Generic.Dictionary[string, PSCustomObject]]::new()

function Add-ToRemediationMap {
    param(
        [object[]]$States,
        [string]$ScopeLabel
    )
    foreach ($state in $States) {
        # Client-side effect filter — only act on remediable effects
        if ($state.PolicyDefinitionAction -notin $script:REMEDIABLE_EFFECTS) { continue }

        $key = "$($state.PolicyAssignmentId)|$($state.PolicyDefinitionReferenceId)"

        if (-not $remediationMap.ContainsKey($key)) {
            $remediationMap[$key] = [PSCustomObject]@{
                PolicyAssignmentId          = $state.PolicyAssignmentId
                PolicyDefinitionReferenceId = $state.PolicyDefinitionReferenceId
                PolicyDefinitionAction      = $state.PolicyDefinitionAction
                PolicyAssignmentName        = $state.PolicyAssignmentName
                PolicyDefinitionName        = $state.PolicyDefinitionName
                NonCompliantCount           = 0
                DiscoveredAt                = $ScopeLabel
            }
        }
        $remediationMap[$key].NonCompliantCount++
    }
}

# Query management groups
foreach ($mg in $mgList) {
    $mgName = $mg.Name   # Short MG name/ID — what all Az cmdlets expect
    Write-Log "Querying MG: $($mg.DisplayName) ($mgName) ..."
    try {
        $states = @(Get-AzPolicyState -ManagementGroupName $mgName `
                -Filter "ComplianceState eq 'NonCompliant'" -ErrorAction Stop)
        $dineModCount = @($states | Where-Object { $_.PolicyDefinitionAction -in $REMEDIABLE_EFFECTS }).Count
        Write-Log "  $($states.Count) non-compliant state(s) total | $dineModCount with DINE/Modify effect"
        Add-ToRemediationMap -States $states -ScopeLabel "MG:$mgName"
    }
    catch {
        Write-Log "  Failed to query policy states for MG '$mgName': $_" -Level WARN
    }
}

# Query subscriptions
foreach ($sub in $subList) {
    $subId = $sub.Id
    Write-Log "Querying Sub: $($sub.Name) ($subId) ..."
    try {
        $states = @(Get-AzPolicyState -SubscriptionId $subId `
                -Filter "ComplianceState eq 'NonCompliant'" -ErrorAction Stop)
        $dineModCount = @($states | Where-Object { $_.PolicyDefinitionAction -in $REMEDIABLE_EFFECTS }).Count
        Write-Log "  $($states.Count) non-compliant state(s) total | $dineModCount with DINE/Modify effect"
        Add-ToRemediationMap -States $states -ScopeLabel "Sub:$subId"
    }
    catch {
        Write-Log "  Failed to query policy states for subscription '$subId': $_" -Level WARN
    }
}

if ($remediationMap.Count -eq 0) {
    Write-Log 'No non-compliant DINE/Modify policy assignments found. Nothing to remediate.' -Level SUCCESS

    $startedRemediations = [System.Collections.Generic.List[PSCustomObject]]::new()
    $resolvedRunPath = Resolve-RunFilePath -InputPath $RunFilePath -ExecutionMode $Mode
    $reportPath = Join-Path $PSScriptRoot "policy-remediation-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').md"

    Save-RunFile -Records $startedRemediations -Path $resolvedRunPath
    Write-RemediationReport -Records $startedRemediations -ReportPath $reportPath
}

Write-Log "Found $($remediationMap.Count) unique assignment(s) with non-compliant resources to remediate." -Level SUCCESS

# Preview table
$remediationTargets = @($remediationMap.Values | Sort-Object PolicyAssignmentName, PolicyDefinitionReferenceId)
if ($MaxRemediations -gt 0 -and $remediationTargets.Count -gt $MaxRemediations) {
    Write-Log "Limiting this run to the first $MaxRemediations remediation target(s) for a smoke test." -Level WARN
    $remediationTargets = @($remediationTargets | Select-Object -First $MaxRemediations)
}

$remediationTargets |
Sort-Object PolicyAssignmentName |
Format-Table -AutoSize -Property `
    PolicyAssignmentName,
PolicyDefinitionAction,
NonCompliantCount,
@{ N = 'InitiativeRef'; E = { if ($_.PolicyDefinitionReferenceId) { $_.PolicyDefinitionReferenceId } else { '—' } } },
DiscoveredAt

# ── Phase 3: Start remediations ───────────────────────────────────────────────
Write-Section 'Phase 3 – Starting remediations'
if ($MaxRemediations -gt 0) {
    Write-Log "Test cap in effect: processing up to $MaxRemediations remediation target(s)."
}

$startedRemediations = [System.Collections.Generic.List[PSCustomObject]]::new()
$resolvedRunPath = Resolve-RunFilePath -InputPath $RunFilePath -ExecutionMode $Mode

foreach ($target in $remediationTargets) {

    $scope = Resolve-AssignmentScope -PolicyAssignmentId $target.PolicyAssignmentId
    $remName = New-RemediationName -AssignmentId $target.PolicyAssignmentId `
        -PolicyDefinitionReferenceId $target.PolicyDefinitionReferenceId

    # Build the Start-AzPolicyRemediation parameter hashtable
    $remParams = @{
        Name               = $remName
        PolicyAssignmentId = $target.PolicyAssignmentId
        ErrorAction        = 'Stop'
    }

    # Include the initiative definition reference when remediating a policy set member
    if ($target.PolicyDefinitionReferenceId) {
        $remParams['PolicyDefinitionReferenceId'] = $target.PolicyDefinitionReferenceId
    }

    # Set the scope-specific parameter and build a readable scope description
    switch ($scope.Type) {
        'ManagementGroup' {
            $remParams['ManagementGroupName'] = $scope.ManagementGroupId
            $scopeDesc = "MG:$($scope.ManagementGroupId)"
        }
        'Subscription' {
            $remParams['SubscriptionId'] = $scope.SubscriptionId
            $scopeDesc = "Sub:$($scope.SubscriptionId)"
        }
        'ResourceGroup' {
            $remParams['SubscriptionId'] = $scope.SubscriptionId
            $remParams['ResourceGroupName'] = $scope.ResourceGroupName
            $scopeDesc = "RG:$($scope.SubscriptionId)/$($scope.ResourceGroupName)"
        }
        default {
            Write-Log "  Cannot determine scope for '$($target.PolicyAssignmentId)' – skipping." -Level WARN
            continue
        }
    }

    $logLine = "$($target.PolicyAssignmentName) | Effect: $($target.PolicyDefinitionAction) | " +
    "Non-compliant: $($target.NonCompliantCount) | Scope: $scopeDesc"

    # Build the record that will be tracked through phases 4 & 5
    $record = [PSCustomObject]@{
        RemediationName             = $remName
        PolicyAssignmentName        = $target.PolicyAssignmentName
        PolicyAssignmentId          = $target.PolicyAssignmentId
        PolicyDefinitionReferenceId = $target.PolicyDefinitionReferenceId
        PolicyDefinitionAction      = $target.PolicyDefinitionAction
        NonCompliantCount           = $target.NonCompliantCount
        Scope                       = $scopeDesc
        ScopeType                   = $scope.Type
        ManagementGroupId           = if ($scope.Type -eq 'ManagementGroup') { $scope.ManagementGroupId } else { $null }
        SubscriptionId              = if ($scope.Type -in @('Subscription', 'ResourceGroup')) { $scope.SubscriptionId } else { $null }
        ResourceGroupName           = if ($scope.Type -eq 'ResourceGroup') { $scope.ResourceGroupName } else { $null }
        ProvisioningState           = 'Pending'
        ResourcesSucceeded          = 0
        ResourcesFailed             = 0
        Status                      = 'Pending'
        StartTime                   = $null
        EndTime                     = $null
        ErrorDetail                 = $null
        DeploymentFailureReasons    = @()
    }

    if ($PSCmdlet.ShouldProcess($logLine, 'Start-AzPolicyRemediation')) {
        try {
            Write-Log "  Starting: $logLine"
            $remediation = Invoke-WithProgressSuppressed {
                Start-AzPolicyRemediation @remParams
            }
            $record.ProvisioningState = $remediation.ProvisioningState
            $record.Status = 'Started'
            $record.StartTime = Get-Date
            Write-Log "  ✓ Started '$remName' (initial state: $($remediation.ProvisioningState))" -Level SUCCESS
        }
        catch {
            $record.ProvisioningState = 'LaunchFailed'
            $record.Status = 'LaunchFailed'
            $record.StartTime = Get-Date
            $record.EndTime = Get-Date
            $record.ErrorDetail = $_.Exception.Message
            Write-Log "  ✗ Failed to start remediation for '$($target.PolicyAssignmentName)': $($_.Exception.Message)" -Level ERROR
        }
        $startedRemediations.Add($record)
    }
    else {
        # -WhatIf path
        $record.Status = 'WhatIf'
        $startedRemediations.Add($record)
        Write-Log "  [WhatIf] Would start: $logLine" -Level WARN
    }
}

# If running with -WhatIf nothing actually started; show preview and exit cleanly
if ($startedRemediations.Count -eq 0 -or @($startedRemediations | Where-Object { $_.Status -eq 'WhatIf' }).Count -eq $startedRemediations.Count) {
    Write-Log 'WhatIf mode – no remediations were actually started.' -Level WARN
    $startedRemediations | Sort-Object PolicyAssignmentName |
    Format-Table -AutoSize -Property PolicyAssignmentName, PolicyDefinitionAction, NonCompliantCount, Scope
    exit 0
}

$launchedCount = @($startedRemediations | Where-Object { $_.Status -eq 'Started' }).Count
Write-Log "$launchedCount remediation(s) started successfully." -Level SUCCESS

Save-RunFile -Records $startedRemediations -Path $resolvedRunPath

if ($Mode -eq 'StartOnly') {
    Write-Section 'StartOnly mode – Kickoff complete'
    Write-Log 'Remediations are now running asynchronously in Azure.' -Level SUCCESS
    Write-Log "Use this to get a later report: .\az-policy-remediation.ps1 -Mode ReportOnly -RunFilePath \"$resolvedRunPath\""

    $startFailures = @($startedRemediations | Where-Object { $_.Status -eq 'LaunchFailed' }).Count
    if ($startFailures -gt 0) {
        Write-Log "$startFailures remediation(s) failed to start." -Level ERROR
        exit 1
    }
    exit 0
}

# ── Phase 4: Monitor remediations ─────────────────────────────────────────────
Write-Section 'Phase 4 – Monitoring remediation progress'

$deadline = (Get-Date).AddMinutes($MaxWaitMinutes)
Write-Log "Polling every $PollIntervalSeconds second(s). Deadline: $(Get-Date $deadline -Format 'HH:mm:ss') (+$MaxWaitMinutes min)."

do {
    Start-Sleep -Seconds $PollIntervalSeconds

    $pending = @($startedRemediations | Where-Object { $_.Status -notin $TERMINAL_STATES })

    foreach ($rem in $pending) {
        try {
            $getParams = @{ Name = $rem.RemediationName; ErrorAction = 'Stop' }
            switch ($rem.ScopeType) {
                'ManagementGroup' { $getParams['ManagementGroupName'] = $rem.ManagementGroupId }
                'Subscription' { $getParams['SubscriptionId'] = $rem.SubscriptionId }
                'ResourceGroup' {
                    $getParams['SubscriptionId'] = $rem.SubscriptionId
                    $getParams['ResourceGroupName'] = $rem.ResourceGroupName
                }
            }

            $current = Get-AzPolicyRemediation @getParams
            $deploymentStatus = $null
            if (@($current.PSObject.Properties.Match('DeploymentStatus')).Count -gt 0) {
                $deploymentStatus = $current.DeploymentStatus
            }

            $rem.ProvisioningState = $current.ProvisioningState
            $rem.ResourcesSucceeded = if ($deploymentStatus) { [int]$deploymentStatus.SuccessfulDeployments } else { 0 }
            $rem.ResourcesFailed = if ($deploymentStatus) { [int]$deploymentStatus.FailedDeployments } else { 0 }

            if ($current.ProvisioningState -in $TERMINAL_STATES) {
                $rem.Status = $current.ProvisioningState
                $rem.EndTime = Get-Date
                $logLevel = if ($current.ProvisioningState -eq 'Succeeded') { 'SUCCESS' } else { 'WARN' }
                Write-Log ("  [{0}] → {1} | Succeeded: {2} | Failed: {3}" -f `
                        $rem.PolicyAssignmentName, $current.ProvisioningState,
                    $rem.ResourcesSucceeded, $rem.ResourcesFailed) -Level $logLevel
            }
        }
        catch {
            Write-Log "  Could not poll '$($rem.RemediationName)': $_" -Level WARN
        }
    }

    $stillPending = @($startedRemediations | Where-Object { $_.Status -notin $TERMINAL_STATES }).Count
    if ($stillPending -gt 0) {
        $remaining = [math]::Max(0, [int]($deadline - (Get-Date)).TotalMinutes)
        Write-Log "$stillPending remediation(s) still running... (~$remaining min until timeout)"
    }

} until (
    @($startedRemediations | Where-Object { $_.Status -notin $TERMINAL_STATES }).Count -eq 0 -or
    (Get-Date) -ge $deadline
)

# Mark any still-running remediations as timed out
foreach ($rem in $startedRemediations | Where-Object { $_.Status -notin $TERMINAL_STATES }) {
    $rem.Status = 'TimedOut'
    $rem.EndTime = Get-Date
    Write-Log "Remediation '$($rem.PolicyAssignmentName)' timed out after $MaxWaitMinutes minute(s)." -Level WARN
}

$reportPath = Join-Path $PSScriptRoot "policy-remediation-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').md"
Save-RunFile -Records $startedRemediations -Path $resolvedRunPath
Enrich-DeploymentFailureReasons -Records $startedRemediations
Write-RemediationReport -Records $startedRemediations -ReportPath $reportPath
