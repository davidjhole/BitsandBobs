param(
    [Parameter(Mandatory = $true, HelpMessage = "List of VM names to run diagnostics on")]
    [string[]]$VmNames,
    
    [Parameter(Mandatory = $true, HelpMessage = "Azure resource group containing the VMs")]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $false, HelpMessage = "Output file path for the HTML report")]
    [string]$OutputPath = ".\VmDiagnostics_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    
    [Parameter(Mandatory = $false, HelpMessage = "List of commands to run on each VM")]
    [string[]]$Commands = @(
        'Get-NetConnectionProfile',
        'Test-NetConnection mystorageacct.file.core.windows.net -Port 445 -InformationLevel Detailed',
        'Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress | ForEach-Object {Test-NetConnection $_ -port 445 }',
        'Test-NetConnection 10.63.5.5 -Port 445 -InformationLevel Detailed',
        'Get-NetRoute -DestinationPrefix "10.63.5.5/32"',
        'Get-NetRoute',
        'Get-NetFirewallRule | Where-Object {$_.Direction -eq "Outbound" -and $_.Action -eq "Block"} | Format-Table -AutoSize',
        'Get-SmbClientConfiguration',
        'netsh advfirewall show allprofiles'
    )
)

# Validate Azure CLI is installed
try {
    $null = az --version
}
catch {
    Write-Error "Azure CLI is not installed or not in PATH. Please install it first."
    exit 1
}

# Function to escape PowerShell command for Azure CLI JSON
function Escape-CommandForAzureCli {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command
    )
    
    # Escape for JSON: double quotes become \"
    # This ensures the command string is properly JSON-encoded when passed to Azure CLI
    $escapedCommand = $Command -replace '"', '\"'
    return $escapedCommand
}

# Verify resource group exists
Write-Host "Verifying resource group '$ResourceGroupName' exists..."
try {
    $rg = az group show --name $ResourceGroupName --query name -o tsv 2>$null
    if (-not $rg) {
        Write-Error "Resource group '$ResourceGroupName' not found."
        exit 1
    }
}
catch {
    Write-Error "Failed to verify resource group: $_"
    exit 1
}

$results = @()
$totalCommands = $VmNames.Count * $Commands.Count
$currentCommand = 0
$debugMode = $PSBoundParameters.ContainsKey('Verbose')

# Run diagnostics on each VM
foreach ($vmName in $VmNames) {
    Write-Host "Processing VM: $vmName" -ForegroundColor Cyan
    
    # Verify VM exists
    try {
        $vm = az vm show --resource-group $ResourceGroupName --name $vmName --query name -o tsv 2>$null
        if (-not $vm) {
            Write-Warning "VM '$vmName' not found in resource group '$ResourceGroupName'. Skipping."
            continue
        }
    }
    catch {
        Write-Warning "Failed to verify VM '$vmName': $_"
        continue
    }
    
    foreach ($command in $Commands) {
        $currentCommand++
        $percentComplete = [math]::Round(($currentCommand / $totalCommands) * 100, 0)
        Write-Progress -Activity "Running diagnostics" -Status "VM: $vmName | Command: $($currentCommand)/$($totalCommands)" -PercentComplete $percentComplete
        
        Write-Host "  Running: $command" -ForegroundColor Yellow
        
        try {
            # Escape the command for Azure CLI
            $escapedCommand = Escape-CommandForAzureCli -Command $command
            
            # Run the command on the VM and get full JSON response
            $jsonResponse = az vm run-command invoke `
                --resource-group $ResourceGroupName `
                --name $vmName `
                --command-id RunPowerShellScript `
                --scripts $escapedCommand `
                -o json 2>&1
            
            # Parse the JSON response
            if ($LASTEXITCODE -eq 0 -and $jsonResponse) {
                try {
                    $parsedResponse = $jsonResponse | ConvertFrom-Json
                    
                    # The response has an array of outputs (stdout, stderr, etc)
                    # Collect all messages
                    $messages = @()
                    $hasRealError = $false
                    
                    foreach ($item in $parsedResponse.value) {
                        $itemMessage = $item.message
                        $itemCode = $item.code
                        
                        # Check if this is stderr or actual PowerShell error
                        if ($itemCode -like "*stderr*") {
                            # Stderr captured
                            if (-not [string]::IsNullOrWhiteSpace($itemMessage)) {
                                # Check if it's a real PowerShell error (has CategoryInfo or FullyQualifiedErrorId)
                                if ($itemMessage -match "CategoryInfo|FullyQualifiedErrorId") {
                                    $hasRealError = $true
                                }
                                $messages += $itemMessage
                            }
                        }
                        else {
                            # This is stdout - capture it all
                            if (-not [string]::IsNullOrWhiteSpace($itemMessage)) {
                                # Check for real PowerShell errors in stdout (error records)
                                if ($itemMessage -match "CategoryInfo.*:.*\[.*\]|FullyQualifiedErrorId.*:") {
                                    $hasRealError = $true
                                }
                                $messages += $itemMessage
                            }
                        }
                    }
                    
                    if ($debugMode) {
                        Write-Verbose "Has real error: $hasRealError | Message lines: $($messages.Count)" -Verbose
                    }
                    
                    # Determine status based on real errors, not warnings
                    if ($hasRealError) {
                        $status = "Error"
                        $commandOutput = if ($messages.Count -eq 0) { 
                            "(Error occurred but no message returned)" 
                        }
                        else { 
                            $messages -join "`n`n"
                        }
                    }
                    else {
                        # Check for test/operation failure patterns in the output
                        $combinedOutput = $messages -join "`n`n"
                        $failurePatterns = @(
                            "TcpTestSucceeded\s*:\s*False",
                            "PingSucceeded\s*:\s*False",
                            "No MSFT_",
                            "not found",
                            "No route"
                        )
                        
                        $isTestFailure = $false
                        foreach ($pattern in $failurePatterns) {
                            if ($combinedOutput -match $pattern) {
                                $isTestFailure = $true
                                break
                            }
                        }
                        
                        if ($isTestFailure) {
                            $status = "Failed"
                            $commandOutput = $combinedOutput
                        }
                        else {
                            $status = "Success"
                            $commandOutput = if ($messages.Count -eq 0) { 
                                "[Command completed successfully with no output]" 
                            }
                            else { 
                                $combinedOutput
                            }
                        }
                    }
                }
                catch {
                    $status = "Error"
                    $commandOutput = "Failed to parse response: $_`n`nRaw response: $($jsonResponse | Out-String)"
                }
            }
            else {
                $status = "Error"
                $commandOutput = "Azure CLI command failed: $jsonResponse"
            }
        }
        catch {
            $status = "Error"
            $commandOutput = "Exception: $_"
        }
        
        # Store results
        $results += [PSCustomObject]@{
            VmName    = $vmName
            Command   = $command
            Status    = $status
            Output    = $commandOutput
            Timestamp = Get-Date
        }
        
        Write-Host "    Status: $status" -ForegroundColor $(if ($status -eq "Success") { "Green" } elseif ($status -eq "Failed") { "Yellow" } else { "Red" })
    }
}

Write-Progress -Activity "Running diagnostics" -Completed

# Generate HTML report
Write-Host "Generating HTML report..." -ForegroundColor Cyan

$htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VM Diagnostics Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #0078d4 0%, #0078d4 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            margin-bottom: 10px;
            font-size: 28px;
        }
        .header p {
            opacity: 0.9;
            font-size: 14px;
        }
        .content {
            padding: 20px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: #f8f9fa;
            border-left: 4px solid #0078d4;
            padding: 20px;
            border-radius: 4px;
        }
        .summary-card h3 {
            color: #666;
            font-size: 12px;
            text-transform: uppercase;
            margin-bottom: 8px;
        }
        .summary-card .value {
            font-size: 24px;
            font-weight: bold;
            color: #0078d4;
        }
        .vm-section {
            margin-bottom: 40px;
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            overflow: hidden;
        }
        .vm-header {
            background-color: #f0f0f0;
            padding: 15px 20px;
            border-bottom: 2px solid #0078d4;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .vm-header h2 {
            font-size: 18px;
            color: #0078d4;
            margin: 0;
        }
        .vm-header .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            background-color: #e8e8e8;
            color: #333;
        }
        .command-result {
            border-bottom: 1px solid #e0e0e0;
            padding: 20px;
        }
        .command-result:last-child {
            border-bottom: none;
        }
        .command-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 12px;
        }
        .command-header .status {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }
        .command-header .status.success {
            background-color: #d4edda;
            color: #155724;
        }
        .command-header .status.failed {
            background-color: #fff3cd;
            color: #856404;
        }
        .command-header .status.error {
            background-color: #f8d7da;
            color: #721c24;
        }
        .command-title {
            font-family: 'Courier New', monospace;
            background-color: #f8f9fa;
            padding: 8px 12px;
            border-radius: 4px;
            word-break: break-all;
            color: #0078d4;
            font-size: 13px;
            margin-bottom: 10px;
            border-left: 3px solid #0078d4;
        }
        .command-output {
            background-color: #1e1e1e;
            color: #d4d4d4;
            padding: 12px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            line-height: 1.4;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .footer {
            background-color: #f0f0f0;
            padding: 20px;
            text-align: center;
            border-top: 1px solid #e0e0e0;
            color: #666;
            font-size: 12px;
        }
        @media print {
            body {
                background-color: white;
                padding: 0;
            }
            .container {
                box-shadow: none;
                border-radius: 0;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Azure VM Diagnostics Report</h1>
            <p>Generated: $(Get-Date -Format 'dddd, MMMM d, yyyy HH:mm:ss')</p>
        </div>
        
        <div class="content">
            <div class="summary">
                <div class="summary-card">
                    <h3>Total VMs</h3>
                    <div class="value">$($VmNames.Count)</div>
                </div>
                <div class="summary-card">
                    <h3>Commands per VM</h3>
                    <div class="value">$($Commands.Count)</div>
                </div>
                <div class="summary-card">
                    <h3>Total Results</h3>
                    <div class="value">$($results.Count)</div>
                </div>
                <div class="summary-card">
                    <h3>Successful</h3>
                    <div class="value">$(($results | Where-Object {$_.Status -eq "Success"}).Count)</div>
                </div>
                <div class="summary-card">
                    <h3>Failed</h3>
                    <div class="value">$(($results | Where-Object {$_.Status -eq "Failed"}).Count)</div>
                </div>
                <div class="summary-card">
                    <h3>Errors</h3>
                    <div class="value">$(($results | Where-Object {$_.Status -eq "Error"}).Count)</div>
                </div>
            </div>
            
            <div class="vm-results">
"@

# Add results for each VM
$groupedResults = $results | Group-Object -Property VmName
foreach ($group in $groupedResults) {
    $vmName = $group.Name
    $successCount = ($group.Group | Where-Object { $_.Status -eq "Success" }).Count
    $failedCount = ($group.Group | Where-Object { $_.Status -eq "Failed" }).Count
    $errorCount = ($group.Group | Where-Object { $_.Status -eq "Error" }).Count
    $totalCount = $group.Group.Count
        
    $htmlContent += @"
                <div class="vm-section">
                    <div class="vm-header">
                        <h2>$vmName</h2>
                        <span class="badge">Success: $successCount | Failed: $failedCount | Errors: $errorCount / $totalCount</span>
                    </div>
"@
    
    foreach ($result in $group.Group) {
        $statusClass = if ($result.Status -eq "Success") { "success" } elseif ($result.Status -eq "Failed") { "failed" } else { "error" }
        $sanitizedOutput = [System.Web.HttpUtility]::HtmlEncode($result.Output)
        
        $htmlContent += @"
                    <div class="command-result">
                        <div class="command-header">
                            <span class="status $statusClass">$($result.Status)</span>
                        </div>
                        <div class="command-title">
                            PS> $($result.Command)
                        </div>
                        <div class="command-output">
$sanitizedOutput
                        </div>
                    </div>
"@
    }
    
    $htmlContent += @"
                </div>
"@
}

$htmlContent += @"
            </div>
        </div>
        
        <div class="footer">
            <p>Resource Group: $ResourceGroupName</p>
            <p>Report generated on $([System.Environment]::MachineName) at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        </div>
    </div>
</body>
</html>
"@

# Save the HTML report
try {
    $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Host "Report generated successfully: $OutputPath" -ForegroundColor Green
    Write-Host "Opening report in default browser..." -ForegroundColor Cyan
    Invoke-Item $OutputPath
}
catch {
    Write-Error "Failed to save report: $_"
    exit 1
}
