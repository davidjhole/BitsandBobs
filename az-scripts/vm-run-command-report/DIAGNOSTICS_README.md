# Azure VM Diagnostics Report Generator

PowerShell script to run diagnostic commands across multiple Azure VMs and generate an HTML report.

## Features

- ✅ Runs commands on multiple Azure VMs sequentially
- ✅ Generates a professional HTML report with results
- ✅ Three-tier status system: Success (green), Failed (yellow), Error (red)
- ✅ Automatic detection of test failures (e.g., TcpTestSucceeded: False)
- ✅ Easy to customize command list
- ✅ Auto-opens the report in your default browser
- ✅ Validation of resource group and VM existence
- ✅ JSON escaping for complex PowerShell commands
- ✅ Progress tracking with percentage complete

## Requirements

- Azure CLI installed and authenticated (`az login`)
- PowerShell 5.1 or higher
- Appropriate permissions to run commands on the target VMs

## Usage

### Basic Usage

```powershell
.\Invoke-VmDiagnostics.ps1 -VmNames "vm1", "vm2", "vm3" -ResourceGroupName "my-rg"
```

### Custom Output Path

```powershell
.\Invoke-VmDiagnostics.ps1 `
    -VmNames "vm1", "vm2" `
    -ResourceGroupName "my-rg" `
    -OutputPath "C:\Reports\diagnostics-report.html"
```

### Custom Commands

```powershell
$commands = @(
    'ipconfig /all',
    'Get-NetAdapter',
    'Test-NetConnection 10.63.5.5 -Port 445 -InformationLevel Detailed'
)

.\Invoke-VmDiagnostics.ps1 `
    -VmNames "vm1", "vm2" `
    -ResourceGroupName "my-rg" `
    -Commands $commands
```

### Using Default Commands

The script comes with these pre-configured commands:

1. `Get-NetConnectionProfile` - Shows network connection profiles
2. `Test-NetConnection mystorageacct.file.core.windows.net -Port 445 -InformationLevel Detailed` - Tests connectivity to Azure Files share (customize the storage account name)
3. `Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress | ForEach-Object {Test-NetConnection $_ -port 445 }` - Tests port 445 connectivity from all local IPv4 addresses
4. `Test-NetConnection 10.63.5.5 -Port 445 -InformationLevel Detailed` - Detailed connectivity test to specific IP (customize as needed)
5. `Get-NetRoute -DestinationPrefix "10.63.5.5/32"` - Shows routing information for target IP (customize as needed)
6. `Get-NetRoute` - Shows all routes
7. `Get-NetFirewallRule | Where-Object {$_.Direction -eq "Outbound" -and $_.Action -eq "Block"} | Format-Table -AutoSize` - Lists outbound firewall blocking rules
8. `Get-SmbClientConfiguration` - Shows SMB client configuration settings
9. `netsh advfirewall show allprofiles` - Shows Windows Firewall profiles

To use the defaults, simply omit the `-Commands` parameter.

## Parameters

### Required Parameters

- **`-VmNames`** (string[])  
  List of Azure VM names to run diagnostics on.  
  Example: `"vm1", "vm2", "vm3"`

- **`-ResourceGroupName`** (string)  
  Azure resource group containing the VMs.  
  Example: `"my-resource-group"`

### Optional Parameters

- **`-Commands`** (string[])  
  PowerShell commands to run on each VM. Defaults to the set of network diagnostic commands.

- **`-OutputPath`** (string)  
  Path for the output HTML report. Defaults to `.\VmDiagnostics_YYYYMMDD_HHmmss.html`

## Output

The script generates an HTML report containing:

- **Summary Section**
  - Total VMs processed
  - Commands per VM
  - Total results count
  - Success count (commands that ran without errors)
  - Failed count (commands that detected test failures like TcpTestSucceeded: False)
  - Error count (commands with PowerShell errors)

- **VM Sections** (one for each VM)
  - VM name with status breakdown (Success/Failed/Errors per VM)
  - Each command with:
    - Status badge:
      - **Success** (green) - Command ran successfully
      - **Failed** (yellow) - Command ran but test/operation failed (e.g., connectivity test failed)
      - **Error** (red) - Command had a PowerShell error
    - Command text
    - Full command output in code formatting
    - Warnings preserved but not marked as errors

## Status Classification

The script uses intelligent status detection:

- **Success**: Command executed without PowerShell errors. Warnings from commands like `Test-NetConnection` are preserved but don't mark it as failed.
- **Failed**: Command executed successfully but detected known failure patterns:
  - `TcpTestSucceeded: False`
  - `PingSucceeded: False`
  - `No MSFT_` (cmdlet object not found)
  - Route not found
- **Error**: PowerShell encountered an exception or error (CategoryInfo, FullyQualifiedErrorId present)

## Command Escaping

The script automatically handles quote escaping for complex PowerShell commands. You can write commands naturally with double quotes for string values:

```powershell
'Get-NetFirewallRule | Where-Object {$_.Direction -eq "Outbound" -and $_.Action -eq "Block"}'
```

The `Escape-CommandForAzureCli` function handles the JSON encoding required by Azure CLI's run-command API.

## Customizing for Your Environment

The default commands include placeholder values that should be customized:

- **Storage Account**: Replace `mystorageacct.file.core.windows.net` with your actual Azure Files endpoint
- **Target IP**: Replace `10.63.5.5` with your target network endpoint or internal service IP
- **Network Prefix**: Replace `10.63.5.5/32` with the appropriate CIDR for route testing

Example customization:

```powershell
$commands = @(
    'Get-NetConnectionProfile',
    'Test-NetConnection mycompany.file.core.windows.net -Port 445 -InformationLevel Detailed',
    'Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress | ForEach-Object {Test-NetConnection $_ -port 445 }',
    'Test-NetConnection 192.168.1.100 -Port 445 -InformationLevel Detailed',
    'Get-NetRoute -DestinationPrefix "192.168.1.100/32"',
    'Get-NetRoute',
    'Get-NetFirewallRule | Where-Object {$_.Direction -eq "Outbound" -and $_.Action -eq "Block"} | Format-Table -AutoSize',
    'Get-SmbClientConfiguration',
    'netsh advfirewall show allprofiles'
)

.\Invoke-VmDiagnostics.ps1 -VmNames "vm1", "vm2" -ResourceGroupName "my-rg" -Commands $commands
```

The report is automatically opened in your default browser after generation.

## Examples

### Example 1: Three VMs, Default Commands

```powershell
.\Invoke-VmDiagnostics.ps1 `
    -VmNames "prod-vm-01", "prod-vm-02", "prod-vm-03" `
    -ResourceGroupName "production-rg"
```

### Example 2: Add Custom Commands

```powershell
$myCommands = @(
    'Test-NetConnection 10.63.5.5 -Port 445 -InformationLevel Detailed',
    'Get-NetRoute -DestinationPrefix 10.63.5.5/32',
    'Get-Disk | Select-Object Number, Size, @{Name="SizeGB"; Expression={$_.Size / 1GB}}',
    'Get-Volume | Select-Object DriveLetter, FileSystem, SizeRemaining, Size'
)

.\Invoke-VmDiagnostics.ps1 `
    -VmNames "vm1", "vm2" `
    -ResourceGroupName "my-rg" `
    -Commands $myCommands
```

### Example 3: Save to Specific Location

```powershell
.\Invoke-VmDiagnostics.ps1 `
    -VmNames "vm1", "vm2", "vm3" `
    -ResourceGroupName "my-rg" `
    -OutputPath "\\network\share\diagnostics\report-$(Get-Date -f yyyy-MM-dd).html"
```

## Troubleshooting

### Azure CLI Not Found

```
Error: Azure CLI is not installed or not in PATH
```

**Solution:** Install Azure CLI from https://aka.ms/cli

### Resource Group Not Found

```
Error: Resource group 'xxx' not found
```

**Solution:** Verify the resource group name and that you have access. Run `az group list` to see available groups.

### VM Not Found

```
Warning: VM 'xxx' not found in resource group 'yyy'. Skipping.
```

**Solution:** Check the VM name spelling and that it exists in the specified resource group.

### Authentication Required

```
Error: Please run 'az login' first
```

**Solution:** Authenticate with Azure:

```powershell
az login
```

## Tips & Tricks

### Getting VMs from a Query

```powershell
# Get all VMs in a resource group
$vms = az vm list --resource-group "my-rg" --query "[].name" -o tsv

# Run diagnostics on all
.\Invoke-VmDiagnostics.ps1 -VmNames $vms -ResourceGroupName "my-rg"
```

### Using with a Support Request

The HTML report is perfect for attaching to support tickets:

- Professional formatting
- Clear VM names and command output
- Easy to read in email or web browsers
- Print-friendly

### Scheduling Regular Diagnostics

```powershell
# Create a scheduled task to run diagnostics daily at 2 AM
$scriptPath = "C:\Scripts\Invoke-VmDiagnostics.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At 2am
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -VmNames 'vm1','vm2' -ResourceGroupName 'my-rg'"
Register-ScheduledTask -TaskName "VM-Diagnostics" -Trigger $trigger -Action $action -RunLevel Highest
```

## Notes

- Commands are executed as PowerShell scripts on the target VMs using Azure CLI's `az vm run-command invoke`
- Output is captured from both stdout and stderr and formatted in the HTML report
- All commands run regardless of individual command success/failure
- The script validates VMs and resource group exist before running commands
- HTML report can be saved and shared easily
- Test failures (like TcpTestSucceeded: False) are automatically detected and highlighted in yellow
- PowerShell errors are captured and highlighted in red
- Reports include timestamps and machine name for traceability
- Perfect for troubleshooting network connectivity, firewall rules, and SMB configuration issues
