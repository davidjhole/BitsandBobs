A dump of queries that i found useful.

# Networking

## List all private IP address ranges on vNET

```
resources
| where type == "microsoft.network/virtualnetworks"
| project id, name, addressSpace = properties.addressSpace.addressPrefixes
| parse kind=regex id with '/subscriptions/' subscriptionId '/resourceGroups/'
| mv-expand addressSpace
| join kind = inner (
    resourcecontainers
    | where type == "microsoft.resources/subscriptions"
    | project subscriptionId, subName=name
) on subscriptionId
| project subscriptionId, subName, name, addressSpace
| where addressSpace startswith "10.118.16"
```

## List all network interfaces with IP and vNET Subnet

```
Resources
| where type =~ 'microsoft.network/networkinterfaces'
| project id, ipConfigurations = properties.ipConfigurations
| parse kind=regex id with '/subscriptions/' subscriptionId '/resourceGroups/'
| join kind = inner  (
    resourcecontainers
    | where type == "microsoft.resources/subscriptions"
    | project subscriptionId, subName=name
) on subscriptionId
| mvexpand ipConfigurations
| project subscriptionId, subName, subnetId = tostring(ipConfigurations.properties.subnet.id), privateIP = tostring(ipConfigurations.properties.privateIPAddress)
| parse kind=regex subnetId with '/virtualNetworks/' virtualNetwork '/subnets/' subnet
| project subscriptionId, subName, virtualNetwork, subnet, privateIP
| order by privateIP
|where privateIP startswith "10.118.2."
```

## Firewall logs

```
AzureDiagnostics//SINGLE IP
| where ResourceProvider == "MICROSOFT.NETWORK"
| where Category in ("AzureFirewallNetworkRule", "AzureFirewallApplicationRule")
| where msg_s contains "10.0.0.4"
| extend SourceIP = extract(@"from ([0-9\.]+):", 1, msg_s)
| extend SourcePort = extract(@"from [0-9\.]+:(\d+)", 1, msg_s)
| extend Destination = extract(@"to ([^: ]+):", 1, msg_s)
| extend DestinationPort = extract(@"to [^: ]+:(\d+)", 1, msg_s)
| extend Protocol = extract(@"^([A-Z]+|[A-Za-z]+) request", 1, msg_s)
| extend Action = extract(@"Action: ([A-Za-z]+)", 1, msg_s)
| where SourceIP == "10.0.0.4"
| project Timestamp = TimeGenerated, LogType = Category, Protocol, SourceIP, SourcePort, Destination, DestinationPort, Action, Message = msg_s
| order by Timestamp desc
```

## Storage File logs

```
StorageFileLogs
| where TimeGenerated > ago(24h) // Adjust the time range as needed (e.g., 1h, 7d)
| project
    Timestamp = TimeGenerated,
    ClientIP = split(CallerIpAddress, ":")[0], // Splits out the port number if present
    HttpStatus = StatusCode,
    AuthenticationType = AuthenticationType,
    Operation = OperationName,
    Uri = Uri
| order by Timestamp desc
```

```
StorageFileLogs//SINGLE IP
| where TimeGenerated > ago(24h)
| extend ClientIP = split(CallerIpAddress, ":")[0]
| where ClientIP == "10.63.4.4"
| project
    Timestamp = TimeGenerated,
    ClientIP,
    HttpStatus = StatusCode,
    AuthenticationType,
    Operation = OperationName,
    Uri
| order by Timestamp desc
```
