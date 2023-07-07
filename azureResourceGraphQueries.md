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