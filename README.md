# Check-AzureFirewall-rules.ps1

## Descripiton
You can check your Azure Firewall rules by this tool on your computer. This tool list all of affeted rules in your Azure Firewall policy and sholw the result whether the traffic is allowed or denied.

## Usage senario
- Check your rules in advance on your computer.
- Troubule shooting when you can not identify which rule is the root cause.

## Parameter
|Prameter|Mandatory|Allowed value|Additional Info|
|:---|:---|:---|:---|
|$Protocol|true|TCP/UDP/ICMP||
|$SourceIpAddress|true|IPv4 Address||
|$DestinationIpAddress|false|IPv4 Address|$DestinationIpAddress or $DestinationFQDN is mandatory|
|$DestinationFQDN|false|FQDN|Not wildcard|
|$DestinationPort|true|Port Number||
|$FW_ARMTemplateFilePath|true|File Path|Firewall Policy or Firewall ARM Template|
|$IPG_ARMTemplateFilePath|false|File Path|IP Group ARM Template. This is should be one file and the group name should be unique.|
|$ServiceTagFilePath|false|File Path|If it is no file path, this script gets the tags from the Internet.|

### Each files
`Firewall Policy / Firewall ARM Template` You can get it from Azure portal or Export-AzResourceGroup with "-IncludeParameterDefaultValue" option.

`IPGroup ARM Template` You can get it from Azure portal or Export-AzResourceGroup with "-IncludeParameterDefaultValue" option.

`ServiceTag` https://www.microsoft.com/en-in/download/confirmation.aspx?id=56519

## Enabled feature
|DNAT|NetworkRule|ApplicationRule|
|:---|:---|:---|
|NotSupported|Supported (IP/IPGroup/ServiceTag/FQDN)|Supported (Only FQDN)|

## Example

 ~~~
 .\Check-AzureFirewall-Rules-FWPolicy.ps1 `
-protocol TCP `
-SourceIpAddress 10.0.0.10 `
-DestinationIpAddress 10.20.0.11 `
-DestinationPort 443 `
-FW_ARMTemplateFilePath "C:\xx\FWPolicy.json" `
-IPG_ARMTemplateFilePath "C:\xx\IPgroup.json" `
-ServiceTagFilePath "C:\xx\ServiceTags_Public_20230320.json"
~~~

DestinationIpAddress
![image](https://user-images.githubusercontent.com/37136042/227856870-5ddff044-ba7d-4e5d-b53b-3f11f2b6c537.png)

DestinationFQDN
![image](https://user-images.githubusercontent.com/37136042/227900720-1083a371-3f58-48c4-9e2d-9c907e54a5d7.png)


### About result
If result is `Traffic : Deny (Return packet [SYN/ACK] is denied.)`, you should check the deny rule. The rule may deny your SYN/ACK packet.
![image](https://user-images.githubusercontent.com/37136042/228413244-49f56890-981f-4031-9f01-831141b846b2.png)

https://learn.microsoft.com/en-us/azure/firewall/rule-processing#three-way-handshake-behavior
~~~
As a result, there's no need to create an explicit deny rule from VNet-B to VNet-A. 
If you create this deny rule, you'll interrupt the three-way handshake from the initial allow rule from VNet-A to VNet-B.
~~~

