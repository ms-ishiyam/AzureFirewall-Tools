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
|$DestinationIpAddress|false|IPv4 Address||
|$DestinationFQDN|false|FQDN|Not wildcard|
|$DestinationPort|true|Port Number||
|$FW_ARMTemplateFilePath|true|File Path|Firewall Policy ARM Template|
|$IPG_ARMTemplateFilePath|false|File Path|IP Group ARM Template. This is should be one file and the group name should be unique.|
|$ServiceTagFilePath|false|File Path|If it is no file path, this script gets the tags from the Internet.|

## Enabled feature
|DNAT|NetworkRule|ApplicationRule|
|:---|:---|:---|
|NotSupported|Supported (IPGroup/ServiceTag/FQDN)|Supported (Only FQDN)|

## Example

 ~~~
 .\Check-AzureFirewall-rules-ipg.ps1 `
-protocol TCP `
-SourceIpAddress 10.0.0.10 `
-DestinationIpAddress 10.20.0.11 `
-DestinationPort 443 `
-FW_ARMTemplateFilePath "C:\xx\FWPolicy.json" `
-IPG_ARMTemplateFilePath "C:\xx\IPgroup.json" `
-ServiceTagFilePath "C:\xx\ServiceTags_Public_20230320.json"
~~~

![image](https://user-images.githubusercontent.com/37136042/227856870-5ddff044-ba7d-4e5d-b53b-3f11f2b6c537.png)

