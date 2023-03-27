# Check-AzureFirewall-rules.ps1

## Descripiton
You can check your Azure Firewall rules on your conmputer.

## Parameter
Prameter|Mandatory|Allowed value
$Protocol|true|TCP,UDP,ICMP
$SourceIpAddress|true|IPv4 Address
$DestinationIpAddress|false|IPv4 Address
$DestinationFQDN|false|FQDN (Not wildcard)
$DestinationPort|true|Port Number
$FW_ARMTemplateFilePath|true|File Path
$IPG_ARMTemplateFilePath|false|File Path
$ServiceTagFilePath|false|File Path
