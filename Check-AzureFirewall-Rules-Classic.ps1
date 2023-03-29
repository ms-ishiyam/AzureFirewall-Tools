<#
This is checking tool for your Azure Firewall rules on your local computer.
.EXAMPLE
 .\Check-AzureFirewall-rules-ipg.ps1 `
>> -protocol TCP `
>> -SourceIpAddress 10.0.0.10 `
>> -DestinationIpAddress 10.20.0.11 `
>> -DestinationPort 443 `
>> -FW_ARMTemplateFilePath "C:\xx\FWPolicy.json" `
>> -IPG_ARMTemplateFilePath "C:\xx\IPGroup.json" `
>> -ServiceTagFilePath "C:\xx\ServiceTags_Public_20230320.json"
#>

Param(
    [ValidateSet("TCP","UDP","ICMP")][Parameter(Mandatory=$true)][String]$Protocol,
    [Parameter(Mandatory=$true)][String]$SourceIpAddress,
    [Parameter(Mandatory=$false)][String]$DestinationIpAddress,
    [Parameter(Mandatory=$false)][String]$DestinationFQDN,
    [Parameter(Mandatory=$true)][String]$DestinationPort,
    [Parameter(Mandatory=$true)][String]$FW_ARMTemplateFilePath,
    [Parameter(Mandatory=$false)][String]$IPG_ARMTemplateFilePath,
    [Parameter(Mandatory=$false)][String]$ServiceTagFilePath
)

function ConvertTo-UInt32IPv4Address{
Param(
    [Parameter(Mandatory=$true)]$IPv4Address
)

    [uint32]$UInt32IPv4Address = 0
    [int[]]$SplitIPv4Address = $IPv4Address.Split(".")
    if($SplitIPv4Address.Count -ne 4){
        Return $false
    }else{
        for($octet = 0; $octet -lt 4; $octet++){
            if(($SplitIPv4Address[$octet] -ge 0) -and ($SplitIPv4Address[$octet] -le 256)){
                $UInt32IPv4Address += ($SplitIPv4Address[$octet]*([math]::Pow(256,3-$octet)))
            }else{
                Return $false
            }
        }
    }
    Return $UInt32IPv4Address
}

function ConvertTo-UInt32IPv4StartAddress{
Param(
    [Parameter(Mandatory=$true)]$IPv4AddressRange
)

    [uint32]$UInt32IPv4Address = 0
    $SplitIPv4AddressRange = $IPv4AddressRange.Split("/")
    [int]$SplitIPv4AddressPrefix = $SplitIPv4AddressRange[1]

    if(($SplitIPv4AddressPrefix -ge 0) -and ($SplitIPv4AddressPrefix -le 32)){
        Return (ConvertTo-UInt32IPv4Address $SplitIPv4AddressRange[0])
    }else{
        Write-Error "IPv4 Address Range is not correctly."
        Return -1
    }
}

function ConvertTo-UInt32IPv4EndAddress{
Param(
    [Parameter(Mandatory=$true)]$IPv4AddressRange
)

    [uint32]$UInt32IPv4Address = 0
    $SplitIPv4AddressRange = $IPv4AddressRange.Split("/")
    [int]$SplitIPv4AddressPrefix = $SplitIPv4AddressRange[1]

    if(($SplitIPv4AddressPrefix -ge 0) -and ($SplitIPv4AddressPrefix -le 32)){
        Return ((ConvertTo-UInt32IPv4Address $SplitIPv4AddressRange[0]) + [math]::Pow(2, 32 - $SplitIPv4AddressPrefix) - 1)
    }else{
        Write-Error "IPv4 Address Range is not correctly."
        Return -1
    }
}

function Check-UInt32IPv4AddressRange{
Param(
    [uint32][Parameter(Mandatory=$true)]$UInt32TargetIPv4Address,
    [uint32][Parameter(Mandatory=$true)]$UInt32StartIPv4Address,
    [uint32][Parameter(Mandatory=$true)]$UInt32EndIPv4Address
)
       
    if(($UInt32TargetIPv4Address -ge $UInt32StartIPv4Address) -and ($UInt32TargetIPv4Address -le $UInt32EndIPv4Address)){
        Return $true
    }else{
        Return $false
    }
}

function Check-FirewallAddressRange{
Param(
    [Parameter(Mandatory=$true)]$FWRuleAddresses,
    [Parameter(Mandatory=$true)]$InputAddress
)

foreach($FwRuleTargetAddr in $FWRuleAddresses){
        switch($FwRuleTargetAddr)
        {
            {$_ -eq "*"} {Return $true}
            {$_ -like ("*-*")} {
                $StartAddress = (ConvertTo-UInt32IPv4Address $_.Split("-")[0])
                $EndAddress = (ConvertTo-UInt32IPv4Address $_.Split("-")[1])
                $TargetAddress = (ConvertTo-UInt32IPv4Address $InputAddress)
            }
            {$_ -notlike "*/*" -and $_ -notlike ("*-*")} {
                $FwRuleTargetAddr="$_/32"
                $StartAddress = (ConvertTo-UInt32IPv4StartAddress $FwRuleTargetAddr)
                $EndAddress = (ConvertTo-UInt32IPv4EndAddress $FwRuleTargetAddr)
                $TargetAddress = (ConvertTo-UInt32IPv4Address $InputAddress)
            }
            {$_ -like "*/*"} {
                $StartAddress = (ConvertTo-UInt32IPv4StartAddress $FwRuleTargetAddr)
                $EndAddress = (ConvertTo-UInt32IPv4EndAddress $FwRuleTargetAddr)
                $TargetAddress = (ConvertTo-UInt32IPv4Address $InputAddress)
            }
        }
        if(Check-UInt32IPv4AddressRange -UInt32TargetIPv4Address $TargetAddress -UInt32StartIPv4Address $StartAddress -UInt32EndIPv4Address $EndAddress){
            Return $true
        }else{
            Return $false
        }
    }
}

function Check-RulesDestinationPorts{
Param(
    [Parameter(Mandatory=$true)]$TargeRuleDestPort
)

    foreach($FwRuleDestPort in $TargeRuleDestPort){
        $CheckDestPort = $false
        if(($FwRuleDestPort -like "$DestinationPort") -or ($FwRuleDestPort -eq "*")){
            $CheckDestPort = $true
            }elseif($FwRuleDestPort.Contains("-")){
            $DestPortRange = $FwRuleDestPort.Split("-")
            if(($DestinationPort -ge $DestPortRange[0]) -and ($DestinationPort -le $DestPortRange[1])){
                $CheckDestPort = $true
            }
        }
        if(($CheckDestPort -eq $true)){
            Return ($FwRuleDestPort)
        }
    }
}

function Check-IPgroup{
Param(
    [Parameter(Mandatory=$true)]$FwRuleIpGrpName,
    [Parameter(Mandatory=$true)]$SrcDstFlag
)

$FwRuleIpGrpName = $FwRuleIpGrpName.Split("'")[1].Split("_")[1]

#Check Azure Firewall rules with IPgroup template
    $JPGJson | ForEach-Object{
        $_.resources | ForEach-Object{
            if($_.type -like "*ipGroups"){
                if($_.name.Contains($FwRuleIpGrpName)){
                    $IpgName = $_.name.Split("'")[1].Split("_")[1]
                    foreach($IpgTemplateIPs in $_.properties.ipAddresses){
                        if(($SrcDstFlag -eq "Src") -and (Check-FirewallAddressRange -FWruleAddresses $IpgTemplateIPs -InputAddress $SourceIpAddress)){
                            Return ($IpgName,$IpgTemplateIPs)
                        }elseif(($SrcDstFlag -eq "Dst") -and (Check-FirewallAddressRange -FWruleAddresses $IpgTemplateIPs -InputAddress $DestinationIpAddress)){
                            Return ($IpgName,$IpgTemplateIPs)
                        }
                    }
                }
            }
        }
    }
}

function Check-ServiceTag{
Param(
    [Parameter(Mandatory=$true)]$FwRuleServiceTag
)
$AzurePrefixTable = @()
    if($ServiceTagFilePath){
    $ServiceTagJson = Get-Content -Path $ServiceTagFilePath | ConvertFrom-Json
    }elseif(-! $ServiceTagJson){
        # Get IP address range and service tags from Download Center
        $downloadUri = "https://www.microsoft.com/en-in/download/confirmation.aspx?id=56519"
        $downloadPage = Invoke-WebRequest -Uri $downloadUri -UseBasicParsing 
        $jsonFileUri = ($downloadPage.RawContent.Split('"') -like "https://*ServiceTags*")[0]
        $response = Invoke-WebRequest -Uri $jsonFileUri
        $ServiceTagJson = [System.Text.Encoding]::UTF8.GetString($response.Content) | ConvertFrom-Json
    }

    $ServiceTagJson.values | foreach{
        if($_.Name -like "$FwRuleServiceTag"){
            $_.properties.addressPrefixes | foreach{
                # IPv4
                if($_ -ne $null -and !$_.Contains(":")){
                    if(Check-FirewallAddressRange -FWruleAddresses $_ -InputAddress $DestinationIpAddress){
                        Return $FwRuleServiceTag
                    }
                }
                else
                {
                    ### for IPv6 ###
                }
            }
        }
    }
}

#Get IP Group ARM template.
if($IPG_ARMTemplateFilePath) {
$JPGJson = Get-Content -Path $IPG_ARMTemplateFilePath | ConvertFrom-Json
}

$OutputObj = @()
$OutputObjAfterCheck = @()

for($h=0;$h -le 1;$h++){
    if($h -eq 1){
    #Check SYN/ACK to deny.
    $TempSourceIpAddress = $SourceIpAddress
    $TempDestinationIpAddress = $DestinationIpAddress
    $SourceIpAddress = $TempDestinationIpAddress
    $DestinationIpAddress = $TempSourceIpAddress
    $SynAckCheck = $true
    }
    #Main
    #Check Azure Firewall rules with input parameter.
    Get-Content -Path $FW_ARMTemplateFilePath | ConvertFrom-Json | ForEach-Object{
        for($i=0;$i -le $_.resources.count;$i++){
            $_.resources[$i] | ForEach-Object{
                if($_.type -like "*azureFirewalls"){
                    $FwRuleCollectionGroupName = "NA"
                    $FwRCGPriolity = "NA"
                    for($j=0;$j -le $_.properties.networkRuleCollections.count;$j++){
                        $_.properties.networkRuleCollections[$j] | ForEach-Object{
                            $FwRuleColName = $_.name
                            $FwRCPriority = $_.properties.priority
                            #NetworkRule
                            if($_.id -like "*networkRuleCollections*"){
                                $FwActionType = $_.properties.action.type
                                :ruleslabel for($k=0;$k -le $_.properties.rules.count;$k++){
                                    $_.properties.rules[$k] | ForEach-Object{
                                        $FwRuleName = $_.name
                                        $FwRuleProtocol = $_.protocols
                                        #Check Protocol.
                                        if($_.protocols -like $Protocol -or $_.protocols -like "ANY"){
                                            $Result  = "" | Select-Object FwRuleCollectionGroupName,FwRuleColName,FwRCGPriolity,FwRuleName,FwRCPriority,FwRuleSrcAddr,FwRuleDestAddr,FwRuleDestFQDN,FwRuleDestPort,FwRuleProtocol,FwActionType,SrcIpgName,SrcIpgIPs,DstIpgName,DstIpgIPs,FwRuleType
                                            foreach($FwRuleSrcAddr in $_.sourceAddresses){
                                                #Check Source IPaddress.
                                                if(Check-FirewallAddressRange -FWRuleAddresses $FwRuleSrcAddr -InputAddress $SourceIpAddress){
                                                    #Check Destination IPs.
                                                    if($DestinationIpAddress){
                                                        foreach($FwRuleDestAddr in $_.destinationAddresses){
                                                            if(($FwRuleDestAddr -ne "*") -and ($FwRuleDestAddr -notlike "*.*.*.*")){
                                                                #Check DestinationIpAddress if it is in IANA Ranges.
                                                                if(-!(Check-FirewallAddressRange -FWRuleAddresses "10.0.0.0/8" -InputAddress $DestinationIpAddress) -and -!(Check-FirewallAddressRange -FWRuleAddresses "172.16.0.0/12" -InputAddress $DestinationIpAddress) -and -!(Check-FirewallAddressRange -FWRuleAddresses "192.168.0.0/16" -InputAddress $DestinationIpAddress)){
                                                                    #Check Destination ServiceTag.
                                                                    if(. Check-ServiceTag -FwRuleServiceTag $FwRuleDestAddr){
                                                                        #Check Destination Port.
                                                                        $CheckPorts = Check-RulesDestinationPorts -TargeRuleDestPort $_.destinationPorts
                                                                        if(($Protocol -like "ICMP") -or $CheckPorts){
                                                                            $Result.FwRuleType = "NetworkRule"
                                                                            $Result.FwRuleCollectionGroupName = $FwRuleCollectionGroupName
                                                                            $Result.FwRuleColName = $FwRuleColName
                                                                            $Result.FwActionType = $FwActionType
                                                                            $Result.FwRuleName = $FwRuleName
                                                                            $Result.FwRuleProtocol = $FwRuleProtocol
                                                                            $Result.FwRCGPriolity = $FwRCGPriolity
                                                                            $Result.FwRCPriority = $FwRCPriority
                                                                            $Result.FwRuleSrcAddr = $FwRuleSrcAddr
                                                                            $Result.FwRuleDestAddr = $FwRuleDestAddr
                                                                            $Result.FwRuleDestPort = $CheckPorts
                                                                            if($SynAckCheck){$OutputObjAfterCheck += $Result}else{
                                                                                $OutputObj += $Result
                                                                            }
                                                                            Continue ruleslabel
                                                                        }
                                                                    }
                                                                }
                                                            }elseif(Check-FirewallAddressRange -FWRuleAddresses $FwRuleDestAddr -InputAddress $DestinationIpAddress){      #Check Destination IP.                                                
                                                                #Check Destination Port.
                                                                $CheckPorts = Check-RulesDestinationPorts -TargeRuleDestPort $_.destinationPorts
                                                                if(($Protocol -like "ICMP") -or $CheckPorts){
                                                                    $Result.FwRuleType = "NetworkRule"
                                                                    $Result.FwRuleCollectionGroupName = $FwRuleCollectionGroupName
                                                                    $Result.FwRuleColName = $FwRuleColName
                                                                    $Result.FwActionType = $FwActionType
                                                                    $Result.FwRuleName = $FwRuleName
                                                                    $Result.FwRuleProtocol = $FwRuleProtocol
                                                                    $Result.FwRCGPriolity = $FwRCGPriolity
                                                                    $Result.FwRCPriority = $FwRCPriority
                                                                    $Result.FwRuleSrcAddr = $FwRuleSrcAddr
                                                                    $Result.FwRuleDestAddr = $FwRuleDestAddr
                                                                    $Result.FwRuleDestPort = $CheckPorts
                                                                    if($SynAckCheck){$OutputObjAfterCheck += $Result}else{
                                                                        $OutputObj += $Result
                                                                    }
                                                                    Continue ruleslabel
                                                                }
                                                            }
                                                        }
                                                        #Check Destination IP Groups.
                                                        foreach($FwRuleDestIpGrpName in $_.destinationIpGroups){
                                                            $CheckDstIPgroup = Check-IPgroup -FwRuleIpGrpName $FwRuleDestIpGrpName -SrcDstFlag "Dst"
                                                            if($CheckDstIPgroup){
                                                                #Check Destination Port.
                                                                $CheckPorts = Check-RulesDestinationPorts -TargeRuleDestPort $_.destinationPorts
                                                                if(($Protocol -like "ICMP") -or $CheckPorts){
                                                                    $Result.FwRuleType = "NetworkRule"
                                                                    $Result.FwRuleCollectionGroupName = $FwRuleCollectionGroupName
                                                                    $Result.FwRuleColName = $FwRuleColName
                                                                    $Result.FwActionType = $FwActionType
                                                                    $Result.FwRuleName = $FwRuleName
                                                                    $Result.FwRuleProtocol = $FwRuleProtocol
                                                                    $Result.FwRCGPriolity = $FwRCGPriolity
                                                                    $Result.FwRCPriority = $FwRCPriority
                                                                    $Result.FwRuleSrcAddr = $FwRuleSrcAddr
                                                                    $Result.FwRuleDestAddr = $FwRuleDestAddr
                                                                    $Result.FwRuleDestPort = $CheckPorts
                                                                    $Result.DstIpgName = $CheckDstIPgroup[0]
                                                                    $Result.DstIpgIPs = $CheckDstIPgroup[1]
                                                                    if($SynAckCheck){$OutputObjAfterCheck += $Result}else{
                                                                        $OutputObj += $Result
                                                                    }
                                                                    Continue ruleslabel
                                                                }
                                                            }
                                                        }
                                                    }elseif($DestinationFQDN){
                                                        #Check Destination FQDN.
                                                        foreach($FwRuleDestFQDN in $_.destinationFqdns){
                                                            if(($FwRuleDestFQDN -like "$DestinationFQDN")){
                                                                $CheckPorts = Check-RulesDestinationPorts -TargeRuleDestPort $_.destinationPorts
                                                                if(($Protocol -like "ICMP") -or $CheckPorts){
                                                                    $Result.FwRuleType = "NetworkRule"
                                                                    $Result.FwRuleCollectionGroupName = $FwRuleCollectionGroupName
                                                                    $Result.FwRuleColName = $FwRuleColName
                                                                    $Result.FwActionType = $FwActionType
                                                                    $Result.FwRuleName = $FwRuleName
                                                                    $Result.FwRuleProtocol = $FwRuleProtocol
                                                                    $Result.FwRCGPriolity = $FwRCGPriolity
                                                                    $Result.FwRCPriority = $FwRCPriority
                                                                    $Result.FwRuleSrcAddr = $FwRuleSrcAddr
                                                                    $Result.FwRuleDestFQDN = $DestinationFQDN
                                                                    $Result.FwRuleDestPort = $CheckPorts
                                                                    if($SynAckCheck){$OutputObjAfterCheck += $Result}else{
                                                                        $OutputObj += $Result
                                                                    }
                                                                    Continue ruleslabel
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            #Check Source IP Group.
                                            if($JPGJson){
                                                $FwRuleSrcAddr = ""
                                                $FwRuleDestAddr = ""
                                                foreach($FwRuleSrcIpGrpName in $_.sourceIpGroups){
                                                    $CheckSrcIPgroup = Check-IPgroup -FwRuleIpGrpName $FwRuleSrcIpGrpName -SrcDstFlag "Src"
                                                        if($CheckSrcIPgroup){
                                                        #Check Destination IPs.
                                                        if($DestinationIpAddress){
                                                            foreach($FwRuleDestAddr in $_.destinationAddresses){
                                                                if(($FwRuleDestAddr -ne "*") -and ($FwRuleDestAddr -notlike "*.*.*.*")){
                                                                    #Check DestinationIpAddress if it is in IANA Ranges.
                                                                    if(-!(Check-FirewallAddressRange -FWRuleAddresses "10.0.0.0/8" -InputAddress $DestinationIpAddress) -and -!(Check-FirewallAddressRange -FWRuleAddresses "172.16.0.0/12" -InputAddress $DestinationIpAddress) -and -!(Check-FirewallAddressRange -FWRuleAddresses "192.168.0.0/16" -InputAddress $DestinationIpAddress)){
                                                                        #Check Destination ServiceTag.
                                                                        if(. Check-ServiceTag -FwRuleServiceTag $FwRuleDestAddr){
                                                                            #Check Destination Port.
                                                                            $CheckPorts = Check-RulesDestinationPorts -TargeRuleDestPort $_.destinationPorts
                                                                            if(($Protocol -like "ICMP") -or $CheckPorts){
                                                                                $Result.FwRuleType = "NetworkRule"
                                                                                $Result.FwRuleCollectionGroupName = $FwRuleCollectionGroupName
                                                                                $Result.FwRuleColName = $FwRuleColName
                                                                                $Result.FwActionType = $FwActionType
                                                                                $Result.FwRuleName = $FwRuleName
                                                                                $Result.FwRuleProtocol = $FwRuleProtocol
                                                                                $Result.FwRCGPriolity = $FwRCGPriolity
                                                                                $Result.FwRCPriority = $FwRCPriority
                                                                                $Result.FwRuleSrcAddr = $FwRuleSrcAddr
                                                                                $Result.FwRuleDestAddr = $FwRuleDestAddr
                                                                                $Result.FwRuleDestPort = $CheckPorts
                                                                                $Result.SrcIpgName = $CheckSrcIPgroup[0]
                                                                                $Result.SrcIpgIPs = $CheckSrcIPgroup[1]
                                                                                if($SynAckCheck){$OutputObjAfterCheck += $Result}else{
                                                                                    $OutputObj += $Result
                                                                                }
                                                                                Continue ruleslabel
                                                                            }
                                                                        }
                                                                    }
                                                                }elseif(Check-FirewallAddressRange -FWRuleAddresses $FwRuleDestAddr -InputAddress $DestinationIpAddress){      #Check Destination IP.                                                
                                                                    #Check Destination Port.
                                                                    $CheckPorts = Check-RulesDestinationPorts -TargeRuleDestPort $_.destinationPorts
                                                                    if(($Protocol -like "ICMP") -or $CheckPorts){
                                                                        $Result.FwRuleType = "NetworkRule"
                                                                        $Result.FwRuleCollectionGroupName = $FwRuleCollectionGroupName
                                                                        $Result.FwRuleColName = $FwRuleColName
                                                                        $Result.FwActionType = $FwActionType
                                                                        $Result.FwRuleName = $FwRuleName
                                                                        $Result.FwRuleProtocol = $FwRuleProtocol
                                                                        $Result.FwRCGPriolity = $FwRCGPriolity
                                                                        $Result.FwRCPriority = $FwRCPriority
                                                                        $Result.FwRuleSrcAddr = $FwRuleSrcAddr
                                                                        $Result.FwRuleDestAddr = $FwRuleDestAddr
                                                                        $Result.FwRuleDestPort = $CheckPorts
                                                                        $Result.SrcIpgName = $CheckSrcIPgroup[0]
                                                                        $Result.SrcIpgIPs = $CheckSrcIPgroup[1]
                                                                        if($SynAckCheck){$OutputObjAfterCheck += $Result}else{
                                                                            $OutputObj += $Result
                                                                        }
                                                                        Continue ruleslabel
                                                                    }
                                                                }
                                                            }
                                                            #Check Destination IP Groups.
                                                            foreach($FwRuleDestIpGrpName in $_.destinationIpGroups){
                                                                $CheckDstIPgroup = Check-IPgroup -FwRuleIpGrpName $FwRuleDestIpGrpName -SrcDstFlag "Dst"
                                                                if($CheckDstIPgroup){
                                                                    #Check Destination Port.
                                                                    $CheckPorts = Check-RulesDestinationPorts -TargeRuleDestPort $_.destinationPorts
                                                                    if(($Protocol -like "ICMP") -or $CheckPorts){
                                                                        $Result.FwRuleType = "NetworkRule"
                                                                        $Result.FwRuleCollectionGroupName = $FwRuleCollectionGroupName
                                                                        $Result.FwRuleColName = $FwRuleColName
                                                                        $Result.FwActionType = $FwActionType
                                                                        $Result.FwRuleName = $FwRuleName
                                                                        $Result.FwRuleProtocol = $FwRuleProtocol
                                                                        $Result.FwRCGPriolity = $FwRCGPriolity
                                                                        $Result.FwRCPriority = $FwRCPriority
                                                                        $Result.FwRuleSrcAddr = $FwRuleSrcAddr
                                                                        $Result.FwRuleDestAddr = $FwRuleDestAddr
                                                                        $Result.FwRuleDestPort = $CheckPorts
                                                                        $Result.SrcIpgName = $CheckSrcIPgroup[0]
                                                                        $Result.SrcIpgIPs = $CheckSrcIPgroup[1]
                                                                        $Result.DstIpgName = $CheckDstIPgroup[0]
                                                                        $Result.DstIpgIPs = $CheckDstIPgroup[1]
                                                                        if($SynAckCheck){$OutputObjAfterCheck += $Result}else{
                                                                            $OutputObj += $Result
                                                                        }
                                                                        Continue ruleslabel
                                                                    }
                                                                }
                                                            }
                                                        }elseif($DestinationFQDN){
                                                            #Check Destination FQDN.
                                                            foreach($FwRuleDestFQDN in $_.destinationFqdns){
                                                                if(($FwRuleDestFQDN -like "$DestinationFQDN")){
                                                                    $CheckPorts = Check-RulesDestinationPorts -TargeRuleDestPort $_.destinationPorts
                                                                    if(($Protocol -like "ICMP") -or $CheckPorts){
                                                                        $Result.FwRuleType = "NetworkRule"
                                                                        $Result.FwRuleCollectionGroupName = $FwRuleCollectionGroupName
                                                                        $Result.FwRuleColName = $FwRuleColName
                                                                        $Result.FwActionType = $FwActionType
                                                                        $Result.FwRuleName = $FwRuleName
                                                                        $Result.FwRuleProtocol = $FwRuleProtocol
                                                                        $Result.FwRCGPriolity = $FwRCGPriolity
                                                                        $Result.FwRCPriority = $FwRCPriority
                                                                        $Result.FwRuleDestFQDN = $DestinationFQDN
                                                                        $Result.FwRuleDestPort = $CheckPorts
                                                                        $Result.SrcIpgName = $CheckSrcIPgroup[0]
                                                                        $Result.SrcIpgIPs = $CheckSrcIPgroup[1]
                                                                        if($SynAckCheck){$OutputObjAfterCheck += $Result}else{
                                                                            $OutputObj += $Result
                                                                        }
                                                                        Continue ruleslabel
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    for($j=0;$j -le $_.properties.applicationRuleCollections.count;$j++){
                        $_.properties.applicationRuleCollections[$j] | ForEach-Object{
                            $FwRuleColName = $_.name
                            $FwRCPriority = $_.properties.priority
                            #NetworkRule
                            if($_.id -like "*applicationRuleCollections*"){  #ApplicationRule
                                $FwActionType = $_.properties.action.type
                                :ruleslabel for($k=0;$k -le $_.properties.rules.count;$k++){
                                    $_.properties.rules[$k] | ForEach-Object{
                                        $FwRuleName = $_.name
                                        $FwRuleProtocol = $_.protocols.protocolType
                                        #If Portocol is match, go to check Source IP.
                                        if($Protocol -like "TCP"){
                                            #If Source IPs are match, go to check Destination IP and IP Groups.
                                            $Result  = "" | Select-Object FwRuleCollectionGroupName,FwRuleColName,FwRCGPriolity,FwRuleName,FwRCPriority,FwRuleSrcAddr,FwRuleDestAddr,FwRuleDestFQDN,FwRuleDestPort,FwRuleProtocol,FwActionType,SrcIpgName,SrcIpgIPs,DstIpgName,DstIpgIPs,FwRuleType
                                            $FwRuleDestFQDN = ""
                                            foreach($FwRuleSrcAddr in $_.sourceAddresses){
                                                #Check Source IPaddress.
                                                if(Check-FirewallAddressRange -FWRuleAddresses $FwRuleSrcAddr -InputAddress $SourceIpAddress){
                                                    #Check Destination FQDN.
                                                    foreach($FwRuleDestFQDN in $_.targetFqdns){                         
                                                        if($DestinationFQDN -like $FwRuleDestFQDN){
                                                            $_.protocols | ForEach-Object{
                                                                if($DestinationPort -eq $_.port){
                                                                    $Result.FwRuleType = "ApplicationRule"
                                                                    $Result.FwRuleCollectionGroupName = $FwRuleCollectionGroupName
                                                                    $Result.FwRuleColName = $FwRuleColName
                                                                    $Result.FwActionType = $FwActionType
                                                                    $Result.FwRuleName = $FwRuleName
                                                                    $Result.FwRuleProtocol = $_.protocolType
                                                                    $Result.FwRCGPriolity = $FwRCGPriolity
                                                                    $Result.FwRCPriority = $FwRCPriority
                                                                    $Result.FwRuleSrcAddr = $FwRuleSrcAddr
                                                                    $Result.FwRuleDestFQDN = $FwRuleDestFQDN
                                                                    $Result.FwRuleDestPort = $_.port
                                                                    if($SynAckCheck){$OutputObjAfterCheck += $Result}else{
                                                                        $OutputObj += $Result
                                                                    }
                                                                    Continue ruleslabel
                                                                }
                                                            }
                                                        }
                                                    }
                                                } 
                                            }
                                            #Check Source IP Group.
                                            if($JPGJson){
                                                $FwRuleSrcAddr = ""
                                                $FwRuleDestAddr = ""
                                                foreach($FwRuleSrcIpGrpName in $_.sourceIpGroups){
                                                    $CheckSrcIPgroup = Check-IPgroup -FwRuleIpGrpName $FwRuleSrcIpGrpName -SrcDstFlag "Src"
                                                        if($CheckSrcIPgroup){
                                                        #Check Destination FQDN.
                                                        foreach($FwRuleDestFQDN in $_.targetFqdns){                         
                                                            if($DestinationFQDN -like $FwRuleDestFQDN){
                                                                $_.protocols | ForEach-Object{
                                                                    if($DestinationPort -eq $_.port){
                                                                        $Result.FwRuleType = "ApplicationRule"
                                                                        $Result.FwRuleCollectionGroupName = $FwRuleCollectionGroupName
                                                                        $Result.FwRuleColName = $FwRuleColName
                                                                        $Result.FwActionType = $FwActionType
                                                                        $Result.FwRuleName = $FwRuleName
                                                                        $Result.FwRuleProtocol = $_.protocolType
                                                                        $Result.FwRCGPriolity = $FwRCGPriolity
                                                                        $Result.FwRCPriority = $FwRCPriority
                                                                        $Result.FwRuleDestFQDN = $FwRuleDestFQDN
                                                                        $Result.FwRuleDestPort = $_.port
                                                                        $Result.SrcIpgName = $CheckSrcIPgroup[0]
                                                                        $Result.SrcIpgIPs = $CheckSrcIPgroup[1]
                                                                        if($SynAckCheck){$OutputObjAfterCheck += $Result}else{
                                                                            $OutputObj += $Result
                                                                        }
                                                                        Continue ruleslabel
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        $CheckAllowDeny = $OutputObj |Sort-Object FwRCGPriolity,FwRCPriority | Select-Object -First 1
        $CheckAllowDenyAfter = $OutputObjAfterCheck |Sort-Object FwRCGPriolity,FwRCPriority | Select-Object -First 1
        if($SynAckCheck){
            #Show result (Priority 1:FwRuleType [Network], 2:FwRCGPriolity, 3:FwRCPriority)
            $OutputObj | Sort-Object -Property @{Expression = "FwRuleType"; Descending = $true},@{Expression = "FwRCGPriolity"; Descending = $false},@{Expression = "FwRCPriority"; Descending = $false},@{Expression = "FwRuleName"; Descending = $false} |Get-Unique -AsString| Format-Table -Property FwRuleCollectionGroupName,FwRuleType,FwRCGPriolity,FwRuleColName,FwRCPriority,FwRuleName,FwRuleSrcAddr,SrcIpgName,SrcIpgIPs,FwRuleDestAddr,DstIpgName,DstIpgIPs,FwRuleDestFQDN,FwRuleDestPort,FwRuleProtocol,FwActionType -AutoSize -Wrap 
            if($CheckAllowDeny.FwActionType -like "Allow" -and $CheckAllowDenyAfter.FwActionType -like "Deny"){
            Write-Host ----Return Packet Check-----
            $OutputObjAfterCheck | Sort-Object -Property @{Expression = "FwRuleType"; Descending = $true},@{Expression = "FwRCGPriolity"; Descending = $false},@{Expression = "FwRCPriority"; Descending = $false},@{Expression = "FwRuleName"; Descending = $false} |Get-Unique -AsString| Format-Table -Property FwRuleCollectionGroupName,FwRuleType,FwRCGPriolity,FwRuleColName,FwRCPriority,FwRuleName,FwRuleSrcAddr,SrcIpgName,SrcIpgIPs,FwRuleDestAddr,DstIpgName,DstIpgIPs,FwRuleDestFQDN,FwRuleDestPort,FwRuleProtocol,FwActionType -AutoSize -Wrap 
            Write-Host Traffic : Deny `("Return packet [SYN/ACK] is denied."`)
                Break
            }elseif($CheckAllowDeny -eq $null){
                Write-Host Traffic : No rule matched
                Break
            }else{
                Write-Host Traffic : $CheckAllowDeny[0].FwActionType
                Break
            }
        }
    }
}
