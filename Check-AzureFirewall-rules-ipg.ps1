Param(
    [ValidateSet("ANY","TCP","UDP","ICMP")][Parameter(Mandatory=$true)][String]$Protocol,
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
            {$_.Contains("-")} {
            $FwRuleTargetStartAddr = (ConvertTo-UInt32IPv4Address $_.Split("-")[0])
            $FwRuleTargetEndAddr = (ConvertTo-UInt32IPv4Address $_.Split("-")[1])
            $TargetAddress = (ConvertTo-UInt32IPv4Address $InputAddress)
            if(Check-UInt32IPv4AddressRange -UInt32TargetIPv4Address $TargetAddress -UInt32StartIPv4Address $FwRuleTargetStartAddr -UInt32EndIPv4Address $FwRuleTargetEndAddr){
                    Return $true
                }
            }
            {$_ -notlike "*/*"} {$FwRuleTargetAddr="$_/32"}
        }

        $StartAddress = (ConvertTo-UInt32IPv4StartAddress $FwRuleTargetAddr)
        $EndAddress = (ConvertTo-UInt32IPv4EndAddress $FwRuleTargetAddr)
        $TargetAddress = (ConvertTo-UInt32IPv4Address $InputAddress)
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
        if(($FwRuleDestPort.Contains($DestinationPort)) -or ($FwRuleDestPort -eq "*")){
            $CheckDestPort = $true
            }elseif($FwRuleDestPort.Contains("-")){
            $DestPortRange = $FwRuleDestPort.Split("-")
            if(($DestinationPort -ge $DestPortRange[0]) -and ($DestinationPort -le $DestPortRange[1])){
                $CheckDestPort = $true
            }
        }
        if(($CheckDestPort -eq $true)){
                Return ($FwRuleSrcAddr, $FwRuleDestAddr, $FwRuleDestPort)
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

# Use Online Cache
if($ServiceTagFilePath){
   $ServiceTagJson = Get-Content -Path $ServiceTagFilePath | ConvertFrom-Json
}else{
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
                    ### need a fix for IPv6 ###
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

#Check Azure Firewall rules with input parameter
Get-Content -Path $FW_ARMTemplateFilePath | ConvertFrom-Json | ForEach-Object{
    for($i=0;$i -lt $_.resources.count;$i++){
        $_.resources[$i] | ForEach-Object{
            if($_.type -like "*ruleCollectionGroups"){
                $FwRuleCollectionGroupName = $_.name.Split("/")[1].Split("'")[0]
                $FwRCGPriolity = $_.properties.priority
                for($j=0;$j -lt $_.properties.ruleCollections.count;$j++){
                    $_.properties.ruleCollections[$j] | ForEach-Object{
                        $FwRuleColName = $_.name
                        $FwRCPriority = $_.priority
                        #Only NetworkRule
                        if("NetworkRule" -eq $_.rules.ruleType -or "NetworkRule" -eq $_.rules.ruleType[0]){
                            $FwActionType = $_.action.type
                            :ruleslabel for($k=0;$k -lt $_.rules.count;$k++){
                                $_.rules[$k] | ForEach-Object{
                                    $FwRuleName = $_.name
                                    $FwRuleProtocol = $_.ipProtocols
                                    #If Portocol is match, go to check Source IP.
                                    if($_.ipProtocols.Contains($Protocol) -or $_.ipProtocols.Contains("ANY")){
                                        #If Source IPs are match, go to check Destination IP and IP Groups.
                                        $Result  = "" | Select-Object FwRuleCollectionGroupName,FwRuleColName,FwRCGPriolity,FwRuleName,FwRCPriority,FwRuleSrcAddr,FwRuleDestAddr,FwRuleDestPort,FwRuleProtocol,FwActionType,SrcIpgName,SrcIpgIPs,DstIpgName,DstIpgIPs
                                        foreach($FwRuleSrcAddr in $_.sourceAddresses){
                                            #Check Source IPaddress
                                            if(Check-FirewallAddressRange -FWRuleAddresses $FwRuleSrcAddr -InputAddress $SourceIpAddress){
                                                #Check Destination IPs.
                                                foreach($FwRuleDestAddr in $_.destinationAddresses){
                                                    if(($FwRuleDestAddr -ne "*") -and ($FwRuleDestAddr -notlike "*.*.*.*")){
                                                        #Check Destination ServiceTag.
                                                        if(Check-ServiceTag -FwRuleServiceTag $FwRuleDestAddr){
                                                            #Check Destination Port.
                                                            $CheckPorts = Check-RulesDestinationPorts -TargeRuleDestPort $_.destinationPorts
                                                            if($CheckPorts){
                                                                $Result.FwRuleCollectionGroupName = $FwRuleCollectionGroupName
                                                                $Result.FwRuleColName = $FwRuleColName
                                                                $Result.FwActionType = $FwActionType
                                                                $Result.FwRuleName = $FwRuleName
                                                                $Result.FwRuleProtocol = $FwRuleProtocol
                                                                $Result.FwRCGPriolity = $FwRCGPriolity
                                                                $Result.FwRCPriority = $FwRCPriority
                                                                $Result.FwRuleSrcAddr = $CheckPorts[0]
                                                                $Result.FwRuleDestAddr = $CheckPorts[1]
                                                                $Result.FwRuleDestPort = $CheckPorts[2]
                                                                $OutputObj += $Result
                                                                Continue ruleslabel
                                                            }
                                                        }
                                                    }elseif(Check-FirewallAddressRange -FWRuleAddresses $FwRuleDestAddr -InputAddress $DestinationIpAddress){                                                     
                                                        #Check Destination Port.
                                                        $CheckPorts = Check-RulesDestinationPorts -TargeRuleDestPort $_.destinationPorts
                                                        if($CheckPorts){
                                                            $Result.FwRuleCollectionGroupName = $FwRuleCollectionGroupName
                                                            $Result.FwRuleColName = $FwRuleColName
                                                            $Result.FwActionType = $FwActionType
                                                            $Result.FwRuleName = $FwRuleName
                                                            $Result.FwRuleProtocol = $FwRuleProtocol
                                                            $Result.FwRCGPriolity = $FwRCGPriolity
                                                            $Result.FwRCPriority = $FwRCPriority
                                                            $Result.FwRuleSrcAddr = $CheckPorts[0]
                                                            $Result.FwRuleDestAddr = $CheckPorts[1]
                                                            $Result.FwRuleDestPort = $CheckPorts[2]
                                                            $OutputObj += $Result
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
                                                        if($CheckPorts){
                                                            $Result.FwRuleCollectionGroupName = $FwRuleCollectionGroupName
                                                            $Result.FwRuleColName = $FwRuleColName
                                                            $Result.FwActionType = $FwActionType
                                                            $Result.FwRuleName = $FwRuleName
                                                            $Result.FwRuleProtocol = $FwRuleProtocol
                                                            $Result.FwRCGPriolity = $FwRCGPriolity
                                                            $Result.FwRCPriority = $FwRCPriority
                                                            $Result.FwRuleSrcAddr = $CheckPorts[0]
                                                            $Result.FwRuleDestAddr = $CheckPorts[1]
                                                            $Result.FwRuleDestPort = $CheckPorts[2]
                                                            $Result.DstIpgName = $CheckDstIPgroup[0]
                                                            $Result.DstIpgIPs = $CheckDstIPgroup[1]
                                                            $OutputObj += $Result
                                                            Continue ruleslabel
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
                                                    foreach($FwRuleDestAddr in $_.destinationAddresses){
                                                        #Check Destination IpAddress.
                                                        if(Check-FirewallAddressRange -FWRuleAddresses $FwRuleDestAddr -InputAddress $DestinationIpAddress){
                                                            #Check Destination Port.
                                                            $CheckPorts = Check-RulesDestinationPorts -TargeRuleDestPort $_.destinationPorts
                                                            if($CheckPorts){
                                                                $Result.FwRuleCollectionGroupName = $FwRuleCollectionGroupName
                                                                $Result.FwRuleColName = $FwRuleColName
                                                                $Result.FwActionType = $FwActionType
                                                                $Result.FwRuleName = $FwRuleName
                                                                $Result.FwRuleProtocol = $FwRuleProtocol
                                                                $Result.FwRCGPriolity = $FwRCGPriolity
                                                                $Result.FwRCPriority = $FwRCPriority
                                                                $Result.FwRuleSrcAddr = $CheckPorts[0]
                                                                $Result.FwRuleDestAddr = $CheckPorts[1]
                                                                $Result.FwRuleDestPort = $CheckPorts[2]
                                                                $Result.SrcIpgName = $CheckSrcIPgroup[0]
                                                                $Result.SrcIpgIPs = $CheckSrcIPgroup[1]
                                                                $OutputObj += $Result
                                                                Continue ruleslabel
                                                            }
                                                        }
                                                    }
                                                    #Check Destination IP Group.
                                                    foreach($FwRuleDestIpGrpName in $_.destinationIpGroups){
                                                        $CheckDstIPgroup = Check-IPgroup -FwRuleIpGrpName $FwRuleDestIpGrpName -SrcDstFlag "Dst"
                                                        if($CheckDstIPgroup){
                                                            #Check Destination Port.
                                                            $CheckPorts = Check-RulesDestinationPorts -TargeRuleDestPort $_.destinationPorts
                                                            if($CheckPorts){
                                                                $Result.FwRuleCollectionGroupName = $FwRuleCollectionGroupName
                                                                $Result.FwRuleColName = $FwRuleColName
                                                                $Result.FwActionType = $FwActionType
                                                                $Result.FwRuleName = $FwRuleName
                                                                $Result.FwRuleProtocol = $FwRuleProtocol
                                                                $Result.FwRCGPriolity = $FwRCGPriolity
                                                                $Result.FwRCPriority = $FwRCPriority
                                                                $Result.FwRuleSrcAddr = $CheckPorts[0]
                                                                $Result.FwRuleDestAddr = $CheckPorts[1]
                                                                $Result.FwRuleDestPort = $CheckPorts[2]
                                                                $Result.SrcIpgName = $CheckSrcIPgroup[0]
                                                                $Result.SrcIpgIPs = $CheckSrcIPgroup[1]
                                                                $Result.DstIpgName = $CheckDstIPgroup[0]
                                                                $Result.DstIpgIPs = $CheckDstIPgroup[1]
                                                                $OutputObj += $Result
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
    $OutputObj |Sort-Object FwRCGPriolity,FwRCPriority |Get-Unique -AsString| Format-Table -Property FwRuleCollectionGroupName,FwRCGPriolity,FwRuleColName,FwRCPriority,FwRuleName,FwRuleSrcAddr,FwRuleDestAddr,SrcIpgName,SrcIpgIPs,DstIpgName,DstIpgIPs,FwRuleDestPort,FwRuleProtocol,FwActionType -AutoSize -Wrap 
    $CheckAllowDeny = $OutputObj |Sort-Object FwRCGPriolity,FwRCPriority
    Write-Host Traffic : $CheckAllowDeny[0].FwActionType
}
