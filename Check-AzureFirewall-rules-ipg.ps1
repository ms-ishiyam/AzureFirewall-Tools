Param(
    [ValidateSet("TCP","UDP","ICMP")][Parameter(Mandatory=$true)][String]$Protocol,
    [Parameter(Mandatory=$true)][String]$SourceIpAddress,
    [Parameter(Mandatory=$true)][String]$DestinationIpAddress,
    [Parameter(Mandatory=$true)][String]$DestinationPort,
    [Parameter(Mandatory=$true)][String]$FW_ARMTemplateFilePath,
    [Parameter(Mandatory=$false)][String]$IPG_ARMTemplateFilePath    
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
                $FwRuleColGrouplName = $_.name.Split("/")[1].Split("'")[0]
                $FwRuleColGroupPriolity = $_.properties.priority
                for($j=0;$j -lt $_.properties.ruleCollections.count;$j++){
                    $_.properties.ruleCollections[$j] | ForEach-Object{
                        $FwRuleColName = $_.name
                        $FwRuleColPriority = $_.priority
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
                                        $Result1  = "" | Select-Object FwRuleColGrouplName,FwRuleColName,FwRuleColGroupPriolity,FwRuleName,FwRuleColPriority,FwRuleSrcAddr,FwRuleDestAddr,FwRuleDestPort,FwRuleProtocol,FwActionType,SrcIpgName,SrcIpgTemplateIPs,DstIpgName,DstIpgTemplateIPs
                                        $Result2  = "" | Select-Object FwRuleColGrouplName,FwRuleColName,FwRuleColGroupPriolity,FwRuleName,FwRuleColPriority,FwRuleSrcAddr,FwRuleDestAddr,FwRuleDestPort,FwRuleProtocol,FwActionType,SrcIpgName,SrcIpgTemplateIPs,DstIpgName,DstIpgTemplateIPs
                                        $Result3  = "" | Select-Object FwRuleColGrouplName,FwRuleColName,FwRuleColGroupPriolity,FwRuleName,FwRuleColPriority,FwRuleSrcAddr,FwRuleDestAddr,FwRuleDestPort,FwRuleProtocol,FwActionType,SrcIpgName,SrcIpgTemplateIPs,DstIpgName,DstIpgTemplateIPs
                                        $Result4  = "" | Select-Object FwRuleColGrouplName,FwRuleColName,FwRuleColGroupPriolity,FwRuleName,FwRuleColPriority,FwRuleSrcAddr,FwRuleDestAddr,FwRuleDestPort,FwRuleProtocol,FwActionType,SrcIpgName,SrcIpgTemplateIPs,DstIpgName,DstIpgTemplateIPs
                                        foreach($FwRuleSrcAddr in $_.sourceAddresses){
                                            if(Check-FirewallAddressRange -FWRuleAddresses $FwRuleSrcAddr -InputAddress $SourceIpAddress){
                                                #If Source IPs are match, go to check Destination IPs.
                                                foreach($FwRuleDestAddr in $_.destinationAddresses){
                                                    if(Check-FirewallAddressRange -FWRuleAddresses $FwRuleDestAddr -InputAddress $DestinationIpAddress){
                                                        #Check Destination Port.
                                                        $CheckPorts = Check-RulesDestinationPorts -TargeRuleDestPort $_.destinationPorts
                                                        if($CheckPorts){
                                                            $Result1.FwRuleColGrouplName = $FwRuleColGrouplName
                                                            $Result1.FwRuleColName = $FwRuleColName
                                                            $Result1.FwActionType = $FwActionType
                                                            $Result1.FwRuleName = $FwRuleName
                                                            $Result1.FwRuleProtocol = $FwRuleProtocol
                                                            $Result1.FwRuleColGroupPriolity = $FwRuleColGroupPriolity
                                                            $Result1.FwRuleColPriority = $FwRuleColPriority
                                                            $Result1.FwRuleSrcAddr = $CheckPorts[0]
                                                            $Result1.FwRuleDestAddr = $CheckPorts[1]
                                                            $Result1.FwRuleDestPort = $CheckPorts[2]
                                                            $OutputObj += $Result1
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
                                                            $Result2.FwRuleColGrouplName = $FwRuleColGrouplName
                                                            $Result2.FwRuleColName = $FwRuleColName
                                                            $Result2.FwActionType = $FwActionType
                                                            $Result2.FwRuleName = $FwRuleName
                                                            $Result2.FwRuleProtocol = $FwRuleProtocol
                                                            $Result2.FwRuleColGroupPriolity = $FwRuleColGroupPriolity
                                                            $Result2.FwRuleColPriority = $FwRuleColPriority
                                                            $Result2.FwRuleSrcAddr = $CheckPorts[0]
                                                            $Result2.FwRuleDestAddr = $CheckPorts[1]
                                                            $Result2.FwRuleDestPort = $CheckPorts[2]
                                                            $Result2.DstIpgName = $CheckDstIPgroup[0]
                                                            $Result2.DstIpgTemplateIPs = $CheckDstIPgroup[1]
                                                            $OutputObj += $Result2
                                                            Continue ruleslabel
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        #If Source IP Groups are match, go to check Destination IP and IP Groups.
                                        if($JPGJson){
                                            $FwRuleSrcAddr = ""
                                            $FwRuleDestAddr = ""
                                            foreach($FwRuleSrcIpGrpName in $_.sourceIpGroups){
                                                $CheckSrcIPgroup = Check-IPgroup -FwRuleIpGrpName $FwRuleSrcIpGrpName -SrcDstFlag "Src"
                                                    if($CheckSrcIPgroup){
                                                    #If Source IP Groups are match, go to check Destination IPs.
                                                    foreach($FwRuleDestAddr in $_.destinationAddresses){
                                                        if(Check-FirewallAddressRange -FWRuleAddresses $FwRuleDestAddr -InputAddress $DestinationIpAddress){
                                                            #Check Destination Port.
                                                            $CheckPorts = Check-RulesDestinationPorts -TargeRuleDestPort $_.destinationPorts
                                                            if($CheckPorts){
                                                                $Result3.FwRuleColGrouplName = $FwRuleColGrouplName
                                                                $Result3.FwRuleColName = $FwRuleColName
                                                                $Result3.FwActionType = $FwActionType
                                                                $Result3.FwRuleName = $FwRuleName
                                                                $Result3.FwRuleProtocol = $FwRuleProtocol
                                                                $Result3.FwRuleColGroupPriolity = $FwRuleColGroupPriolity
                                                                $Result3.FwRuleColPriority = $FwRuleColPriority
                                                                $Result3.FwRuleSrcAddr = $CheckPorts[0]
                                                                $Result3.FwRuleDestAddr = $CheckPorts[1]
                                                                $Result3.FwRuleDestPort = $CheckPorts[2]
                                                                $Result3.SrcIpgName = $CheckSrcIPgroup[0]
                                                                $Result3.srcIpgTemplateIPs = $CheckSrcIPgroup[1]
                                                                $OutputObj += $Result3
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
                                                                $Result4.FwRuleColGrouplName = $FwRuleColGrouplName
                                                                $Result4.FwRuleColName = $FwRuleColName
                                                                $Result4.FwActionType = $FwActionType
                                                                $Result4.FwRuleName = $FwRuleName
                                                                $Result4.FwRuleProtocol = $FwRuleProtocol
                                                                $Result4.FwRuleColGroupPriolity = $FwRuleColGroupPriolity
                                                                $Result4.FwRuleColPriority = $FwRuleColPriority
                                                                $Result4.FwRuleSrcAddr = $CheckPorts[0]
                                                                $Result4.FwRuleDestAddr = $CheckPorts[1]
                                                                $Result4.FwRuleDestPort = $CheckPorts[2]
                                                                $Result4.SrcIpgName = $CheckSrcIPgroup[0]
                                                                $Result4.srcIpgTemplateIPs = $CheckSrcIPgroup[1]
                                                                $Result4.DstIpgName = $CheckDstIPgroup[0]
                                                                $Result4.DstIpgTemplateIPs = $CheckDstIPgroup[1]
                                                                $OutputObj += $Result4
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
    $OutputObj |Sort-Object FwRuleColGroupPriolity,FwRuleColPriority |Get-Unique -AsString| Format-Table -Property FwRuleColGrouplName,FwRuleColGroupPriolity,FwRuleColName,FwRuleColPriority,FwRuleName,FwRuleSrcAddr,FwRuleDestAddr,FwRuleDestPort,FwRuleProtocol,FwActionType,SrcIpgName,SrcIpgTemplateIPs,DstIpgName,DstIpgTemplateIPs -AutoSize -Wrap 
}
