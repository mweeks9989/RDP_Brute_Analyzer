$logs = get-winevent -Path z:\temp\Security1.evtx
write-host "[*] Initial Logs Ingestion completed - " + $logs.count " - ingested."
write-host "[*] Analyzing failed and successful logins."

#Parse IP ranges for failed logins
$ipsDenied = @()
$ipsAllowed = @()
function combineLogs {
    [xml]$stuffs = $log.toxml()
    $source = ($stuffs.Event.EventData.ChildNodes).Where({$_.name -eq "IpAddress"}).'#text'
    $user=($stuffs.Event.EventData.Data).Where({$_.name -eq "TargetUserName"}).'#text'
    $recordID = $log.RecordId
    $dateTime = $log.TimeCreated
    [pscustomobject]$combinedLog = @{ RecordID=$recordID; DateTime=$dateTime; User=$user; srcIP=$source }

    return $combinedLog
}

foreach ($log in $logs)
{
    Switch($log.id)
    {
        4625 {
            combineLogs
            $ipsDenied += $combinedLog
        }
        4625 {
            combineLogs
            $ipsAllowed += $combinedLog
        }
        default {
            Out-Null
        }
    }
}

$bruteIPsDenied = $ipsDenied.srcIP | Group-Object | where {$_.count -gt 3 } | select -ExpandProperty name 
$dedupAllowIP = $ipsAllowed.srcIP | Sort-Object -Unique

if ([string]::IsNullOrEmpty($dedupAllowIP)){
    Write-Output 'No RDP login events are available in log.'
    exit
}
elseif ([string]::IsNullOrEmpty($bruteIPsDenied)){
    Write-Output 'No RDP denied logins were found in log.'
    exit
}

$comp = ((Compare-Object -ReferenceObject $bruteIPsDenied -DifferenceObject $dedupAllowIP -IncludeEqual).Where({$_.SideIndicator -eq "=="})).InputObject

if ([string]::IsNullOrEmpty($comp)){
    write-host "No indication of unauthorized successful login found."
    exit
}
else{
    write-host "[*] Found as a brute force attacker that successfully logged in"
    "Allowed Events: $ipsDenied.where($_.srcIP -eq $comp)"
    "Denied Events: $ipsAllowed.where($_.srcIP -eq $comp)"
}
