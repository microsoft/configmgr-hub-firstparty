$ComputerLocalHost = Get-Content env:computername
$UserProperty = @{n="User";e={(New-Object System.Security.Principal.SecurityIdentifier $_.ReplacementStrings[1]).Translate([System.Security.Principal.NTAccount])}}
$TypeProperty = @{n="Action";e={if($_.EventID -eq 7001) {"Logon"} else {"Logoff"}}}
$TimeProperty = @{n="Time";e={$_.TimeGenerated}}
$MachineNameProperty = @{n="MachineName";e={$_.MachineName}}

Get-EventLog System -Source Microsoft-Windows-Winlogon -ComputerName $ComputerLocalHost | select $UserProperty, $TypeProperty,$TimeProperty,$MachineNameProperty 
