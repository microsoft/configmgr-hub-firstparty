<#  Reset Client Policy #>
#Requires -RunAsAdministrator
#----------------------------------------------------------------------------------------------------------
#
#                                          Parameter Declarations
#
#----------------------------------------------------------------------------------------------------------

Param(
# File share to store logs, the maximum length is 130 since the script would create sub folders and files 
[Parameter(Position=1)]
[string]$LogPath,

# LogMode == 0 log to console only
# LogMode == 1 log to file and console
# LogMode == 2 log to file only
[Parameter(Position=2)]
[Int16]$LogMode = 1
)

#----------------------------------------------------------------------------------------------------------
#
#                                          Parameter Intialization and Validation 
#
#----------------------------------------------------------------------------------------------------------

# Parameter: $LogPath
if([String]::IsNullOrEmpty($LogPath) -or [String]::IsNullOrWhiteSpace($LogPath))
{
    # Set to default value
    $LogPath = "$Env:SystemDrive\ResetClientPolicyLog"
}
else
{
    Write-Verbose "Validating path length no more than 124: $LogPath"
    $LogPath = $LogPath.Trim().TrimEnd('\')
    if($LogPath.Length -gt 124)
    {
        throw "Failed to validate the length of the given path: $LogPath"
    }

    # Validate parameter: $LogPath
    Write-Verbose "Validating path format: $LogPath"
    $validateResult = $false
    
    if((Test-Path $LogPath -IsValid) -eq $true)
    {
        $testSplitArray = $LogPath.Split(':')

        if($testSplitArray.Count -eq 1)
        {
            $validateResult = $true
        }
        elseif($testSplitArray.Count -eq 2)
        {
            $targetDrv = Get-PSDrive -Name $testSplitArray[0]   

            if($targetDrv -ne $null)
            {
                $fileDrv = Get-PSProvider -PSProvider FileSystem

                if($fileDrv -ne $null)
                {
                    if($fileDrv.Drives.Contains($targetDrv) -eq $true)
                    {
                         $validateResult = $true
                    }
                }
            }
        }
    }

    if($validateResult -eq $false)
    {
        throw "Failed to validate the format of the given path: $LogPath"
    }
}

Write-Verbose "Output Path = $LogPath"

# Parameter: $LogMode
Write-Verbose "Validating log mode(0|1|2): $LogMode"

if(($LogMode -ne 0) -and ($LogMode -ne 1) -and ($LogMode -ne 2))
{
    throw "Failed to validate the given log mode: $LogMode"
}

Write-Verbose "Log Mode = $LogMode"

#----------------------------------------------------------------------------------------------------------
#
#                                          Global Variables
#
#----------------------------------------------------------------------------------------------------------

# Script folder root
$global:scriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path

# Set the exit code to the first exception exit code
$global:errorCode = [string]::Empty;

# Total error count while running the script
[int]$global:errorCount = 0;

# Global utc trace name
$global:timeStart=Get-Date
$global:timeStartString=$global:timeStart.ToString("yy_MM_dd_HH_mm_ss")
$global:utcTraceName = "utctrace" + $global:timeStartString

#----------------------------------------------------------------------------------------------------------------
#
#                                                   Main
#
#----------------------------------------------------------------------------------------------------------------

$main = {
    Try
    {
        Get-CmClientVersion

        CreateLogFile

        Log "Starting ResetClientPolicy..."
        Log "UTC DateTime: $global:utcDate"
        Log "Configuration Manager Client Version: $global:smsClientVersion"

        ResetPolicy

        RetrieveMachinePolicy

        Log "Completed ResetClientPolicy successfully."
    }  
    Catch
    {
        Log "Unexpected error occured while executing the script" "Error" "1" "UnExpectedException" $_.Exception.HResult $_.Exception.Message
        Log "Script failed" "Failure" "1" "ScriptEnd"
        [System.Environment]::Exit(1)
    }
}

#----------------------------------------------------------------------------------------------------------
#
#                                          Function Definitions
#
#----------------------------------------------------------------------------------------------------------
function ResetPolicy()
{
    Log "Calling WMI method to reset client policy..."
    Invoke-WmiMethod -Namespace 'root\ccm' -Class 'SMS_Client' -Name "ResetPolicy" -ArgumentList 0x1
    Log "Called WMI method successfully."
}

function RetrieveMachinePolicy()
{
    Log "Calling WMI to retrieve machine policy..."
    Invoke-WmiMethod -Namespace 'root\ccm' -Class 'SMS_Client' -Name "TriggerSchedule" -ArgumentList ('{00000000-0000-0000-0000-000000000021}')
    Log "Called WMI method successfully."
}

function Get-CmClientVersion
{
    try 
    {
        $propertyPath = "HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client"
        $propertyName = "SmsClientVersion"
        if (Test-Path -Path $propertyPath)
        {
            $property = Get-ItemProperty -Path $propertyPath -Name $propertyName -ErrorAction SilentlyContinue
            if ($null -eq $property)
            {
                Log "Get-CmClientVersion: Could not find registry value $propertyName at path $propertyPath" "Warning"
            }
            else {
                $global:smsClientVersion = $property.SmsClientVersion
            }
        }
        else 
        {
            Log "Get-CmClientVersion: Could not find registry key $propertyPath" "Warning"
        }
    }
    catch 
    {
        Log "Get-CmClientVersion: Error getting $propertyName registry value at path $propertyPath" "Warning" $null "Get-CmClientVersion" $_.Exception.HResult $_.Exception.Message
    }    
}


function CreateLogFile
{
    Write-Verbose "Creating output folder"
    $timeStart=Get-Date
    $timeStartString=$timeStart.ToString("yy_MM_dd_HH_mm_ss")
    $logFolderName = "ResetClientPolicyLog_" + $timeStartString
    $global:logFolder = $logPath +"\"+$logFolderName

    Try
    {   
        $outputFolder = New-Item $global:logFolder -type directory
        Write-Host "Output folder created successfully: $outputFolder"
    }
    Catch
    {
        $hexHresult = "{0:X}" -f $_.Exception.HResult
        $exceptionMessage = $_.Exception.Message
        Write-Error "Could not create output folder at the given logPath: $LogPath`nException: $exceptionMessage HResult:  0x$hexHresult"
        [System.Environment]::Exit(28)
    }

    if($LogMode -ne 0)
    {
        Write-Verbose "Creating Log File"
        $fileName = $logFolderName+".txt"
        $global:logFile=$global:logFolder+"\"+$fileName

        Try
        {
            New-Item $global:logFile -type file | Out-Null
            Write-Verbose "Log File created successfully: $global:logFile"
        }
        Catch
        {
            $hexHresult = "{0:X}" -f $_.Exception.HResult
            $exceptionMessage = $_.Exception.Message
            Write-Error "Could not create log file at the given logPath: $LogPath`nException: $exceptionMessage HResult:  0x$hexHresult"
            [System.Environment]::Exit(28)
        }
    }
}

function Log($logMessage, $logLevel, $errorCode, $operation, $exceptionHresult, $exceptionMessage)
{
    $global:logDate = Get-Date -Format s
    $global:utcDate = ((Get-Date).ToUniversalTime()).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $logMessageForAppInsights = $logMessage

    if(($logLevel -eq $null) -or ($logLevel -eq [string]::Empty))
    {
        $logLevel = "Info"
    }

    if($logLevel -eq "Error")
    {
        # check and update the errorCode (the script will exit with the first errorCode)
        if(($errorCode -ne $null) -and ($errorCode -ne [string]::Empty))
        {
            if(($global:errorCode -eq $null) -or ($global:errorCode -eq [string]::Empty))
            {
                $global:errorCode = $errorCode
            }

            $logMessage = "ErrorCode " + $errorCode + " : " + $logMessage
        }

        if($exceptionHresult -ne $null)
        {
             $logMessage = $logMessage + " HResult: " + $exceptionHresult
        }

        if($exceptionMessage -ne $null)
        {
            $logMessage = $logMessage + " ExceptionMessage: " + $exceptionMessage
        }

        $global:errorCount++
    }
    elseif($logLevel -eq "Exception")
    {
        if($exceptionHresult -ne $null)
        {
             $logMessage = $logMessage + " HResult: " + $exceptionHresult
        }

        if($exceptionMessage -ne $null)
        {
            $logMessage = $logMessage + " ExceptionMessage: " + $exceptionMessage
        }
    }
    elseif($logLevel -eq "Warning")
    {
        if($exceptionHresult -ne $null)
        {
             $logMessage = $logMessage + " HResult: " + $exceptionHresult
        }

        if($exceptionMessage -ne $null)
        {
            $logMessage = $logMessage + " ExceptionMessage: " + $exceptionMessage
        }
    }

    if ($LogMode -eq 0)
    {
        Try
        {
            WriteLogToConsole $logLevel $logMessage
        }
        Catch
        {
            # Error when logging to console
            $exceptionDetails = "Exception: " + $_.Exception.Message + "HResult: " + $_.Exception.HResult
            $message = "Error when logging to console."
            Write-Error "$message`n$exceptionDetails"
            SendEventToAppInsights "logging" $message "Failure" $global:utcDate "2" $_.Exception.HResult $_.Exception.Message
            [System.Environment]::Exit(2)
        }
    }
    elseif ($LogMode -eq 1)
    {
        Try
        {
            WriteLogToConsole $logLevel $logMessage
            Add-Content $global:logFile "$global:logDate : $logLevel : $logMessage"
        }
        Catch
        {
            # Error when logging to console and file
            $exceptionDetails = "Exception: " + $_.Exception.Message + "HResult: " + $_.Exception.HResult
            $message = "Error when logging to console and file."
            Write-Error "$message`n$exceptionDetails"
            SendEventToAppInsights "logging" $message "Failure" $global:utcDate "3" $_.Exception.HResult $_.Exception.Message
            [System.Environment]::Exit(3)
        }
    }
    elseif ($LogMode -eq 2)
    {
        Try
        {
            Add-Content $global:logFile "$global:logDate : $logLevel : $logMessage"
        }
        Catch
        {
            # Error when logging to file
            $exceptionDetails = "Exception: " + $_.Exception.Message + "HResult: " + $_.Exception.HResult
            $message = "Error when logging to file."
            Write-Error "$message`n$exceptionDetails"
            SendEventToAppInsights "logging" $message "Failure" $global:utcDate "4" $_.Exception.HResult $_.Exception.Message
            [System.Environment]::Exit(4)
        }
    }
    else
    {
        Try
        {
            WriteLogToConsole $logLevel $logMessage
            Add-Content $global:logFile "$global:logDate : $logLevel : $logMessage"
        }
        Catch
        {
            # Error when logging to console and file
            $exceptionDetails = "Exception: " + $_.Exception.Message + "HResult: " + $_.Exception.HResult
            $message = "Error when logging to console and file."
            Write-Error "$message`n$exceptionDetails"
            SendEventToAppInsights "logging" $message "Failure" $global:utcDate "5" $_.Exception.HResult $_.Exception.Message
            [System.Environment]::Exit(5)
        }
    }
}

function WriteLogToConsole($logLevel, $logMessage)
{
    switch ($logLevel)
    {
        "Error"   
            {    
                Write-Error "$global:logDate : $logMessage"; Break
            }
        "Exception"    
            {    
                Write-Error "$global:logDate : $logMessage"; Break
            }
        "Warning"    
            {    
                Write-Warning "$global:logDate : $logMessage"; Break
            }
        default     
            {    
                Write-Host "$global:logDate : $logMessage"; Break
            }
    }
}

# Calling the main function
&$main
# SIG # Begin signature block
# MIIjhgYJKoZIhvcNAQcCoIIjdzCCI3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBeZ0J+fZ2+gess
# KlOH23hbt3oWpg482AACdhzS/mDHSqCCDYEwggX/MIID56ADAgECAhMzAAABh3IX
# chVZQMcJAAAAAAGHMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAwMzA0MTgzOTQ3WhcNMjEwMzAzMTgzOTQ3WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDOt8kLc7P3T7MKIhouYHewMFmnq8Ayu7FOhZCQabVwBp2VS4WyB2Qe4TQBT8aB
# znANDEPjHKNdPT8Xz5cNali6XHefS8i/WXtF0vSsP8NEv6mBHuA2p1fw2wB/F0dH
# sJ3GfZ5c0sPJjklsiYqPw59xJ54kM91IOgiO2OUzjNAljPibjCWfH7UzQ1TPHc4d
# weils8GEIrbBRb7IWwiObL12jWT4Yh71NQgvJ9Fn6+UhD9x2uk3dLj84vwt1NuFQ
# itKJxIV0fVsRNR3abQVOLqpDugbr0SzNL6o8xzOHL5OXiGGwg6ekiXA1/2XXY7yV
# Fc39tledDtZjSjNbex1zzwSXAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUhov4ZyO96axkJdMjpzu2zVXOJcsw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDU4Mzg1MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAixmy
# S6E6vprWD9KFNIB9G5zyMuIjZAOuUJ1EK/Vlg6Fb3ZHXjjUwATKIcXbFuFC6Wr4K
# NrU4DY/sBVqmab5AC/je3bpUpjtxpEyqUqtPc30wEg/rO9vmKmqKoLPT37svc2NV
# BmGNl+85qO4fV/w7Cx7J0Bbqk19KcRNdjt6eKoTnTPHBHlVHQIHZpMxacbFOAkJr
# qAVkYZdz7ikNXTxV+GRb36tC4ByMNxE2DF7vFdvaiZP0CVZ5ByJ2gAhXMdK9+usx
# zVk913qKde1OAuWdv+rndqkAIm8fUlRnr4saSCg7cIbUwCCf116wUJ7EuJDg0vHe
# yhnCeHnBbyH3RZkHEi2ofmfgnFISJZDdMAeVZGVOh20Jp50XBzqokpPzeZ6zc1/g
# yILNyiVgE+RPkjnUQshd1f1PMgn3tns2Cz7bJiVUaqEO3n9qRFgy5JuLae6UweGf
# AeOo3dgLZxikKzYs3hDMaEtJq8IP71cX7QXe6lnMmXU/Hdfz2p897Zd+kU+vZvKI
# 3cwLfuVQgK2RZ2z+Kc3K3dRPz2rXycK5XCuRZmvGab/WbrZiC7wJQapgBodltMI5
# GMdFrBg9IeF7/rP4EqVQXeKtevTlZXjpuNhhjuR+2DMt/dWufjXpiW91bo3aH6Ea
# jOALXmoxgltCp1K7hrS6gmsvj94cLRf50QQ4U8Qwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVWzCCFVcCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAYdyF3IVWUDHCQAAAAABhzAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgHBED/lwJ
# hvZn8R6L7/Lple4ZVOA1tk+IW1SIlV8pXAEwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQBY0cz1JUUtHJuBq7YrlQRdtVR+eYH+Vt/6sv3UnjUR
# 16N6TxxU5qToDlvqp4bmkDNBfQKFzMepqYU5Nl1Qs1HCP+qUk/AF+pRxbHwH7EfQ
# T4AXus+ym4adev2btvzM+mHIILQOtaUvtbmDQlNUUgyj5IFqwWN1OLPe2aIwN125
# skEPuJtv0D2iyfvSp01eQ3mlyJag4BzRrxmTPoeEY2WKwfgBloB/+sxD63gLA43v
# vckvqRq6BzsZy2zs27qHjBhkmc7FJHGOrNTDtkbjUiaAWV+6sf2mJoS5J+CCBpMq
# 02DsWROicPteMC61Aqg2Nau6kNqN7kH2JsgQ+Jy77eISoYIS5TCCEuEGCisGAQQB
# gjcDAwExghLRMIISzQYJKoZIhvcNAQcCoIISvjCCEroCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIHz/ywKB/zE/ETU7SveLZ5nmKXVJh1kXF5O1+/Qs
# 8Q06AgZfOqy25FkYEzIwMjAwODMxMDUzMjA4LjE2OVowBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjdCRjEtRTNFQS1CODA4MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIOPDCCBPEwggPZoAMCAQICEzMAAAEfTiXNrAr0uB8AAAAAAR8w
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MTkxMTEzMjE0MDQxWhcNMjEwMjExMjE0MDQxWjCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046N0JGMS1FM0VBLUI4
# MDgxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQClTA/MVvc/HIx/TjowtYUK0XCUKnO7
# XA+LbpynRBjFrX3Jts+cMX7XGWNDWnqleP6E8tNAiCxX/EsCcOgqdEaarfsvh5JV
# JeAyYJMNpktlTAmLcPKxCB0Jfy7Cj5yeV8Z8UJnQ7NMhWCO3jBrWha2qSDR4n7+H
# gJ6IZ91J+vP0Oz2j/OfxVal/Oxxbu8cWMCZPdeQBOXdnVQhXGJtIOE4ZL580Rvy3
# B3bhGf6oGmK1GpUtskZ8tqQgyP1w5FdeG9hYbIJB/K4+ZY8ppDX3iJmKpYv+z/0J
# Zbn7fzX77s5Fr1qq06YPJEJNUO8a0tMhmewD9YgPtJBXFeCry7li2wizAgMBAAGj
# ggEbMIIBFzAdBgNVHQ4EFgQUFaMfADowE2MEN2UiWyvBNon64MAwHwYDVR0jBBgw
# FoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDov
# L2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENB
# XzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAx
# MC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDAN
# BgkqhkiG9w0BAQsFAAOCAQEAmNFHwNxk4spiq8nOic9RxCwL2X8/C73gy/7uXxfU
# Fbb7MoSoANP2iAkPc6ntwCDfHfHptoQvqrDiHA4JTd1ZQSbEBLqE7pZ3wV2L+hRm
# Uzip6wKJf3UNnk/3FeIQPPVRdDFtmRj8qB6AkAjgI7JAi2kvKUaCabHnxfXLmBhR
# SaXMQdjAJ7dRgsKboATao379NDnWHKWKbsE1HqzbCogQmAUsbLXVmBIk6Lm1DkGo
# s6H7Ai1hGquhlHRAg01NnT4pXSrKZtqdiogyJ8Ztzkz181z5/ZE2cbgxm8wB+whR
# WWr/cyGtY3+QMqC+3u/HQsj85+DWVwU8U+PB+4rNi2psRDCCBnEwggRZoAMCAQIC
# CmEJgSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRp
# ZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1NVoXDTI1MDcwMTIx
# NDY1NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/aZRrdFQQ1aUKAIKF
# ++18aEssX8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP8WCIhFRD
# DNdNuDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhHhjKEHnRhZ5FfgVSx
# z5NMksHEpl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tkiVBisV39dx898Fd1
# rL2KQk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox8NpOBpG2iAg16Hgc
# sOmZzTznL0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJNAgMBAAGjggHmMIIB
# 4jAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIoxkPNDe3xGG8UzaFqF
# bVUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1Ud
# EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYD
# VR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwv
# cHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEB
# BE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB/wSBlTCB
# kjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUFBwICMDQe
# MiAdAEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEAdABlAG0AZQBuAHQA
# LiAdMA0GCSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXEDPZ2joSFvs+umzPUx
# vs8F4qn++ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgrUYJEEvu5U4zM9GAS
# inbMQEBBm9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c8pl5SpFSAK84Dxf1
# L3mBZdmptWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1Vry/+tuWO
# M7tiX5rbV0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFtw5yjojz6f32WapB4
# pm3S4Zz5Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk7Pf0v35jWSUPei45
# V3aicaoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9ddJgiCGHasFAeb73x
# 4QDf5zEHpJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zGy9iCtHLNHfS4hQEe
# gPsbiSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3yKxO2ii4sanblrKn
# QqLJzxlBTeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHXodLFVeNp
# 3lfB0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wknHNWzfjUeCLraNtvT
# X4/edIhJEqGCAs4wggI3AgEBMIH4oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBP
# cGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo3QkYxLUUzRUEtQjgw
# ODElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcG
# BSsOAwIaAxUA1C9ElrZa/BiqStHYFgMOixJeSQyggYMwgYCkfjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOL29uUwIhgPMjAy
# MDA4MzExMjExMTdaGA8yMDIwMDkwMTEyMTExN1owdzA9BgorBgEEAYRZCgQBMS8w
# LTAKAgUA4vb25QIBADAKAgEAAgIKzwIB/zAHAgEAAgIRuzAKAgUA4vhIZQIBADA2
# BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIB
# AAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAFXpX36WNf7wf69rcP14cI+ZIVE/9A4p
# fSwrJwyGKO1QPNZ8KuosyGESRwQQCo9QHnBs1ldtyHR6PiN7gfeacTkB7LUs4hLX
# fVyWty+I6gurAftZZuOfNb+LWxjxqXKULDnAozd+szUdcNXW1fGdlhIraJXx138C
# VFXM13nXgUZkMYIDDTCCAwkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAEfTiXNrAr0uB8AAAAAAR8wDQYJYIZIAWUDBAIBBQCgggFKMBoG
# CSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgraCTHG/2
# 84iffRkzBTmoYtxVzi8WwjcGFyddlJSzSEkwgfoGCyqGSIb3DQEJEAIvMYHqMIHn
# MIHkMIG9BCCqpXD3AFt/+Tv/03FY5+PR4QgtJyYHI0TVft9WwT6DpTCBmDCBgKR+
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABH04lzawK9LgfAAAA
# AAEfMCIEIPJQEEZWFmFP3kljch1KK+76sWx1RW1WRwCxui165eoPMA0GCSqGSIb3
# DQEBCwUABIIBAJH1t34OoUApay1AKd8yC3PNNoZ5Z/JAP61fpGQUpO5QPpZMkHhA
# Z+jLu3c09XD8xbuLR3iP8VFNbEreE8TCLuxtd7AyfKF8K7Lj8L+5g8bs2y3nUTBH
# oLnQYA2z5mb18P/SIhlYnKD05qA9LiGIOwHIB1MACj1oFdyHjBrG/lj3mhr4KoMx
# G3WyXlDU2to9CY3HtEbje+GTLzNLY+XOgzeTPeTyFsqx4OUsvYwe6IHkMtPrPxSm
# Vj1feLUN3Oa6taTfA6i0s95mSIKoW1uc4rS7TXMSJGARS7S1ZJhAHIYazjlnhVV9
# U5pZo4zYIvkWIkp5Kmg1fY9YmlsQKcy0f9E=
# SIG # End signature block
