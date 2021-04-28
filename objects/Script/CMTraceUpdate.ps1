<# Update CMTrace to Latest Version on Client #>

#----------------------------------------------------------------------------------------------------------
#
#                                          Parameter Declarations
#
#----------------------------------------------------------------------------------------------------------

Param(
# File share to store logs, the maximum length is 150 since the script would create sub folders and files 
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
    $LogPath = "$Env:SystemDrive\CMTraceUpdateLog"
}
else
{
    Write-Verbose "Validating path length no more than 150: $LogPath"
    $LogPath = $LogPath.Trim().TrimEnd('\')
    if($LogPath.Length -gt 150)
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
#                                          Variables
#
#----------------------------------------------------------------------------------------------------------
$global:timeStart=Get-Date
$global:timeStartString=$global:timeStart.ToString("yy_MM_dd_HH_mm_ss")
$global:errorCount = 0
$regKey = "Microsoft.PowerShell.Core\Registry::HKLM\SOFTWARE\Microsoft\sms\Client\Configuration\Client Properties"
$regValue = "Local SMS Path"
$fileName = "CMTrace.exe"
$procName = $fileName.Replace(".exe", "")
$baselineFile = $null
$expectedVersion = $null
$clientInstallationPath = $null
$hasOldFile = $false
$oldFilePaths = New-Object Collections.Generic.List[String]

#----------------------------------------------------------------------------------------------------------------
#
#                                                   Main
#
#----------------------------------------------------------------------------------------------------------------

$main = {
  Try
  {
    # Create the log file if logMode requires logging to file.
    CreateLogFile

    Log "Starting CMTraceUpdate script"
    Log "UTC DateTime: $global:utcDate"

    #
    # Get client installation path from HKLM\SOFTWARE\Microsoft\sms\Client\Configuration\Client Properties\Local SMS Path
    #
    $regProperty = Get-ItemProperty -Path $regKey

    if($regProperty -ne $null)
    {
      $clientInstallationPath = $regProperty.$regValue
    }
    else
    {
      Log "Failed to access reg key '$regKey' to get client installation path." "Error"
    }

    #
    # Get the latest cmtrace file as baseline under the client installation path
    #
    if($clientInstallationPath -ne $null)
    {
      $baselineFile = Get-Childitem –Path "$clientInstallationPath\$fileName" -File

      if($baselineFile -ne $null)
      {
        $expectedVersion = [System.Version]$baselineFile.VersionInfo.FileVersion
      }
      else
      {
        Log "Failed to get baseline file $fileName in $clientInstallationPath" "Error"
      }
    }
    else
    {
      Log "Failed to access value '$regValue' in reg key'$regKey' to get client installation path." "Error"
    }

    #
    # Search in whole file system to catch any low version cmtrace.exe
    #
    if($expectedVersion -ne $null)
    {
      Log "Searching $fileName which version lower than $expectedVersion ..."

      foreach($drv in Get-PSDrive -PSProvider "FileSystem")
      {
        $file = Get-Childitem –Path $drv.Root -Filter $fileName -File -Recurse -ErrorAction Ignore -WarningAction Ignore | Where-Object { [System.Version]$_.VersionInfo.ProductVersion -lt $expectedVersion }
    
        if($file -ne $null)
        {
          foreach($f in $file)
          {
            $fileVersion = $f.VersionInfo.ProductVersion
            Log "Found '$f' in lower version: $fileVersion"
            $oldFilePaths.Add($f.FullName)
          }

          $hasOldFile = $true
        }
      }
    }
    else
    {
      Log "Failed to get expected version from baseline file $fileName" "Error"
    }

    #----------------------------Remediation----------------------------------------------------------

    #
    # If there is low version cmtrace file, we would upgrade it to latest
    #
    if($hasOldFile -eq $true)
    {
      Log "Starting remediation for lower version $fileName"

      if($baselineFile -ne $null)
      {
        foreach($path in $oldFilePaths)
        {
          #
          # Trying to find and kill process of the low version cmtrace
          #
          Write-Verbose "Trying to get running process of $path ..."
          $proc = Get-Process -Name $procName -ErrorAction SilentlyContinue | Where-Object {$_.path -eq $path }
          if($proc -ne $null)
          {
            foreach($pc in $proc)
            {
              $procPath = $pc.Path

              try 
              {
                Write-Verbose "Trying to kill a process of $procPath"
                $pc.Kill();         
              }
              catch
              {
                Write-Verbose "Failed to kill a process of $procPath" "Warning"
              }
            }

            $chkProc =Get-Process -Name $procName -ErrorAction SilentlyContinue | Where-Object {$_.path -eq $path }
            if($chkProc -ne $null)
            {
              Write-Verbose "There are still running processes of $procPath" "Warning"
            }
            else
            {
              Write-Verbose "Killed all processes of $procPath"
            }
          }
          else
          {
            Write-Verbose "There is no running process of $path"
          }

          #
          # Trying to replace the low version cmtrace with the latest one
          #
          Write-Verbose "Trying to upgrade $path to latest..."
          Copy-Item -Path $baselineFile.PSPath -Destination $path -ErrorAction SilentlyContinue

          $chkFile = Get-Childitem –Path $path -File -ErrorAction Ignore | Where-Object { [System.Version]$_.VersionInfo.ProductVersion -lt $expectedVersion }
          if($chkFile -ne $null)
          {
            Log "Failed to upgrade $path" "Warning"
          }
          else
          {
            Log "Upgraded $path"
          }
        }

        Log "Remediation completed."
      }
      else
      {
        Log "Baseline file missed." "Error"
      }
    }
    else
    {
      Log "No need remediation"
    }

    if($global:errorCount -eq 0)
    {
      Log "Script finished successfully"
      Exit(0)
    }
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
function CreateLogFile
{
    Write-Verbose "Creating output folder"
    $timeStart=Get-Date
    $timeStartString=$timeStart.ToString("yy_MM_dd_HH_mm_ss")
    $logFolderName = "CMTraceUpdate_" + $timeStartString
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
            $message = "Error when logging to consloe."
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
            $message = "Error when logging to consloe and file."
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
            $message = "Error when logging to consloe and file."
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBXQdvyeEE0wDs2
# kixevJYPfa/X4j7ulfG9l1tTE1BGGaCCDYEwggX/MIID56ADAgECAhMzAAAB32vw
# LpKnSrTQAAAAAAHfMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ1WhcNMjExMjAyMjEzMTQ1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC2uxlZEACjqfHkuFyoCwfL25ofI9DZWKt4wEj3JBQ48GPt1UsDv834CcoUUPMn
# s/6CtPoaQ4Thy/kbOOg/zJAnrJeiMQqRe2Lsdb/NSI2gXXX9lad1/yPUDOXo4GNw
# PjXq1JZi+HZV91bUr6ZjzePj1g+bepsqd/HC1XScj0fT3aAxLRykJSzExEBmU9eS
# yuOwUuq+CriudQtWGMdJU650v/KmzfM46Y6lo/MCnnpvz3zEL7PMdUdwqj/nYhGG
# 3UVILxX7tAdMbz7LN+6WOIpT1A41rwaoOVnv+8Ua94HwhjZmu1S73yeV7RZZNxoh
# EegJi9YYssXa7UZUUkCCA+KnAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUOPbML8IdkNGtCfMmVPtvI6VZ8+Mw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDYzMDA5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAnnqH
# tDyYUFaVAkvAK0eqq6nhoL95SZQu3RnpZ7tdQ89QR3++7A+4hrr7V4xxmkB5BObS
# 0YK+MALE02atjwWgPdpYQ68WdLGroJZHkbZdgERG+7tETFl3aKF4KpoSaGOskZXp
# TPnCaMo2PXoAMVMGpsQEQswimZq3IQ3nRQfBlJ0PoMMcN/+Pks8ZTL1BoPYsJpok
# t6cql59q6CypZYIwgyJ892HpttybHKg1ZtQLUlSXccRMlugPgEcNZJagPEgPYni4
# b11snjRAgf0dyQ0zI9aLXqTxWUU5pCIFiPT0b2wsxzRqCtyGqpkGM8P9GazO8eao
# mVItCYBcJSByBx/pS0cSYwBBHAZxJODUqxSXoSGDvmTfqUJXntnWkL4okok1FiCD
# Z4jpyXOQunb6egIXvkgQ7jb2uO26Ow0m8RwleDvhOMrnHsupiOPbozKroSa6paFt
# VSh89abUSooR8QdZciemmoFhcWkEwFg4spzvYNP4nIs193261WyTaRMZoceGun7G
# CT2Rl653uUj+F+g94c63AhzSq4khdL4HlFIP2ePv29smfUnHtGq6yYFDLnT0q/Y+
# Di3jwloF8EWkkHRtSuXlFUbTmwr/lDDgbpZiKhLS7CBTDj32I0L5i532+uHczw82
# oZDmYmYmIUSMbZOgS65h797rj5JJ6OkeEUJoAVwwggd6MIIFYqADAgECAgphDpDS
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
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgLH4UBfW7
# m/V8UzYwLAuHCiBc1ms3L6cn/2IlJEjyf1swQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQCceoCLSLJw0yafR1wtixj1+S9qJTPHF02wQM8S+r8/
# a+Z6xyHescoZnwM0fVSpPh/tRy6ioUVHeVDLPs8U5Sqmw7GQB1jdeNNt2lTyvVqK
# NiylELvxPv08dWzQZ9BLTF2IfX7xXxg+xbTXZSm3JLXOrDHaNUzjRxUjxPjAqQ6M
# 3UwZ6QVjtLInUyq36eOdjXS3+bkwK7j18CttXTITJY1lwISP2HYarL5PbfgbBJ9J
# e1rPMYIqeySzakkiUBwcsYXm5NWDchep651Mm3ckyoM6qoeD4bknXUCd3v2MCbVD
# NXH2eYzam5TLMZN+1otNID6dHkr+pb/Z/7KlarTdbsryoYIS5TCCEuEGCisGAQQB
# gjcDAwExghLRMIISzQYJKoZIhvcNAQcCoIISvjCCEroCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIIZGnAm8V1Pz5VrbNPZqZv3QPrmEIcrU1cWtJyAw
# cT8oAgZgYyOvuecYEzIwMjEwNDI1MDQzNTMxLjk2OFowBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjNCQkQtRTMzOC1FOUExMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIOPDCCBPEwggPZoAMCAQICEzMAAAFPZC519noDWoMAAAAAAU8w
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MjAxMTEyMTgyNjAyWhcNMjIwMjExMTgyNjAyWjCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0JCRC1FMzM4LUU5
# QTExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCjFHe1ZPZoKOwb5P3E7/tIHSavithf
# Mf8sJodyJbULIHlrUnaxSeCxNyFKB3pLcWOdyQDyJCTRbqRqmC0bSeD1DfT1PIv6
# /A6HDsZ3Ng7z3QlDg/DElXlfQaSvp32dfT9U742O0fvJC7sATEenBaz7fhTXQilw
# juHVfU5WqbSxHnTciFWpmAbJc9BPuP+7pYXMUpS3awGJZk9cBFfVc9C1rA5cqT4C
# uIEMSw4HUQsIm4EFbDTMBSPR/hpLSVgoI3up1TTOp76o9gGtL+nQcVfVTNE2ffsz
# pHxECA/Fs7XrwcbEFe002RHva0WBPbikZaZeHQEHDi2EZ9MlsjytP2r9AgMBAAGj
# ggEbMIIBFzAdBgNVHQ4EFgQUjo3u1xYGEH5Vk781wmTxMV/yoKAwHwYDVR0jBBgw
# FoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDov
# L2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENB
# XzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAx
# MC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDAN
# BgkqhkiG9w0BAQsFAAOCAQEAPDHkqxxc5DIOesrRezybooFfl4QxGmNCa6Ru2+vg
# L27C6wZB0R58kBniWl5AmjLovJlKvJeJJPaeYhU7wVHeXwxwf+kRkQYuGFF2nRkI
# P8dl2ob6Ad4yb0weD9o6X5hSb6SaQCyD/YjoSlD5AgA4KCnsm2Auva7zBm5EIh6f
# ie5LOqM3rnm/OAl2UOnNbffF5sg6vaFy48PB1FMJUZ4gr3T2y8kEXmsE97+2ZjjJ
# UbcE1r+vs+b1v6xZwef1dctBTUWkW1v/a/7WqMXtNIjrOHjCwssHhwAfulF7ms4F
# O1v/PYPOusHG4qbKvMRhxA4MnoYD7h1hyScKdxvUrN3luTCCBnEwggRZoAMCAQIC
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
# cGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozQkJELUUzMzgtRTlB
# MTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcG
# BSsOAwIaAxUA6CIM4qrSBzqcjNeHUndeKXgqq+iggYMwgYCkfjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOQvP8UwIhgPMjAy
# MTA0MjUwOTA5MjVaGA8yMDIxMDQyNjA5MDkyNVowdzA9BgorBgEEAYRZCgQBMS8w
# LTAKAgUA5C8/xQIBADAKAgEAAgIhuAIB/zAHAgEAAgISYTAKAgUA5DCRRQIBADA2
# BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIB
# AAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAJBxLgJohD9Id/C4ZC97WXZKLfjjoApz
# MarDkZuts0WvVMZwnRVtMIiHAxfsWSJwOCdrnDgJzNQJN1rlDcsK+xmKO8TmmaA9
# YueKZDSW+UtzQ5KWLWTvp313ftGulQ8S1U2gJy0dlGF7HrJ/dOKnMWz1W9ZyWRkw
# edLgyK/lH5R7MYIDDTCCAwkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAFPZC519noDWoMAAAAAAU8wDQYJYIZIAWUDBAIBBQCgggFKMBoG
# CSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgjIzMDlmj
# 0pkKc9hZyRX5x08OPu+yul6+li6apwMXzFwwgfoGCyqGSIb3DQEJEAIvMYHqMIHn
# MIHkMIG9BCAAZyYQ9oJYpMDGciFtGHJ6Q8+q+HltMI0QxcbBALU3AjCBmDCBgKR+
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABT2QudfZ6A1qDAAAA
# AAFPMCIEICj7TXSoR/Y7xAErVNEYIa/rLoYBGbvbK+wOtf/Q1Vf9MA0GCSqGSIb3
# DQEBCwUABIIBACn5X0VDUk/1iVPHxJiPbFO+eQT6H7P5Ep0wlhWsGgYcb1+Bv8lG
# XORQPMmQZS98b5CfP8ySLCeUp+vpKNAgo6eS8N2JUXeSettvaK1cRc2OZANsF1+3
# YkbVuUmJ8dJVSL8qdbKbU1BIbKVCabnEpHvLHeGj6k9e8nqOYCG6DHrZlbIUr/b1
# 6Laf4jWw8vSPtN7xjl61RUHHMMyCqpriwF4xQKJnW7lEV5R2ezYwQTKAUgwxEGiw
# M9OzxSO1Ms44x4znSjHs3//EDRlvKKJRGWPIamTum1hH9QJW5RYLnxe8Wh/ChcnG
# VSVgWeh3dxbQlUcenFBysLrFNmbUc7YOKzw=
# SIG # End signature block
