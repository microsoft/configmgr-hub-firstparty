<#
.SYNOPSIS
   Disables any enabled maintenance task, or enables tasks that are disabled.
.DESCRIPTION
   Meant to be run before and after ConfigMgr upgrade. 
   Stores the status of all maintenance tasks to the registry,
   and either disables or enables them.
.INFO
   Author: Baard Hermansen
#>

#Requires -RunAsAdministrator

# Registry key where information about tasks is stored
$registryPath = "HKLM:\SOFTWARE\Itera\MEMCM\Tasks"

# Import the ConfigMgr module 
if ($null -eq (Get-Module ConfigurationManager)) {
    Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1"  
}

# Get the site code
$siteCode = Get-PSDrive -PSProvider CMSite

# Adding PS drive if needed
if ($null -eq (Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $ProviderMachineName
}

# Connect to the site
try {
    Push-Location -Path "$($SiteCode):\"
}
catch {
    Write-Error -Message "Could not connect to ConfigMgr!"
    $Error[0]
    exit
}

# Check to see if the tasks are disabled. If so, enable them again
if ($allDisabledTasks = Get-Item -Path $registryPath -ErrorAction SilentlyContinue) {
    Write-Host "Found disabled tasks. Now enabling them..." -ForegroundColor Yellow
    foreach ($disabledTask in $allDisabledTasks.Property) {
        Write-Host -Object "`tEnabling " -ForegroundColor Yellow -NoNewline
        Write-Host -Object $disabledTask -ForegroundColor Cyan
        try {
            Set-CMSiteMaintenanceTask -Name $disabledTask -Enabled $true -ErrorAction Stop -ErrorVariable setMaint
            Remove-ItemProperty -Path $registryPath -Name $disabledTask -Force -ErrorAction Stop
        }
        catch {
            Write-Host -Object "`tFailed to enable '$disabledTask'." -ForegroundColor Red
            Write-Host -Object "`tError code: $($_)" -ForegroundColor Red
        }
    }
    # Removing registry key Tasks if it's empty
    if (-not (Get-ItemProperty -Path $registryPath)) {
        Write-Host "`n All tasks enabled." -ForegroundColor Green
        Remove-Item -Path $registryPath
    }
    else {
        Write-Host -Object "Not all tasks were enabled. Please try again." -ForegroundColor Yellow
    }
}
else {
    # Tasks are enabled, need to be disabled
    # Create registry key if not exists
    if (-not (Test-Path -Path $registryPath)) {
        New-Item -Path $registryPath -ItemType Directory -Force | Out-Null
    }
    # Getting enabled tasks
    $allEnabledTasks = Get-CMSiteMaintenanceTask | Where-Object { $_.Enabled -eq "True" } | Select-Object -Property TaskName -ExpandProperty TaskName
    Write-Host "Disabling tasks..." -ForegroundColor Yellow
    foreach ($enabledTask in $allEnabledTasks) {
        Write-Host -Object "`tDisabling " -ForegroundColor Yellow -NoNewline
        Write-Host -Object $enabledTask -ForegroundColor Cyan
        try {
            Set-CMSiteMaintenanceTask -Name $enabledTask -Enabled $false -ErrorAction Stop
            Set-ItemProperty -Path $registryPath -Name $enabledTask -Value "Disabled"
        }
        catch {
            Write-Host -Object "Could not disable task: $enabledTask" -ForegroundColor Red
        }
    }
}
