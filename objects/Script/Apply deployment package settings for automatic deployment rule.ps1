<# Apply-ADRDeploymentPackageSettings #>

#=============================================
# START SCRIPT
#=============================================
param
(
[parameter(Mandatory = $true)]
[ValidateNotNullOrEmpty()]
[ValidateLength(1,256)]
[string]$sourceADRName,

[parameter(Mandatory = $true)]
[ValidateNotNullOrEmpty()]
[ValidateLength(1,256)]
[string]$targetADRName
)

Try {
       # Source ADR that already has the needed deployment package. You may need to create one if it doesn’t exist.
       $sourceADR = Get-CMSoftwareUpdateAutoDeploymentRule -Name $sourceADRName

       # Target ADR that will be updated to use the source ADR’s deployment package. Typically, this is the ADR that used the “No deployment package” option. 
       $targetADR = Get-CMSoftwareUpdateAutoDeploymentRule -Name $targetADRName

       # Apply the deployment package settings
       $targetADR.ContentTemplate = $sourceADR.ContentTemplate

       # Update the wmi object
       $targetADR.Put()
}
Catch{
       $exceptionDetails = "Exception: " + $_.Exception.Message + "HResult: " + $_.Exception.HResult
       Write-Error "Failed to apply ADR deployment package settings: $exceptionDetails"
}
#=============================================
# END SCRIPT
#=============================================

