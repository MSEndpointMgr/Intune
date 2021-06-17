<#PSScriptInfo
.VERSION 1.0.0
.GUID c30dcb72-e391-49ae-ad06-e5438b8c72a1
.AUTHOR NickolajA
.DESCRIPTION Validate that the configured Azure AD device record for all Autopilot device identities exist in Azure AD.
.COMPANYNAME MSEndpointMgr
.COPYRIGHT 
.TAGS AzureAD Autopilot Windows Intune
.LICENSEURI 
.PROJECTURI https://github.com/MSEndpointMgr/Intune/blob/master/Autopilot/Test-AutopilotAzureADDeviceAssociation.ps1
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
#Requires -Module MSGraphRequest
#Requires -Module MSAL.PS
<#
.SYNOPSIS
    Validate that the configured Azure AD device record for all Autopilot device identities exist in Azure AD.

.DESCRIPTION
    This script will retrieve all Autopilot identities and foreach validate if the given Azure AD device record that's 
    currently associated actually exist in Azure AD.

.PARAMETER TenantID
    Specify the tenant name or ID, e.g. tenant.onmicrosoft.com or <GUID>.

.EXAMPLE
    .\Test-AutopilotAzureADDeviceAssociation.ps1 -TenantID "tenantname.onmicrosoft.com"

.NOTES
    FileName:    Test-AutopilotAzureADDeviceAssociation.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2021-05-06
    Updated:     2021-05-06

    Version history:
    1.0.0 - (2021-05-06) Script created
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [parameter(Mandatory = $true, HelpMessage = "Specify the tenant name or ID, e.g. tenant.onmicrosoft.com or <GUID>.")]
    [ValidateNotNullOrEmpty()]
    [string]$TenantID
)
Process {
    # Functions
    function Get-AutopilotDevice {
        <#
        .SYNOPSIS
            Retrieve all Autopilot device identities.
            
        .DESCRIPTION
            Retrieve all Autopilot device identities.
            
        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2021-01-27
            Updated:     2021-01-27

            Version history:
            1.0.0 - (2021-01-27) Function created
        #>    
        Process {
            # Retrieve all Windows Autopilot device identities
            $ResourceURI = "deviceManagement/windowsAutopilotDeviceIdentities"
            $GraphResponse = Invoke-MSGraphOperation -Get -APIVersion "Beta" -Resource $ResourceURI

            # Handle return response
            return $GraphResponse
        }
    }

    function Get-AzureADDeviceRecord {
        <#
        .SYNOPSIS
            Retrieve an Azure AD device record.
            
        .DESCRIPTION
            Retrieve an Azure AD device record.

        .PARAMETER DeviceId
            Specify the Device ID of the Azure AD device record.
            
        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2021-05-05
            Updated:     2021-05-05

            Version history:
            1.0.0 - (2021-05-05) Function created
        #> 
        param(
            [parameter(Mandatory = $true, HelpMessage = "Specify the Device ID of the Azure AD device record.")]
            [ValidateNotNullOrEmpty()]
            [string]$DeviceId
        )   
        Process {
            # Retrieve all Windows Autopilot device identities
            $ResourceURI = "devices?`$filter=deviceId eq '$($DeviceId)'"
            $GraphResponse = (Invoke-MSGraphOperation -Get -APIVersion "v1.0" -Resource $ResourceURI).value

            # Handle return response
            return $GraphResponse
        }
    }

    # Get access token
    $AccessToken = Get-AccessToken -TenantID $TenantID

    # Construct array list for all Autopilot device identities with broken associations
    $AutopilotDeviceList = New-Object -TypeName "System.Collections.ArrayList"

    # Gather Autopilot device details
    Write-Verbose -Message "Attempting to retrieve all Autopilot device identities, this could take some time"
    $AutopilotDevices = Get-AutopilotDevice

    # Measure detected Autopilot identities count
    $AutopilotIdentitiesCount = ($AutopilotDevices | Measure-Object).Count

    if ($AutopilotDevices -ne $null) {
        Write-Verbose -Message "Detected count of Autopilot identities: $($AutopilotIdentitiesCount)"

        # Construct and start a timer for output
        $Timer = [System.Diagnostics.Stopwatch]::StartNew()
        $AutopilotIdentitiesCurrentCount = 0
        $SecondsCount = 0

        # Process each Autopilot device identity
        foreach ($AutopilotDevice in $AutopilotDevices) {
            # Increase current progress count
            $AutopilotIdentitiesCurrentCount++

            # Handle output count for progress visibility
            if ([math]::Round($Timer.Elapsed.TotalSeconds) -gt ($SecondsCount + 30)) {
                # Increase minutes count for next output frequence
                $SecondsCount = [math]::Round($Timer.Elapsed.TotalSeconds)

                # Write output every 30 seconds
                Write-Verbose -Message "Elapsed time: $($Timer.Elapsed.Hours) hour $($Timer.Elapsed.Minutes) min $($Timer.Elapsed.Seconds) seconds"
                Write-Verbose -Message "Progress count: $($AutopilotIdentitiesCurrentCount) / $($AutopilotIdentitiesCount)"
                Write-Verbose -Message "Detected devices: $($AutopilotDeviceList.Count)"
            }

            # Handle access token refresh if required
            $AccessTokenRenew = Test-AccessToken
            if ($AccessTokenRenew -eq $false) {
                $AccessToken = Get-AccessToken -TenantID $TenantID -Refresh
            }

            # Get Azure AD device record for associated device based on what's set for the Autopilot identity
            $AzureADDevice = Get-AzureADDeviceRecord -DeviceId $AutopilotDevice.azureAdDeviceId
            if ($AzureADDevice -eq $null) {
                # Construct custom object for output
                $PSObject = [PSCustomObject]@{
                    Id = $AutopilotDevice.id
                    SerialNumber = $AutopilotDevice.serialNumber
                    Model = $AutopilotDevice.model
                    Manufacturer = $AutopilotDevice.manufacturer
                }
                $AutopilotDeviceList.Add($PSObject) | Out-Null
            }
        }

        # Handle output at script completion
        Write-Verbose -Message "Successfully detected a total of '$($AutopilotDeviceList.Count)' Autopilot identities with a broken Azure AD device association"
        Write-Output -InputObject $AutopilotDeviceList
    }
    else {
        Write-Warning -Message "Could not detect any Autopilot device identities"
    }
}