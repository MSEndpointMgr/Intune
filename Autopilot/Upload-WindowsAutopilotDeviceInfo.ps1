<#PSScriptInfo
.VERSION 1.2.0
.GUID 8d3532b3-ff9f-4031-b06f-25fcab76c626
.AUTHOR NickolajA
.DESCRIPTION Gather device hash from local machine and automatically upload it to Autopilot
.COMPANYNAME MSEndpointMgr.com
.COPYRIGHT 
.TAGS Autopilot Windows Intune
.LICENSEURI 
.PROJECTURI https://github.com/MSEndpointMgr/Intune/blob/master/Autopilot/Upload-WindowsAutopilotDeviceInfo.ps1
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
#Requires -Module MSAL.PS
#Requires -Module MSGraphRequest
<#
.SYNOPSIS
    Gather device hash from local machine and automatically upload it to Autopilot.

.DESCRIPTION
    This script automatically gathers the device hash, serial number, manufacturer and model and uploads that data into Autopilot.
    Authentication is required within this script and required permissions for creating Autopilot device identities are needed.

.PARAMETER TenantName
    Specify the tenant name, e.g. tenantname.onmicrosoft.com.

.PARAMETER ApplicationID
    Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration (d1ddf0e4-d672-4dae-b554-9d5bdfd93547).

.PARAMETER GroupTag
    Specify the group tag to easier differentiate Autopilot devices, e.g. 'ABCSales'.

.PARAMETER UserPrincipalName
    Specify the primary user principal name, e.g. 'firstname.lastname@domain.com'.

.EXAMPLE
    # Gather device hash from local computer and upload to Autopilot using Intune Graph API's:
    .\Upload-WindowsAutopilotDeviceInfo.ps1 -TenantName "tenant.onmicrosoft.com"

    # Gather device hash from local computer and upload to Autopilot using Intune Graph API's with a given group tag as 'AADUserDriven':
    .\Upload-WindowsAutopilotDeviceInfo.ps1 -TenantName "tenant.onmicrosoft.com" -GroupTag "AADUserDriven"

    # Gather device hash from local computer and upload to Autopilot using Intune Graph API's with a given group tag as 'AADUserDriven' and 'somone@domain.com' as the assigned user:
    .\Upload-WindowsAutopilotDeviceInfo.ps1 -TenantName "tenant.onmicrosoft.com" -GroupTag "AADUserDriven" -UserPrincipalName "someone@domain.com"

.NOTES
    FileName:    Upload-WindowsAutopilotDeviceInfo.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2019-03-21
    Updated:     2023-06-03
    
    Version history:
    1.0.0 - (2019-03-21) Script created.
    1.1.0 - (2019-10-29) Added support for specifying the primary user assigned to the uploaded Autopilot device as well as renaming the OrderIdentifier parameter to GroupTag. Thanks to @Stgrdk for his contributions. Switched from Get-CimSession to Get-WmiObject to get device details from WMI.
    1.1.1 - (2021-03-24) Script now uses the groupTag property instead of the depcreated OrderIdentifier property. Also removed the code section that attempted to perform an Autopilot sync operation
    1.1.2 - (2021-03-24) Corrected a spelling mistake of 'GroupTag' to 'groupTag'
    1.2.0 - (2023-06-03) Switched from AzureAD and PSIntuneAuth modules to MSAL.PS and MSGraphRequest
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [parameter(Mandatory=$true, HelpMessage="Specify the tenant name, e.g. tenantname.onmicrosoft.com.")]
    [ValidateNotNullOrEmpty()]
    [string]$TenantName,

    [parameter(Mandatory=$false, HelpMessage="Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration (d1ddf0e4-d672-4dae-b554-9d5bdfd93547).")]
    [ValidateNotNullOrEmpty()]
    [string]$ApplicationID = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547",

    [parameter(Mandatory=$false, HelpMessage="Specify the group tag to easier differentiate Autopilot devices, e.g. 'ABCSales'.")]
    [ValidateNotNullOrEmpty()]
    [string]$GroupTag,

    [parameter(Mandatory=$false, HelpMessage="Specify the primary user principal name, e.g. 'firstname.lastname@domain.com'.")]
    [ValidateNotNullOrEmpty()]
    [string]$UserPrincipalName
)
Begin {
    # Ensure required modules are installed and running the latest version
    $Modules = @("MSAL.PS", "MSGraphRequest")
    foreach ($Module in $Modules) {
        try {
            Write-Verbose -Message "Attempting to locate $($Module) module"
            $ModuleItem = Get-InstalledModule -Name $Module -ErrorAction Stop -Verbose:$false
            if ($ModuleItem -ne $null) {
                Write-Verbose -Message "$($Module) module detected, checking for latest version"
                $LatestModuleItemVersion = (Find-Module -Name $Module -ErrorAction Stop -Verbose:$false).Version
                if ($LatestModuleItemVersion -gt $ModuleItem.Version) {
                    Write-Verbose -Message "Latest version of $($Module) module is not installed, attempting to install: $($LatestModuleVersion.ToString())"
                    $UpdateModuleInvocation = Update-Module -Name $Module -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
                }
            }
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to detect MSAL.PS module, attempting to install from PSGallery"
            try {
                # Install NuGet package provider
                $PackageProvider = Install-PackageProvider -Name "NuGet" -Force -Verbose:$false
    
                # Install MSAL.PS module
                Install-Module -Name $Module -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
                Write-Verbose -Message "Successfully installed $($Module)"
            }
            catch [System.Exception] {
                Write-Warning -Message "An error occurred while attempting to install $($Module) module. Error message: $($_.Exception.Message)" ; break
            }
        }
    }

    # Check if token has expired and if, request a new
    Write-Verbose -Message "Checking for existing authentication token"
    if ($Global:AuthToken -ne $null) {
        $UTCDateTime = (Get-Date).ToUniversalTime()
        $TokenExpireMins = ($Global:AuthToken.ExpiresOn.datetime - $UTCDateTime).Minutes
        Write-Verbose -Message "Current authentication token expires in (minutes): $($TokenExpireMins)"
        if ($TokenExpireMins -le 0) {
            Write-Verbose -Message "Existing token found but has expired, requesting a new token"
            $Global:AuthToken = Get-MSIntuneAuthToken -TenantName $TenantName -ClientID $ApplicationID
        }
        else {
            Write-Verbose -Message "Existing authentication token has not expired, will not request a new token"
        }
    }
    else {
        Write-Verbose -Message "Authentication token does not exist, requesting a new token"
        $AuthToken = Get-AccessToken -TenantID $TenantName -ClientID $ApplicationID
    }
}
Process {
    # Functions
    function Get-ErrorResponseBody {
        param(   
            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [System.Exception]$Exception
        )

        # Read the error stream
        $ErrorResponseStream = $Exception.Response.GetResponseStream()
        $StreamReader = New-Object System.IO.StreamReader($ErrorResponseStream)
        $StreamReader.BaseStream.Position = 0
        $StreamReader.DiscardBufferedData()
        $ResponseBody = $StreamReader.ReadToEnd();

        # Handle return object
        return $ResponseBody
    }

    # Gather device hash data
    Write-Verbose -Message "Gather device hash data from local machine"
    $DeviceHashData = (Get-WmiObject -Namespace "root/cimv2/mdm/dmmap" -Class "MDM_DevDetail_Ext01" -Filter "InstanceID='Ext' AND ParentID='./DevDetail'" -Verbose:$false).DeviceHardwareData
    $SerialNumber = (Get-WmiObject -Class "Win32_BIOS" -Verbose:$false).SerialNumber
    $ProductKey = (Get-WmiObject -Class "SoftwareLicensingService" -Verbose:$false).OA3xOriginalProductKey

    # Construct Graph variables
    $GraphResource = "deviceManagement/importedWindowsAutopilotDeviceIdentities"

    # Construct hash table for new Autopilot device identity and convert to JSON
    Write-Verbose -Message "Constructing required JSON body based upon parameter input data for device hash upload"
    $AutopilotDeviceIdentity = [ordered]@{
        '@odata.type' = '#microsoft.graph.importedWindowsAutopilotDeviceIdentity'
        'groupTag' = if ($GroupTag) { "$($GroupTag)" } else { "" }
        'serialNumber' = "$($SerialNumber)"
        'productKey' = if ($ProductKey) { "$($ProductKey)" } else { "" }
        'hardwareIdentifier' = "$($DeviceHashData)"
        'assignedUserPrincipalName' = if ($UserPrincipalName) { "$($UserPrincipalName)" } else { "" }
        'state' = @{
            '@odata.type' = 'microsoft.graph.importedWindowsAutopilotDeviceIdentityState'
            'deviceImportStatus' = 'pending'
            'deviceRegistrationId' = ''
            'deviceErrorCode' = 0
            'deviceErrorName' = ''
        }
    }
    $AutopilotDeviceIdentityJSON = $AutopilotDeviceIdentity | ConvertTo-Json

    try {
        # Call Graph API and post JSON data for new Autopilot device identity
        Write-Verbose -Message "Attempting to post data for hardware hash upload"
        Invoke-MSGraphOperation -Post -APIVersion "Beta" -Resource $GraphResource -Body $AutopilotDeviceIdentityJSON -ErrorAction "Stop"
    }
    catch [System.Exception] {
        # Construct stream reader for reading the response body from API call
        $ResponseBody = Get-ErrorResponseBody -Exception $_.Exception

        # Handle response output and error message
        Write-Output -InputObject "Response content:`n$ResponseBody"
        Write-Warning -Message "Failed to upload hardware hash. Request failed with HTTP Status $($_.Exception.Response.StatusCode) and description: $($_.Exception.Response.StatusDescription)"
    }  
}