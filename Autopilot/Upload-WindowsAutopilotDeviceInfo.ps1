<#PSScriptInfo
.VERSION 1.0.0
.GUID 8d3532b3-ff9f-4031-b06f-25fcab76c626
.AUTHOR NickolajA
.DESCRIPTION Gather device hash from local machine and automatically upload it to Autopilot
.COMPANYNAME SCConfigMgr
.COPYRIGHT 
.TAGS Autopilot Windows Intune
.LICENSEURI 
.PROJECTURI https://github.com/SCConfigMgr/Intune/blob/master/Autopilot/Upload-WindowsAutopilotDeviceInfo.ps1
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
#Requires -Module AzureAD
#Requires -Module PSIntuneAuth
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

.PARAMETER OrderIdentifier
    Specify the order identifier, e.g. 'Purchase<ID>'.

.EXAMPLE
    # Gather device hash from local computer and upload to Autopilot using Intune Graph API's with a given order identifier as 'AADUserDriven':
    .\Upload-WindowsAutopilotDeviceInfo.ps1 -TenantName "tenant.onmicrosoft.com" -OrderIdentifier "AADUserDriven"

.NOTES
    FileName:    Upload-WindowsAutopilotDeviceInfo.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2019-03-21
    Updated:     2019-03-21
    
    Version history:
    1.0.0 - (2019-03-21) Script created

    Required modules:
    AzureAD (Install-Module -Name AzureAD)
    PSIntuneAuth (Install-Module -Name PSIntuneAuth)    
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [parameter(Mandatory=$true, HelpMessage="Specify the tenant name, e.g. tenantname.onmicrosoft.com.")]
    [ValidateNotNullOrEmpty()]
    [string]$TenantName,

    [parameter(Mandatory=$false, HelpMessage="Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration (d1ddf0e4-d672-4dae-b554-9d5bdfd93547).")]
    [ValidateNotNullOrEmpty()]
    [string]$ApplicationID = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547",

    [parameter(Mandatory=$true, HelpMessage="Specify the order identifier, e.g. 'Purchase<ID>'.")]
    [ValidateNotNullOrEmpty()]
    [string]$OrderIdentifier
)
Begin {
    # Determine if the AzureAD module needs to be installed
    try {
        Write-Verbose -Message "Attempting to locate AzureAD module"
        $AzureADModule = Get-InstalledModule -Name AzureAD -ErrorAction Stop -Verbose:$false
        if ($AzureADModule -ne $null) {
            Write-Verbose -Message "AzureAD module detected, checking for latest version"
            $LatestModuleVersion = (Find-Module -Name AzureAD -ErrorAction Stop -Verbose:$false).Version
            if ($LatestModuleVersion -gt $AzureADModule.Version) {
                Write-Verbose -Message "Latest version of AzureAD module is not installed, attempting to install: $($LatestModuleVersion.ToString())"
                $UpdateModuleInvocation = Update-Module -Name AzureAD -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
            }
        }
    }
    catch [System.Exception] {
        Write-Warning -Message "Unable to detect AzureAD module, attempting to install from PSGallery"
        try {
            # Install NuGet package provider
            $PackageProvider = Install-PackageProvider -Name NuGet -Force -Verbose:$false

            # Install PSIntuneAuth module
            Install-Module -Name AzureAD -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
            Write-Verbose -Message "Successfully installed AzureAD"
        }
        catch [System.Exception] {
            Write-Warning -Message "An error occurred while attempting to install AzureAD module. Error message: $($_.Exception.Message)" ; break
        }
    }    

    # Determine if the PSIntuneAuth module needs to be installed
    try {
        Write-Verbose -Message "Attempting to locate PSIntuneAuth module"
        $PSIntuneAuthModule = Get-InstalledModule -Name PSIntuneAuth -ErrorAction Stop -Verbose:$false
        if ($PSIntuneAuthModule -ne $null) {
            Write-Verbose -Message "Authentication module detected, checking for latest version"
            $LatestModuleVersion = (Find-Module -Name PSIntuneAuth -ErrorAction Stop -Verbose:$false).Version
            if ($LatestModuleVersion -gt $PSIntuneAuthModule.Version) {
                Write-Verbose -Message "Latest version of PSIntuneAuth module is not installed, attempting to install: $($LatestModuleVersion.ToString())"
                $UpdateModuleInvocation = Update-Module -Name PSIntuneAuth -Scope CurrentUser -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
            }
        }
    }
    catch [System.Exception] {
        Write-Warning -Message "Unable to detect PSIntuneAuth module, attempting to install from PSGallery"
        try {
            # Install NuGet package provider
            $PackageProvider = Install-PackageProvider -Name NuGet -Force -Verbose:$false

            # Install PSIntuneAuth module
            Install-Module -Name PSIntuneAuth -Scope AllUsers -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
            Write-Verbose -Message "Successfully installed PSIntuneAuth"
        }
        catch [System.Exception] {
            Write-Warning -Message "An error occurred while attempting to install PSIntuneAuth module. Error message: $($_.Exception.Message)" ; break
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
        $Global:AuthToken = Get-MSIntuneAuthToken -TenantName $TenantName -ClientID $ApplicationID
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
    $CimSession = New-CimSession -Verbose:$false
    $DeviceHashData = (Get-CimInstance -CimSession $CimSession -Namespace "root/cimv2/mdm/dmmap" -Class "MDM_DevDetail_Ext01" -Filter "InstanceID='Ext' AND ParentID='./DevDetail'" -Verbose:$false).DeviceHardwareData
    $SerialNumber = (Get-CimInstance -CimSession $CimSession -ClassName "Win32_BIOS" -Verbose:$false).SerialNumber

    # Construct Graph variables
    $GraphVersion = "beta"
    $GraphResource = "deviceManagement/importedWindowsAutopilotDeviceIdentities"
    $GraphURI = "https://graph.microsoft.com/$($GraphVersion)/$($GraphResource)"

    # Construct hash table for new Autopilot device identity and convert to JSON
    Write-Verbose -Message "Constructing required JSON body based upon parameter input data for device hash upload"
    $AutopilotDeviceIdentity = [ordered]@{
        '@odata.type' = '#microsoft.graph.importedWindowsAutopilotDeviceIdentity'
        'orderIdentifier' = "$($OrderIdentifier)"
        'serialNumber' = "$($SerialNumber)"
        'productKey' = ''
        'hardwareIdentifier' = "$($DeviceHashData)"
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
        $AutopilotDeviceIdentityResponse = Invoke-RestMethod -Uri $GraphURI -Headers $AuthToken -Method Post -Body $AutopilotDeviceIdentityJSON -ContentType "application/json" -ErrorAction Stop -Verbose:$false
        $AutopilotDeviceIdentityResponse
    }
    catch [System.Exception] {
        # Construct stream reader for reading the response body from API call
        $ResponseBody = Get-ErrorResponseBody -Exception $_.Exception

        # Handle response output and error message
        Write-Output -InputObject "Response content:`n$ResponseBody"
        Write-Warning -Message "Failed to upload hardware hash. Request to $($GraphURI) failed with HTTP Status $($_.Exception.Response.StatusCode) and description: $($_.Exception.Response.StatusDescription)"
    }

    try {
        # Call Graph API and post Autopilot devices sync command
        Write-Verbose -Message "Attempting to perform a sync action in Autopilot"
        $GraphResource = "deviceManagement/windowsAutopilotSettings/sync"
        $GraphURI = "https://graph.microsoft.com/$($GraphVersion)/$($GraphResource)"
        (Invoke-RestMethod -Uri $GraphURI -Headers $AuthToken -Method Post -ErrorAction Stop -Verbose:$false).Value
    }
    catch [System.Exception] {
        # Construct stream reader for reading the response body from API call
        $ResponseBody = Get-ErrorResponseBody -Exception $_.Exception

        # Handle response output and error message
        Write-Output -InputObject "Response content:`n$ResponseBody"
        Write-Warning -Message "Request to $GraphURI failed with HTTP Status $($_.Exception.Response.StatusCode) and description: $($_.Exception.Response.StatusDescription)"
    }    
}