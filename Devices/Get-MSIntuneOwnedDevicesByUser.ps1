<#
.SYNOPSIS
    Get owned devices for a specific user in Microsoft Intune

.DESCRIPTION
    Get owned devices for a specific user in Microsoft Intune

.PARAMETER UserName
    Define a user name in the user principal name format, e.g. user@domain.com.

.PARAMETER TenantName
    A tenant name should be provided in the following format: tenantname.onmicrosoft.com.

.PARAMETER ApplicationID
    Application ID of an Azure AD native application registration.

.EXAMPLE
    .\Get-OwnedDevicesByUser.ps1 -UserName user@domain.com

.NOTES
    FileName:    Get-OwnedDevicesByUser.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2016-10-25
    Updated:     2016-10-25
    
    Version history:
    1.0.0 - (2016-10-25) Script created
#>
[CmdletBinding(SupportsShouldProcess=$true)]
[OutputType('MSIntuneGraph.OwnedDevices')]
param(
    [parameter(Mandatory=$true, HelpMessage="Specify the tenant name, e.g. domain.onmicrosoft.com.")]
    [ValidateNotNullOrEmpty()]
    [string]$TenantName,

    [parameter(Mandatory=$true, HelpMessage="Define a user name in the user principal name format, e.g. user@domain.com.")]
    [ValidateNotNullOrEmpty()]
    [string]$UserName,

    [parameter(Mandatory=$false, HelpMessage="Specify the Application ID of the app registration in Azure AD. When no parameter is manually passed, script will attempt to use well known Microsoft Intune PowerShell app registration.")]
    [ValidateNotNullOrEmpty()]
    [string]$ApplicationID = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
)
Begin {
    # Determine if the PSIntuneAuth module needs to be installed
    try {
        Write-Verbose -Message "Attempting to locate PSIntuneAuth module"
        $PSIntuneAuthModule = Get-InstalledModule -Name PSIntuneAuth -ErrorAction Stop
        if ($PSIntuneAuthModule -ne $null) {
            Write-Verbose -Message "Authentication module detected, checking for latest version"
            $LatestModuleVersion = (Find-Module -Name PSIntuneAuth -ErrorAction Stop -Verbose:$false).Version
            if ($LatestModuleVersion -gt $PSIntuneAuthModule.Version) {
                Write-Verbose -Message "Latest version of PSIntuneAuth module is not installed, attempting to install: $($LatestModuleVersion.ToString())"
                $UpdateModuleInvocation = Update-Module -Name PSIntuneAuth -Scope CurrentUser -Force -ErrorAction Stop -Confirm:$false
            }
        }
    }
    catch [System.Exception] {
        Write-Warning -Message "Unable to detect PSIntuneAuth module, attempting to install from PSGallery"
        try {
            Install-Module -Name PSIntuneAuth -Scope AllUsers -Force -ErrorAction Stop -Confirm:$false
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
    # Define resources
    $GraphURI = "https://graph.microsoft.com/beta/users/$($UserName)/ownedDevices"

    # Invoke REST method
    $OwnedDevices = (Invoke-RestMethod -Uri $GraphURI -Headers $AuthToken -Method Get).Value

    # Construct custom PS object for output
    if ($OwnedDevices -ne $null) {
        foreach ($Object in $OwnedDevices) {
            # Create MSIntuneGraph.OwnedDevices custom object
            $PSObject = [PSCustomObject]@{
                PSTypeName = "MSIntuneGraph.OwnedDevices"
                DeviceName = $Object.displayName
                Id = $Object.deviceId
                Compliant = $Object.isCompliant
                Managed = $Object.isManaged
                OS = $Object.operatingSystem
                OSVersion = $Object.operatingSystemVersion
            }

            # Output object to pipeline
            Write-Output -InputObject $PSObject
        }
    }
}