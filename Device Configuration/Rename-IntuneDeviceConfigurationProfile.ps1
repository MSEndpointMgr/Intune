<#
.SYNOPSIS
    Rename a specified string (match pattern) in Device Configuration profile display names with a new string (replace pattern).

.DESCRIPTION
    Rename a specified string (match pattern) in Device Configuration profile display names with a new string (replace pattern).

.PARAMETER TenantName
    Specify the tenant name, e.g. domain.onmicrosoft.com.

.PARAMETER Match
    Specify the match pattern as a string that's represented in the device configuration profile name and will be updated with that's specified for the Replace parameter.

.PARAMETER Replace
    Specify the replace pattern as a string that will replace what's matched in the device configuration profile name.    

.PARAMETER ApplicationID
    Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration.

.PARAMETER PromptBehavior
    Set the prompt behavior when acquiring a token.

.EXAMPLE
    # Rename all Device Configuration Profiles with a display name that matches 'Win10' with 'W10' in a tenant named 'domain.onmicrosoft.com':
    .\Rename-IntuneDeviceConfigurationProfile.ps1 -TenantName "domain.onmicrosoft.com" -Match "Win10" -Replace "W10" -Verbose

.NOTES
    FileName:    Rename-IntuneDeviceConfigurationProfile.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2019-10-15
    Updated:     2019-10-15

    Version history:
    1.0.0 - (2019-10-15) Script created

    Required modules:
    AzureAD (Install-Module -Name AzureAD)
    PSIntuneAuth (Install-Module -Name PSIntuneAuth)    
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [parameter(Mandatory = $true, HelpMessage = "Specify the tenant name, e.g. domain.onmicrosoft.com.")]
    [ValidateNotNullOrEmpty()]
    [string]$TenantName,

    [parameter(Mandatory = $true, HelpMessage = "Specify the match pattern as a string that's represented in the device configuration profile name and will be updated with that's specified for the Replace parameter.")]
    [ValidateNotNullOrEmpty()]
    [string]$Match,

    [parameter(Mandatory = $true, HelpMessage = "Specify the replace pattern as a string that will replace what's matched in the device configuration profile name.")]
    [ValidateNotNullOrEmpty()]
    [string]$Replace,

    [parameter(Mandatory = $false, HelpMessage = "Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration.")]
    [ValidateNotNullOrEmpty()]
    [string]$ApplicationID = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547",

    [parameter(Mandatory=$false, HelpMessage="Set the prompt behavior when acquiring a token.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("Auto", "Always", "Never", "RefreshSession")]
    [string]$PromptBehavior = "Auto"
)
Begin {
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
            Write-Warning -Message "An error occurred while attempting to install PSIntuneAuth module. Error message: $($_.Exception.Message)"; break
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
            $Global:AuthToken = Get-MSIntuneAuthToken -TenantName $TenantName -ClientID $ApplicationID -PromptBehavior $PromptBehavior
        }
        else {
            if ($PromptBehavior -like "Always") {
                Write-Verbose -Message "Existing authentication token has not expired but prompt behavior was set to always ask for authentication, requesting a new token"
                $Global:AuthToken = Get-MSIntuneAuthToken -TenantName $TenantName -ClientID $ApplicationID -PromptBehavior $PromptBehavior
            }
            else {
                Write-Verbose -Message "Existing authentication token has not expired, will not request a new token"
            }
        }
    }
    else {
        Write-Verbose -Message "Authentication token does not exist, requesting a new token"
        $Global:AuthToken = Get-MSIntuneAuthToken -TenantName $TenantName -ClientID $ApplicationID -PromptBehavior $PromptBehavior
    }
}
Process {
    # Functions
    function Get-ErrorResponseBody {
        param(   
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [System.Exception]$Exception
        )

        # Read the error stream
        $ErrorResponseStream = $Exception.Response.GetResponseStream()
        $StreamReader = New-Object System.IO.StreamReader($ErrorResponseStream)
        $StreamReader.BaseStream.Position = 0
        $StreamReader.DiscardBufferedData()
        $ResponseBody = $StreamReader.ReadToEnd()

        # Handle return object
        return $ResponseBody
    }

    function Invoke-IntuneGraphRequest {
        param(   
            [parameter(Mandatory = $true, ParameterSetName = "Get")]
            [parameter(ParameterSetName = "Patch")]
            [ValidateNotNullOrEmpty()]
            [string]$URI,

            [parameter(Mandatory = $true, ParameterSetName = "Patch")]
            [ValidateNotNullOrEmpty()]
            [System.Object]$Body
        )
        try {
            # Construct array list for return values
            $ResponseList = New-Object -TypeName System.Collections.ArrayList

            # Call Graph API and get JSON response
            switch ($PSCmdlet.ParameterSetName) {
                "Get" {
                    Write-Verbose -Message "Current Graph API call is using method: Get"
                    $GraphResponse = Invoke-RestMethod -Uri $URI -Headers $AuthToken -Method Get -ErrorAction Stop -Verbose:$false
                    if ($GraphResponse -ne $null) {
                        if ($GraphResponse.value -ne $null) {
                            foreach ($Response in $GraphResponse.value) {
                                $ResponseList.Add($Response) | Out-Null
                            }
                        }
                        else {
                            $ResponseList.Add($GraphResponse) | Out-Null
                        }
                    }
                }
                "Patch" {
                    Write-Verbose -Message "Current Graph API call is using method: Patch"
                    $GraphResponse = Invoke-RestMethod -Uri $URI -Headers $AuthToken -Method Patch -Body $Body -ContentType "application/json" -ErrorAction Stop -Verbose:$false
                    if ($GraphResponse -ne $null) {
                        foreach ($ResponseItem in $GraphResponse) {
                            $ResponseList.Add($ResponseItem) | Out-Null
                        }
                    }
                    else {
                        Write-Warning -Message "Response was null..."
                    }
                }
            }

            return $ResponseList
        }
        catch [System.Exception] {
            # Construct stream reader for reading the response body from API call
            $ResponseBody = Get-ErrorResponseBody -Exception $_.Exception
    
            # Handle response output and error message
            Write-Output -InputObject "Response content:`n$ResponseBody"
            Write-Warning -Message "Request to $($URI) failed with HTTP Status $($_.Exception.Response.StatusCode) and description: $($_.Exception.Response.StatusDescription)"
        }
    }

    function Get-IntuneDeviceConfigurationProfile {
        # Construct Graph variables
        $GraphVersion = "beta"
        $GraphResource = "deviceManagement/deviceConfigurations"
        $GraphURI = "https://graph.microsoft.com/$($GraphVersion)/$($GraphResource)"

        # Invoke Graph API resource call
        $GraphResponse = Invoke-IntuneGraphRequest -URI $GraphURI

        # Handle return objects from response
        return $GraphResponse
    }

    function Set-IntuneDeviceConfigurationProfileDisplayName {
        param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$DeviceConfigurationProfileID,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [System.Object]$Body
        )
        # Construct Graph variables
        $GraphVersion = "beta"
        $GraphResource = "deviceManagement/deviceConfigurations/$($DeviceConfigurationProfileID)"
        $GraphURI = "https://graph.microsoft.com/$($GraphVersion)/$($GraphResource)"

        # Invoke Graph API resource call
        $GraphResponse = Invoke-IntuneGraphRequest -URI $GraphURI -Body $Body
    }    

    # Get all device configuration profiles and process each object
    $DeviceConfigurationProfiles = Get-IntuneDeviceConfigurationProfile
    if ($DeviceConfigurationProfiles -ne $null) {
        foreach ($DeviceConfigurationProfile in $DeviceConfigurationProfiles) {
            Write-Verbose -Message "Processing current device configuration profile with name: $($DeviceConfigurationProfile.displayName)"

            if ($DeviceConfigurationProfile.displayName -match $Match) {
                Write-Verbose -Message "Match found for current device configuration profile, will attempt to rename object"

                # Construct JSON object for POST call
                $NewName = $DeviceConfigurationProfile.displayName.Replace($Match, $Replace)
                $JSONTable = @{
                    '@odata.type' = $DeviceConfigurationProfile.'@odata.type'
                    'id' = $DeviceConfigurationProfile.id
                    'displayName' = $NewName
                }
                $JSONData = $JSONTable | ConvertTo-Json
                
                # Call Graph API post operation with new display name
                Write-Verbose -Message "Attempting to rename '$($DeviceConfigurationProfile.displayName)' profile to: $($NewName)"
                Set-IntuneDeviceConfigurationProfileDisplayName -DeviceConfigurationProfileID $DeviceConfigurationProfile.id -Body $JSONData
            }
        }
    }
}