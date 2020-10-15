<#
.SYNOPSIS
    Export device configuration profiles for Windows, iOS/iPadOS, AndroidEnterprise, macOS platforms in Intune to a local path as JSON files.

.DESCRIPTION
    Export device configuration profiles for Windows, iOS/iPadOS, AndroidEnterprise, macOS platforms in Intune to a local path as JSON files.

.PARAMETER TenantName
    Specify the tenant name, e.g. domain.onmicrosoft.com.

.PARAMETER Platform
    Specify the given platforms that device configuration profiles should be exported for.

.PARAMETER Path
    Specify an existing local path to where the exported Device Configuration JSON files will be stored.

.PARAMETER SkipPrefix
    When specified, the prefix (e.g. COMPANY-) in the following naming convention 'COMPANY-W10-Custom' will be removed.

.PARAMETER ApplicationID
    Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration.

.PARAMETER PromptBehavior
    Set the prompt behavior when acquiring a token.    

.EXAMPLE
    # Export all device configuration profiles for all platforms from a tenant named 'domain.onmicrosoft.com' to local path 'C:\Temp\Intune':
    .\Export-IntuneDeviceConfigurationProfile.ps1 -TenantName "domain.onmicrosoft.com" -Platform "Windows", "iOS", "AndroidEnterprise", "macOS" -Path C:\Temp\Intune -Verbose

.NOTES
    FileName:    Export-IntuneDeviceConfigurationProfile.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2019-10-04
    Updated:     2019-10-04

    Version history:
    1.0.0 - (2019-10-04) Script created

    Required modules:
    AzureAD (Install-Module -Name AzureAD)
    PSIntuneAuth (Install-Module -Name PSIntuneAuth)    
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [parameter(Mandatory = $true, HelpMessage = "Specify the tenant name, e.g. domain.onmicrosoft.com.")]
    [ValidateNotNullOrEmpty()]
    [string]$TenantName,

    [parameter(Mandatory = $false, HelpMessage = "Specify the given platforms that device configuration profiles should be exported for.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("Windows", "iOS", "AndroidEnterprise", "macOS")]
    [string[]]$Platform,

    [parameter(Mandatory = $true, HelpMessage = "Specify an existing local path to where the exported Device Configuration JSON files will be stored.")]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern("^[A-Za-z]{1}:\\\w+")]
    [ValidateScript({
        # Check if path contains any invalid characters
        if ((Split-Path -Path $_ -Leaf).IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
            Write-Warning -Message "$(Split-Path -Path $_ -Leaf) contains invalid characters"
        }
        else {
            # Check if the whole path exists
            if (Test-Path -Path $_ -PathType Container) {
                    return $true
            }
            else {
                Write-Warning -Message "Unable to locate part of or the whole specified path, specify a valid path"
            }
        }
    })]
    [string]$Path,

    [parameter(Mandatory = $false, HelpMessage = "When specified, the prefix (e.g. COMPANY-) in the following naming convention 'COMPANY-W10-Custom' will be removed.")]
    [ValidateNotNullOrEmpty()]
    [string]$SkipPrefix,    

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
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$URI
        )
        try {
            # Construct array list for return values
            $ResponseList = New-Object -TypeName System.Collections.ArrayList

            # Call Graph API and get JSON response
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

            # Handle return objects from response
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

    function Export-JSON {
        param(   
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [System.Object]$InputObject,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$Path,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$Name,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [ValidateSet("General", "AdministrativeTemplate")]
            [string]$Type
        )
        try {
            # Handle removal of prefix from display name
            if ($Type -like "General") {
                if ($Script:PSBoundParameters["SkipPrefix"]) {
                    $InputObject.displayName = $InputObject.displayName.Replace($SkipPrefix, "")
                    $Name = $Name.Replace($SkipPrefix, "")
                }
            }

            # Convert input data to JSON and remove unwanted properties
            $JSONData = ($InputObject | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, supportsScopeTags | ConvertTo-Json -Depth 10).Replace("\u0027","'")

            # Construct file name
            $FilePath = Join-Path -Path $Path -ChildPath (-join($Name, ".json"))

            # Output to file
            Write-Verbose -Message "Exporting device configuration profile with name: $($Name)"
            $JSONData | Set-Content -Path $FilePath -Encoding "Ascii" -Force -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message "Failed to export JSON input data to path '$($FilePath)'. Error message: $($_.Exception.Message)"
        }
    }

    function Get-IntuneDeviceConfigurationProfile {
        param(   
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$Platform
        )
        # Construct Graph variables
        $GraphVersion = "beta"
        $GraphResource = "deviceManagement/deviceConfigurations"
        $GraphURI = "https://graph.microsoft.com/$($GraphVersion)/$($GraphResource)"

        # Invoke Graph API resource call
        $ResponseList = New-Object -TypeName System.Collections.ArrayList
        $GraphResponse = Invoke-IntuneGraphRequest -URI $GraphURI

        if ($GraphResponse -ne $null) {
            foreach ($ResponseItem in $GraphResponse) {
                switch -Regex ($ResponseItem.'@odata.type') {
                    "microsoft.graph.androidDeviceOwner" {
                        $PlatformType = "AndroidEnterprise"
                    }
                    "microsoft.graph.androidWorkProfile" {
                        $PlatformType = "AndroidEnterprise"
                    }
                    "microsoft.graph.windows" {
                        $PlatformType = "Windows"
                    }
                    "microsoft.graph.ios" {
                        $PlatformType = "iOS"
                    }
                }

                if ($PlatformItem -like $PlatformType) {
                    $ResponseList.Add($ResponseItem) | Out-Null
                }
            }
        }

        # Handle return objects from response
        return $ResponseList
    }    

    function Get-IntuneAdministrativeTemplateProfiles {
        # Construct Graph variables
        $GraphVersion = "beta"
        $GraphResource = "deviceManagement/groupPolicyConfigurations"
        $GraphURI = "https://graph.microsoft.com/$($GraphVersion)/$($GraphResource)"

        # Invoke Graph API resource call
        $ResponseList = New-Object -TypeName System.Collections.ArrayList
        $GraphResponse = Invoke-IntuneGraphRequest -URI $GraphURI

        foreach ($ResponseItem in $GraphResponse) {
            $ResponseList.Add($ResponseItem) | Out-Null
        }

        # Handle return objects from response
        return $ResponseList
    }

    function Get-IntuneAdministrativeTemplateDefinitionValues {
        param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$AdministrativeTemplateId
        )
        # Construct Graph variables
        $GraphVersion = "beta"
        $GraphResource = "deviceManagement/groupPolicyConfigurations/$($AdministrativeTemplateId)/definitionValues"
        $GraphURI = "https://graph.microsoft.com/$($GraphVersion)/$($GraphResource)"

        # Invoke Graph API resource call
        Invoke-IntuneGraphRequest -URI $GraphURI
    }

    function Get-IntuneAdministrativeTemplateDefinitionValuesPresentationValues {
        param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$AdministrativeTemplateId,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$DefinitionValueID
        )
        # Construct Graph variables
        $GraphVersion = "beta"
        $GraphResource = "deviceManagement/groupPolicyConfigurations/$($AdministrativeTemplateId)/definitionValues/$($DefinitionValueID)/presentationValues"
        $GraphURI = "https://graph.microsoft.com/$($GraphVersion)/$($GraphResource)"

        # Invoke Graph API resource call
        Invoke-IntuneGraphRequest -URI $GraphURI
    }

    function Get-IntuneAdministrativeTemplateDefinitionValuesDefinition {
        param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$AdministrativeTemplateId,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$DefinitionValueID
        )
        # Construct Graph variables
        $GraphVersion = "beta"
        $GraphResource = "deviceManagement/groupPolicyConfigurations/$($AdministrativeTemplateId)/definitionValues/$($DefinitionValueID)/definition"
        $GraphURI = "https://graph.microsoft.com/$($GraphVersion)/$($GraphResource)"

        # Invoke Graph API resource call
        Invoke-IntuneGraphRequest -URI $GraphURI
    }

    function Get-IntuneAdministrativeTemplateDefinitionsPresentations {
        param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$AdministrativeTemplateId,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$DefinitionValueID
        )
        # Construct Graph variables
        $GraphVersion = "beta"
        $GraphResource = "deviceManagement/groupPolicyConfigurations/$($AdministrativeTemplateId)/definitionValues/$($DefinitionValueID)/presentationValues?`$expand=presentation"
        $GraphURI = "https://graph.microsoft.com/$($GraphVersion)/$($GraphResource)"

        # Invoke Graph API resource call
        (Invoke-IntuneGraphRequest -URI $GraphURI).presentation
    }

    # Process export operation based on specified platforms
    foreach ($PlatformItem in $Platform) {
        Write-Verbose -Message "Currently processing device configuration profiles for platform: $($PlatformItem)"
        
        # Retrieve all device configuration profiles for current platform
        $DeviceConfigurationProfiles = Get-IntuneDeviceConfigurationProfile -Platform $PlatformItem

        if (($DeviceConfigurationProfiles | Measure-Object).Count -ge 1) {
            foreach ($DeviceConfigurationProfile in $DeviceConfigurationProfiles) {
                $DeviceConfigurationProfileName = $DeviceConfigurationProfile.displayName
                Export-JSON -InputObject $DeviceConfigurationProfile -Path $Path -Name $DeviceConfigurationProfileName -Type "General"
            }
        }
        else {
            Write-Warning -Message "Empty query result for device configuration profiles for platform: $($PlatformItem)"
        }

        # Retrieve all device configuration administrative templates for current platform
        if ($PlatformItem -like "Windows") {
            $AdministrativeTemplateProfiles = Get-IntuneAdministrativeTemplateProfiles
            if (($AdministrativeTemplateProfiles | Measure-Object).Count -ge 1) {
                foreach ($AdministrativeTemplateProfile in $AdministrativeTemplateProfiles) {
                    Write-Verbose -Message "Exporting administrative template with name: $($AdministrativeTemplateProfile.displayName)"
                    
                    # Handle removal of prefix
                    $AdministrativeTemplateProfileName = $AdministrativeTemplateProfile.displayName
                    if ($PSBoundParameters["SkipPrefix"]) {
                        $AdministrativeTemplateProfileName = $AdministrativeTemplateProfile.displayName.Replace($SkipPrefix ,"")
                    }

                    # Define new folder with administrative template profile name to contain any subsequent JSON files
                    $AdministrativeTemplateProfileFolderPath = Join-Path -Path $Path -ChildPath $AdministrativeTemplateProfileName
                    if (-not(Test-Path -Path $AdministrativeTemplateProfileFolderPath)) {
                        New-Item -Path $AdministrativeTemplateProfileFolderPath -ItemType Directory -Force | Out-Null
                    }     

                    # Retrieve all definition values for current administrative template and loop through them
                    $AdministrativeTemplateDefinitionValues = Get-IntuneAdministrativeTemplateDefinitionValues -AdministrativeTemplateId $AdministrativeTemplateProfile.id
                    foreach ($AdministrativeTemplateDefinitionValue in $AdministrativeTemplateDefinitionValues) {
                        # Retrieve the defintion of the current definition value
                        $DefinitionValuesDefinition = Get-IntuneAdministrativeTemplateDefinitionValuesDefinition -AdministrativeTemplateId $AdministrativeTemplateProfile.id -DefinitionValueID $AdministrativeTemplateDefinitionValue.id
                        $DefinitionValuesDefinitionID = $DefinitionValuesDefinition.id
                        $DefinitionValuesDefinitionDisplayName = $DefinitionValuesDefinition.displayName

                        # Retrieve the presentations of the current definition value
                        $DefinitionsPresentations = Get-IntuneAdministrativeTemplateDefinitionsPresentations -AdministrativeTemplateId $AdministrativeTemplateProfile.id -DefinitionValueID $AdministrativeTemplateDefinitionValue.id

                        # Rertrieve the presentation values of the current definition value
                        $DefinitionValuesPresentationValues = Get-IntuneAdministrativeTemplateDefinitionValuesPresentationValues -AdministrativeTemplateId $AdministrativeTemplateProfile.id -DefinitionValueID $AdministrativeTemplateDefinitionValue.id

                        # Create custom definition object to be exported
                        $PSObject = New-Object -TypeName PSCustomObject
                        $PSObject | Add-Member -MemberType "NoteProperty" -Name "definition@odata.bind" -Value "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($DefinitionValuesDefinition.id)')"
                        $PSObject | Add-Member -MemberType "NoteProperty" -Name "enabled" -Value $($AdministrativeTemplateDefinitionValue.enabled.ToString().ToLower())
 
                        # Check whether presentation values exist for current definition value
                        if (($DefinitionValuesPresentationValues.id | Measure-Object).Count -ge 1) {
                            $i = 0
                            $PresentationValues = New-Object -TypeName System.Collections.ArrayList
                            foreach ($PresentationValue in $DefinitionValuesPresentationValues) {
                                # Handle multiple items in case of an array
                                if (($DefinitionsPresentations.id).Count -ge 1) {
                                    $DefinitionsPresentationsID = $DefinitionsPresentations[$i].id
                                }
                                else {
                                    $DefinitionsPresentationsID = $DefinitionsPresentations.id
                                }

                                # Construct new presentation value object
                                $CurrentObject = $PresentationValue | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version
                                $CurrentObject | Add-Member -MemberType "NoteProperty" -Name "presentation@odata.bind" -Value "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($DefinitionValuesDefinition.id)')/presentations('$($DefinitionsPresentationsID)')"
                                $PresentationValues.Add($CurrentObject) | Out-Null
                                $i++
                            }

                            # Add all presentation value objects to custom object
                            $PSObject | Add-Member -MemberType NoteProperty -Name "presentationValues" -Value $PresentationValues
                        }

                        Write-Verbose -Message "Exporting administrative template setting with name: $($DefinitionValuesDefinitionDisplayName)"
                        Export-JSON -InputObject $PSObject -Path $AdministrativeTemplateProfileFolderPath -Name $DefinitionValuesDefinitionDisplayName -Type "AdministrativeTemplate"
                    }
                }
            }
        }
    }
}