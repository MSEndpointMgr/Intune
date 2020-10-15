<#
.SYNOPSIS
    Import device configuration profiles for Windows, iOS/iPadOS, AndroidEnterprise, macOS platforms stored as JSON files into a specific Intune tenant.

.DESCRIPTION
    Import device configuration profiles for Windows, iOS/iPadOS, AndroidEnterprise, macOS platforms stored as JSON files into a specific Intune tenant.

.PARAMETER TenantName
    Specify the tenant name, e.g. domain.onmicrosoft.com.

.PARAMETER Platform
    Specify the given platforms that device configuration profiles should be imported for.

.PARAMETER Path
    Specify an existing local path to where the Device Configuration JSON files are located.

.PARAMETER Prefix
    Specify the prefix that will be added to the device configuration profile name.    

.PARAMETER ApplicationID
    Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration.

.PARAMETER PromptBehavior
    Set the prompt behavior when acquiring a token.

.EXAMPLE
    # Import all device configuration profiles for all platforms from 'C:\Temp\Intune' into a tenant named 'domain.onmicrosoft.com':
    .\Import-IntuneDeviceConfigurationProfile.ps1 -TenantName "domain.onmicrosoft.com" -Platform "Windows", "iOS", "AndroidEnterprise", "macOS" -Path C:\Temp\Intune -Prefix "CompanyName" -Verbose

.NOTES
    FileName:    Import-IntuneDeviceConfigurationProfile.ps1
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

    [parameter(Mandatory = $false, HelpMessage = "Specify the given platforms that device configuration profiles should be imported for.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("Windows", "iOS", "AndroidEnterprise", "macOS")]
    [string[]]$Platform,

    [parameter(Mandatory = $true, HelpMessage = "Specify an existing local path to where the Device Configuration JSON files are located.")]
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

    [parameter(Mandatory = $false, HelpMessage = "Specify the prefix that will be added to the device configuration profile name.")]
    [ValidateNotNullOrEmpty()]
    [string]$Prefix,

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

    # Validate that given path contains JSON files
    try {
        $JSONFiles = Get-ChildItem -Path $Path -Filter *.json -ErrorAction Stop
        if ($JSONFiles -eq $null) {
            $SkipDeviceConfigurationProfiles = $true
            Write-Warning -Message "Specified path doesn't contain any .json files, skipping device configuration profile import actions"
        }
        else {
            $SkipDeviceConfigurationProfiles = $false
            Write-Verbose -Message "Specified path contains .json files for device configuration profiles, will include those for import"
        }
    }
    catch [System.Exception] {
        Write-Warning -Message "An error occurred while attempting to validate .json files existence in given path. Error message: $($_.Exception.Message)"; break
    }

    # Check if given path contains any directories assuming they're exported administrative templates
    try {
        $AdministrativeTemplateFolders = Get-ChildItem -Path $Path -Directory -ErrorAction Stop
        if ($AdministrativeTemplateFolders -eq $null) {
            $SkipAdministrativeTemplateProfiles = $true
            Write-Warning -Message "Specified path doesn't contain any exported Administrative Template folders, skipping administrative template profile import actions"
        }
        else {
            Write-Verbose -Message "Specified path contains exported administrative template folders, will include those for import"
            $SkipAdministrativeTemplateProfiles = $false
        }
    }
    catch [System.Exception] {
        Write-Warning -Message "An error occurred while attempting to validate administrative template folders existence in given path. Error message: $($_.Exception.Message)"; break
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
            [string]$URI,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [System.Object]$Body
        )
        try {
            # Call Graph API and get JSON response
            $GraphResponse = Invoke-RestMethod -Uri $URI -Headers $AuthToken -Method Post -Body $Body -ContentType "application/json" -ErrorAction Stop -Verbose:$false

            return $GraphResponse
        }
        catch [System.Exception] {
            # Construct stream reader for reading the response body from API call
            $ResponseBody = Get-ErrorResponseBody -Exception $_.Exception
    
            # Handle response output and error message
            Write-Output -InputObject "Response content:`n$ResponseBody"
            Write-Warning -Message "Request to $($URI) failed with HTTP Status $($_.Exception.Response.StatusCode) and description: $($_.Exception.Response.StatusDescription)"
        }
    }

    function Test-JSON {
        param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [System.Object]$InputObject
        )
        try {
            # Convert from hash-table to JSON
            ConvertTo-Json -InputObject $InputObject -ErrorAction Stop
    
            # Return true if conversion was successful
            return $true
        }
        catch [System.Exception] {
            return $false
        }
    }

    function Get-Platform {
        param(   
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$InputObject
        )
        switch -Regex ($InputObject) {
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

        # Handle return value
        return $PlatformType
    }

    function New-IntuneDeviceConfigurationProfile {
        param(   
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$JSON
        )
        # Construct Graph variables
        $GraphVersion = "beta"
        $GraphResource = "deviceManagement/deviceConfigurations"
        $GraphURI = "https://graph.microsoft.com/$($GraphVersion)/$($GraphResource)"

        # Invoke Graph API resource call
        Invoke-IntuneGraphRequest -URI $GraphURI -Body $JSON
    }

    function New-IntuneAdministrativeTemplateProfile {
        param(   
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$JSON
        )
        # Construct Graph variables
        $GraphVersion = "beta"
        $GraphResource = "deviceManagement/groupPolicyConfigurations"
        $GraphURI = "https://graph.microsoft.com/$($GraphVersion)/$($GraphResource)"

        # Invoke Graph API resource call
        $GraphResponse = Invoke-IntuneGraphRequest -URI $GraphURI -Body $JSON

        # Handle return value
        return $GraphResponse.id
    }

    function New-IntuneAdministrativeTemplateDefinitionValues {
        param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$AdministrativeTemplateID,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$JSON
        )
        # Construct Graph variables
        $GraphVersion = "beta"
        $GraphResource = "deviceManagement/groupPolicyConfigurations/$($AdministrativeTemplateID)/definitionValues"
        $GraphURI = "https://graph.microsoft.com/$($GraphVersion)/$($GraphResource)"

        # Invoke Graph API resource call
        Invoke-IntuneGraphRequest -URI $GraphURI -Body $JSON
    }    

    # Ensure all given platforms are available in a list array for further reference
    $PlatformList = New-Object -TypeName System.Collections.ArrayList
    foreach ($PlatformItem in $Platform) {
        $PlatformList.Add($PlatformItem) | Out-Null
    }

    # Process each JSON file located in given path
    if ($SkipDeviceConfigurationProfiles -eq $false) {
        foreach ($JSONFile in $JSONFiles.FullName) {
            Write-Verbose -Message "Processing JSON data file from: $($JSONFile)"
    
            try {
                # Read JSON data from current file
                $JSONDataContent = Get-Content -Path $JSONFile -ErrorAction Stop -Verbose:$false
    
                try {
                    $JSONData = $JSONDataContent | ConvertFrom-Json -ErrorAction Stop | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, supportsScopeTags
                    $JSONPlatform = Get-Platform -InputObject $JSONData.'@odata.type'
                    $JSONDisplayName = $JSONData.displayName
    
                    # Handle device configuration profile name if prefix parameter is specified
                    if ($PSBoundParameters["Prefix"]) {
                        $JSONDisplayName = -join($Prefix, $JSONData.displayName)
                        $JSONData.displayName = $JSONDisplayName
                    }
    
                    if ($JSONPlatform -in $Platform) {
                        Write-Verbose -Message "Validating JSON data content import for profile: $($JSONDisplayName)"
    
                        if (Test-JSON -InputObject $JSONData) {
                            Write-Verbose -Message "Successfully validated JSON data content for import, proceed to import profile"
                            
                            # Convert from object to JSON string
                            $JSONDataConvert = $JSONData | ConvertTo-Json -Depth 5
    
                            # Create new device configuration profile based on JSON data
                            Write-Verbose -Message "Attempting to create new device configuration profile with name: $($JSONDisplayName)"
                            $GraphRequest = New-IntuneDeviceConfigurationProfile -JSON $JSONDataConvert
    
                            if ($GraphRequest.'@odata.type' -like $JSONPlatform) {
                                Write-Verbose -Message "Successfully created device configuration profile"
                            }
                        }
                        else {
                            Write-Verbose -Message "Failed to validate JSON data object to be converted to JSON string"
                        }
                    }
                    else {
                        Write-Verbose -Message "Current JSON data file for platform type '$($JSONPlatform)' was not allowed to be imported, skipping"
                    }
                }
                catch [System.Exception] {
                    Write-Warning -Message "Failed to convert JSON data content. Error message: $($_.Exception.Message)"
                }
            }
            catch [System.Exception] {
                Write-Warning -Message "Failed to read JSON data content from file '$($JSONFile)'. Error message: $($_.Exception.Message)"
            }
        }
    }
    else {
        Write-Verbose -Message "Skipping device configuration profile import actions as no .json files was found in given location"
    }

    # Process each administrative template folder
    if ($SkipAdministrativeTemplateProfiles -eq $false) {
        foreach ($AdministrativeTemplateFolder in $AdministrativeTemplateFolders) {
            # Get administrative template variable parameters
            $AdministrativeTemplateName = $AdministrativeTemplateFolder.Name
            $AdministrativeTemplatePath = $AdministrativeTemplateFolder.FullName

            # Validate that current administrative template folder contains JSON files
            $AdministrativeTemplateFolderJSONFiles = Get-ChildItem -Path $AdministrativeTemplatePath -Filter *.json
            if ($AdministrativeTemplateFolderJSONFiles -ne $null) {
                # Handle administrative template profile name if prefix parameter is specified
                if ($PSBoundParameters["Prefix"]) {
                    $AdministrativeTemplateName = -join($Prefix, $AdministrativeTemplateName)
                }

                # Construct new administrative template profile object
                Write-Verbose -Message "Attempting to create new administrative template profile with name: $($AdministrativeTemplateName)"
                $AdministrativeTemplateProfileJSONDataTable = @{
                    "displayName" = $AdministrativeTemplateName
                    "description" = [string]::Empty
                }
                $AdministrativeTemplateProfileJSONData = $AdministrativeTemplateProfileJSONDataTable | ConvertTo-Json
                $AdministrativeTemplateProfileID = New-IntuneAdministrativeTemplateProfile -JSON $AdministrativeTemplateProfileJSONData
                
                # Process each subsequent JSON file in current administrative template profile folder
                foreach ($AdministrativeTemplateFolderJSONFile in $AdministrativeTemplateFolderJSONFiles) {
                    # Read JSON data from current file
                    $JSONDataContent = Get-Content -Path $AdministrativeTemplateFolderJSONFile.FullName -ErrorAction Stop -Verbose:$false

                    try {
                        $JSONData = $JSONDataContent | ConvertFrom-Json -ErrorAction Stop
                        Write-Verbose -Message "Validating JSON data content import for defintion values: $($AdministrativeTemplateFolderJSONFile.Name)"
    
                        if (Test-JSON -InputObject $JSONData) {
                            Write-Verbose -Message "Successfully validated JSON data content for import, proceed to import defintion values"
                            
                            # Convert from object to JSON string
                            $JSONDataConvert = $JSONData | ConvertTo-Json -Depth 5
    
                            # Create new administrative template definition values based on JSON data
                            Write-Verbose -Message "Attempting to create new administrative template definition values with name: $($AdministrativeTemplateFolderJSONFile.Name)"
                            $GraphRequest = New-IntuneAdministrativeTemplateDefinitionValues -AdministrativeTemplateID $AdministrativeTemplateProfileID -JSON $JSONDataConvert

                            if ($GraphRequest.configurationType -like "policy") {
                                Write-Verbose -Message "Successfully created administrative template definition values"
                            }
                        }
                        else {
                            Write-Verbose -Message "Failed to validate JSON data object to be converted to JSON string"
                        }                        
                    }
                    catch [System.Exception] {
                        Write-Warning -Message "Failed to convert JSON data content from file. Error message: $($_.Exception.Message)"
                    }
                }
            }
            else {
                Write-Warning -Message "Failed to locate sub-sequent .json files within administrative template profile folder: $($AdministrativeTemplatePath)"
            }
        }
    }
    else {
        Write-Verbose -Message "Skipping administrative template import actions as no sub-directories was found in given location"
    }
}