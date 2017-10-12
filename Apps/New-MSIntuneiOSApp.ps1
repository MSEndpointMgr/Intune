<#
.SYNOPSIS
    Add a single or multiple new managed or non-managed iOS apps in Intune.

.DESCRIPTION
    This script will add a single or multiple new managed or non-managed iOS apps in the specified Intune tenant. Application information
    will automatically be detected from the iTunes app store and passed to the app created in Intune.

.PARAMETER TenantName
    Specify the tenant name, e.g. domain.onmicrosoft.com.

.PARAMETER AppName
    Name of the app that will be added.

.PARAMETER AppType
    App type, either Managed or Non-Managed. A managed app wraps the Intune SDK.

.PARAMETER Featured
    Use this switch if the app should be set as featured in the Company Portal app.

.PARAMETER ApplicationID
    Specify the Application ID of the app registration in Azure AD. When no parameter is manually passed, script will attempt to use well known Microsoft Intune PowerShell app registration.

.EXAMPLE
    # Add a single app called 'Microsoft Outlook':
    .\New-MSIntuneiOSApp.ps1 -TenantName domain.onmicrosoft.com -AppName 'Microsoft Outlook' -AppType ManagedApp

    # Add two apps called 'Microsoft Outlook' and 'Microsoft Word':
    .\New-MSIntuneiOSApp.ps1 -TenantName domain.onmicrosoft.com -AppName 'Microsoft Outlook', 'Microsoft Word' -AppType ManagedApp

.NOTES
    FileName:    New-MSIntuneiOSApp.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2017-07-25
    Updated:     2017-07-25
    
    Version history:
    1.0.0 - (2017-07-25) Script created

    Required modules:
    AzureAD (Install-Module -Name AzureAD)
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [parameter(Mandatory=$true, HelpMessage="Specify the tenant name, e.g. domain.onmicrosoft.com.")]
    [ValidateNotNullOrEmpty()]
    [string]$TenantName,

    [parameter(Mandatory=$true, HelpMessage="Name of the app that will be added.")]
    [ValidateNotNullOrEmpty()]
    [string[]]$AppName,

    [parameter(Mandatory=$true, HelpMessage="App type, either Managed or Non-Managed. A managed app wraps the Intune SDK.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("ManagedApp", "NonManagedApp")]
    [string]$AppType,

    [parameter(Mandatory=$false, HelpMessage="Use this switch if the app should be set as featured in the Company Portal app.")]
    [switch]$Featured,

    [parameter(Mandatory=$false, HelpMessage="Specify the Application ID of the app registration in Azure AD. When no parameter is manually passed, script will attempt to use well known Microsoft Intune PowerShell app registration.")]
    [ValidateNotNullOrEmpty()]
    [string]$ApplicationID = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
)
Begin {
    # Determine if the PSIntuneAuth module needs to be installed or updated
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
            Install-Module -Name PSIntuneAuth -Scope CurrentUser -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
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
    # Define Intune Graph API resources
    $GraphURI = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"

    # Process each app from parameter input
    foreach ($App in $AppName) {
        # Trim app name if it contains spaces
        $AppUntrimmed = $App
        $App = ($App -replace " ", "+").ToLower()

        # Construct app store search URL
        $AppStoreURL = "https://itunes.apple.com/search?term=$($App)&entity=software&limit=1"
        
        # Call app store for objects matching name
        try {
            Write-Verbose -Message "Attempting to locate '$($AppUntrimmed)' in iTunes app store"
            $WebRequest = Invoke-WebRequest -Method Get -Uri $AppStoreURL -ErrorAction Stop
            $AppStoreContent = ConvertFrom-Json -InputObject $WebRequest.Content -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message "An error occurred while attempting retrieve apps from iTunes app store. Error message: $($_.Exception.Message)" ; break
        }

        # Validate results from web request
        if ($AppStoreContent.results -ne $null) {
            # Set app object
            $AppResult = $AppStoreContent.results
            Write-Verbose -Message "App search returned object: $($AppResult.trackName)"

            # Determine app icon URL
            Write-Verbose -Message "Attempting to use app icon size: 60x60"
            $AppIconURL = $AppResult.artworkUrl60
            if ([System.String]::IsNullOrEmpty($AppIconURL)) {
                Write-Verbose -Message "Attempting to use app icon size: 100x100"
                $AppIconURL = $AppResult.artworkUrl100
                if ([System.String]::IsNullOrEmpty($AppIconURL)) {
                    Write-Verbose -Message "Attempting to use app icon size: 512x512"
                    $AppIconURL = $AppResult.artworkUrl512
                }
            }

            # Get icon information
            try {
                $IconWebRequest = Invoke-WebRequest -Uri $AppIconURL -ErrorAction Stop
                $IconContent = [System.Convert]::ToBase64String($IconWebRequest.Content)
                $IconType = $IconWebRequest.Headers["Content-Type"]
            }
            catch [System.Exception] {
                Write-Warning -Message "An error occurred while reading icon content. Error message: $($_.Exception.Message)" ; break
            }

            # Get app general information
            Write-Verbose -Message "Processing app details: minimumOSVersion, description, appVersion"
            $AppSystemVersion = [System.Version]$AppResult.minimumOsVersion
            $AppVersion = -join($AppSystemVersion.Major, ".", $AppSystemVersion.Minor)
            $AppDescription = $AppResult.description -replace "[^\x00-\x7F]+",""

            # Detect app supported devices
            Write-Verbose -Message "Processing app details: supportedDevices"
            if ($AppResult.supportedDevices -match "iPad") {
                $iPadSupport = $true
            }
            else {
                $iPadSupport = $false
            }
            if ($AppResult.supportedDevices -match "iPhone") {
                $iPhoneSupport = $true
            }
            else {
                $iPhoneSupport = $false
            }

            # Determine odata type
            $ODataTypeTable = @{
                "NonManagedApp" = "#microsoft.graph.iosStoreApp"
                "ManagedApp" = "#microsoft.graph.managedIOSStoreApp"
            }

            # Construct hash-table object of the application
            Write-Verbose -Message "Construct hash-table with required properties for BODY"
            $AppDataTable = @{
                '@odata.type' = "$($ODataTypeTable[$AppType])";
                displayName = $AppResult.trackName;
                publisher = $AppResult.artistName;
                description = $AppDescription;
                largeIcon = @{
                    type = $IconType;
                    value = $IconContent;
                };
                isFeatured = $false;
                appStoreUrl = $AppResult.trackViewUrl;
                applicableDeviceType=@{
                    iPad = $iPadSupport;
                    iPhoneAndIPod = $iPhoneSupport;
                };
                minimumSupportedOperatingSystem = @{
                    v8_0 = $AppVersion -lt 9.0;
                    v9_0 = $AppVersion -eq 9.0;
                    v10_0 = $AppVersion -gt 9.0;
                };
            };            
            
            # Convert to JSON and create application
            Write-Verbose -Message "Converting hash-table data to JSON"
            $AppDataJSON = ConvertTo-Json -InputObject $AppDataTable
            Write-Verbose -Message "Attempting to create app: $($AppUntrimmed)"
            $InvocationResult = Invoke-RestMethod -Uri $GraphURI -Method Post -ContentType "application/json" -Body $AppDataJSON -Headers $AuthToken
            Write-Verbose -Message "Successfully created app '$($AppUntrimmed)' with ID: $($GraphURI)/$($InvocationResult.id)"
        }
        else {
            Write-Warning -Message "iTunes app store search returned zero matches for '$($AppUntrimmed)'"
        }
    }
}