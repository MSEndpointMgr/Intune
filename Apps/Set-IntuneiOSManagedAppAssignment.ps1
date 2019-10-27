<#
.SYNOPSIS
    Update the UninstallOnDeviceRemoval property value to either $true or $false for iOS managed app assignments.

.DESCRIPTION
    Update the UninstallOnDeviceRemoval property value to either $true or $false for iOS managed app assignments.

.PARAMETER TenantName
    Specify the tenant name, e.g. domain.onmicrosoft.com.

.PARAMETER UninstallOnDeviceRemoval
    Specify either True or False to change the Uninstall on device removal app assignment setting.

.PARAMETER Force
    When passed the script will set the UninstallOnDeviceRemoval property value even if it's been set before.

.PARAMETER ApplicationID
    Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration.

.PARAMETER PromptBehavior
    Set the prompt behavior when acquiring a token.

.EXAMPLE
    .\Set-IntuneiOSManagedAppAssignment.ps1 -TenantName 'name.onmicrosoft.com' -UninstallOnDeviceRemoval $true -Force -Verbose

.NOTES
    FileName:    Set-IntuneiOSManagedAppAssignment.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2019-10-01
    Updated:     2019-10-27
    
    Version history:
    1.0.0 - (2019-10-01) Script created
    1.0.1 - (2019-10-27) Changed the filter for mobileApps resource to include managed apps too.

    Required modules:
    AzureAD (Install-Module -Name AzureAD)
    PSIntuneAuth (Install-Module -Name PSIntuneAuth)
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [parameter(Mandatory = $true, HelpMessage = "Specify the tenant name, e.g. domain.onmicrosoft.com.")]
    [ValidateNotNullOrEmpty()]
    [string]$TenantName,

    [parameter(Mandatory = $true, HelpMessage = "Specify either True or False to change the Uninstall on device removal app assignment setting.")]
    [ValidateNotNullOrEmpty()]
    [bool]$UninstallOnDeviceRemoval,

    [parameter(Mandatory = $false, HelpMessage = "When passed the script will set the UninstallOnDeviceRemoval property value even if it's been set before.")]
    [ValidateNotNullOrEmpty()]
    [switch]$Force,    

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

    function Get-IntuneManagedApp {
        # Construct Graph variables
        $GraphVersion = "beta"
        $GraphResource = "deviceAppManagement/mobileApps"
        $GraphURI = "https://graph.microsoft.com/$($GraphVersion)/$($GraphResource)"

        # Invoke Graph API resource call
        $GraphResponse = Invoke-IntuneGraphRequest -URI $GraphURI

        # Handle return objects from response
        return $GraphResponse
    }

    function Get-IntuneManagedAppAssignment {
        param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$AppID
        )
        # Construct Graph variables
        $GraphVersion = "beta"
        $GraphResource = "deviceAppManagement/mobileApps/$($AppID)/assignments"
        $GraphURI = "https://graph.microsoft.com/$($GraphVersion)/$($GraphResource)"

        # Invoke Graph API resource call
        $GraphResponse = Invoke-IntuneGraphRequest -URI $GraphURI

        # Handle return objects from response
        return $GraphResponse        
    }

    function Set-IntuneManagedAppAssignment {
        param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$AppID,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$AssignmentID,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [System.Object]$Body            
        )
        # Construct Graph variables
        $GraphVersion = "beta"
        $GraphResource = "deviceAppManagement/mobileApps/$($AppID)/assignments/$($AssignmentID)"
        $GraphURI = "https://graph.microsoft.com/$($GraphVersion)/$($GraphResource)"

        # Invoke Graph API resource call
        $GraphResponse = Invoke-IntuneGraphRequest -URI $GraphURI -Body $Body

        # Handle return objects from response
        return $GraphResponse
    }

    # Retrieve all managed apps and filter on iOS
    $ManagedApps = Get-IntuneManagedApp | Where-Object { $_.'@odata.type' -match "iosVppApp|iosStoreApp|managedIOSStoreApp" }

    # Process each managed app
    foreach ($ManagedApp in $ManagedApps) {
        Write-Verbose -Message "Attempting to retrieve assignments for managed app: $($ManagedApp.displayName)"

        # Retrieve assignments for current managed iOS app
        $ManagedAppAssignments = Get-IntuneManagedAppAssignment -AppID $ManagedApp.id

        # Continue if id property is not null, meaning that there's assignments for the current managed app
        if ($ManagedAppAssignments.id -ne $null) {
            Write-Verbose -Message "Detected assignments for current managed app"

            foreach ($ManagedAppAssignment in $ManagedAppAssignments) {
                # Handle uninstall at device removal value
                if ($ManagedAppAssignment.settings.uninstallOnDeviceRemoval -eq $null) {
                    Write-Verbose -Message "Detected empty property value for uninstall at device removal, updating property value"
                    $ManagedAppAssignment.settings.uninstallOnDeviceRemoval = $UninstallOnDeviceRemoval
                }

                # Force update non-set property values
                if ($PSBoundParameters["Force"]) {
                    $ManagedAppAssignment.settings.uninstallOnDeviceRemoval = $UninstallOnDeviceRemoval
                }
                
                # Construct JSON object for POST call
                $JSONTable = @{
                    'id' = $ManagedAppAssignment.id
                    'settings' = $ManagedAppAssignment.settings
                }
                $JSONData = $JSONTable | ConvertTo-Json
                
                # Call Graph API post operation with updated settings values for assignment
                Write-Verbose -Message "Attempting to update uninstallOnDeviceRemoval for assignment ID '$($ManagedAppAssignment.id)' with value: $($UninstallOnDeviceRemoval)"
                $Invocation = Set-IntuneManagedAppAssignment -AppID $ManagedApp.id -AssignmentID $ManagedAppAssignment.id -Body $JSONData
            }           
        }
        else {
            Write-Verbose -Message "Empty query returned for managed app assignments"
        }
    }
}