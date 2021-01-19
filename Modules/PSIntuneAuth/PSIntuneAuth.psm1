function Get-MSIntuneAuthToken {
    <#
    .SYNOPSIS
        Get an authentication token required for interacting with Microsoft Intune using Microsoft Graph API
        NOTE: This function requires that AzureAD module is installed. Use 'Install-Module -Name AzureAD' to install it.

    .PARAMETER TenantName
        A tenant name should be provided in the following format: tenantname.onmicrosoft.com.

    .PARAMETER ClientID
        Application ID for an Azure AD application. Uses by default the Microsoft Intune PowerShell application ID.

    .PARAMETER ClientSecret
        Web application client secret.

    .PARAMETER Credential
        Specify a PSCredential object containing username and password.

    .PARAMETER Resource
        Resource recipient (app, e.g. Graph API). Leave empty to use https://graph.microsoft.com as default.

    .PARAMETER RedirectUri
        Redirect URI for Azure AD application. Leave empty to leverage Azure PowerShell well known redirect URI.

    .PARAMETER PromptBehavior
        Set the prompt behavior when acquiring a token.

    .EXAMPLE
        # Manually specify username and password to acquire an authentication token:
        Get-MSIntuneAuthToken -TenantName domain.onmicrsoft.com

        # Manually specify username and password to acquire an authentication token using a specific client ID:
        Get-MSIntuneAuthToken -TenantName domain.onmicrsoft.com -ClientID "<GUID>"

        # Retrieve a PSCredential object with username and password to acquire an authentication token:
        $Credential = Get-Credential
        Get-MSIntuneAuthToken -TenantName domain.onmicrsoft.com -Credential $Credential

        # Retrieve a PSCredential object for usage with Azure Automation containing the username and password to acquire an authentication token:
        $Credential = Get-AutomationPSCredential -Name "<CredentialName>"
        Get-MSIntuneAuthToken -TenantName domain.onmicrsoft.com -ClientID "<GUID>" -Credential $Credential

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2017-09-27
        Updated:     2021-01-12

        Version history:
        1.0.0 - (2017-09-27) Function created
        1.0.1 - (2017-10-08) Added ExpiresOn property
        1.0.2 - (2018-01-22) Added support for specifying PSCredential object for silently retrieving an authentication token without being prompted
        1.0.3 - (2018-01-22) Fixed an issue with prompt behavior parameter not being used
        1.0.4 - (2018-01-22) Fixed an issue when detecting the AzureAD module presence
        1.0.5 - (2018-01-22) Enhanced the AzureAD module detection logic
        1.0.6 - (2018-01-28) Changed so that the Microsoft Intune PowerShell application ID is set as default for ClientID parameter
        1.2.0 - (2019-10-27) Added support for using app-only authentication using a client ID and client secret for a web app. Resource recipient is now also possible
                             to specify directly on the command line instead of being hard-coded. Now using the latest authority URI and installs the AzureAD module automatically.
        1.2.1 - (2020-01-15) Fixed an issue where when multiple versions of the AzureAD module installed would cause an error attempting in re-installing the Azure AD module
        1.2.2 - (2020-01-28) Added more verbose logging output for further troubleshooting in case an auth token is not aquired
        1.2.3 - (2021-01-12) Added support for installing the AzureAD module along side with the AzureADPreview module
    #>
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true, ParameterSetName="AuthPrompt", HelpMessage="A tenant name should be provided in the following format: tenantname.onmicrosoft.com.")]
        [parameter(Mandatory=$true, ParameterSetName="AuthCredential")]
        [parameter(Mandatory=$false, ParameterSetName="AuthAppOnly")]
        [ValidateNotNullOrEmpty()]
        [string]$TenantName,

        [parameter(Mandatory=$false, ParameterSetName="AuthPrompt", HelpMessage="Application ID for an Azure AD application. Uses by default the Microsoft Intune PowerShell application ID.")]
        [parameter(Mandatory=$false, ParameterSetName="AuthCredential")]
        [parameter(Mandatory=$false, ParameterSetName="AuthAppOnly")]
        [ValidateNotNullOrEmpty()]
        [string]$ClientID = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547",

        [parameter(Mandatory=$true, ParameterSetName="AuthAppOnly", HelpMessage="Web application client secret.")]
        [ValidateNotNullOrEmpty()]
        [string]$ClientSecret,

        [parameter(Mandatory=$true, ParameterSetName="AuthCredential", HelpMessage="Specify a PSCredential object containing username and password.")]
        [ValidateNotNullOrEmpty()]
        [PSCredential]$Credential,

        [parameter(Mandatory=$false, ParameterSetName="AuthPrompt", HelpMessage="Resource recipient (app, e.g. Graph API). Leave empty to use https://graph.microsoft.com as default.")]
        [parameter(Mandatory=$false, ParameterSetName="AuthCredential")]
        [parameter(Mandatory=$false, ParameterSetName="AuthAppOnly")]
        [ValidateNotNullOrEmpty()]
        [string]$Resource = "https://graph.microsoft.com",

        [parameter(Mandatory=$false, ParameterSetName="AuthPrompt", HelpMessage="Redirect URI for Azure AD application. Leave empty to leverage Azure PowerShell well known redirect URI.")]
        [parameter(Mandatory=$false, ParameterSetName="AuthCredential")]
        [ValidateNotNullOrEmpty()]
        [string]$RedirectUri = "urn:ietf:wg:oauth:2.0:oob",

        [parameter(Mandatory=$false, ParameterSetName="AuthPrompt", HelpMessage="Set the prompt behavior when acquiring a token.")]
        [parameter(Mandatory=$false, ParameterSetName="AuthCredential")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Auto", "Always", "Never", "RefreshSession")]
        [string]$PromptBehavior = "Auto"
    )
    Process {
        $ErrorActionPreference = "Stop"

        # Determine if the AzureAD module needs to be installed or updated to latest version
        try {
            Write-Verbose -Message "Attempting to locate AzureAD module on local system"
            $AzureADModule = Get-Module -Name "AzureAD" -ListAvailable -Verbose:$false
            if ($AzureADModule -ne $null) {
                if (($AzureADModule | Measure-Object).Count -eq 1) {
                    $CurrentModuleVersion = Get-Module -Name "AzureAD" -ListAvailable -ErrorAction Stop -Verbose:$false | Select-Object -ExpandProperty Version
                }
                else {
                    $CurrentModuleVersion = Get-Module -Name "AzureAD" -ListAvailable -ErrorAction Stop -Verbose:$false | Sort-Object -Property Version -Descending | Select-Object -First 1 -ExpandProperty Version
                }
                $LatestModuleVersion = (Find-Module -Name "AzureAD" -ErrorAction Stop -Verbose:$false).Version
                Write-Verbose -Message "AzureAD module detected, checking for latest version"
                if ($LatestModuleVersion -gt $CurrentModuleVersion) {
                    Write-Verbose -Message "Latest version of AzureAD module is not installed, attempting to install: $($LatestModuleVersion.ToString())"
                    $UpdateModuleInvocation = Update-Module -Name "AzureAD" -Scope "AllUsers" -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
                }
                else {
                    Write-Verbose -Message "Latest version for AzureAD module was detected, continue to aquire authentication token"
                }
            }
            else {
                throw "Unable to detect Azure AD module"
            }
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to detect AzureAD module, attempting to install from online repository"
            try {
                # Install NuGet package provider
                $PackageProvider = Install-PackageProvider -Name NuGet -Force -Verbose:$false

                # Install AzureAD module
                $InstallArgs = @{
                    "Name" = "AzureAD"
                    "Scope" = "AllUsers"
                    "Force" = $true
                    "ErrorAction" = "Stop"
                    "Confirm" = $false
                    "Verbose" = $false
                }

                # Amend install args if AzureADPreview module is detected
                $AzureADPreviewModule = Get-Module -Name "AzureADPreview" -ListAvailable -Verbose:$false
                if ($AzureADPreviewModule -ne $null) {
                    Write-Verbose -Message "Detected that the AzureADPreview module was installed, adding 'AllowClobber' parameter"
                    $InstallArgs.Add("AllowClobber", $true)
                }

                Install-Module @InstallArgs
                Write-Verbose -Message "Successfully installed AzureAD"
            }
            catch [System.Exception] {
                Write-Warning -Message "An error occurred while attempting to install AzureAD module. Error message: $($_.Exception.Message)"; break
            }
        }

        try {
            # Get installed Azure AD module
            $AzureADModules = Get-Module -Name "AzureAD" -ListAvailable -ErrorAction Stop -Verbose:$false

            if ($AzureADModules -ne $null) {
                # Check if multiple modules exist and determine the module path for the most current version
                if (($AzureADModules | Measure-Object).Count -gt 1) {
                    $LatestAzureADModule = ($AzureADModules | Select-Object -Property Version | Sort-Object)[-1]
                    $AzureADModulePath = $AzureADModules | Where-Object { $_.Version -like $LatestAzureADModule.Version } | Select-Object -ExpandProperty ModuleBase
                }
                else {
                    $AzureADModulePath = $AzureADModules | Select-Object -ExpandProperty ModuleBase
                }

                try {
                    # Construct array for required assemblies from Azure AD module
                    $Assemblies = @(
                        (Join-Path -Path $AzureADModulePath -ChildPath "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"),
                        (Join-Path -Path $AzureADModulePath -ChildPath "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll")
                    )

                    # Load required assemblies
                    Add-Type -Path $Assemblies -ErrorAction Stop -Verbose:$false

                    try {
                        # Construct variable for authority URI
                        switch ($PSCmdlet.ParameterSetName) {
                            "AuthAppOnly" {
                                $Authority = "https://login.microsoftonline.com/$($TenantName)"
                            }
                            default {
                                $Authority = "https://login.microsoftonline.com/$($TenantName)/oauth2/v2.0/token"       
                            }
                        }

                        # Construct new authentication context
                        $AuthenticationContext = New-Object -TypeName "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $Authority -ErrorAction Stop

                        # Construct platform parameters
                        $PlatformParams = New-Object -TypeName "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList $PromptBehavior -ErrorAction Stop

                        try {
                            # Determine parameters when acquiring token
                            Write-Verbose -Message "Currently running in parameter set context: $($PSCmdlet.ParameterSetName)"
                            switch ($PSCmdlet.ParameterSetName) {
                                "AuthPrompt" {
                                    # Acquire access token
                                    Write-Verbose -Message "Attempting to acquire access token using user delegation"
                                    $AuthenticationResult = ($AuthenticationContext.AcquireTokenAsync($Resource, $ClientID, $RedirectUri, $PlatformParams)).Result
                                }
                                "AuthCredential" {
                                    # Construct required identity model user password credential
                                    Write-Verbose -Message "Attempting to acquire access token using legacy user delegation with username and password"
                                    $UserPasswordCredential = New-Object -TypeName "Microsoft.IdentityModel.Clients.ActiveDirectory.UserPasswordCredential" -ArgumentList ($Credential.UserName, $Credential.Password) -ErrorAction Stop
            
                                    # Acquire access token
                                    $AuthenticationResult = ([Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContextIntegratedAuthExtensions]::AcquireTokenAsync($AuthenticationContext, $Resource, $ClientID, $UserPasswordCredential)).Result
                                }
                                "AuthAppOnly" {
                                    # Construct required identity model client credential
                                    Write-Verbose -Message "Attempting to acquire access token using app-based authentication"
                                    $ClientCredential = New-Object -TypeName "Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential" -ArgumentList ($ClientID, $ClientSecret) -ErrorAction Stop

                                    # Acquire access token
                                    $AuthenticationResult = ($AuthenticationContext.AcquireTokenAsync($Resource, $ClientCredential)).Result
                                }
                            }
                            
                            # Check if access token was acquired
                            if ($AuthenticationResult.AccessToken -ne $null) {
                                Write-Verbose -Message "Successfully acquired an access token for authentication"

                                # Construct authentication hash table for holding access token and header information
                                $Authentication = @{
                                    "Content-Type" = "application/json"
                                    "Authorization" = -join("Bearer ", $AuthenticationResult.AccessToken)
                                    "ExpiresOn" = $AuthenticationResult.ExpiresOn
                                }
            
                                # Return the authentication token
                                return $Authentication                    
                            }
                            else {
                                Write-Warning -Message "Failure to acquire access token. Response with access token was null"; break
                            }
                        }
                        catch [System.Exception] {
                            Write-Warning -Message "An error occurred when attempting to call AcquireTokenAsync method. Error message: $($_.Exception.Message)"; break
                        }
                    }
                    catch [System.Exception] {
                        Write-Warning -Message "An error occurred when constructing an authentication token. Error message: $($_.Exception.Message)"; break
                    }
                }
                catch [System.Exception] {
                    Write-Warning -Message "Unable to load required assemblies from AzureAD module to construct an authentication token. Error message: $($_.Exception.Message)"; break
                }
            }
            else {
                Write-Warning -Message "Azure AD PowerShell module is not present on this system, please install before you continue"; break
            }
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to load required AzureAD module to for retrieving an authentication token. Error message: $($_.Exception.Message)"; break
        }
    }
}

function Set-MSIntuneAdminConsent {
    <#
    .SYNOPSIS
        Grant admin consent for delegated admin permissions.
        NOTE: This function requires that AzureAD module is installed. Use 'Install-Module -Name AzureAD' to install it.

    .PARAMETER TenantName
        A tenant name should be provided in the following format: tenantname.onmicrosoft.com.

    .PARAMETER ClientID
        Specify a Global Admin user principal name.

    .EXAMPLE
        # Grant admin consent for delegated admin permissions for an Intune tenant:
        Set-MSIntuneAdminConsent -TenantName domain.onmicrsoft.com -UserPrincipalName "globaladmin@domain.onmicrosoft.com"

    .NOTES
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2018-01-28
    Updated:     2018-01-28

    Version history:
    1.0.0 - (2018-01-28) Function created
    1.0.1 - (2018-01-28) Added static prompt behavior parameter with value of Auto

    #>
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true, HelpMessage="A tenant name should be provided in the following format: tenantname.onmicrosoft.com.")]
        [ValidateNotNullOrEmpty()]
        [string]$TenantName,

        [parameter(Mandatory=$true, HelpMessage="Specify a Global Admin user principal name.")]
        [ValidateNotNullOrEmpty()]
        [string]$UserPrincipalName
    )

    try {
        # Get installed Azure AD modules
        $AzureADModules = Get-Module -Name "AzureAD" -ListAvailable -ErrorAction Stop -Verbose:$false

        if ($AzureADModules -ne $null) {
            # Check if multiple modules exist and determine the module path for the most current version
            if (($AzureADModules | Measure-Object).Count -gt 1) {
                $LatestAzureADModule = ($AzureADModules | Select-Object -Property Version | Sort-Object)[-1]
                $AzureADModulePath = $AzureADModules | Where-Object { $_.Version -like $LatestAzureADModule.Version } | Select-Object -ExpandProperty ModuleBase
            }
            else {
                $AzureADModulePath = Get-Module -Name "AzureAD" -ListAvailable -ErrorAction Stop -Verbose:$false | Select-Object -ExpandProperty ModuleBase
            }

            # Construct array for required assemblies from Azure AD module
            $Assemblies = @(
                (Join-Path -Path $AzureADModulePath -ChildPath "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"),
                (Join-Path -Path $AzureADModulePath -ChildPath "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll")
            )
            Add-Type -Path $Assemblies -ErrorAction Stop

            try {
                # Set static variables
                $Authority = "https://login.microsoftonline.com/$($TenantName)/oauth2/token"
                $ResourceRecipient = "https://graph.microsoft.com"
                $RedirectUri = "urn:ietf:wg:oauth:2.0:oob"
                $ClientID = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547" # Default Microsoft Intune PowerShell enterprise application

                # Construct new authentication context
                $AuthenticationContext = New-Object -TypeName "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $Authority -ErrorAction Stop

                # Construct platform parameters
                $PlatformParams = New-Object -TypeName "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto" -ErrorAction Stop

                # Construct user identifier
                $UserIdentifier = New-Object -TypeName "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($UserPrincipalName, "OptionalDisplayableId")

                # Acquire authentication token and invoke admin consent
                $AuthenticationResult = ($AuthenticationContext.AcquireTokenAsync($ResourceRecipient, $ClientID, $RedirectUri, $PlatformParams, $UserIdentifier, "prompt=admin_consent")).Result
               
                # Check if access token was acquired
                if ($AuthenticationResult.AccessToken -ne $null) {
                    # Construct authentication hash table for holding access token and header information
                    $Authentication = @{
                        "Content-Type" = "application/json"
                        "Authorization" = -join("Bearer ", $AuthenticationResult.AccessToken)
                        "ExpiresOn" = $AuthenticationResult.ExpiresOn
                    }

                    # Return the authentication token
                    return $Authentication                    
                }
                else {
                    Write-Warning -Message "Failure to acquire access token. Response with access token was null" ; break
                }
            }
            catch [System.Exception] {
                Write-Warning -Message "An error occurred when constructing an authentication token: $($_.Exception.Message)" ; break
            }
        }
        else {
            Write-Warning -Message "Azure AD PowerShell module is not present on this system, please install before you continue" ; break
        }
    }
    catch [System.Exception] {
        Write-Warning -Message "Unable to load required assemblies (Azure AD PowerShell module) to construct an authentication token. Error: $($_.Exception.Message)" ; break
    }    
}