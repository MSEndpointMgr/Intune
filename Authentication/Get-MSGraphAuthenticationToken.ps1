function Get-MSGraphAuthenticationToken {
    <#
    .SYNOPSIS
        Get an authentication token required for interacting with Microsoft Intune using Microsoft Graph API
        NOTE: This function requires that AzureAD module is installed. Use 'Install-Module -Name AzureAD' to install it.

    .PARAMETER TenantName
        A tenant name should be provided in the following format: tenantname.onmicrosoft.com.

    .PARAMETER ClientID
        Application ID for an Azure AD application.

    .PARAMETER RedirectUri
        Redirect URI for Azure AD application. Leave empty to leverage Azure PowerShell well known redirect URI.

    .EXAMPLE
        Get-MSGraphAuthenticationToken -TenantName domain.onmicrsoft.com -ClientID "<GUID>"

    .NOTES
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2017-09-27
    Updated:     2017-09-27

    Version history:
    1.0.0 - (2017-09-27) Script created
    1.0.1 - (2017-09-28) N/A - module manifest update
    1.0.2 - (2017-10-08) Added ExpiresOn property

    #>
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true, HelpMessage="A tenant name should be provided in the following format: tenantname.onmicrosoft.com.")]
        [ValidateNotNullOrEmpty()]
        [string]$TenantName,

        [parameter(Mandatory=$true, HelpMessage="Application ID for an Azure AD application.")]
        [ValidateNotNullOrEmpty()]
        [string]$ClientID,

        [parameter(Mandatory=$false, HelpMessage="Redirect URI for Azure AD application. Leave empty to leverage Azure PowerShell well known redirect URI.")]
        [ValidateNotNullOrEmpty()]
        [string]$RedirectUri = "urn:ietf:wg:oauth:2.0:oob"
    )

    try {
        # Get installed Azure AD modules
        $AzureADModules = Get-InstalledModule -Name "AzureAD" -ErrorAction Stop -Verbose:$false

        if ($AzureADModules -ne $null) {
            # Check if multiple modules exist and determine the module path for the most current version
            if (($AzureADModules | Measure-Object).Count -gt 1) {
                $LatestAzureADModule = ($AzureADModules | Select-Object -Property Version | Sort-Object)[-1]
                $AzureADModulePath = $AzureADModules | Where-Object { $_.Version -like $LatestAzureADModule.Version } | Select-Object -ExpandProperty InstalledLocation
            }
            else {
                $AzureADModulePath = Get-InstalledModule -Name "AzureAD" | Select-Object -ExpandProperty InstalledLocation
            }

            # Construct array for required assemblies from Azure AD module
            $Assemblies = @(
                (Join-Path -Path $AzureADModulePath -ChildPath "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"),
                (Join-Path -Path $AzureADModulePath -ChildPath "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll")
            )
            Add-Type -Path $Assemblies -ErrorAction Stop

            try {
                $Authority = "https://login.microsoftonline.com/$($TenantName)/oauth2/token"
                $ResourceRecipient = "https://graph.microsoft.com"

                # Construct new authentication context
                $AuthenticationContext = New-Object -TypeName "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $Authority

                # Construct platform parameters
                $PlatformParams = New-Object -TypeName "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Always" # Arguments: Auto, Always, Never, RefreshSession

                # Acquire access token
                $AuthenticationResult = ($AuthenticationContext.AcquireTokenAsync($ResourceRecipient, $ClientID, $RedirectUri, $PlatformParams)).Result
                
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