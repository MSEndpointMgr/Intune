<#
.SYNOPSIS


.DESCRIPTION


.PARAMETER TenantName
    Specify the tenant name, e.g. domain.onmicrosoft.com.

.PARAMETER ApplicationID
    Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration.

.PARAMETER PromptBehavior
    Set the prompt behavior when acquiring a token.

.EXAMPLE
    

.NOTES
    FileName:    <script name>.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2019-10-01
    Updated:     2019-10-01
    
    Version history:
    1.0.0 - (2019-10-01) Script created

    Required modules:
    AzureAD (Install-Module -Name AzureAD)
    PSIntuneAuth (Install-Module -Name PSIntuneAuth)
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [parameter(Mandatory = $true, HelpMessage = "Specify the tenant name, e.g. domain.onmicrosoft.com.")]
    [ValidateNotNullOrEmpty()]
    [string]$TenantName,

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

    # Construct Graph variables
    $GraphVersion = "beta"
    $GraphResource = ""
    $GraphURI = "https://graph.microsoft.com/$($GraphVersion)/$($GraphResource)"

    #
    # Main code
    #

    try {
        #
        # Select either the POST or GET method below depending on purpose of the script
        #

        # Call Graph API and post JSON response
        $GraphResponse = Invoke-RestMethod -Uri $GraphURI -Headers $AuthToken -Method Post -Body $Body -ContentType "application/json" -ErrorAction Stop -Verbose:$false

        # Call Graph API and get JSON response
        $GraphResponse = Invoke-RestMethod -Uri $GraphURI -Headers $AuthToken -Method Get -ErrorAction Stop -Verbose:$false
        
        # Handle return objects from response
        $GraphResponse.value
    }
    catch [System.Exception] {
        # Construct stream reader for reading the response body from API call
        $ResponseBody = Get-ErrorResponseBody -Exception $_.Exception

        # Handle response output and error message
        Write-Output -InputObject "Response content:`n$ResponseBody"
        Write-Warning -Message "Request to $($GraphURI) failed with HTTP Status $($_.Exception.Response.StatusCode) and description: $($_.Exception.Response.StatusDescription)"
    }
}