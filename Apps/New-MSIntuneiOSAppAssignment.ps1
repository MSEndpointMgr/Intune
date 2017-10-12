<#
.SYNOPSIS
    Assign an iOS app in Intune to an Azure AD group.

.DESCRIPTION
    This script will create a new app assignment for an iOS app in Intune for an Azure AD group.

.PARAMETER TenantName
    Specify the tenant name, e.g. domain.onmicrosoft.com.

.PARAMETER ApplicationID
    Application ID property of the application that will be assigned to a given Azure AD group.

.PARAMETER GroupID
    Group ID property of an Azure AD group.

.PARAMETER InstallIntent
    Specify the installation intent for the app assignment. Valid values are: available, notApplicable, required, uninstall, availableWithoutEnrollment.

.PARAMETER ApplicationID
    Specify the Application ID of the app registration in Azure AD. When no parameter is manually passed, script will attempt to use well known Microsoft Intune PowerShell app registration.

.EXAMPLE
    # Assign an iOS app in Intune called 'App1' to an Azure AD group called 'All Users':
    .\New-MSIntuneiOSAppAssignment.ps1 -TenantName "domain.onmicrosoft.com" -AppID "<GUID>" -GroupID "<GUID>" -InstallIntent available

.NOTES
    FileName:    New-MSIntuneiOSAppAssignment.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2017-10-12
    Updated:     2017-10-12
    
    Version history:
    1.0.0 - (2017-10-12) Script created

    Required modules:
    AzureAD (Install-Module -Name AzureAD)        
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [parameter(Mandatory=$true, HelpMessage="Specify the tenant name, e.g. domain.onmicrosoft.com.")]
    [ValidateNotNullOrEmpty()]
    [string]$TenantName,

    [parameter(Mandatory=$true, HelpMessage="Application ID property of the application that will be assigned to a given Azure AD group.")]
    [ValidateNotNullOrEmpty()]
    [string]$AppID,
    
    [parameter(Mandatory=$true, HelpMessage="Group ID property of an Azure AD group.")]
    [ValidateNotNullOrEmpty()]
    [string]$GroupID,

    [parameter(Mandatory=$true, HelpMessage="Specify the installation intent for the app assignment. Valid values are: available, notApplicable, required, uninstall, availableWithoutEnrollment.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("available", "notApplicable", "required", "uninstall", "availableWithoutEnrollment")]
    [string]$InstallIntent,

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
    # Graph URI
    $GraphURI = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($AppID)/groupAssignments"

    # Construct hash-table object of the app assignment
    $AssignmentDataTable = @{
        "@odata.type" = "#microsoft.graph.mobileAppGroupAssignment"
        "targetGroupId" = "$($GroupID)"
        "installIntent" = "$($InstallIntent)"
    }

    # Convert to JSON and create application
    Write-Verbose -Message "Converting hash-table data to JSON"
    $AssignmentDataJSON = ConvertTo-Json -InputObject $AssignmentDataTable
    Write-Verbose -Message "Attempting to create app assignment for app with ID: $($AppID)"
    $InvocationResult = Invoke-RestMethod -Uri $GraphURI -Method Post -ContentType "application/json" -Body $AssignmentDataJSON -Headers $AuthToken
    Write-Verbose -Message "Successfully created app assignment"
}