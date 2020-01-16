function Get-AuthToken {
    <#
    .SYNOPSIS
        Get an authorization token from Azure AD.

    .DESCRIPTION
        Get an authorization token from Azure AD.

    .PARAMETER TenantName
        Specify the tenant name, e.g. domain.onmicrosoft.com."

    .PARAMETER ApplicationID
        Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration.

    .PARAMETER PromptBehavior
        Set the prompt behavior when acquiring a token.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>    
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the tenant name, e.g. domain.onmicrosoft.com.")]
        [ValidateNotNullOrEmpty()]
        [string]$TenantName,

        [parameter(Mandatory = $false, HelpMessage = "Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration.")]
        [ValidateNotNullOrEmpty()]
        [string]$ApplicationID = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547",
    
        [parameter(Mandatory = $false, HelpMessage = "Set the prompt behavior when acquiring a token.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Auto", "Always", "Never", "RefreshSession")]
        [string]$PromptBehavior = "Auto"
    )
    # Determine if the PSIntuneAuth module needs to be installed
    try {
        Write-Verbose -Message "Attempting to locate PSIntuneAuth module"
        $PSIntuneAuthModule = Get-InstalledModule -Name "PSIntuneAuth" -ErrorAction Stop -Verbose:$false
        if ($PSIntuneAuthModule -ne $null) {
            Write-Verbose -Message "Authentication module detected, checking for latest version"
            $LatestModuleVersion = (Find-Module -Name "PSIntuneAuth" -ErrorAction Stop -Verbose:$false).Version
            if ($LatestModuleVersion -gt $PSIntuneAuthModule.Version) {
                Write-Verbose -Message "Latest version of PSIntuneAuth module is not installed, attempting to install: $($LatestModuleVersion.ToString())"
                $UpdateModuleInvocation = Update-Module -Name "PSIntuneAuth" -Scope "AllUsers" -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
            }
        }
    }
    catch [System.Exception] {
        Write-Warning -Message "Unable to detect PSIntuneAuth module, attempting to install from PSGallery"
        try {
            # Install NuGet package provider
            $PackageProvider = Install-PackageProvider -Name "NuGet" -Force -Verbose:$false

            # Install PSIntuneAuth module
            Install-Module -Name "PSIntuneAuth" -Scope "AllUsers" -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
            Write-Verbose -Message "Successfully installed PSIntuneAuth module"
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

function Get-ErrorResponseBody {
    <#
    .SYNOPSIS
        Get error details from Graph invocation.

    .DESCRIPTION
        Get error details from Graph invocation.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>      
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

function New-IntuneWin32AppPackage {
    <#
    .SYNOPSIS
        Package an application as a Win32 application container (.intunewin) for usage with Microsoft Intune.

    .DESCRIPTION
        Package an application as a Win32 application container (.intunewin) for usage with Microsoft Intune.

    .PARAMETER SourceFolder
        Specify the full path of the source folder where the setup file and all of it's potential dependency files reside.

    .PARAMETER SetupFile
        Specify the complete setup file name including it's file extension, e.g. Setup.exe or Installer.msi.

    .PARAMETER OutputFolder
        Specify the full path of the output folder where the packaged .intunewin file will be exported to.

    .PARAMETER IntuneWinAppUtilPath
        Specify the full path to the IntuneWinAppUtil.exe file.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>    
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the full path of the source folder where the setup file and all of it's potential dependency files reside.")]
        [ValidateNotNullOrEmpty()]
        [string]$SourceFolder,

        [parameter(Mandatory = $true, HelpMessage = "Specify the complete setup file name including it's file extension, e.g. Setup.exe or Installer.msi.")]
        [ValidateNotNullOrEmpty()]
        [string]$SetupFile,

        [parameter(Mandatory = $true, HelpMessage = "Specify the full path of the output folder where the packaged .intunewin file will be exported to.")]
        [ValidateNotNullOrEmpty()]
        [string]$OutputFolder,

        [parameter(Mandatory = $false, HelpMessage = "Specify the full path to the IntuneWinAppUtil.exe file.")]
        [ValidateNotNullOrEmpty()]
        [string]$IntuneWinAppUtilPath = (Join-Path -Path $env:TEMP -ChildPath "IntuneWinAppUtil.exe")
    )
    Process {
        if (Test-Path -Path $SourceFolder) {
            Write-Verbose -Message "Successfully detected specified source folder: $($SourceFolder)"

            if (Test-Path -Path (Join-Path -Path $SourceFolder -ChildPath $SetupFile)) {
                Write-Verbose -Message "Successfully detected specified setup file '$($SetupFile)' in source folder"

                if (Test-Path -Path $OutputFolder) {
                    Write-Verbose -Message "Successfully detected specified output folder: $($OutputFolder)"

                    if (-not(Test-Path -Path $IntuneWinAppUtilPath)) {                      
                        if (-not($PSBoundParameters["IntuneWinAppUtilPath"])) {
                            # Download IntuneWinAppUtil.exe if not present in context temporary folder
                            Write-Verbose -Message "Unable to detect IntuneWinAppUtil.exe in specified location, attempting to download to: $($env:TEMP)"
                            Start-DownloadFile -URL "https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool/raw/master/IntuneWinAppUtil.exe" -Path $env:TEMP -Name "IntuneWinAppUtil.exe"

                            # Override path for IntuneWinApputil.exe if custom path was passed as a parameter, but was not found and downloaded to temporary location
                            $IntuneWinAppUtilPath = Join-Path -Path $env:TEMP -ChildPath "IntuneWinAppUtil.exe"
                        }
                    }

                    if (Test-Path -Path $IntuneWinAppUtilPath) {
                        Write-Verbose -Message "Successfully detected IntuneWinAppUtil.exe in: $($IntuneWinAppUtilPath)"

                        # Invoke IntuneWinAppUtil.exe with parameter inputs
                        $PackageInvocation = Invoke-Executable -FilePath $IntuneWinAppUtilPath -Arguments "-c ""$($SourceFolder)"" -s ""$($SetupFile)"" -o ""$($OutPutFolder)""" # -q
                        if ($PackageInvocation -eq 0) {
                            $IntuneWinAppPackage = Join-Path -Path $OutputFolder -ChildPath "$([System.IO.Path]::GetFileNameWithoutExtension($SetupFile)).intunewin"
                            if (Test-Path -Path $IntuneWinAppPackage) {
                                Write-Verbose -Message "Successfully created Win32 app package object"

                                # Retrieve Win32 app package meta data
                                $IntuneWinAppMetaData = Get-IntuneWin32AppMetaData -FilePath $IntuneWinAppPackage

                                # Construct output object with package details
                                $PSObject = [PSCustomObject]@{
                                    "Name" = $IntuneWinAppMetaData.ApplicationInfo.Name
                                    "FileName" = $IntuneWinAppMetaData.ApplicationInfo.FileName
                                    "SetupFile" = $IntuneWinAppMetaData.ApplicationInfo.SetupFile
                                    "UnencryptedContentSize" = $IntuneWinAppMetaData.ApplicationInfo.UnencryptedContentSize
                                    "Path" = $IntuneWinAppPackage
                                }
                                Write-Output -InputObject $PSObject
                            }
                            else {
                                Write-Warning -Message "Unable to detect expected '$($SetupFile).intunewin' file after IntuneWinAppUtil.exe invocation"
                            }
                        }
                        else {
                            Write-Warning -Message "Unexpect error occurred while packaging Win32 app. Return code from invocation: $($PackageInvocation)"
                        }
                    }
                    else {
                        Write-Warning -Message "Unable to detect IntuneWinAppUtil.exe in: $($IntuneWinAppUtilPath)"
                    }
                }
                else {
                    Write-Warning -Message "Unable to detect specified output folder: $($OutputFolder)"
                }
            }
            else {
                Write-Warning -Message "Unable to detect specified setup file '$($SetupFile)' in source folder: $($SourceFolder)"
            }
        }
        else {
            Write-Warning -Message "Unable to detect specified source folder: $($SourceFolder)"
        }
    }
}

function Get-IntuneWin32App {
    <#
    .SYNOPSIS
        Get all or a specific Win32 app by either DisplayName or ID.

    .DESCRIPTION
        Get all or a specific Win32 app by either DisplayName or ID.

    .PARAMETER TenantName
        Specify the tenant name, e.g. domain.onmicrosoft.com.

    .PARAMETER DisplayName
        Specify the display name for a Win32 application.

    .PARAMETER ID
        Specify the ID for a Win32 application.

    .PARAMETER ApplicationID
        Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration.

    .PARAMETER PromptBehavior
        Set the prompt behavior when acquiring a token.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>
    [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = "Default")]
    param(
        [parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage = "Specify the tenant name, e.g. domain.onmicrosoft.com.")]
        [parameter(Mandatory = $true, ParameterSetName = "DisplayName")]
        [parameter(Mandatory = $true, ParameterSetName = "ID")]
        [ValidateNotNullOrEmpty()]
        [string]$TenantName,

        [parameter(Mandatory = $true, ParameterSetName = "DisplayName", HelpMessage = "Specify the display name for a Win32 application.")]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName,

        [parameter(Mandatory = $true, ParameterSetName = "ID", HelpMessage = "Specify the ID for a Win32 application.")]
        [ValidateNotNullOrEmpty()]
        [string]$ID,
        
        [parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration.")]
        [parameter(Mandatory = $false, ParameterSetName = "DisplayName")]
        [parameter(Mandatory = $false, ParameterSetName = "ID")]
        [ValidateNotNullOrEmpty()]
        [string]$ApplicationID = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547",
    
        [parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Set the prompt behavior when acquiring a token.")]
        [parameter(Mandatory = $false, ParameterSetName = "DisplayName")]
        [parameter(Mandatory = $false, ParameterSetName = "ID")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Auto", "Always", "Never", "RefreshSession")]
        [string]$PromptBehavior = "Auto"        
    )
    Begin {
        # Ensure required auth token exists or retrieve a new one
        Get-AuthToken -TenantName $TenantName -ApplicationID $ApplicationID -PromptBehavior $PromptBehavior
    }
    Process {
        Write-Verbose -Message "Attempting to retrieve all mobileApps resources"
        $MobileApps = Invoke-IntuneGraphRequest -APIVersion "Beta" -Resource "mobileApps" -Method "GET"
        if ($MobileApps.value.Count -ge 1) {
            Write-Verbose -Message "Filtering query response for mobileApps matching type '#microsoft.graph.win32LobApp'"
            $Win32MobileApps = $MobileApps.value | Where-Object { $_.'@odata.type' -like "#microsoft.graph.win32LobApp" }
            if ($Win32MobileApps -ne $null) {
                switch ($PSCmdlet.ParameterSetName) {
                    "DisplayName" {
                        Write-Verbose -Message "Querying for Win32 apps matching displayName: $($DisplayName)"
                        $Win32App = $Win32MobileApps | Where-Object { $_.displayName -like "*$($DisplayName)*" }
                    }
                    "ID" {
                        Write-Verbose -Message "Querying for Win32 apps matching id: $($ID)"
                        $Win32App = $Win32MobileApps | Where-Object { $_.id -like $ID }
                    }
                    default {
                        Write-Verbose -Message "Querying for all Win32 apps"
                        $Win32App = $Win32MobileApps
                    }
                }
    
                # Handle return value
                if ($Win32App -ne $null) {
                    return $Win32App
                }
                else {
                    Write-Warning -Message "Query for Win32 apps returned empty a result, no apps matching the specified search criteria was found"
                }
            }
            else {
                Write-Warning -Message "Query for Win32 apps returned empty a result, no apps matching type 'win32LobApp' was found in tenant"
            }
        }
        else {
            Write-Warning -Message "Query for mobileApps resources returned empty"
        }
    }
}

function Add-IntuneWin32AppAssignment {
<#
    .SYNOPSIS
        Add an assignment to a Win32 app.

    .DESCRIPTION
        Add an assignment to a Win32 app.

    .PARAMETER TenantName
        Specify the tenant name, e.g. domain.onmicrosoft.com.

    .PARAMETER DisplayName
        Specify the display name for a Win32 application.

    .PARAMETER ID
        Specify the ID for a Win32 application.

    .PARAMETER Target
        Specify the target of the assignment, either AllUsers or Group.

    .PARAMETER Intent
        Specify the intent of the assignment, either required or available.

    .PARAMETER GroupID
        Specify the ID for an Azure AD group.

    .PARAMETER Notification
        Specify the notification setting for the assignment of the Win32 app.

    .PARAMETER ApplicationID
        Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration.

    .PARAMETER PromptBehavior
        Set the prompt behavior when acquiring a token.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [parameter(Mandatory = $true, ParameterSetName = "DisplayName", HelpMessage = "Specify the tenant name, e.g. domain.onmicrosoft.com.")]
        [parameter(Mandatory = $true, ParameterSetName = "ID")]
        [ValidateNotNullOrEmpty()]
        [string]$TenantName,

        [parameter(Mandatory = $true, ParameterSetName = "DisplayName", HelpMessage = "Specify the display name for a Win32 application.")]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName,

        [parameter(Mandatory = $true, ParameterSetName = "ID", HelpMessage = "Specify the ID for a Win32 application.")]
        [ValidateNotNullOrEmpty()]
        [string]$ID,

        [parameter(Mandatory = $true, ParameterSetName = "DisplayName", HelpMessage = "Specify the target of the assignment, either AllUsers or Group.")]
        [parameter(Mandatory = $true, ParameterSetName = "ID")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("AllUsers", "Group")]
        [string]$Target,

        [parameter(Mandatory = $false, ParameterSetName = "DisplayName", HelpMessage = "Specify the intent of the assignment, either required or available.")]
        [parameter(Mandatory = $false, ParameterSetName = "ID")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("required", "available")]
        [string]$Intent = "available",

        [parameter(Mandatory = $false, ParameterSetName = "DisplayName", HelpMessage = "Specify the ID for an Azure AD group.")]
        [parameter(Mandatory = $false, ParameterSetName = "ID")]
        [ValidateNotNullOrEmpty()]
        [string]$GroupID,

        [parameter(Mandatory = $false, ParameterSetName = "DisplayName", HelpMessage = "Specify the notification setting for the assignment of the Win32 app.")]
        [parameter(Mandatory = $false, ParameterSetName = "ID")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("showAll", "showReboot", "hideAll")]
        [string]$Notification = "showAll",
        
        [parameter(Mandatory = $false, ParameterSetName = "DisplayName", HelpMessage = "Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration.")]
        [parameter(Mandatory = $false, ParameterSetName = "ID")]
        [ValidateNotNullOrEmpty()]
        [string]$ApplicationID = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547",
    
        [parameter(Mandatory = $false, ParameterSetName = "DisplayName", HelpMessage = "Set the prompt behavior when acquiring a token.")]
        [parameter(Mandatory = $false, ParameterSetName = "ID")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Auto", "Always", "Never", "RefreshSession")]
        [string]$PromptBehavior = "Auto"        
    )
    Begin {
        # Ensure required auth token exists or retrieve a new one
        Get-AuthToken -TenantName $TenantName -ApplicationID $ApplicationID -PromptBehavior $PromptBehavior

        # Validate group identifier is passed as input if target is set to Group
        if ($Target -like "Group") {
            if (-not($PSBoundParameters["GroupID"])) {
                Write-Warning -Message "Validation failed for parameter input, target set to Group but GroupID parameter was not specified"
            }
        }
    }
    Process {
        switch ($PSCmdlet.ParameterSetName) {
            "DisplayName" {
                $MobileApps = Invoke-IntuneGraphRequest -APIVersion "Beta" -Resource "mobileApps" -Method "GET"
                if ($MobileApps.value.Count -ge 1) {
                    $Win32MobileApps = $MobileApps.value | Where-Object { $_.'@odata.type' -like "#microsoft.graph.win32LobApp" }
                    if ($Win32MobileApps -ne $null) {
                        $Win32App = $Win32MobileApps | Where-Object { $_.displayName -like $DisplayName }
                        if ($Win32App -ne $null) {
                            Write-Verbose -Message "Detected Win32 app with ID: $($Win32App.id)"
                            $Win32AppID = $Win32App.id
                        }
                        else {
                            Write-Warning -Message "Query for Win32 apps returned empty a result, no apps matching the specified search criteria was found"
                        }
                    }
                    else {
                        Write-Warning -Message "Query for Win32 apps returned empty a result, no apps matching type 'win32LobApp' was found in tenant"
                    }
                }
                else {
                    Write-Warning -Message "Query for mobileApps resources returned empty"
                }
            }
            "ID" {
                $Win32AppID = $ID
            }
        }

        if (-not([string]::IsNullOrEmpty($Win32AppID))) {
            # Determine target property body based on parameter input
            switch ($Target) {
                "AllUsers" {
                    $TargetAssignment = @{
                        "@odata.type" = "#microsoft.graph.allLicensedUsersAssignmentTarget"
                    }                    
                }
                "Group" {
                    $TargetAssignment = @{
                        "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                        "groupId" = $GroupID
                    }
                }
            }

            # Construct table for Win32 app assignment body
            $Win32AppAssignmentBody = [ordered]@{
                "@odata.type" = "#microsoft.graph.mobileAppAssignment"
                "intent" = $Intent
                "source" = "direct"
                "target" = $TargetAssignment
                "settings" = @{
                    "@odata.type" = "#microsoft.graph.win32LobAppAssignmentSettings"
                    "notifications" = $Notification
                    "restartSettings" = $null
                    "installTimeSettings" = $null
                }
            }

            try {
                # Attempt to call Graph and create new assignment for Win32 app
                $Win32AppAssignmentResponse = Invoke-IntuneGraphRequest -APIVersion "Beta" -Resource "mobileApps/$($Win32AppID)/assignments" -Method "POST" -Body ($Win32AppAssignmentBody | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop
                if ($Win32AppAssignmentResponse.id) {
                    Write-Verbose -Message "Successfully created Win32 app assignment with ID: $($Win32AppAssignmentResponse.id)"
                    Write-Output -InputObject $Win32AppAssignmentResponse
                }
            }
            catch [System.Exception] {
                Write-Warning -Message "An error occurred while creating a CryptoStream and writing decoded chunks of data to file: $($TargetFilePath). Error message: $($_.Exception.Message)"
            }
        }
        else {
            Write-Warning -Message "Unable to determine the Win32 app identification for assignment"
        }
    }
}

function Expand-IntuneWin32AppPackage {
    <#
    .SYNOPSIS
        Decode an existing .intunewin file already packaged as a Win32 application and allow it's contents to be extracted.

    .DESCRIPTION
        Decode an existing .intunewin file already packaged as a Win32 application and allow it's contents to be extracted.

    .PARAMETER FilePath
        Specify the full path of the locally available packaged Win32 application, e.g. 'C:\Temp\AppName.intunewin'.

    .PARAMETER Force
        Specify parameter to overwrite existing files already in working directory.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the full path of the locally available packaged Win32 application, e.g. 'C:\Temp\AppName.intunewin'.")]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^[A-Za-z]{1}:\\\w+\\\w+")]
        [ValidateScript({
            # Check if path contains any invalid characters
            if ((Split-Path -Path $_ -Leaf).IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
                Write-Warning -Message "$(Split-Path -Path $_ -Leaf) contains invalid characters"; break
            }
            else {
            # Check if file extension is intunewin
                if ([System.IO.Path]::GetExtension((Split-Path -Path $_ -Leaf)) -like ".intunewin") {
                    return $true
                }
                else {
                    Write-Warning -Message "$(Split-Path -Path $_ -Leaf) contains unsupported file extension. Supported extension is '.intunewin'"; break
                }
            }
        })]
        [string]$FilePath,

        [parameter(Mandatory = $false, HelpMessage = "Specify parameter to overwrite existing files already in working directory.")]
        [switch]$Force
    )
    Begin {
        # Load System.IO.Compression assembly for managing compressed files
        try {
            $ClassImport = Add-Type -AssemblyName "System.IO.Compression.FileSystem" -ErrorAction Stop -Verbose:$false
        }
        catch [System.Exception] {
            Write-Warning -Message "An error occurred while loading System.IO.Compression.FileSystem assembly. Error message: $($_.Exception.Message)"; break
        }

        # Set script variable for error action preference
        $ErrorActionPreference = "Stop"        
    }
    Process {
        if (Test-Path -Path $FilePath) {
            try {
                # Read Win32 app meta data
                Write-Verbose -Message "Attempting to gather required Win32 app meta data from file: $($FilePath)"
                $IntuneWinMetaData = Get-IntuneWin32AppMetaData -FilePath $FilePath -ErrorAction Stop
                if ($IntuneWinMetaData -ne $null) {
                    # Retrieve Base64 encoded encryption key
                    $Base64Key = $IntuneWinMetaData.ApplicationInfo.EncryptionInfo.EncryptionKey
                    Write-Verbose -Message "Found Base64 encoded encryption key from meta data: $($Base64Key)"

                    # Retrieve Base64 encoded initialization vector
                    $Base64IV = $IntuneWinMetaData.ApplicationInfo.EncryptionInfo.InitializationVector
                    Write-Verbose -Message "Found Base64 encoded initialization vector from meta data: $($Base64IV)"

                    try {
                        # Extract encoded .intunewin from Contents folder
                        Write-Verbose -Message "Attempting to extract encoded .intunewin file from inside Contents folder of the Win32 application package"
                        $ExtractedIntuneWinFile = $FilePath + ".extracted"
                        $ZipFile = [System.IO.Compression.ZipFile]::OpenRead($IntuneWinFile)
                        $IntuneWinFileName = Split-Path -Path $FilePath -Leaf
                        $ZipFile.Entries | Where-Object { $_.Name -like $IntuneWinFileName } | ForEach-Object {
                            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, $ExtractedIntuneWinFile, $true)
                        }

                        # Dispose of ZipFile from memory
                        $ZipFile.Dispose()

                        try {
                            # Convert Base64 encryption info to bytes
                            Write-Verbose -Message "Attempting to convert Base64 encoded encryption key and initialization vector secure strings"
                            $Key = [System.Convert]::FromBase64String($Base64Key)
                            $IV = [System.Convert]::FromBase64String($Base64IV)

                            try {
                                # Open target filestream for read/write
                                $TargetFilePath = $FilePath + ".decoded"
                                $TargetFilePathName = Split-Path -Path $TargetFilePath -Leaf
                                if (Test-Path -Path $TargetFilePath) {
                                    if ($PSBoundParameters["Force"]) {
                                        try {
                                            Remove-Item -Path $TargetFilePath -Force -ErrorAction Stop
                                        }
                                        catch [System.Exception] {
                                            Write-Warning -Message "An error occurred while removing existing decoded file: $($TargetFilePathName). Error message: $($_.Exception.Message)"; break
                                        }
                                    }
                                    else {
                                        Write-Warning -Message "Existing file '$($TargetFilePathName)' already exists, use Force parameter to overwrite"; break
                                    }
                                }

                                Write-Verbose -Message "Attempting to create a new decoded .intunewin file: $($TargetFilePath)"
                                [System.IO.FileStream]$FileStreamTarget = [System.IO.File]::Open($TargetFilePath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)

                                try {
                                    # Create AES decryptor
                                    Write-Verbose -Message "Attempting to construct new AES decryptor with encryption key and initialization vector"
                                    $AES = [System.Security.Cryptography.Aes]::Create()
                                    [System.Security.Cryptography.ICryptoTransform]$Decryptor = $AES.CreateDecryptor($Key, $IV)

                                    try {
                                        # Open source filestream for read-only
                                        Write-Verbose -Message "Attepmting to open extracted .intunewin file: $($ExtractedIntuneWinFile)"
                                        [System.IO.FileStream]$FileStreamSource = [System.IO.File]::Open($ExtractedIntuneWinFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
                                        $FileStreamSourceSeek = $FileStreamSource.Seek(48l, [System.IO.SeekOrigin]::Begin)

                                        try {
                                            # Construct new CryptoStream
                                            Write-Verbose -Message "Attempting to create CryptoStream and write decoded chunks of data to file: $($TargetFilePath)"
                                            [System.Security.Cryptography.CryptoStream]$CryptoStream = New-Object -TypeName System.Security.Cryptography.CryptoStream -ArgumentList @($FileStreamTarget, $Decryptor, [System.Security.Cryptography.CryptoStreamMode]::Write) -ErrorAction Stop

                                            # Write all chunks of data to decoded target file
                                            $buffer = New-Object byte[](2097152)
                                            while ($BytesRead = $FileStreamSource.Read($buffer, 0, 2097152)) {
                                                $CryptoStream.Write($buffer, 0, $BytesRead)
                                                $CryptoStream.Flush()
                                            }

                                            # Flush final block in cryptostream
                                            $CryptoStream.FlushFinalBlock()
                                            Write-Verbose -Message "Successfully decoded '$($IntuneWinFileName)' Win32 app package file to: $($TargetFilePath)"
                                        }
                                        catch [System.Exception] {
                                            Write-Warning -Message "An error occurred while creating a CryptoStream and writing decoded chunks of data to file: $($TargetFilePath). Error message: $($_.Exception.Message)"
                                        }
                                    }
                                    catch [System.Exception] {
                                        Write-Warning -Message "An error occurred while opening extracted .intunewin file '$($ExtractedIntuneWinFile)'. Error message: $($_.Exception.Message)"
                                    }
                                }
                                catch [System.Exception] {
                                    Write-Warning -Message "An error occurred while creating AES decryptor. Error message: $($_.Exception.Message)"
                                }
                            }
                            catch [System.Exception] {
                                Write-Warning -Message "An error occurred while creating a new decoded .intunewin file: $($TargetFilePath). Error message: $($_.Exception.Message)"
                            }
                        }
                        catch [System.Exception] {
                            Write-Warning -Message "An error occurred while converting Base64 encoded encryption key and initialization vector secure strings. Error message: $($_.Exception.Message)"
                        }
                    }
                    catch [System.Exception] {
                        Write-Warning -Message "An error occurred while extracing encoded .intunewin file from inside Contents folder of the Win32 application package. Error message: $($_.Exception.Message)"
                    }
                }
            }
            catch [System.Exception] {
                Write-Warning -Message "An error occurred while gathering Win32 app meta data. Error message: $($_.Exception.Message)"
            }
        }
        else {
            Write-Warning -Message "Unable to locate specified .intunewin file"
        }
    }
    End {
        # Dispose of objects and release locks
        if ($CryptoStream -ne $null) {
            $CryptoStream.Dispose()
        }
        if ($FileStreamSource -ne $null) {
            $FileStreamSource.Dispose()
        }
        if ($Decryptor -ne $null) {
            $Decryptor.Dispose()
        }
        if ($FileStreamTarget -ne $null) {
            $FileStreamTarget.Dispose()
        }
        if ($AES -ne $null) {
            $AES.Dispose()
        }

        # Remove extracted intunewin file
        if (Test-Path -Path $ExtractedIntuneWinFile) {
            Remove-Item -Path $ExtractedIntuneWinFile -Force
        }        
    }
}

function Add-IntuneWin32App {
    <#
    .SYNOPSIS
        Create a new Win32 application in Microsoft Intune.

    .DESCRIPTION
        Create a new Win32 application in Microsoft Intune.

    .PARAMETER TenantName
        Specify the tenant name, e.g. domain.onmicrosoft.com.

    .PARAMETER FilePath
        Specify a local path to where the win32 app .intunewin file is located.

    .PARAMETER DisplayName
        Specify a display name for the Win32 application.
    
    .PARAMETER Description
        Specify a description for the Win32 application.
    
    .PARAMETER Publisher
        Specify a publisher name for the Win32 application.
    
    .PARAMETER Developer
        Specify the developer name for the Win32 application.

    .PARAMETER InstallCommandLine
        Specify the install command line for the Win32 application.
    
    .PARAMETER UninstallCommandLine
        Specify the uninstall command line for the Win32 application.

    .PARAMETER InstallExperience
        Specify the install experience for the Win32 application. Supported values are: system or user.
    
    .PARAMETER RestartBehavior
        Specify the restart behavior for the Win32 application. Supported values are: allow, basedOnReturnCode, suppress or force.
    
    .PARAMETER DetectionRule
        Provide an array of a single or multiple OrderedDictionary objects as detection rules that will be used for the Win32 application.

    .PARAMETER ReturnCode
        Provide an array of a single or multiple hash-tables for the Win32 application with return code information.

    .PARAMETER Icon
        Provide a Base64 encoded string of the PNG/JPG/JPEG file.

    .PARAMETER ApplicationID
        Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration.

    .PARAMETER PromptBehavior
        Set the prompt behavior when acquiring a token.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created

        Required modules:
        AzureAD (Install-Module -Name AzureAD)
        PSIntuneAuth (Install-Module -Name PSIntuneAuth)
    #>
    [CmdletBinding(SupportsShouldProcess=$true, DefaultParameterSetName = "MSI")]
    param(
        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the tenant name, e.g. domain.onmicrosoft.com.")]
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [string]$TenantName,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify a local path to where the win32 app .intunewin file is located.")]
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^[A-Za-z]{1}:\\\w+\\\w+")]
        [ValidateScript({
            # Check if path contains any invalid characters
            if ((Split-Path -Path $_ -Leaf).IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
                Write-Warning -Message "$(Split-Path -Path $_ -Leaf) contains invalid characters"; break
            }
            else {
            # Check if file extension is intunewin
                if ([System.IO.Path]::GetExtension((Split-Path -Path $_ -Leaf)) -like ".intunewin") {
                    return $true
                }
                else {
                    Write-Warning -Message "$(Split-Path -Path $_ -Leaf) contains unsupported file extension. Supported extension is '.intunewin'"; break
                }
            }
        })]
        [string]$FilePath,

        [parameter(Mandatory = $false, ParameterSetName = "MSI", HelpMessage = "Specify a display name for the Win32 application.")]
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName,

        [parameter(Mandatory = $false, ParameterSetName = "MSI", HelpMessage = "Specify a description for the Win32 application.")]
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [string]$Description,

        [parameter(Mandatory = $false, ParameterSetName = "MSI", HelpMessage = "Specify a publisher name for the Win32 application.")]
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [string]$Publisher,

        [parameter(Mandatory = $false, ParameterSetName = "MSI", HelpMessage = "Specify the developer name for the Win32 application.")]
        [parameter(Mandatory = $false, ParameterSetName = "EXE")]
        [string]$Developer = [string]::Empty,

        [parameter(Mandatory = $true, ParameterSetName = "EXE", HelpMessage = "Specify the install command line for the Win32 application.")]
        [ValidateNotNullOrEmpty()]
        [string]$InstallCommandLine,

        [parameter(Mandatory = $true, ParameterSetName = "EXE", HelpMessage = "Specify the uninstall command line for the Win32 application.")]
        [ValidateNotNullOrEmpty()]
        [string]$UninstallCommandLine,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the install experience for the Win32 application. Supported values are: system or user.")]
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("system", "user")]
        [string]$InstallExperience,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the restart behavior for the Win32 application. Supported values are: allow, basedOnReturnCode, suppress or force.")]
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("allow", "basedOnReturnCode", "suppress", "force")]
        [string]$RestartBehavior,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Provide an array of a single or multiple OrderedDictionary objects as detection rules that will be used for the Win32 application.")]
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Specialized.OrderedDictionary[]]$DetectionRule,

        [parameter(Mandatory = $false, ParameterSetName = "MSI", HelpMessage = "Provide an array of a single or multiple hash-tables for the Win32 application with return code information.")]
        [parameter(Mandatory = $false, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Hashtable[]]$ReturnCode,

        [parameter(Mandatory = $false, ParameterSetName = "MSI", HelpMessage = "Provide a Base64 encoded string of the PNG/JPG/JPEG file.")]
        [parameter(Mandatory = $false, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [string]$Icon,

        ###
        ### Requirement Rule param here
        ###

        [parameter(Mandatory = $false, ParameterSetName = "MSI", HelpMessage = "Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration.")]
        [parameter(Mandatory = $false, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [string]$ApplicationID = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547",

        [parameter(Mandatory = $false, ParameterSetName = "MSI", HelpMessage = "Set the prompt behavior when acquiring a token.")]
        [parameter(Mandatory = $false, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Auto", "Always", "Never", "RefreshSession")]
        [string]$PromptBehavior = "Auto"
    )
    Begin {
        # Ensure required auth token exists or retrieve a new one
        Get-AuthToken -TenantName $TenantName -ApplicationID $ApplicationID -PromptBehavior $PromptBehavior

        # Set script variable for error action preference
        $ErrorActionPreference = "Stop"
    }
    Process {
        try {
            # Attempt to gather all possible meta data from specified .intunewin file
            Write-Verbose -Message "Attempting to gather additional meta data from .intunewin file: $($FilePath)"
            $IntuneWinXMLMetaData = Get-IntuneWin32AppMetaData -FilePath $FilePath -ErrorAction Stop

            if ($IntuneWinXMLMetaData -ne $null) {
                Write-Verbose -Message "Successfully gathered additional meta data from .intunewin file"

                # Generate Win32 application body data table with different parameters based upon parameter set name
                Write-Verbose -Message "Start constructing basic layout of Win32 app body"
                switch ($PSCmdlet.ParameterSetName) {
                    "MSI" {
                        # Determine the execution context of the MSI installer and define the installation purpose
                        $MSIExecutionContext = $IntuneWinXMLMetaData.ApplicationInfo.MsiInfo.MsiExecutionContext
                        $MSIInstallPurpose = "DualPurpose"
                        switch ($MSIExecutionContext) {
                            "System" {
                                $MSIInstallPurpose = "PerMachine"
                            }
                            "User" {
                                $MSIInstallPurpose = "PerUser"
                            }
                        }

                        # Handle special meta data variable values
                        $MSIRequiresReboot = $IntuneWinXMLMetaData.ApplicationInfo.MsiInfo.MsiRequiresReboot
                        switch ($MSIRequiresReboot) {
                            "true" {
                                $MSIRequiresReboot = $true
                            }
                            "false" {
                                $MSIRequiresReboot = $false
                            }
                        }

                        # Handle special parameter inputs
                        if (-not($PSBoundParameters["DisplayName"])) {
                            $DisplayName = $IntuneWinXMLMetaData.ApplicationInfo.Name
                        }
                        if (-not($PSBoundParameters["Description"])) {
                            $Description = $IntuneWinXMLMetaData.ApplicationInfo.Name
                        }
                        if (-not($PSBoundParameters["Publisher"])) {
                            $Publisher = $IntuneWinXMLMetaData.ApplicationInfo.MsiInfo.MsiPublisher
                        }
                        if (-not($PSBoundParameters["Developer"])) {
                            $Developer = [string]::Empty
                        }
                        
                        # Generate Win32 application body
                        $AppBodySplat = @{
                            "MSI" = $true
                            "DisplayName" = $DisplayName
                            "Description" = $Description
                            "Publisher" = $Publisher
                            "Developer" = $Developer
                            "FileName" = $IntuneWinXMLMetaData.ApplicationInfo.FileName
                            "SetupFileName" = $IntuneWinXMLMetaData.ApplicationInfo.SetupFile
                            "InstallExperience" = $InstallExperience
                            "RestartBehavior" = $RestartBehavior
                            "MSIInstallPurpose" = $MSIInstallPurpose
                            "MSIProductCode" = $IntuneWinXMLMetaData.ApplicationInfo.MsiInfo.MsiProductCode
                            "MSIProductName" = $DisplayName
                            "MSIProductVersion" = $IntuneWinXMLMetaData.ApplicationInfo.MsiInfo.MsiProductVersion
                            "MSIRequiresReboot" = $MSIRequiresReboot
                            "MSIUpgradeCode" = $IntuneWinXMLMetaData.ApplicationInfo.MsiInfo.MsiUpgradeCode
                        }
                        if ($PSBoundParameters["Icon"]) {
                            $AppBodySplat.Add("Icon", $Icon)
                        }

                        $Win32AppBody = New-IntuneWin32AppBody @AppBodySplat
                        Write-Verbose -Message "Constructed the basic layout for 'MSI' Win32 app body type"
                    }
                    "EXE" {
                        # Generate Win32 application body
                        $AppBodySplat = @{
                            "EXE" = $true
                            "DisplayName" = $DisplayName
                            "Description" = $Description
                            "Publisher" = $Publisher
                            "Developer" = $Developer
                            "FileName" = $IntuneWinXMLMetaData.ApplicationInfo.FileName
                            "SetupFileName" = $IntuneWinXMLMetaData.ApplicationInfo.SetupFile
                            "InstallExperience" = $InstallExperience
                            "RestartBehavior" = $RestartBehavior
                            "InstallCommandLine" = $InstallCommandLine
                            "UninstallCommandLine" = $UninstallCommandLine
                        }
                        if ($PSBoundParameters["Icon"]) {
                            $AppBodySplat.Add("Icon", $Icon)
                        }

                        $Win32AppBody = New-IntuneWin32AppBody @AppBodySplat
                        Write-Verbose -Message "Constructed the basic layout for 'EXE' Win32 app body type"
                    }
                }

                # Validate that correct detection rules have been passed on command line, only 1 PowerShell script based detection rule is allowed
                if (($DetectionRule.'@odata.type' -contains "#microsoft.graph.win32LobAppPowerShellScriptDetection") -and (@($DetectionRules).'@odata.type'.Count -gt 1)) {
                    Write-Warning -Message "Multiple PowerShell Script detection rules were detected, this is not a supported configuration"; break
                }
                else {
                    # Add detection rules to Win32 app body object
                    Write-Verbose -Message "Detection rule objects passed validation checks, attempting to add to existing Win32 app body"
                    $Win32AppBody.Add("detectionRules", $DetectionRule)

                    # Retrieve the default return codes for a Win32 app
                    Write-Verbose -Message "Retrieving default set of return codes for Win32 app body construction"
                    $DefaultReturnCodes = Get-IntuneWin32AppDefaultReturnCode

                    # Add custom return codes from parameter input to default set of objects
                    if ($PSBoundParameters["ReturnCode"]) {
                        Write-Verbose -Message "Additional return codes where passed as command line input, adding to array of default return codes"
                        foreach ($ReturnCodeItem in $ReturnCode) {
                            $DefaultReturnCodes += $ReturnCodeItem
                        }
                    }

                    # Add return codes to Win32 app body object
                    Write-Verbose -Message "Adding array of return codes to Win32 app body construction"
                    $Win32AppBody.Add("returnCodes", $DefaultReturnCodes)

                    #
                    ## Placeholder for adding requirement rules here
                    #

                    # Create the Win32 app
                    Write-Verbose -Message "Attempting to create Win32 app using constructed body converted to JSON content"
                    $Win32MobileAppRequest = Invoke-IntuneGraphRequest -APIVersion "Beta" -Resource "mobileApps" -Method "POST" -Body ($Win32AppBody | ConvertTo-Json)
                    if ($Win32MobileAppRequest.'@odata.type' -notlike "#microsoft.graph.win32LobApp") {
                        Write-Warning -Message "Failed to create Win32 app using constructed body. Passing converted body as JSON to output."; break
                        Write-Output -InputObject ($Win32AppBody | ConvertTo-Json)
                    }
                    else {
                        Write-Verbose -Message "Successfully created Win32 app with ID: $($Win32MobileAppRequest.id)"

                        # Create Content Version for the Win32 app
                        Write-Verbose -Message "Attempting to create contentVersions resource for the Win32 app"
                        $Win32MobileAppContentVersionRequest = Invoke-IntuneGraphRequest -APIVersion "Beta" -Resource "mobileApps/$($Win32MobileAppRequest.id)/microsoft.graph.win32LobApp/contentVersions" -Method "POST" -Body "{}"
                        if ([string]::IsNullOrEmpty($Win32MobileAppContentVersionRequest.id)) {
                            Write-Warning -Message "Failed to create contentVersions resource for Win32 app"; break
                        }
                        else {
                            Write-Verbose -Message "Successfully created contentVersions resource with ID: $($Win32MobileAppContentVersionRequest.id)"

                            # Extract compressed .intunewin file to subfolder
                            $IntuneWinFilePath = Expand-IntuneWin32AppCompressedFile -FilePath $FilePath -FileName $IntuneWinXMLMetaData.ApplicationInfo.FileName -FolderName ($IntuneWinXMLMetaData.ApplicationInfo.Name).Replace(".intunewin", "")
                            if ($IntuneWinFilePath -ne $null) {
                                # Create a new file entry in Intune for the upload of the .intunewin file
                                Write-Verbose -Message "Constructing Win32 app content file body for uploading of .intunewin file"
                                $Win32AppFileBody = [ordered]@{
                                    "@odata.type" = "#microsoft.graph.mobileAppContentFile"
                                    "name" = $IntuneWinXMLMetaData.ApplicationInfo.FileName
                                    "size" = [int64]$IntuneWinXMLMetaData.ApplicationInfo.UnencryptedContentSize
                                    "sizeEncrypted" = (Get-Item -Path $IntuneWinFilePath).Length
                                    "manifest" = $null
                                    "isDependency" = $false
                                }

                                # Create the contentVersions files resource
                                $Win32MobileAppFileContentRequest = Invoke-IntuneGraphRequest -APIVersion "Beta" -Resource "mobileApps/$($Win32MobileAppRequest.id)/microsoft.graph.win32LobApp/contentVersions/$($Win32MobileAppContentVersionRequest.id)/files" -Method "POST" -Body ($Win32AppFileBody | ConvertTo-Json)
                                if ([string]::IsNullOrEmpty($Win32MobileAppFileContentRequest.id)) {
                                    Write-Warning -Message "Failed to create Azure Storage blob for contentVersions/files resource for Win32 app"; break
                                }
                                else {
                                    # Wait for the Win32 app file content URI to be created
                                    Write-Verbose -Message "Waiting for Intune service to process contentVersions/files request"
                                    $FilesUri = "mobileApps/$($Win32MobileAppRequest.id)/microsoft.graph.win32LobApp/contentVersions/$($Win32MobileAppContentVersionRequest.id)/files/$($Win32MobileAppFileContentRequest.id)"
                                    $ContentVersionsFiles = Wait-IntuneWin32AppFileProcessing -Stage "AzureStorageUriRequest" -Resource $FilesUri
                                    
                                    # Upload .intunewin file to Azure Storage blob
                                    Invoke-AzureStorageBlobUpload -StorageUri $ContentVersionsFiles.azureStorageUri -FilePath $IntuneWinFilePath -Resource $FilesUri

                                    # Retrieve encryption meta data from .intunewin file
                                    $IntuneWinEncryptionInfo = [ordered]@{
                                        "encryptionKey" = $IntuneWinXMLMetaData.ApplicationInfo.EncryptionInfo.EncryptionKey
                                        "macKey" = $IntuneWinXMLMetaData.ApplicationInfo.EncryptionInfo.macKey
                                        "initializationVector" = $IntuneWinXMLMetaData.ApplicationInfo.EncryptionInfo.initializationVector
                                        "mac" = $IntuneWinXMLMetaData.ApplicationInfo.EncryptionInfo.mac
                                        "profileIdentifier" = "ProfileVersion1"
                                        "fileDigest" = $IntuneWinXMLMetaData.ApplicationInfo.EncryptionInfo.fileDigest
                                        "fileDigestAlgorithm" = $IntuneWinXMLMetaData.ApplicationInfo.EncryptionInfo.fileDigestAlgorithm
                                    }
                                    $IntuneWinFileEncryptionInfo = @{
                                        "fileEncryptionInfo" = $IntuneWinEncryptionInfo
                                    }

                                    # Create file commit request
                                    $CommitResource = "mobileApps/$($Win32MobileAppRequest.id)/microsoft.graph.win32LobApp/contentVersions/$($Win32MobileAppContentVersionRequest.id)/files/$($Win32MobileAppFileContentRequest.id)/commit"
                                    $Win32AppFileCommitRequest = Invoke-IntuneGraphRequest -APIVersion "Beta" -Resource $CommitResource -Method "POST" -Body ($IntuneWinFileEncryptionInfo | ConvertTo-Json)

                                    # Wait for Intune service to process the commit file request
                                    Write-Verbose -Message "Waiting for Intune service to process the commit file request"
                                    $CommitFileRequest = Wait-IntuneWin32AppFileProcessing -Stage "CommitFile" -Resource $FilesUri
                                    
                                    # Update committedContentVersion property for Win32 app
                                    Write-Verbose -Message "Updating committedContentVersion property with ID '$($Win32MobileAppContentVersionRequest.id)' for Win32 app with ID: $($Win32MobileAppRequest.id)"
                                    $Win32AppFileCommitBody = [ordered]@{
                                        "@odata.type" = "#microsoft.graph.win32LobApp"
                                        "committedContentVersion" = $Win32MobileAppContentVersionRequest.id
                                    }
                                    $Win32AppFileCommitBodyRequest = Invoke-IntuneGraphRequest -APIVersion "Beta" -Resource "mobileApps/$($Win32MobileAppRequest.id)" -Method "PATCH" -Body ($Win32AppFileCommitBody | ConvertTo-Json)

                                    # Handle return output
                                    Write-Verbose -Message "Successfully created Win32 app and committed file content to Azure Storage blob"
                                    $Win32MobileAppRequest = Invoke-IntuneGraphRequest -APIVersion "Beta" -Resource "mobileApps/$($Win32MobileAppRequest.id)" -Method "GET"
                                    Write-Output -InputObject $Win32MobileAppRequest
                                }
                            }
                        }                     
                    }
                }
            }
        }
        catch [System.Exception] {
            Write-Warning -Message "An error occurred while creating the Win32 application. Error message: $($_.Exception.Message)"
        }
    }
}

function Invoke-Executable {
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the file name or path of the executable to be invoked, including the extension.")]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [parameter(Mandatory = $false, HelpMessage = "Specify arguments that will be passed to the executable.")]
        [ValidateNotNull()]
        [string]$Arguments
    )

    # Construct a hash-table for default parameter splatting
    $SplatArgs = @{
        FilePath = $FilePath
        NoNewWindow = $true
        Passthru = $true
        ErrorAction = "Stop"
    }

    # Add ArgumentList param if present
    if (-not([System.String]::IsNullOrEmpty($Arguments))) {
        $SplatArgs.Add("ArgumentList", $Arguments)
    }

    # Invoke executable and wait for process to exit
    try {
        $Invocation = Start-Process @SplatArgs
        $Handle = $Invocation.Handle
        $Invocation.WaitForExit()
    }
    catch [System.Exception] {
        Write-Warning -Message $_.Exception.Message; break
    }

    return $Invocation.ExitCode
}

function Start-DownloadFile {
    <#
    .SYNOPSIS
        Download a file from a given URL and save it in a specific location.

    .DESCRIPTION
        Download a file from a given URL and save it in a specific location.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>     
    param(
        [parameter(Mandatory = $true, HelpMessage = "URL for the file to be downloaded.")]
        [ValidateNotNullOrEmpty()]
        [string]$URL,

        [parameter(Mandatory = $true, HelpMessage = "Folder where the file will be downloaded.")]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [parameter(Mandatory = $true, HelpMessage = "Name of the file including file extension.")]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
    Begin {
        # Set global variable
        $ErrorActionPreference = "Stop"

        # Construct WebClient object
        $WebClient = New-Object -TypeName System.Net.WebClient
    }
    Process {
        # Create path if it doesn't exist
        if (-not(Test-Path -Path $Path)) {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
        }

        # Register events for tracking download progress
        $Global:DownloadComplete = $false
        $EventDataComplete = Register-ObjectEvent $WebClient DownloadFileCompleted -SourceIdentifier WebClient.DownloadFileComplete -Action {$Global:DownloadComplete = $true}
        $EventDataProgress = Register-ObjectEvent $WebClient DownloadProgressChanged -SourceIdentifier WebClient.DownloadProgressChanged -Action { $Global:DPCEventArgs = $EventArgs }                

        # Start download of file
        $WebClient.DownloadFileAsync($URL, (Join-Path -Path $Path -ChildPath $Name))

        # Track the download progress
        do {
            $PercentComplete = $Global:DPCEventArgs.ProgressPercentage
            $DownloadedBytes = $Global:DPCEventArgs.BytesReceived
            if ($DownloadedBytes -ne $null) {
                Write-Progress -Activity "Downloading file: $($Name)" -Id 1 -Status "Downloaded bytes: $($DownloadedBytes)" -PercentComplete $PercentComplete
            }
        }
        until ($Global:DownloadComplete)
    }
    End {
        # Dispose of the WebClient object
        $WebClient.Dispose()

        # Unregister events used for tracking download progress
        Unregister-Event -SourceIdentifier WebClient.DownloadProgressChanged
        Unregister-Event -SourceIdentifier WebClient.DownloadFileComplete
    }

}

function Invoke-AzureStorageBlobUpload {
    <#
    .SYNOPSIS
        Upload and commit .intunewin file into Azure Storage blob container.

    .DESCRIPTION
        Upload and commit .intunewin file into Azure Storage blob container.

        This is a modified function that was originally developed by Dave Falkus and is available here:
        https://github.com/microsoftgraph/powershell-intune-samples/blob/master/LOB_Application/Win32_Application_Add.ps1        

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>    
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$StorageUri,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Resource
    )
    $ChunkSizeInBytes = 1024l * 1024l * 6l;

    # Start the timer for SAS URI renewal
    $SASRenewalTimer = [System.Diagnostics.Stopwatch]::StartNew()

    # Find the file size and open the file
    $FileSize = (Get-Item -Path $FilePath).Length
    $ChunkCount = [System.Math]::Ceiling($FileSize / $ChunkSizeInBytes)
    $BinaryReader = New-Object -TypeName System.IO.BinaryReader([System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open))
    $Position = $BinaryReader.BaseStream.Seek(0, [System.IO.SeekOrigin]::Begin)

    # Upload each chunk. Check whether a SAS URI renewal is required after each chunk is uploaded and renew if needed
    $ChunkIDs = @()
    for ($Chunk = 0; $Chunk -lt $ChunkCount; $Chunk++) {
        $ChunkID = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($Chunk.ToString("0000")))
        $ChunkIDs += $ChunkID
        $Start = $Chunk * $ChunkSizeInBytes
        $Length = [System.Math]::Min($ChunkSizeInBytes, $FileSize - $Start)
        $Bytes = $BinaryReader.ReadBytes($Length)
        $CurrentChunk = $Chunk + 1

        Write-Progress -Activity "Uploading File to Azure Storage blob" -Status "Uploading chunk $CurrentChunk of $ChunkCount" -PercentComplete ($CurrentChunk / $ChunkCount * 100)
        $UploadResponse = Invoke-AzureStorageBlobUploadChunk -StorageUri $StorageUri -ChunkID $ChunkID -Bytes $Bytes
        if (($CurrentChunk -lt $ChunkCount) -and ($SASRenewalTimer.ElapsedMilliseconds -ge 450000)) {
            Invoke-AzureStorageBlobUploadRenew -Resource $Resource
            $SASRenewalTimer.Restart()
        }
    }

    # Complete write status progress bar
    Write-Progress -Completed -Activity "Uploading File to Azure Storage blob"

    # Finalize the upload of the content file to Azure Storage blob
    Invoke-AzureStorageBlobUploadFinalize -StorageUri $StorageUri -ChunkID $ChunkIDs

    # Close and dispose binary reader object
    $BinaryReader.Close()
    $BinaryReader.Dispose()
}

function Invoke-AzureStorageBlobUploadFinalize {
    <#
    .SYNOPSIS
        Finalize upload of chunks of the .intunewin file into Azure Storage blob container.

    .DESCRIPTION
        Finalize upload of chunks of the .intunewin file into Azure Storage blob container.

        This is a modified function that was originally developed by Dave Falkus and is available here:
        https://github.com/microsoftgraph/powershell-intune-samples/blob/master/LOB_Application/Win32_Application_Add.ps1        

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>    
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$StorageUri,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Object]$ChunkID
    )
    $Uri = "$($StorageUri)&comp=blocklist"
	$Request = "PUT $($Uri)"
	$XML = '<?xml version="1.0" encoding="utf-8"?><BlockList>'
	foreach ($Chunk in $ChunkID) {
		$XML += "<Latest>$($Chunk)</Latest>"
	}
	$XML += '</BlockList>'

	try {
		Invoke-RestMethod -Uri $Uri -Method "Put" -Body $XML
	}
	catch {
		Write-Host -ForegroundColor Red $Request;
		Write-Host -ForegroundColor Red $_.Exception.Message;
		throw;
	}
}

function Invoke-AzureStorageBlobUploadRenew {
    <#
    .SYNOPSIS
        Renew the SAS URI.

    .DESCRIPTION
        Renew the SAS URI.

        This is a modified function that was originally developed by Dave Falkus and is available here:
        https://github.com/microsoftgraph/powershell-intune-samples/blob/master/LOB_Application/Win32_Application_Add.ps1

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>    
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Resource
    )
    $RenewSASURIRequest = Invoke-IntuneGraphRequest -APIVersion "Beta" -Resource "$($Resource)/renewUpload" -Method "POST" -Body ""
    $FilesProcessingRequest = Wait-IntuneWin32AppFileProcessing -Stage "AzureStorageUriRenewal" -Resource $Resource
}

function Invoke-AzureStorageBlobUploadChunk {
    <#
    .SYNOPSIS
        Upload a chunk of the .intunewin file into Azure Storage blob container.

    .DESCRIPTION
        Upload a chunk of the .intunewin file into Azure Storage blob container.

        This is a modified function that was originally developed by Dave Falkus and is available here:
        https://github.com/microsoftgraph/powershell-intune-samples/blob/master/LOB_Application/Win32_Application_Add.ps1

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>    
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$StorageUri,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Object]$ChunkID,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Object]$Bytes
    )
	$Uri = "$($StorageUri)&comp=block&blockid=$($ChunkID)"
	$Request = "PUT $($Uri)"
	$ISOEncoding = [System.Text.Encoding]::GetEncoding("iso-8859-1")
	$EncodedBytes = $ISOEncoding.GetString($Bytes)
	$Headers = @{
		"x-ms-blob-type" = "BlockBlob"
	}

	try	{
		$WebResponse = Invoke-WebRequest $Uri -Method "Put" -Headers $Headers -Body $EncodedBytes
	}
	catch {
        Write-Warning -Message "Failed to upload chunk to Azure Storage blob. Error message: $($_.Exception.Message)"
	} 
}

function Wait-IntuneWin32AppFileProcessing {
    <#
    .SYNOPSIS
        Wait for contentVersions/files resource processing.

    .DESCRIPTION
        Wait for contentVersions/files resource processing.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>    
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Stage,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Resource
    )
    do {
        $GraphRequest = Invoke-IntuneGraphRequest -APIVersion "Beta" -Resource $Resource -Method "GET"
        switch ($GraphRequest.uploadState) {
            "$($Stage)Pending" {
                Write-Verbose -Message "Intune service request for operation '$($Stage)' is in pending state, sleeping for 10 seconds"
                Start-Sleep -Seconds 10
            }
            "$($Stage)Failed" {
                Write-Warning -Message "Intune service request for operation '$($Stage)' failed"
                return $GraphRequest
            }
            "$($Stage)TimedOut" {
                Write-Warning -Message "Intune service request for operation '$($Stage)' timed out"
                return $GraphRequest
            }
        }
    }
    until ($GraphRequest.uploadState -like "$($Stage)Success")
    Write-Verbose -Message "Intune service request for operation '$($Stage)' was successful with uploadState: $($GraphRequest.uploadState)"

    return $GraphRequest
}

function Test-IntuneGraphRequest {
    <#
    .SYNOPSIS
        Test if a certain resource is available in Intune Graph API.

    .DESCRIPTION
        Test if a certain resource is available in Intune Graph API.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Beta", "v1.0")]
        [string]$APIVersion,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Resource
    )
    try {
        # Construct full URI
        $GraphURI = "https://graph.microsoft.com/$($APIVersion)/deviceAppManagement/$($Resource)"

        # Call Graph API and get JSON response
        $GraphResponse = Invoke-RestMethod -Uri $GraphURI -Headers $AuthToken -Method "GET" -ErrorAction Stop -Verbose:$false
        if ($GraphResponse -ne $null) {
            return $true
        }
    }
    catch [System.Exception] {
        return $false
    }
}

function Invoke-IntuneGraphRequest {
    <#
    .SYNOPSIS
        Perform a specific call to Intune Graph API, either as GET, POST or PATCH methods.

    .DESCRIPTION
        Perform a specific call to Intune Graph API, either as GET, POST or PATCH methods.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>    
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Beta", "v1.0")]
        [string]$APIVersion,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Resource,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("GET", "POST", "PATCH")]
        [string]$Method,

        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Object]$Body,

        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("application/json", "image/png")]
        [string]$ContentType = "application/json"
    )
    try {
        # Construct full URI
        $GraphURI = "https://graph.microsoft.com/$($APIVersion)/deviceAppManagement/$($Resource)"
        Write-Verbose -Message "$($Method) $($GraphURI)"

        # Call Graph API and get JSON response
        switch ($Method) {
            "GET" {
                $GraphResponse = Invoke-RestMethod -Uri $GraphURI -Headers $AuthToken -Method $Method -ErrorAction Stop -Verbose:$false
            }
            "POST" {
                $GraphResponse = Invoke-RestMethod -Uri $GraphURI -Headers $AuthToken -Method $Method -Body $Body -ContentType $ContentType -ErrorAction Stop -Verbose:$false
            }
            "PATCH" {
                $GraphResponse = Invoke-RestMethod -Uri $GraphURI -Headers $AuthToken -Method $Method -Body $Body -ContentType $ContentType -ErrorAction Stop -Verbose:$false
            }
        }

        return $GraphResponse
    }
    catch [System.Exception] {
        # Construct stream reader for reading the response body from API call
        $ResponseBody = Get-ErrorResponseBody -Exception $_.Exception

        # Handle response output and error message
        Write-Output -InputObject "Response content:`n$ResponseBody"
        Write-Warning -Message "Request to $($GraphURI) failed with HTTP Status $($_.Exception.Response.StatusCode) and description: $($_.Exception.Response.StatusDescription)"
    }
}

function New-IntuneWin32AppReturnCode {
    <#
    .SYNOPSIS
        Return a hash-table with a specified return code.

    .DESCRIPTION
        Return a hash-table with a specified return code.

    .PARAMETER ReturnCode
        Specify the return code value for the Win32 application body.

    .PARAMETER Type
        Specify the type for the return code value for the Win32 application body. Supported values are: success, softReboot, hardReboot or retry.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the return code value for the Win32 application body.")]
        [ValidateNotNullOrEmpty()]
        [int]$ReturnCode,

        [parameter(Mandatory = $true, HelpMessage = "Specify the type for the return code value for the Win32 application body. Supported values are: success, softReboot, hardReboot or retry.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("success", "softReboot", "hardReboot", "retry")]
        [string]$Type
    )
    $ReturnCodeTable = @{
        "returnCode" = $ReturnCode
        "type" = $Type
    }

    return $ReturnCodeTable
}

function Get-IntuneWin32AppDefaultReturnCode {
    <#
    .SYNOPSIS
        Return an array of default return codes.

    .DESCRIPTION
        Return an array of default return codes.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>
    $ReturnCodeArray = @()
    $ReturnCodeArray += @{ "returnCode" = 0; "type" = "success" }
    $ReturnCodeArray += @{ "returnCode" = 1707; "type" = "success" }
    $ReturnCodeArray += @{ "returnCode" = 3010; "type" = "softReboot" }
    $ReturnCodeArray += @{ "returnCode" = 1641; "type" = "hardReboot" }
    $ReturnCodeArray += @{ "returnCode" = 1618; "type" = "retry" }
    
    return $ReturnCodeArray
}

function New-IntuneWin32AppBody {
    <#
    .SYNOPSIS
        Retrieves meta data from the detection.xml file inside the packaged Win32 application .intunewin file.

    .DESCRIPTION
        Retrieves meta data from the detection.xml file inside the packaged Win32 application .intunewin file.

    .PARAMETER FilePath
        Specify an existing local path to where the win32 app .intunewin file is located.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Define that the Win32 application body will be MSI based.")]
        [switch]$MSI,

        [parameter(Mandatory = $true, ParameterSetName = "EXE", HelpMessage = "Define that the Win32 application body will be File based.")]
        [switch]$EXE,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify a display name for the Win32 application body.")]
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify a description for the Win32 application body.")]
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [string]$Description,        

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify a publisher name for the Win32 application body.")]
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [string]$Publisher,

        [parameter(Mandatory = $false, ParameterSetName = "MSI", HelpMessage = "Specify a developer name for the Win32 application body.")]
        [parameter(Mandatory = $false, ParameterSetName = "EXE")]
        [string]$Developer = [string]::Empty,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the file name (e.g. name.intunewin) for the Win32 application body.")]
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [string]$FileName,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the setup file name (e.g. setup.exe) for the Win32 application body.")]
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [string]$SetupFileName,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the installation experience for the Win32 application body.")]
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("system", "user")]
        [string]$InstallExperience,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the installation experience for the Win32 application body.")]
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("allow", "basedOnReturnCode", "suppress", "force")]
        [string]$RestartBehavior,

        [parameter(Mandatory = $false, ParameterSetName = "MSI", HelpMessage = "Provide a Base64 encoded string as icon for the Win32 application body.")]
        [parameter(Mandatory = $false, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [string]$Icon,

        [parameter(Mandatory = $true, ParameterSetName = "EXE", HelpMessage = "Specify the install command line for the Win32 application body.")]
        [ValidateNotNullOrEmpty()]
        [string]$InstallCommandLine,

        [parameter(Mandatory = $true, ParameterSetName = "EXE", HelpMessage = "Specify the uninstall command line for the Win32 application body.")]
        [ValidateNotNullOrEmpty()]
        [string]$UninstallCommandLine,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the MSI installation purpose for the Win32 application body.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("DualPurpose", "PerMachine", "PerUser")]
        [string]$MSIInstallPurpose,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the MSI product code for the Win32 application body.")]
        [ValidateNotNullOrEmpty()]
        [string]$MSIProductCode,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the MSI product name for the Win32 application body.")]
        [ValidateNotNullOrEmpty()]
        [string]$MSIProductName,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the MSI product version for the Win32 application body.")]
        [ValidateNotNullOrEmpty()]
        [string]$MSIProductVersion,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the MSI requires reboot value for the Win32 application body.")]
        [ValidateNotNullOrEmpty()]
        [bool]$MSIRequiresReboot,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the MSI upgrade code for the Win32 application body.")]
        [ValidateNotNullOrEmpty()]
        [string]$MSIUpgradeCode
    )
    switch ($PSCmdlet.ParameterSetName) {
        "MSI" {
            $Win32AppBody = [ordered]@{
                "@odata.type" = "#microsoft.graph.win32LobApp"
                "applicableArchitectures" = "x64,x86"
                "description" = $Description
                "developer" = $Developer
                "displayName" = $DisplayName
                "fileName" = $FileName
                "setupFilePath" = $SetupFileName
                "installCommandLine" = "msiexec.exe /i `"$SetupFileName`""
                "uninstallCommandLine" = "msiexec.exe /x `"$MSIProductCode`""
                "installExperience" = @{
                    "runAsAccount" = $InstallExperience
                    "deviceRestartBehavior" = $RestartBehavior
                }
                "informationUrl" = $null
                "isFeatured" = $false
                "minimumSupportedOperatingSystem" = @{
                    "v10_1607" = $true
                }
                "msiInformation" = @{
                    "packageType" = $MSIInstallPurpose
                    "productCode" = $MSIProductCode
                    "productName" = $MSIProductName
                    "productVersion" = $MSIProductVersion
                    "publisher" = $MSIPublisher
                    "requiresReboot" = $MSIRequiresReboot
                    "upgradeCode" = $MSIUpgradeCode
                };
                "notes" = ""
                "owner" = ""
                "privacyInformationUrl" = $null
                "publisher" = $Publisher
                "runAs32bit" = $false
            }

            if ($PSBoundParameters["Icon"]) {
                $Win32AppBody.Add("largeIcon", @{
                    "type" = "image/png"
                    "value" = $Icon
                })
            }
        }
        "EXE" {
            $Win32AppBody = [ordered]@{
                "@odata.type" = "#microsoft.graph.win32LobApp"
                "applicableArchitectures" = "x64,x86"
                "description" = $Description
                "developer" = $Developer
                "displayName" = $DisplayName
                "fileName" = $FileName
                "setupFilePath" = $SetupFileName
                "installCommandLine" = $InstallCommandLine
                "uninstallCommandLine" = $UninstallCommandLine
                "installExperience" = @{
                    "runAsAccount" = $InstallExperience
                    "deviceRestartBehavior" = $RestartBehavior
                }
                "informationUrl" = $null
                "isFeatured" = $false
                "minimumSupportedOperatingSystem" = @{
                    "v10_1607" = $true
                }
                "msiInformation" = $null
                "notes" = ""
                "owner" = ""
                "privacyInformationUrl" = $null
                "publisher" = $Publisher
                "runAs32bit" = $false
            }

            if ($PSBoundParameters["Icon"]) {
                $Win32AppBody.Add("largeIcon", @{
                    "type" = "image/png"
                    "value" = $Icon
                })
            }
        }
    }

    # Handle return value with constructed Win32 application body
    return $Win32AppBody
}

function Expand-IntuneWin32AppCompressedFile {
    <#
    .SYNOPSIS
        Expands a named file from inside the packaged Win32 application .intunewin file to a directory named as input from FolderName parameter.

    .DESCRIPTION
        Expands a named file from inside the packaged Win32 application .intunewin file to a directory named as input from FolderName parameter.

    .PARAMETER FilePath
        Specify an existing local path to where the win32 app .intunewin file is located.

    .PARAMETER FileName
        Specify the file name inside of the Win32 app .intunewin file to be expanded.

    .PARAMETER FolderName
        Specify the name of the extraction folder.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify an existing local path to where the win32 app .intunewin file is located.")]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^[A-Za-z]{1}:\\\w+\\\w+")]
        [ValidateScript({
            # Check if path contains any invalid characters
            if ((Split-Path -Path $_ -Leaf).IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
                Write-Warning -Message "$(Split-Path -Path $_ -Leaf) contains invalid characters"; break
            }
            else {
            # Check if file extension is intunewin
                if ([System.IO.Path]::GetExtension((Split-Path -Path $_ -Leaf)) -like ".intunewin") {
                    return $true
                }
                else {
                    Write-Warning -Message "$(Split-Path -Path $_ -Leaf) contains unsupported file extension. Supported extension is '.intunewin'"; break
                }
            }
        })]
        [string]$FilePath,

        [parameter(Mandatory = $true, HelpMessage = "Specify the file name inside of the Win32 app .intunewin file to be expanded.")]
        [ValidateNotNullOrEmpty()]
        [string]$FileName,

        [parameter(Mandatory = $true, HelpMessage = "Specify the name of the extraction folder.")]
        [ValidateNotNullOrEmpty()]
        [string]$FolderName
    )
    Begin {
        # Load System.IO.Compression assembly for managing compressed files
        try {
            $ClassImport = Add-Type -AssemblyName "System.IO.Compression.FileSystem" -ErrorAction Stop -Verbose:$false
        }
        catch [System.Exception] {
            Write-Warning -Message "An error occurred while loading System.IO.Compression.FileSystem assembly. Error message: $($_.Exception.Message)"; break
        }
    }
    Process {
        try {
            # Attemp to open compressed .intunewin archive file from parameter input
            $IntuneWin32AppFile = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
    
            # Construct extraction directory in the same location of the .intunewin file
            $ExtractionFolderPath = Join-Path -Path (Split-Path -Path $FilePath -Parent) -ChildPath $FolderName
            if (-not(Test-Path -Path ($ExtractionFolderPath))) {
                New-Item -Path $ExtractionFolderPath -ItemType Directory -Force | Out-Null
            }

            # Attempt to extract named file from .intunewin file
            try {
                if ($IntuneWin32AppFile -ne $null) {
                    # Determine the detection.xml file inside zip archive
                    $IntuneWin32AppFile.Entries | Where-Object { $_.Name -like $FileName } | ForEach-Object {
                        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, (Join-Path -Path $ExtractionFolderPath -ChildPath $FileName), $true)
                    }
                    $IntuneWin32AppFile.Dispose()
    
                    # Handle return value with XML content from detection.xml
                    return (Join-Path -Path $ExtractionFolderPath -ChildPath $FileName)
                }
            }
            catch [System.Exception] {
                Write-Warning -Message "An error occurred while extracing '$($FileName)' from '$($FilePath)' file. Error message: $($_.Exception.Message)"
            }
        }
        catch [System.Exception] {
            Write-Warning -Message "An error occurred while attempting to open compressed '$($FilePath)' file. Error message: $($_.Exception.Message)"
        }
    }
}

function New-IntuneWin32AppIcon {
    <#
    .SYNOPSIS
        Converts a PNG/JPG/JPEG image file available locally to a Base64 encoded string.

    .DESCRIPTION
        Converts a PNG/JPG/JPEG image file available locally to a Base64 encoded string.

    .PARAMETER FilePath
        Specify an existing local path to where the PNG/JPG/JPEG image file is located.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify an existing local path to where the PNG/JPG/JPEG image file is located.")]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^[A-Za-z]{1}:\\\w+\\\w+")]
        [ValidateScript({
            # Check if path contains any invalid characters
            if ((Split-Path -Path $_ -Leaf).IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
                Write-Warning -Message "$(Split-Path -Path $_ -Leaf) contains invalid characters"; break
            }
            else {
            # Check if file extension is PNG/JPG/JPEG
                $FileExtension = [System.IO.Path]::GetExtension((Split-Path -Path $_ -Leaf))
                if (($FileExtension -like ".png") -or ($FileExtension -like ".jpg") -or ($FileExtension -like ".jpeg")) {
                    return $true
                }
                else {
                    Write-Warning -Message "$(Split-Path -Path $_ -Leaf) contains unsupported file extension. Supported extensions are '.png', '.jpg' and '.jpeg'"; break
                }
            }
        })]
        [string]$FilePath
    )
    # Handle error action preference for non-cmdlet code
    $ErrorActionPreference = "Stop"

    try {
        # Encode image file as Base64 string
        $EncodedBase64String = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("$($FilePath)"))
        Write-Output -InputObject $EncodedBase64String
    }
    catch [System.Exception] {
        Write-Warning -Message "Failed to encode image file to Base64 encoded string. Error message: $($_.Exception.Message)"
    }
}

function Get-IntuneWin32AppMetaData {
    <#
    .SYNOPSIS
        Retrieves meta data from the detection.xml file inside the packaged Win32 application .intunewin file.

    .DESCRIPTION
        Retrieves meta data from the detection.xml file inside the packaged Win32 application .intunewin file.

    .PARAMETER FilePath
        Specify an existing local path to where the Win32 app .intunewin file is located.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify an existing local path to where the win32 app .intunewin file is located.")]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^[A-Za-z]{1}:\\\w+\\\w+")]
        [ValidateScript({
            # Check if path contains any invalid characters
            if ((Split-Path -Path $_ -Leaf).IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
                Write-Warning -Message "$(Split-Path -Path $_ -Leaf) contains invalid characters"; break
            }
            else {
            # Check if file extension is intunewin
                if ([System.IO.Path]::GetExtension((Split-Path -Path $_ -Leaf)) -like ".intunewin") {
                    return $true
                }
                else {
                    Write-Warning -Message "$(Split-Path -Path $_ -Leaf) contains unsupported file extension. Supported extension is '.intunewin'"; break
                }
            }
        })]
        [string]$FilePath
    )
    Begin {
        # Load System.IO.Compression assembly for managing compressed files
        try {
            $ClassImport = Add-Type -AssemblyName "System.IO.Compression.FileSystem" -ErrorAction Stop -Verbose:$false
        }
        catch [System.Exception] {
            Write-Warning -Message "An error occurred while loading System.IO.Compression.FileSystem assembly. Error message: $($_.Exception.Message)"; break
        }
    }
    Process {
        try {
            # Attemp to open compressed .intunewin archive file from parameter input
            $IntuneWin32AppFile = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
    
            # Attempt to extract meta data from .intunewin file
            try {
                if ($IntuneWin32AppFile -ne $null) {
                    # Determine the detection.xml file inside zip archive
                    $DetectionXMLFile = $IntuneWin32AppFile.Entries | Where-Object { $_.Name -like "detection.xml" }
                    
                    # Open the detection.xml file
                    $FileStream = $DetectionXMLFile.Open()
    
                    # Construct new stream reader, pass file stream and read XML content to the end of the file
                    $StreamReader = New-Object -TypeName "System.IO.StreamReader" -ArgumentList $FileStream -ErrorAction Stop
                    $DetectionXMLContent = [xml]($StreamReader.ReadToEnd())
                    
                    # Close and dispose objects to preserve memory usage
                    $FileStream.Close()
                    $StreamReader.Close()
                    $IntuneWin32AppFile.Dispose()
    
                    # Handle return value with XML content from detection.xml
                    return $DetectionXMLContent
                }
            }
            catch [System.Exception] {
                Write-Warning -Message "An error occurred while reading application information from detection.xml file. Error message: $($_.Exception.Message)"
            }
        }
        catch [System.Exception] {
            Write-Warning -Message "An error occurred while attempting to open compressed '$($FilePath)' file. Error message: $($_.Exception.Message)"
        }
    }
}

function New-IntuneWin32AppDetectionRule {
    <#
    .SYNOPSIS
        Construct a new detection rule required for Add-IntuneWin32App cmdlet.

    .DESCRIPTION
        Construct a new detection rule required for Add-IntuneWin32App cmdlet.

    .PARAMETER MSI
        Define that the detection rule will be MSI based.

    .PARAMETER File
        Define that the detection rule will be File based.

    .PARAMETER Registry
        Define that the detection rule will be Registry based.

    .PARAMETER PowerShellScript
        Define that the detection rule will be PowerShell script based.

    .PARAMETER MSIProductCode
        Specify the MSI product code for the application.

    .PARAMETER MSIProductVersionOperator
        Specify the MSI product version operator. Supported values are: notConfigured, equal, notEqual, greaterThanOrEqual, greaterThan, lessThanOrEqual or lessThan.

    .PARAMETER MSIProductVersion
        Specify the MSI product version, e.g. 1.0.0.

    .PARAMETER FilePath
        Specify the path for a folder or file.

    .PARAMETER FileOrFolderName
        Specify the folder or file name.

    .PARAMETER FileDetectionType
        Specify the file detection type. Supported values are: notConfigured, exists, modifiedDate, createdDate, version or sizeInMB.

    .PARAMETER FileDetectionValue
        Specify the file detection value.

    .PARAMETER Check32BitOn64System
        Specify if detection should check for 32-bit on 64-bit systems.

    .PARAMETER RegistryKeyPath
        Specify the registry key path, e.g. 'HKEY_LOCAL_MACHINE\SOFTWARE\Program'.

    .PARAMETER RegistryDetectionType
        Specify the registry detection type. Supported values are: exists, doesNotExist, string, integer or version.

    .PARAMETER RegistryValueName
        Specify the registry value name.

    .PARAMETER Check32BitRegOn64System
        Specify if detection should check for 32-bit on 64-bit system.

    .PARAMETER ScriptFile
        Specify the full path to the PowerShell detection script, e.g. 'C:\Scripts\Detection.ps1'.

    .PARAMETER EnforceSignatureCheck
        Specify if PowerShell script signature check should be enforced.

    .PARAMETER RunAs32Bit
        Specify is PowerShell script should be executed as a 32-bit process.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Define that the detection rule will be MSI based.")]
        [switch]$MSI,

        [parameter(Mandatory = $true, ParameterSetName = "File", HelpMessage = "Define that the detection rule will be File based.")]
        [switch]$File,

        [parameter(Mandatory = $true, ParameterSetName = "Registry", HelpMessage = "Define that the detection rule will be Registry based.")]
        [switch]$Registry,

        [parameter(Mandatory = $true, ParameterSetName = "PowerShell", HelpMessage = "Define that the detection rule will be PowerShell script based.")]
        [switch]$PowerShellScript,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the MSI product code for the application.")]
        [ValidateNotNullOrEmpty()]
        [string]$MSIProductCode,

        [parameter(Mandatory = $false, ParameterSetName = "MSI", HelpMessage = "Specify the MSI product version operator. Supported values are: notConfigured, equal, notEqual, greaterThanOrEqual, greaterThan, lessThanOrEqual or lessThan.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("notConfigured", "equal", "notEqual", "greaterThanOrEqual", "greaterThan", "lessThanOrEqual", "lessThan")]
        [string]$MSIProductVersionOperator = "notConfigured",

        [parameter(Mandatory = $false, ParameterSetName = "MSI", HelpMessage = "Specify the MSI product version, e.g. 1.0.0.")]
        [ValidateNotNullOrEmpty()]
        [string]$MSIProductVersion = [string]::Empty,

        [parameter(Mandatory = $true, ParameterSetName = "File", HelpMessage = "Specify the path for a folder or file.")]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [parameter(Mandatory = $true, ParameterSetName = "File", HelpMessage = "Specify the folder or file name.")]
        [ValidateNotNullOrEmpty()]
        [string]$FileOrFolderName,

        [parameter(Mandatory = $false, ParameterSetName = "File", HelpMessage = "Specify the file detection type. Supported values are: notConfigured, exists, modifiedDate, createdDate, version or sizeInMB.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("notConfigured", "exists", "modifiedDate", "createdDate", "version", "sizeInMB")]
        [string]$FileDetectionType = "notConfigured",

        [parameter(Mandatory = $false, ParameterSetName = "File", HelpMessage = "Specify the file detection value.")]
        [ValidateNotNullOrEmpty()]
        [string]$FileDetectionValue = [string]::Empty,

        [parameter(Mandatory = $false, ParameterSetName = "File", HelpMessage = "Specify if detection should check for 32-bit on 64-bit systems.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("True", "False")]
        [string]$Check32BitOn64System = "False",

        [parameter(Mandatory = $true, ParameterSetName = "Registry", HelpMessage = "Specify the registry key path, e.g. 'HKEY_LOCAL_MACHINE\SOFTWARE\Program'.")]
        [ValidateNotNullOrEmpty()]
        [string]$RegistryKeyPath,
       
        [parameter(Mandatory = $true, ParameterSetName = "Registry", HelpMessage = "Specify the registry detection type. Supported values are: exists, doesNotExist, string, integer or version.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("exists", "doesNotExist", "string", "integer", "version")]
        [string]$RegistryDetectionType,
       
        [parameter(Mandatory = $false, ParameterSetName = "Registry", HelpMessage = "Specify the registry value name.")]
        [ValidateNotNullOrEmpty()]
        [string]$RegistryValueName,
       
        [parameter(Mandatory = $false, ParameterSetName = "Registry", HelpMessage = "Specify if detection should check for 32-bit on 64-bit system.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("True","False")]
        [string]$Check32BitRegOn64System = "False",

        [parameter(Mandatory = $true, ParameterSetName = "PowerShell", HelpMessage = "Specify the full path to the PowerShell detection script, e.g. 'C:\Scripts\Detection.ps1'.")]
        [ValidateNotNullOrEmpty()]
        [string]$ScriptFile,
       
        [parameter(Mandatory = $false, ParameterSetName = "PowerShell", HelpMessage = "Specify if PowerShell script signature check should be enforced.")]
        [ValidateNotNullOrEmpty()]
        [bool]$EnforceSignatureCheck = $false,
       
        [parameter(Mandatory = $false, ParameterSetName = "PowerShell", HelpMessage = "Specify is PowerShell script should be executed as a 32-bit process.")]
        [ValidateNotNullOrEmpty()]
        [bool]$RunAs32Bit = $false
    )
    # Handle initial value for return
    $DetectionRule = $null

    # Determine detection rule generation method based upon parameter set name
    switch ($PSCmdlet.ParameterSetName) {
        "MSI" {
            $DetectionRule = [ordered]@{
                "@odata.type" = "#microsoft.graph.win32LobAppProductCodeDetection"
                "productCode" = $MSIProductCode
                "productVersionOperator" = $MSIProductVersionOperator
                "productVersion" = $MSIProductVersion
            }
        }
        "File" {
            # NOTE: Currently only supports detection method type as "File or folder exists", other methods will be implemented in a future release
            $DetectionRule = [ordered]@{
                "@odata.type" = "#microsoft.graph.win32LobAppFileSystemDetection"
                "check32BitOn64System" = $Check32BitOn64System
                "detectionType" = $FileDetectionType
                "detectionValue" = $FileDetectionValue
                "fileOrFolderName" = $FileOrFolderName
                "operator" = "notConfigured"
                "path" = $FilePath
            }
        }
        "Registry" {
            # NOTE: Currently only supports detection method type as "Key/Value exists", other methods will be implemented in a future release
            $DetectionRule = [ordered]@{
                "@odata.type" = "#microsoft.graph.win32LobAppRegistryDetection"
                "check32BitOn64System" = $Check32BitRegOn64System
                "detectionType" = "exists"
                "detectionValue" = ""
                "keyPath" = $RegistryKeyPath
                "operator" = "notConfigured"
            }

            # Handle valueName property value depending on parameter input
            if ($PSBoundParameters["RegistryValueName"]) {
                $DetectionRule.Add("valueName", $RegistryValueName)
            }
            else {
                $DetectionRule.Add("valueName", [string]::Empty)
            }
        }
        "PowerShell" {
            # Detect if passed script file exists
            if (Test-Path -Path $ScriptFile) {
                # Convert script file contents to base64 string
                $ScriptContent = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("$($ScriptFile)"))

                # Construct detection rule ordered table
                $DetectionRule = [ordered]@{
                    "@odata.type" = "#microsoft.graph.win32LobAppPowerShellScriptDetection"
                    "enforceSignatureCheck" = $EnforceSignatureCheck
                    "runAs32Bit" = $RunAs32Bit
                    "scriptContent" = $ScriptContent
                }
            }
            else {
                Write-Warning -Message "Unable to detect the presence of specified script file"
            }
        }
    }
    
    # Handle return value with constructed detection rule
    return $DetectionRule
}