function Save-IntuneWin32AppContent {
    <#
    .SYNOPSIS
        Download the content (.intunewin file) associated with a specific Win32 app.

    .DESCRIPTION
        Download the content (.intunewin file) associated with a specific Win32 app.

    .PARAMETER TenantName
        Specify the tenant name, e.g. domain.onmicrosoft.com.

    .PARAMETER ID
        Specify the ID for a Win32 application.

    .PARAMETER Path
        Specify the download path where the Win32 application content will be placed.

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
        [parameter(Mandatory = $true, HelpMessage = "Specify the tenant name, e.g. domain.onmicrosoft.com.")]

        [ValidateNotNullOrEmpty()]
        [string]$TenantName,

        [parameter(Mandatory = $true, HelpMessage = "Specify the ID for a Win32 application.")]
        [ValidateNotNullOrEmpty()]
        [string]$ID,

        [parameter(Mandatory = $true, HelpMessage = "Specify the download path where the Win32 application content will be placed.")]
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
        
        [parameter(Mandatory = $false, HelpMessage = "Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration.")]
        [ValidateNotNullOrEmpty()]
        [string]$ApplicationID = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547",
    
        [parameter(Mandatory = $false, HelpMessage = "Set the prompt behavior when acquiring a token.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Auto", "Always", "Never", "RefreshSession")]
        [string]$PromptBehavior = "Auto"
    )
    Begin {
        # Ensure required auth token exists or retrieve a new one
        Get-AuthToken -TenantName $TenantName -ApplicationID $ApplicationID -PromptBehavior $PromptBehavior
    }
    Process {
        Write-Verbose -Message "Attempting to locate content files for Win32 app with ID: $($ID)"
        $Win32AppContentVersions = (Invoke-IntuneGraphRequest -APIVersion "Beta" -Resource "mobileApps/$($ID)/microsoft.graph.win32LobApp/contentVersions" -Method "GET").value
        if ($Win32AppContentVersions -ne $null) {
            switch ($Win32AppContentVersions.Count) {
                0 {
                    Write-Warning -Message "Unable to locate any contentVersions resources for specified Win32 app"
                }
                1 {
                    Write-Verbose -Message "Located contentVersions resource with ID: $($Win32AppContentVersions.id)"
                    $Win32AppContentVersionID = $Win32AppContentVersions.id
                }
                default {
                    Write-Verbose -Message "Located '$($Win32AppContentVersions.Count)' contentVersions resources for specified Win32 app, attempting to determine the latest item"
                    $Win32AppContentVersionID = $Win32AppContentVersions | Sort-Object -Property id -Descending | Select-Object -First 1 -ExpandProperty id
                }
            }

            if ($Win32AppContentVersions.Count -ge 1) {
                Write-Verbose -Message "Attempting to locate latest files details using contentVersions ID: $($Win32AppContentVersionID)"
                $Win32AppContentVersionsFiles = (Invoke-IntuneGraphRequest -APIVersion "Beta" -Resource "mobileApps/$($ID)/microsoft.graph.win32LobApp/contentVersions/$($Win32AppContentVersionID)/files" -Method "GET").value
                if ($Win32AppContentVersionsFiles -ne $null) {
                    foreach ($Win32AppContentVersionsFile in $Win32AppContentVersionsFiles) {
                        $ValidateContentVersionsFile = Test-IntuneGraphRequest -APIVersion "Beta" -Resource "mobileApps/$($ID)/microsoft.graph.win32LobApp/contentVersions/$($Win32AppContentVersionID)/files/$($Win32AppContentVersionsFile.id)"
                        if ($ValidateContentVersionsFile -eq $true) {
                            $Win32AppContentVersionsFileResource = Invoke-IntuneGraphRequest -APIVersion "Beta" -Resource "mobileApps/$($ID)/microsoft.graph.win32LobApp/contentVersions/$($Win32AppContentVersionID)/files/$($Win32AppContentVersionsFile.id)" -Method "GET"
                            if ($Win32AppContentVersionsFileResource -ne $null) {
                                # Start download of .intunewin content file
                                Write-Verbose -Message "Attempting to download '$($Win32AppContentVersionsFileResource.name)' from: $($Win32AppContentVersionsFileResource.azureStorageUri)"
                                Start-DownloadFile -URL $Win32AppContentVersionsFileResource.azureStorageUri -Path $Path -Name $Win32AppContentVersionsFileResource.name
                            }
                        }
                    }
                }
                else {
                    Write-Warning -Message "Unable to locate any contentVersions resources"
                }
            }
        }
    }
}