<#
.SYNOPSIS
    Replace the default img0.jpg wallpaper image in Windows 10, by downloading the new wallpaper stored in an Azure Storage blob.

.DESCRIPTION
    Downloads a single or multiple desktop wallpaper files located in an Azure Storage Blog container to a folder named Wallpaper in ProgramData.

.PARAMETER StorageAccountName
    Name of the Azure Storage Account.

.PARAMETER ContainerName
    Name of the Azure Storage Blob container.

.EXAMPLE
    .\Set-WindowsDesktopWallpaper.ps1

.NOTES
    FileName:    Set-DesktopWallpaperContent.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2020-06-04
    Updated:     2020-11-26

    Version history:
    1.0.0 - (2020-06-04) Script created
    1.1.0 - (2020-11-26) Added support for 4K wallpapers
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [parameter(Mandatory = $false, HelpMessage = "Name of the Azure Storage Account.")]
    [ValidateNotNullOrEmpty()]
    [string]$StorageAccountName = "<StorageAccountName>",

    [parameter(Mandatory = $false, HelpMessage = "Name of the Azure Storage Blob container.")]
    [ValidateNotNullOrEmpty()]
    [string]$ContainerName = "<ContainerName>"
)
Begin {
    # Install required modules for script execution
    $Modules = @("NTFSSecurity", "Az.Storage", "Az.Resources")
    foreach ($Module in $Modules) {
        try {
            $CurrentModule = Get-InstalledModule -Name $Module -ErrorAction Stop -Verbose:$false
            if ($CurrentModule -ne $null) {
                $LatestModuleVersion = (Find-Module -Name $Module -ErrorAction Stop -Verbose:$false).Version
                if ($LatestModuleVersion -gt $CurrentModule.Version) {
                    $UpdateModuleInvocation = Update-Module -Name $Module -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
                }
            }
        }
        catch [System.Exception] {
            try {
                # Install NuGet package provider
                $PackageProvider = Install-PackageProvider -Name NuGet -Force -Verbose:$false
        
                # Install current missing module
                Install-Module -Name $Module -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
            }
            catch [System.Exception] {
                Write-Warning -Message "An error occurred while attempting to install $($Module) module. Error message: $($_.Exception.Message)"
            }
        }
    }

    # Determine the localized name of the principals required for the functionality of this script
    $LocalAdministratorsPrincipal = "BUILTIN\Administrators"
    $LocalUsersPrincipal = "BUILTIN\Users"
    $LocalSystemPrincipal = "NT AUTHORITY\SYSTEM"
    $TrustedInstallerPrincipal = "NT SERVICE\TrustedInstaller"
    $RestrictedApplicationPackagesPrincipal = "ALL RESTRICTED APPLICATION PACKAGES"
    $ApplicationPackagesPrincipal = "ALL APPLICATION PACKAGES"

    # Retrieve storage account context
    $StorageAccountContext = New-AzStorageContext -StorageAccountName $StorageAccountName -Anonymous -ErrorAction Stop
}
Process {
    # Functions
    function Write-LogEntry {
        param (
            [parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
            [ValidateNotNullOrEmpty()]
            [string]$Value,
    
            [parameter(Mandatory = $true, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
            [ValidateNotNullOrEmpty()]
            [ValidateSet("1", "2", "3")]
            [string]$Severity,
    
            [parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will written to.")]
            [ValidateNotNullOrEmpty()]
            [string]$FileName = "Set-WindowsDesktopWallpaper.log"
        )
        # Determine log file location
        $LogFilePath = Join-Path -Path (Join-Path -Path $env:windir -ChildPath "Temp") -ChildPath $FileName
        
        # Construct time stamp for log entry
        $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), "+", (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
        
        # Construct date for log entry
        $Date = (Get-Date -Format "MM-dd-yyyy")
        
        # Construct context for log entry
        $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        
        # Construct final log entry
        $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""WindowsDesktopWallpaper"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
        
        # Add value to log file
        try {
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to append log entry to Set-WindowsDesktopWallpaper.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    }

    function Get-AzureBlobContent {
        param(
            [parameter(Mandatory = $true, HelpMessage = "Name of the Azure Storage Account.")]
            [ValidateNotNullOrEmpty()]
            [string]$StorageAccountName,
    
            [parameter(Mandatory = $true, HelpMessage = "Name of the Azure Storage Blob container.")]
            [ValidateNotNullOrEmpty()]
            [string]$ContainerName
        )
        try {   
            # Construct array list for return value containing file names
            $BlobList = New-Object -TypeName System.Collections.ArrayList
    
            try {
                # Retrieve content from storage account blob
                $StorageBlobContents = Get-AzStorageBlob -Container $ContainerName -Context $StorageAccountContext -ErrorAction Stop
                if ($StorageBlobContents -ne $null) {
                    foreach ($StorageBlobContent in $StorageBlobContents) {
                        Write-LogEntry -Value "Adding content file from Azure Storage Blob to return list: $($StorageBlobContent.Name)" -Severity 1
                        $BlobList.Add($StorageBlobContent) | Out-Null
                    }
                }
    
                # Handle return value
                return $BlobList
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Failed to retrieve storage account blob contents. Error message: $($_.Exception.Message)" -Severity 3
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value "Failed to retrieve storage account context. Error message: $($_.Exception.Message)" -Severity 3
        }
    }

    function Invoke-WallpaperFileDownload {
        param(
            [parameter(Mandatory = $true, HelpMessage = "Name of the image file in the Azure Storage blob.")]
            [ValidateNotNullOrEmpty()]
            [string]$FileName,

            [parameter(Mandatory = $true, HelpMessage = "Download destination directory for the image file.")]
            [ValidateNotNullOrEmpty()]
            [string]$Destination
        )        
        try {
            # Download default wallpaper content file from storage account
            Write-LogEntry -Value "Downloading content file from Azure Storage Blob: $($FileName)" -Severity 1
            $StorageBlobContent = Get-AzStorageBlobContent -Container $ContainerName -Blob $FileName -Context $StorageAccountContext -Destination $Destination -Force -ErrorAction Stop

            try {
                # Grant non-inherited permissions for wallpaper item
                $WallpaperImageFilePath = Join-Path -Path $Destination -ChildPath $FileName
                Write-LogEntry -Value "Granting '$($LocalSystemPrincipal)' Read and Execute on: $($WallpaperImageFilePath)" -Severity 1
                Add-NTFSAccess -Path $WallpaperImageFilePath -Account $LocalSystemPrincipal -AccessRights "ReadAndExecute" -ErrorAction Stop
                Write-LogEntry -Value "Granting '$($LocalAdministratorsPrincipal)' Read and Execute on: $($WallpaperImageFilePath)" -Severity 1
                Add-NTFSAccess -Path $WallpaperImageFilePath -Account $LocalAdministratorsPrincipal -AccessRights "ReadAndExecute" -ErrorAction Stop
                Write-LogEntry -Value "Granting '$($LocalUsersPrincipal)' Read and Execute on: $($WallpaperImageFilePath)" -Severity 1
                Add-NTFSAccess -Path $WallpaperImageFilePath -Account $LocalUsersPrincipal -AccessRights "ReadAndExecute" -ErrorAction Stop
                Write-LogEntry -Value "Granting '$($ApplicationPackagesPrincipal)' Read and Execute on: $($WallpaperImageFilePath)" -Severity 1
                Add-NTFSAccess -Path $WallpaperImageFilePath -Account $ApplicationPackagesPrincipal -AccessRights "ReadAndExecute" -ErrorAction Stop
                Write-LogEntry -Value "Granting '$($RestrictedApplicationPackagesPrincipal)' Read and Execute on: $($WallpaperImageFilePath)" -Severity 1
                Add-NTFSAccess -Path $WallpaperImageFilePath -Account $RestrictedApplicationPackagesPrincipal -AccessRights "ReadAndExecute" -ErrorAction Stop
                Write-LogEntry -Value "Granting '$($TrustedInstallerPrincipal)' Full Control on: $($WallpaperImageFilePath)" -Severity 1
                Add-NTFSAccess -Path $WallpaperImageFilePath -Account $TrustedInstallerPrincipal -AccessRights "FullControl" -ErrorAction Stop
                Write-LogEntry -Value "Disabling inheritance on: $($WallpaperImageFilePath)" -Severity 1
                Disable-NTFSAccessInheritance -Path $WallpaperImageFilePath -RemoveInheritedAccessRules -ErrorAction Stop

                try {
                    # Set owner to trusted installer for new wallpaper file
                    Write-LogEntry -Value "Setting ownership for '$($TrustedInstallerPrincipal)' on wallpaper image file: $($WallpaperImageFilePath)" -Severity 1
                    Set-NTFSOwner -Path $WallpaperImageFilePath -Account $TrustedInstallerPrincipal -ErrorAction Stop
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Failed to set ownership for '$($TrustedInstallerPrincipal)' on wallpaper image file: $($WallpaperImageFilePath). Error message: $($_.Exception.Message)" -Severity 3
                }
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Failed to revert permissions for wallpaper image file. Error message: $($_.Exception.Message)" -Severity 3
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value "Failed to downloaded wallpaper content from Azure Storage Blob. Error message: $($_.Exception.Message)" -Severity 3
        }
    }

    function Remove-WallpaperFile {
        param(
            [parameter(Mandatory = $true, HelpMessage = "Full path to the image file to be removed.")]
            [ValidateNotNullOrEmpty()]
            [string]$FilePath
        )
        try {
            # Take ownership of the wallpaper file
            Write-LogEntry -Value "Determining if ownership needs to be changed for file: $($FilePath)" -Severity 1
            $CurrentOwner = Get-Item -Path $FilePath | Get-NTFSOwner
            if ($CurrentOwner.Owner -notlike $LocalAdministratorsPrincipal) {
                Write-LogEntry -Value "Amending owner as '$($LocalAdministratorsPrincipal)' temporarily for: $($FilePath)" -Severity 1
                Set-NTFSOwner -Path $FilePath -Account $LocalAdministratorsPrincipal -ErrorAction Stop
            }

            try {
                # Grant local Administrators group and system full control
                Write-LogEntry -Value "Granting '$($LocalSystemPrincipal)' Full Control on: $($FilePath)" -Severity 1
                Add-NTFSAccess -Path $FilePath -Account $LocalSystemPrincipal -AccessRights "FullControl" -AccessType "Allow" -ErrorAction Stop
                Write-LogEntry -Value "Granting '$($LocalAdministratorsPrincipal)' Full Control on: $($FilePath)" -Severity 1
                Add-NTFSAccess -Path $FilePath -Account $LocalAdministratorsPrincipal -AccessRights "FullControl" -AccessType "Allow" -ErrorAction Stop

                try {
                    # Remove existing local default wallpaper file
                    Write-LogEntry -Value "Attempting to remove existing default wallpaper image file: $($FilePath)" -Severity 1
                    Remove-Item -Path $FilePath -Force -ErrorAction Stop
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Failed to remove wallpaper image file '$($FilePath)'. Error message: $($_.Exception.Message)" -Severity 3
                }                    
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Failed to grant Administrators and local system with full control for wallpaper image file. Error message: $($_.Exception.Message)" -Severity 3
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value "Failed to take ownership of '$($FilePath)'. Error message: $($_.Exception.Message)" -Severity 3
        }
    }

    # Check if desktop wallpaper content exists on the specified storage account
    $AzureStorageBlobContent = Get-AzureBlobContent -StorageAccountName $StorageAccountName -ContainerName $ContainerName
    if ($AzureStorageBlobContent -ne $null) {
        # Replace default wallpaper content locally with item from storage account
        $DefaultWallpaperBlobFile = $AzureStorageBlobContent | Where-Object { $PSItem.Name -like "img0.jpg" }
        if ($DefaultWallpaperBlobFile -ne $null) {
            Write-LogEntry -Value "Detected default wallpaper file 'img0' in container, will replace local wallpaper file" -Severity 1

            # Remove default wallpaper image file
            $DefaultWallpaperImagePath = Join-Path -Path $env:windir -ChildPath "Web\Wallpaper\Windows\img0.jpg"
            Remove-WallpaperFile -FilePath $DefaultWallpaperImagePath

            # Download new wallpaper content from storage account
            Invoke-WallpaperFileDownload -FileName $DefaultWallpaperBlobFile.Name -Destination (Split-Path -Path $DefaultWallpaperImagePath -Parent)
        }

        # Check if additional wallpaper files are present in the Azure Storage blob and replace those in the default location
        $WallpaperBlobFiles = $AzureStorageBlobContent | Where-Object { $PSItem.Name -match "^img(\d?[1-9]|[1-9]0).jpg$" }
        if ($WallpaperBlobFiles -ne $null) {
            Write-LogEntry -Value "Detected theme wallpaper files in container, will replace matching local theme wallpaper files" -Severity 1

            # Remove all items in '%windir%\Web\Wallpaper\Theme1' (Windows 10) directory and replace with wallpaper content from storage account
            $ThemeWallpaperImagePath = Join-Path -Path $env:windir -ChildPath "Web\Wallpaper\Theme1"
            $ThemeWallpaperImages = Get-ChildItem -Path $ThemeWallpaperImagePath -Filter "*.jpg"
            foreach ($ThemeWallpaperImage in $ThemeWallpaperImages) {
                # Remove current theme wallpaper image file
                Remove-WallpaperFile -FilePath $ThemeWallpaperImage.FullName
            }

            foreach ($WallpaperBlobFile in $WallpaperBlobFiles) {
                # Download new wallpaper content from storage account
                Invoke-WallpaperFileDownload -FileName $WallpaperBlobFile.Name -Destination $ThemeWallpaperImagePath
            }
        }

        # Check if 4K wallpaper files are present in the Azure Storage blog and replace those in the default location
        $WallpaperBlob4KFiles = $AzureStorageBlobContent | Where-Object { $PSItem.Name -match "^img0_(\d+)x(\d+).*.jpg$" }
        if ($WallpaperBlob4KFiles -ne $null) {
            Write-LogEntry -Value "Detected 4K wallpaper files in container, will replace matching local wallpaper file" -Severity 1

            # Define 4K wallpaper path and retrieve all image files
            $4KWallpaperImagePath = Join-Path -Path $env:windir -ChildPath "Web\4K\Wallpaper\Windows"
            $4KWallpaperImages = Get-ChildItem -Path $4KWallpaperImagePath -Filter "*.jpg"
            
            foreach ($WallpaperBlob4KFile in $WallpaperBlob4KFiles) {
                # Remove current 4K wallpaper image file and replace with image from storage account
                if ($WallpaperBlob4KFile.Name -in $4KWallpaperImages.Name) {
                    Write-LogEntry -Value "Current container item with name '$($WallpaperBlob4KFile.Name)' matches local wallpaper item, starting replacement process" -Severity 1
                    
                    # Get matching local wallpaper image for current container item
                    $4KWallpaperImage = $4KWallpaperImages | Where-Object { $PSItem.Name -like $WallpaperBlob4KFile.Name }

                    # Remove current theme wallpaper image file
                    Remove-WallpaperFile -FilePath $4KWallpaperImage.FullName

                    # Download new wallpaper content from storage account
                    Invoke-WallpaperFileDownload -FileName $WallpaperBlob4KFile.Name -Destination $4KWallpaperImagePath
                }
                else {
                    Write-LogEntry -Value "Downloaded 4K wallpaper with file name '$($WallpaperBlob4KFile.Name)' doesn't match any of the built-in 4K wallpaper image file names, skipping" -Severity 2
                }
            }
        }
    }
}