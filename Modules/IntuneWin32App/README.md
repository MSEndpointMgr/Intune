# Overview
This module was created to provide means to automate the packaging, creation and publishing of Win32 applications in Microsoft Intune.

Currently the following functions are supported in the module:
- Get-IntuneWin32App
- Get-IntuneWin32AppMetaData
- Add-IntuneWin32App
- Add-IntuneWin32AppAssignment
- New-IntuneWin32AppPackage
- New-IntuneWin32AppDetectionRule
- New-IntuneWin32AppReturnCode
- New-IntuneWin32AppIcon

## Installing the module from PSGallery
The IntuneWin32App module is published to the PowerShell Gallery. Install it on your system by running the following in an elevated PowerShell console:
```PowerShell
Install-Module -Name "IntuneWin32App"
```

## Package application source files into Win32 app package (.intunewin)
Use the New-IntuneWin32AppPackage function in the module to create a content package for a Win32 app. MSI, EXE and script-based applications are supported by this function. In this sample example, application source files for 7-Zip including the setup file are specified and being packaged into an .intunewin encrypted file. File will be exported to the output folder.
```PowerShell
# Package MSI as .intunewin file
$SourceFolder = "C:\Temp\IntuneWinAppUtil\Source\7-Zip"
$SetupFile = "7z1900-x64.msi"
$OutputFolder = "C:\Temp\IntuneWinAppUtil\Output"
New-IntuneWin32AppPackage -SourceFolder $SourceFolder -SetupFile $SetupFile -OutputFolder $OutputFolder -Verbose
```

## Create a new MSI based installation as a Win32 app


```PowerShell
# Get MSI meta data from .intunewin file
$IntuneWinFile = "C:\Temp\IntuneWinAppUtil\Output\7z1900-x64.intunewin"
$IntuneWinMetaData = Get-IntuneWin32AppMetaData -FilePath $IntuneWinFile
$IntuneWinMetaData.ApplicationInfo.EncryptionInfo
```