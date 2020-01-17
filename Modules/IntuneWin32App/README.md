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
- Expand-IntuneWin32AppPackage

## Installing the module from PSGallery
The IntuneWin32App module is published to the PowerShell Gallery. Install it on your system by running the following in an elevated PowerShell console:
```PowerShell
Install-Module -Name "IntuneWin32App"
```

## Module and authentication requirements
IntuneWin32App module requires the following modules to be installed on the system where it's used:
- AzureAD
- PSIntuneAuth

Delegated authentication (username / password) is currently the only authentication mechanism that's being supported. App-based authentication will be added in a future release.

## Common parameter inputs
A set of functions in this module, those that interact with Microsoft Intune (essentially query the Graph API for resources), all have common parameters that requires input. These parameters are:
- TenantName
  - This parameter should be given the full tenant name, e.g. name.onmicrosoft.com.
- ApplicationID (optional)
  - Provide the Application ID of the app registration in Azure AD. By default, the script will attempt to use the well known Microsoft Intune PowerShell app registration.
- PromptBehavior (optional)
  - Define the prompt behavior when acquiring a token. Possible values are: Auto, Always, Never, RefreshSession

The functions that have these parameters, an authorization token is acquired. This will by default happen for the sign-in user, if possible. For scenarios when another credential is required to acquire the authorization token, specify Always as the value for PromptBehavior.

## Get existing Win32 apps
Get-IntuneWin32App function can be used to retrieve existing Win32 apps in Microsoft Intune. Retrieving an existing Win32 app could either be done passing the display name of the app, which performs a wildcard search meaning it's not required to specify the full name of the Win32 app. The ID if a specific Win32 app could also be used for this function. Additionally, by not specifying either a display name or an ID, all Win32 apps available will be retrieved. Below are a few examples of how this function could be used:
```PowerShell
# Get all Win32 apps
Get-IntuneWin32App -TenantName "name.onmicrosoft.com" -Verbose

# Get a specific Win32 app by it's display name
Get-IntuneWin32App -TenantName "name.onmicrosoft.com" -DisplayName "7-zip" -Verbose

# Get a specific Win32 app by it's id
Get-IntuneWin32App -TenantName "name.onmicrosoft.com" -ID "<Win32 app ID>" -Verbose
```

## Package application source files into Win32 app package (.intunewin)
Use the New-IntuneWin32AppPackage function in the module to create a content package for a Win32 app. MSI, EXE and script-based applications are supported by this function. This function automatically downloads the IntuneWinAppUtil.exe application that's essentially the engine behind the packaging and encryption process. The utility will be downloaded to the temporary directory of the user running the function, more specifically the location of the environment variable %TEMP%. If required, a custom path to where IntuneWinAppUtil.exe already exists is possible to pass to the function using the IntuneWinAppUtilPath parameter. In the sample below, application source files for 7-Zip including the setup file are specified and being packaged into an .intunewin encrypted file. Package will be exported to the output folder.
```PowerShell
# Package MSI as .intunewin file
$SourceFolder = "C:\IntuneWinAppUtil\Source\7-Zip"
$SetupFile = "7z1900-x64.msi"
$OutputFolder = "C:\IntuneWinAppUtil\Output"
New-IntuneWin32AppPackage -SourceFolder $SourceFolder -SetupFile $SetupFile -OutputFolder $OutputFolder -Verbose
```

## Create a new MSI based installation as a Win32 app
Use the New-IntuneWin32AppPackage function to first create the packaged Win32 app content file (.intunewin). Then call the Add-IntuneWin32App function to create a new Win32 app in Microsoft Intune. This function has dependencies for other functions in the module. For instance when passing the detection rule for the Win32 app, you need to use the New-IntuneWin32AppDetectionRule function to create the required input object. Below is an example how the dependent functions in this module can be used together with the Add-IntuneWin32App function to successfully upload a packaged Win32 app content file to Microsoft Intune:
```PowerShell
# Get MSI meta data from .intunewin file
$IntuneWinFile = "C:\IntuneWinAppUtil\Output\7z1900-x64.intunewin"
$IntuneWinMetaData = Get-IntuneWin32AppMetaData -FilePath $IntuneWinFile

# Create custom display name like 'Name' and 'Version'
$DisplayName = $IntuneWinMetaData.ApplicationInfo.Name + " " + $IntuneWinMetaData.ApplicationInfo.MsiInfo.MsiProductVersion

# Create MSI detection rule
$DetectionRule = New-IntuneWin32AppDetectionRule -MSI -MSIProductCode $IntuneWinMetaData.ApplicationInfo.MsiInfo.MsiProductCode

# Add new MSI Win32 app
Add-IntuneWin32App -TenantName "name.onmicrosoft.com" -FilePath $IntuneWinFile -DisplayName $DisplayName -InstallExperience "system" -RestartBehavior "suppress" -DetectionRule $DetectionRule -Verbose
```

## Create a new EXE/script based installation as a Win32 app
Use the New-IntuneWin32AppPackage function to first create the packaged Win32 app content file (.intunewin). Then call the Add-IntuneWin32App much like the example above illustrates for a MSI installation based Win32 app. Apart from the above example, for an EXE/script based Win32 app, a few other parameters are required:
- InstallCommandLine
- UninstallCommandLine

The detection rule is also constructed differently, for example in the below script it's using a PowerShell script as the detection logic. In the example below a Win32 app is created that's essentially a PowerShell script that executes and another PowerShell script used for detection:
```PowerShell
# Get MSI meta data from .intunewin file
$IntuneWinFile = "C:\IntuneWinAppUtil\Output\Enable-BitLockerEncryption.intunewin"
$IntuneWinMetaData = Get-IntuneWin32AppMetaData -FilePath $IntuneWinFile

# Create custom display name like 'Name' and 'Version'
$DisplayName = "Enable BitLocker Encryption 1.0"

# Create PowerShell script detection rule
$DetectionScriptFile = "C:\IntuneWinAppUtil\Output\Get-BitLockerEncryptionDetection.ps1"
$DetectionRule = New-IntuneWin32AppDetectionRule -PowerShellScript -ScriptFile $DetectionScriptFile -EnforceSignatureCheck $false -RunAs32Bit $false

# Add new EXE Win32 app
$InstallCommandLine = "powershell.exe -ExecutionPolicy Bypass -File .\Enable-BitLockerEncryption.ps1"
$UninstallCommandLine = "cmd.exe /c"
Add-IntuneWin32App -TenantName "name.onmicrosoft.com" -FilePath $IntuneWinFile -DisplayName $DisplayName -Description "Start BitLocker silent encryption" -Publisher "SCConfigMgr" -InstallExperience "system" -RestartBehavior "suppress" -DetectionRule $DetectionRule -ReturnCode $ReturnCode -InstallCommandLine $InstallCommandLine -UninstallCommandLine $UninstallCommandLine -Verbose
```

## Additional parameters for Add-IntuneWin32App function
When creating a Win32 app, additional configuration is possible when using the Add-IntuneWin32App function. It's possible to set the icon for the Win32 app using the Icon parameter. If desired, it's also possible to add custom, in addition to the default, return codes by adding the ReturnCode parameter. Below is an example of how the Add-IntuneWin32App function could be extended with those parameters by using the New-IntuneWin32AppIcon and New-IntuneWin32AppReturnCode functions:

```PowerShell
# Create custom return code
$ReturnCode = New-IntuneWin32AppReturnCode -ReturnCode 1337 -Type "retry"

# Convert image file to icon
$ImageFile = "C:\IntuneWinAppUtil\Logos\Image.png"
$Icon = New-IntuneWin32AppIcon -FilePath $ImageFile
```

## Create a Win32 app assignment
IntuneWin32App module also supports adding assignments. In version 1.0.0, functionality for creating an assignment for an existing Win32 app in Microsoft Intune (or one created with the Add-IntuneWin32App function), consists of targeting for:
- All Users
- Specified group

Assignments created with this module doesn't currently support specifying an installation deadline or available time. The assignment will by default be created with the settings for installation deadline and availability configured as 'As soon as possible'. Below is an example of how to add assignments using the module:
### Adding for a group
```PowerShell
# Get a specific Win32 app by it's display name
$Win32App = Get-IntuneWin32App -TenantName "name.onmicrosoft.com" -DisplayName "7-zip" -Verbose

# Add assignment for a specific Azure AD group
$GroupID = "<Azure AD group ID>"
Add-IntuneWin32AppAssignment -TenantName "name.onmicrosoft.com" -DisplayName $Win32App.displayName -Target "Group" -GroupID $GroupID -Intent "available" -Notification "showAll" -Verbose
```
### Adding for all users
```PowerShell
# Get a specific Win32 app by it's display name
$Win32App = Get-IntuneWin32App -TenantName "name.onmicrosoft.com" -DisplayName "7-zip" -Verbose

# Add assignment for all users
Add-IntuneWin32AppAssignment -TenantName "name.onmicrosoft.com" -DisplayName $Win32App.displayName -Target "AllUsers" -Intent "available" -Notification "showAll" -Verbose
```

## Expand
The New-IntuneWin32AppPackage function packages and encrypts a Win32 app content file (.intunewin file). This file can be uncompressed using any decompression tool, e.g. 7-Zip. Inside the file resides a folder structure resides essentially two important files for that's required for the Expand-IntuneWin32AppPackage function. These two files, detection.xml <PackageName>.intunewin, was generated when IntuneWinAppUtil.exe executed. Detection.xml contains the encryption info, more specifically the encryptionKey and initializationVector details. <PackageName>.intunewin is the actual encrypted file, that with the encryptionKey and initializationVector info, can be decrypted. This function can 'expand', meaning to uncompress and decrypt the original Win32 app content file containing the two files already mentioned, but does not support decryption only of the <PackageName>.intunewin file that was already uploaded to Microsoft Intune for a given Win32 app and then later downloaded from the Azure Storage blob associated with that app. This is because Graph API does not expose the encryptionKey and initializationVector data once a Win32 app content file has been uploaded to Microsoft Intune. A request to expose this data in Graph API has been sent to Microsoft, but the future will tell if they decide to fullfil that request. Below is an example of how to use the Expand-IntuneWin32AppPackage function using the full Win32 app content file created either manually with IntuneWinAppUtil.exe or with the New-IntuneWin32AppPackage function:

```PowerShell
# Decode an existing Win32 app content file
$IntuneWinFile = "C:\IntuneWinAppUtil\Output\7z1900-x64.intunewin"
Expand-IntuneWin32AppPackage -FilePath $IntuneWinFile -Force -Verbose
```

## Full example of packaging and creating a Win32 app
Below is an example that automates the complete process of creating the Win32 app content file, adding a new Win32 app in Microsoft Intune and assigns it to all users.
```PowerShell
# Package MSI as .intunewin file
$SourceFolder = "C:\IntuneWinAppUtil\Source\7-Zip"
$SetupFile = "7z1900-x64.msi"
$OutputFolder = "C:\IntuneWinAppUtil\Output"
$Win32AppPackage = New-IntuneWin32AppPackage -SourceFolder $SourceFolder -SetupFile $SetupFile -OutputFolder $OutputFolder -Verbose

# Get MSI meta data from .intunewin file
$IntuneWinFile = $Win32AppPackage.Path
$IntuneWinMetaData = Get-IntuneWin32AppMetaData -FilePath $IntuneWinFile

# Create custom display name like 'Name' and 'Version'
$DisplayName = $IntuneWinMetaData.ApplicationInfo.Name + " " + $IntuneWinMetaData.ApplicationInfo.MsiInfo.MsiProductVersion

# Create MSI detection rule
$DetectionRule = New-IntuneWin32AppDetectionRule -MSI -MSIProductCode $IntuneWinMetaData.ApplicationInfo.MsiInfo.MsiProductCode

# Create custom return code
$ReturnCode = New-IntuneWin32AppReturnCode -ReturnCode 1337 -Type "retry"

# Convert image file to icon
$ImageFile = "C:\IntuneWinAppUtil\Logos\7-Zip.png"
$Icon = New-IntuneWin32AppIcon -FilePath $ImageFile

# Add new MSI Win32 app
$Win32App = Add-IntuneWin32App -TenantName "name.onmicrosoft.com" -FilePath $IntuneWinFile -DisplayName $DisplayName -InstallExperience "system" -RestartBehavior "suppress" -DetectionRule $DetectionRule -ReturnCode $ReturnCode -Icon $Icon -Verbose

# Add assignment for all users
Add-IntuneWin32AppAssignment -TenantName "name.onmicrosoft.com" -DisplayName $Win32App.displayName -Target "AllUsers" -Intent "available" -Notification "showAll" -Verbose
```