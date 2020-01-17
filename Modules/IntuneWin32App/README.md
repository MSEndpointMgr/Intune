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

## Package application source files into Win32 app package (.intunewin)
Use the New-IntuneWin32AppPackage function in the module to create a content package for a Win32 app. MSI, EXE and script-based applications are supported by this function. In the sample below, application source files for 7-Zip including the setup file are specified and being packaged into an .intunewin encrypted file. Package will be exported to the output folder.
```PowerShell
# Package MSI as .intunewin file
$SourceFolder = "C:\IntuneWinAppUtil\Source\7-Zip"
$SetupFile = "7z1900-x64.msi"
$OutputFolder = "C:\IntuneWinAppUtil\Output"
New-IntuneWin32AppPackage -SourceFolder $SourceFolder -SetupFile $SetupFile -OutputFolder $OutputFolder -Verbose
```

## Create a new MSI based installation as a Win32 app
Use the New-IntuneWin32AppPackage function to first create the packaged Win32 app content file (.intunewin). Then call the Add-IntuneWin32App function to create a new Win32 app in Microsoft Intune. This function has dependencies for other functions in the module. For instance when passing the detection rule for the Win32 app, you need to use the New-IntuneWin32AppDetectionRule function to create the required input object. Below is an example how the dependent functions in this module can be used together with the Add-IntuneWin32App function to successfully upload a packaged Win32 app content file to Microsoft Intune.
```PowerShell
# Get MSI meta data from .intunewin file
$IntuneWinFile = "C:\IntuneWinAppUtil\Output\7z1900-x64.intunewin"
$IntuneWinMetaData = Get-IntuneWin32AppMetaData -FilePath $IntuneWinFile
$IntuneWinMetaData.ApplicationInfo.EncryptionInfo

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
The detection rule is also constructed differently, for example in the below script it's using a PowerShell script as the detection logic. In the example below a Win32 app is created that's essentially a PowerShell script that executes and another PowerShell script used for detection.
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
Icon, return code