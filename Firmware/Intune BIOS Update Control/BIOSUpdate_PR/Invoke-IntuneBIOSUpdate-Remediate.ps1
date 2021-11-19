<#
.SYNOPSIS
    BIOS Control remediation script for MSEndpointMgr Intune MBM
.DESCRIPTION
    This proactive remediation script is part of the Intune version of Modern BIOS management. More information can be found at https://msendpointmgr.com 
    NB: Only edit variables in the Declarations region of the script. 
    The following variables MUST be set: 
    1. DATUri - Url path to BIOSPackages.xml 
    2. LogoImageUri - Url to logo image for toast notification 
    3. HeroImageUri - Url to hero image for toast notification 

    If you have a common BIOS password on all devices, that can be added to this script for support (HP), but be aware that both local admin users on the devices and Intune admins will 
    be able to retrive this password if you do so. 

.EXAMPLE
	Invoke-IntuneBIOSUpdateRemediate.ps1 - Run as SYSTEM 
.NOTES
	Version:    0.9 Beta
    Author:     Maurice Daly / Jan Ketil Skanke @ Cloudway
    Contact:    @JankeSkanke @Modaly_IT
    Creation Date:  01.10.2021
    Purpose/Change: Initial script development
    Created:     2021-14-11
    Updated:     
    Version history:
    0.9 - (2021.14.11) Beta Release
#>

#region Initialisations
# Set Error Action to Silently Continue
$Script:ErrorActionPreference = "SilentlyContinue"
# Enable TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Script:ExitCode = 0
#endregion Initialisations
#region Decalarations 
# Create and define Eventlog for logging - edit with caution 
$Script:EventLogName = 'MSEndpointMgr'
$Script:EventLogSource = 'MSEndpointMgrBIOSMgmt'
New-EventLog -LogName $EventLogName -Source $EventLogSource -ErrorAction SilentlyContinue
# Set Toast Notification App Parameters - do not edit 
$Script:AppID = "MSEndpointMgr.SystemToast.UpdateNotification"
$Script:AppDisplayName = "MSEndpointMgr"
$Script:IconUri = "%SystemRoot%\system32\@WindowsUpdateToastIcon.png"
$Script:ToastMediafolder = "$env:programdata\MSEndpointMgr\ToastNotification"

#Set Toast Settings - Adjust to your own requirements - modification required
$Script:ToastSettings = @{
    LogoImageUri = "<TO BE SET>"
    HeroImageUri = "<TO BE SET>"
    LogoImage = "$ToastMediafolder\ToastLogoImage.png"
    HeroImage = "$ToastMediafolder\ToastHeroImage.png"
    AttributionText = "Bios Update Notification"
    HeaderText = "It is time to update your BIOS!"
    TitleText = "Firmware update needed!"
    BodyText1 = "For security reasons it is important that the firmware on your machine is up to date. This update requires a reboot of your device"
    BodyText2 = "Please save your work and restart your device today. Thank you in advance."
    ActionButtonContent = "Restart Now"
}
$Script:Scenario = 'reminder' # <!-- Possible values are: reminder | short | long | alarm
# Define BIOS Password
$Script:BIOSPswd = $null
# Define path to DAT provisioned XML - must be set
$Script:DATUri = "<TO BE SET>"
# Get manufacturer 
$Script:Manufacturer = (Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty Manufacturer).Trim()
# Registry path for status messages - do not edit
$Script:RegPath = 'HKLM:\SOFTWARE\MSEndpointMgr\BIOSUpdateManagemement'

#EndRegion Declarations 

#Region Functions

function Add-NotificationApp {
    <#
    .SYNOPSIS
    Function to verify and register toast notification app in registry as system

    .DESCRIPTION
    This function must be run as system and registers the toast notification app with your own name and icon. 

    .PARAMETER AppID
    The AppID (Name) to be used to the toast notification. Example: MSEndpointMgr.SystemToast.UpdateNotification

    .PARAMETER AppDisplayName
    The Display Name for your  toast notification app. Example: MSEndpointMgr

    .PARAMETER IconUri
    The path to the icon shown in the Toast Notification. Expample: %SystemRoot%\system32\@WindowsUpdateToastIcon.png

    .PARAMETER ShowInSettings
    Default Value 0 is recommended. Not required. But can be change to 1. Not recommended for this solution
    #>    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]$AppID,
        [Parameter(Mandatory=$true)]$AppDisplayName,
        [Parameter(Mandatory=$true)]$IconUri,
        [Parameter(Mandatory=$false)][int]$ShowInSettings = 0
    )
    # Verify if PSDrive Exists
    $HKCR = Get-PSDrive -Name HKCR -ErrorAction SilentlyContinue
    If (!($HKCR))
    {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -Scope Script
    }
    $AppRegPath = "HKCR:\AppUserModelId"
    $RegPath = "$AppRegPath\$AppID"
    # Verify if App exists in registry
    If (!(Test-Path $RegPath))
    {
        Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "Toast Notification App does not exists - creating"
        $null = New-Item -Path $AppRegPath -Name $AppID -Force
    }
    # Verify Toast App Displayname
    $DisplayName = Get-ItemProperty -Path $RegPath -Name DisplayName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName -ErrorAction SilentlyContinue
    If ($DisplayName -ne $AppDisplayName)
    {
        $null = New-ItemProperty -Path $RegPath -Name DisplayName -Value $AppDisplayName -PropertyType String -Force
        Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "Toast notification app $($DisplayName) created"
    }
    # Verify Show in settings value
    $ShowInSettingsValue = Get-ItemProperty -Path $RegPath -Name ShowInSettings -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ShowInSettings -ErrorAction SilentlyContinue
    If ($ShowInSettingsValue -ne $ShowInSettings)
    {
        $null = New-ItemProperty -Path $RegPath -Name ShowInSettings -Value $ShowInSettings -PropertyType DWORD -Force
        Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "Toast notification app settings applied"
    }
    # Verify toast icon value
    $IconSettingsValue = Get-ItemProperty -Path $RegPath -Name IconUri -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IconUri -ErrorAction SilentlyContinue
    If ($IconSettingsValue -ne $IconUri)
    {
        $null = New-ItemProperty -Path $RegPath -Name IconUri -Value $IconUri -PropertyType ExpandString -Force
        Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "Toast notification app icon set"
    }
    # Clean up
    Remove-PSDrive -Name HKCR -Force
}#endfunction
function Add-ToastRebootProtocolHandler{
    <#
    .SYNOPSIS
    Function to add the reboot protocol handler for your toast notifications

    .DESCRIPTION
    This function must be run as system and registers the protocal handler for toast reboot. 
    #>    
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue | out-null
    $ProtocolHandler = Get-Item 'HKCR:\MSEndpointMgrToastReboot' -ErrorAction SilentlyContinue
    if (!$ProtocolHandler) {
        #create handler for reboot
        New-Item 'HKCR:\MSEndpointMgrToastReboot' -Force
        Set-Itemproperty 'HKCR:\MSEndpointMgrToastReboot' -Name '(DEFAULT)' -Value 'url:MSEndpointMgrToastReboot' -Force
        Set-Itemproperty 'HKCR:\MSEndpointMgrToastReboot' -Name 'URL Protocol' -Value '' -Force
        New-Itemproperty -path 'HKCR:\MSEndpointMgrToastReboot' -PropertyType DWORD -Name 'EditFlags' -Value 2162688
        New-Item 'HKCR:\MSEndpointMgrToastReboot\Shell\Open\command' -Force
        Set-Itemproperty 'HKCR:\MSEndpointMgrToastReboot\Shell\Open\command' -Name '(DEFAULT)' -Value 'C:\Windows\System32\shutdown.exe -r -t 60 -c "Your computer will be restarted in 1 minute to complete the BIOS Update process." ' -Force
    }
    Remove-PSDrive -Name HKCR -Force -ErrorAction SilentlyContinue
}#endfunction
function Test-UserSession {
    #Check if a user is currently logged on before doing user action
    [String]$CurrentlyLoggedOnUser = (Get-WmiObject -Class Win32_ComputerSystem |  Where-Object {$_.Username} | Select-Object UserName).UserName
    if ($CurrentlyLoggedOnUser){
        $SAMName = [String]$CurrentlyLoggedOnUser.Split("\")[1]
        #$UserPath = (Get-ChildItem  -Path HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache\ -Recurse -ErrorAction SilentlyContinue | ForEach-Object { if((Get-ItemProperty -Path $_.PsPath) -match $SAMName) {$_.PsPath} } ) | Where-Object {$PSItem -Match 'S-\d-\d{2}-\d-\d{10}-\d{10}-\d{10}-\d{10}'}
        #$FullName = (Get-ItemProperty -Path $UserPath | Select-Object DisplayName).DisplayName
        $ReturnObject = $SAMName 
    }else {
        $ReturnObject = $false
    }
    Return $ReturnObject
}#endfunction
function Invoke-ToastNotification {
    Param(
        [Parameter(Mandatory=$false)]$FullName,
        [parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[array]$ToastSettings,
        [Parameter(Mandatory=$true)]$AppID,
        [Parameter(Mandatory=$true)]$Scenario
    )

$MyScriptBlockString = "
function Start-ToastNotification {
    `$Load = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
    `$Load = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
    # Load the notification into the required format
    `$ToastXML = New-Object -TypeName Windows.Data.Xml.Dom.XmlDocument
    `$ToastXML.LoadXml(`$Toast.OuterXml)
    # Display the toast notification
    try {
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier(`"$AppID`").Show(`$ToastXml)
    }
    catch { 
        Write-Output -Message 'Something went wrong when displaying the toast notification' -Level Warn     
        Write-EventLog -LogName $EventLogName -EntryType Warning -EventId 8002 -Source $EventLogSource -Message `"Something went wrong when displaying the toast notification`"
    }
    Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message `"Toast Notification successfully delivered to logged on user`"
}
#Fetching images from uri
Invoke-WebRequest -Uri $($ToastSettings.LogoImageUri) -OutFile $($ToastSettings.LogoImage)
Invoke-WebRequest -Uri $($ToastSettings.HeroImageUri) -OutFile $($ToastSettings.HeroImage)

[xml]`$Toast = @`"
<toast scenario=`"$Scenario`">
    <visual>
    <binding template=`"ToastGeneric`">
        <image placement=`"hero`" src=`"$($ToastSettings.HeroImage)`"/>
        <image id=`"1`" placement=`"appLogoOverride`" hint-crop=`"circle`" src=`"$($ToastSettings.LogoImage)`"/>
        <text placement=`"attribution`">$($ToastSettings.AttributionText)</text>
        <text>$($ToastSettings.HeaderText)</text>
        <group>
            <subgroup>
                <text hint-style=`"title`" hint-wrap=`"true`" >$($ToastSettings.TitleText)</text>
            </subgroup>
        </group>
        <group>
            <subgroup>     
                <text hint-style=`"body`" hint-wrap=`"true`" >$($ToastSettings.BodyText1)</text>
            </subgroup>
        </group>
        <group>
            <subgroup>     
                <text hint-style=`"body`" hint-wrap=`"true`" >$($ToastSettings.BodyText2)</text>
            </subgroup>
        </group>
    </binding>
    </visual>
    <actions>
        <input id=`"snoozeTime`" type=`"selection`" defaultInput=`"60`">
        <selection id=`"1`" content=`"1 minute`"/>
        <selection id=`"15`" content=`"15 minutes`"/>
        <selection id=`"60`" content=`"1 hour`"/>
        <selection id=`"240`" content=`"4 hours`"/>
        <selection id=`"1440`" content=`"1 day`"/>
        </input>
        <action activationType=`"protocol`" arguments=`"MSEndpointMgrToastReboot:`" content=`"$($ToastSettings.ActionButtonContent)`"/>
        <action activationType=`"system`" arguments=`"snooze`" hint-inputId=`"snoozeTime`" content=`"Snooze`" />
    </actions>
    <audio src=`"ms-winsoundevent:Notification.Default`"/>
</toast>
`"@

Start-ToastNotification
"

$MyScriptBlock = [ScriptBlock]::create($MyScriptBlockString) 
$EncodedScript = [System.Convert]::ToBase64String([System.Text.Encoding]::UNICODE.GetBytes($MyScriptBlock))

#Set Unique GUID for the Toast
If (!($ToastGUID)) {
    $ToastGUID = ([guid]::NewGuid()).ToString().ToUpper()
}
$Task_TimeToRun = (Get-Date).AddSeconds(10).ToString('s')
$Task_Expiry = (Get-Date).AddSeconds(120).ToString('s')
$Task_Trigger = New-ScheduledTaskTrigger -Once -At $Task_TimeToRun
$Task_Trigger.EndBoundary = $Task_Expiry
$Task_Principal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -RunLevel Limited
$Task_Settings = New-ScheduledTaskSettingsSet -Compatibility V1 -DeleteExpiredTaskAfter (New-TimeSpan -Seconds 600) -AllowStartIfOnBatteries
$Task_Action = New-ScheduledTaskAction -Execute "C:\WINDOWS\system32\WindowsPowerShell\v1.0\PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -EncodedCommand $EncodedScript"

$New_Task = New-ScheduledTask -Description "Toast_Notification_$($ToastGuid) Task for user notification" -Action $Task_Action -Principal $Task_Principal -Trigger $Task_Trigger -Settings $Task_Settings
Register-ScheduledTask -TaskName "Toast_Notification_$($ToastGuid)" -InputObject $New_Task | Out-Null
Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "Toast Notification Task created for logged on user: Toast_Notification_$($ToastGuid)"
}#endfunction
function Invoke-BIOSUpdateHP{
    param (
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [version]$BIOSApprovedVersion,
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$SystemID
        )  
    $Output = @{}
    # Import HP Module 
    Import-Module HP.ClientManagement
    # Get Date
    $Date = Get-Date
    # Obtain current BIOS verison
    [version]$CurrentBIOSVersion = Get-HPBIOSVersion

    # Inform current BIOS deployment state
    if ($BIOSApprovedVersion -gt $CurrentBIOSVersion){
        $HPBIOSVersions = Get-HPBIOSUpdates
        foreach ($HPBIOSVersion in $HPBIOSVersions.Ver){
            if ([version]$HPBIOSVersion -eq $BIOSApprovedVersion) {
                $HPVersion = $HPBIOSVersion
            }
        }
        if ([version]$HPVersion -contains $BIOSApprovedVersion) {
            # Process BIOS update
            Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "Processing BIOS flash update process"
            # Check for BIOS password and update flash cmdline
            Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "Checking if BIOS password is set"
            $BIOSPasswordSet = Get-HPBIOSSetupPasswordIsSet
            switch ($BIOSPasswordSet) {
                $true {
                    # Verify that an password has been provided
                    Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "BIOS password is password protected"
                    if (-not ([string]::IsNullOrEmpty($BIOSPswd))){ 
                        # Perform BIOS flash update using provided password
                        Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "Updating HP BIOS to version $HPVersion using supplied password"
                        $HPBIOSUpdateProcess = Get-HPBIOSUpdates -Version $HPVersion -Password $BIOSPswd -Flash -Bitlocker suspend -Yes -Quiet -ErrorAction SilentlyContinue
                        # Writing status to registry for detection
                        [int]$Attempts = Get-ItemPropertyValue -Path $RegPath -Name 'BIOSUpdateAttempts'
                        $Attempts++ 
                        Set-ItemProperty -Path $RegPath -Name 'BIOSUpdateAttempts' -Value $Attempts
                        Set-ItemProperty -Path "$RegPath" -Name 'BIOSUpdateInprogress' -Value 1
                        Set-ItemProperty -Path "$RegPath" -Name 'BIOSUpdateTime' -Value $Date 
                        Set-ItemProperty -Path "$RegPath" -Name 'BIOSDeployedVersion' -Value $HPVersion
                        $OutputMessage = "Updating HP BIOS to version $HPVersion using supplied password"
                        $ExitCode = 0
                        #Invoke Toast 
                        if (Test-UserSession){
                            #User is logged on - send toast to user to perform the reboot
                            Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "User session found - notify user to reboot with toast"
                            Invoke-ToastNotification -ToastSettings $ToastSettings -AppID $AppID -Scenario $Scenario
                        } else {
                            #No user logged on - enforcing a reboot to finalize BIOS flashing                
                            Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "No user currenty logged on - restarting computer to finalize BIOS flashing"
                            $RestartCommand = 'C:\Windows\System32\shutdown.exe'
                            $RestartArguments = '-r -t 60 -c "Your computer will be restarted in 1 minute to complete the BIOS Update process."'
                            Start-Process $RestartCommand -ArgumentList $RestartArguments -NoNewWindow
                        }
                    } else {
                        Write-EventLog -LogName $EventLogName -EntryType Warning -EventId 8002 -Source $EventLogSource -Message "Password is set, but not password is provided. BIOS Update is halted"
                        $OutputMessage = "Password is set, but not password is provided. BIOS Update is halted"
                        $ExitCode = 1
                    }
                }
                $false {
                    # Perform BIOS flash update
                    Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "Updating HP BIOS to version $HPVersion"
                    $HPBIOSUpdateProcess = Get-HPBIOSUpdates -Version $HPVersion -Flash -Bitlocker suspend -Yes -Quiet -ErrorAction SilentlyContinue
                    # Writing status to registry for detection
                    [int]$Attempts = Get-ItemPropertyValue -Path $RegPath -Name 'BIOSUpdateAttempts'
                    $Attempts++ 
                    Set-ItemProperty -Path $RegPath -Name 'BIOSUpdateAttempts' -Value $Attempts
                    Set-ItemProperty -Path "$RegPath" -Name 'BIOSUpdateInprogress' -Value 1
                    Set-ItemProperty -Path "$RegPath" -Name 'BIOSUpdateTime' -Value $Date 
                    Set-ItemProperty -Path "$RegPath" -Name 'BIOSDeployedVersion' -Value $HPVersion
                    #Invoke Toast 
                    if (Test-UserSession){
                        #User is logged on - send toast to user to perform the reboot
                        Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "User session found - notify user to reboot with toast"
                        Invoke-ToastNotification -ToastSettings $ToastSettings -AppID $AppID -Scenario $Scenario
                    } else {
                        #No user logged on - enforcing a reboot to finalize BIOS flashing                
                        Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "No user currenty logged on - restarting computer to finalize BIOS flashing"
                        $RestartCommand = 'C:\Windows\System32\shutdown.exe'
                        $RestartArguments = '-r -t 60 -c "Your computer will be restarted in 1 minute to complete the BIOS Update process."'
                        Start-Process $RestartCommand -ArgumentList $RestartArguments -NoNewWindow
                    }
                    $OutputMessage = "Updated HP BIOS to version $HPVersion"
                    $ExitCode = 0
                }                
            }
        } 
        else {
            $OutputMessage = "BIOS update not found. $BIOSApprovedVersion not found in HP returned values from HP"
            $ExitCode = 1
        }
    } 
    elseif ($BIOSApprovedVersion -eq $CurrentBIOSVersion) {
        $OutputMessage = "BIOS is current on version $CurrentBIOSVersion"
        $ExitCode = 0
    } 
    elseif ($BIOSApprovedVersion -lt $CurrentBIOSVersion) {
        $OutputMessage = "BIOS is on a higher version than approved $CurrentBIOSVersion. Approved version $BIOSApprovedVersion"
        $ExitCode = 0
    } 
    
    $Output = @{
            "Message" = $OutputMessage
            "ExitCode" = $ExitCode
    }

    Return $Output
}#endfunction
function Invoke-BIOSUpdateDell{
    param (
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [array]$BIOSPackageDetails 
        )  
$OutputMessage = "Dell not Implemented yet"
$ExitCode = 0
$Output = @{
    "Message" = $OutputMessage
    "ExitCode" = $ExitCode
}
Return $Output
}#endfunction
function Invoke-BIOSUpdateLenovo{
    param (
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [array]$BIOSPackageDetails 
        )  
$OutputMessage = "Dell not Implemented yet"
$ExitCode = 0
$Output = @{
    "Message" = $OutputMessage
    "ExitCode" = $ExitCode
}
return $Output
}#endfunction
function Test-BIOSVersionHP{
param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [version]$BIOSApprovedVersion,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SystemID
    )  
    $Output = @{}
    # Import HP Module 
    Import-Module HP.ClientManagement

    # Obtain current BIOS verison
    [version]$CurrentBIOSVersion = Get-HPBIOSVersion

    # Inform current BIOS deployment state
    if ($BIOSApprovedVersion -gt $CurrentBIOSVersion){
        $OutputMessage = "BIOS needs an update. Current version is $CurrentBIOSVersion, available version is $BIOSApprovedVersion"
        $ExitCode = 1
    } 
    elseif ($BIOSApprovedVersion -eq $CurrentBIOSVersion) {
        $OutputMessage = "BIOS is current on version $CurrentBIOSVersion"
        $ExitCode = 0
    } 
    elseif ($BIOSApprovedVersion -lt $CurrentBIOSVersion) {
        $OutputMessage = "BIOS is on a higher version than approved $CurrentBIOSVersion. Approved version $BIOSApprovedVersion"
        $ExitCode = 0
    } 
    
    $Output = @{
            "Message" = $OutputMessage
            "ExitCode" = $ExitCode
    }

    Return $Output
}#endfunction
function Test-BiosVersionDell{
    param (
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [array]$BIOSPackageDetails 
        )
    $OutputMessage = "Dell Not implemented"
    $ExitCode = 0
    $Output = @{
        "Message" = $OutputMessage
        "ExitCode" = $ExitCode
    }
    Return $Output
}#endfunction
function Test-BiosVersionLenovo{
    param (
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [array]$BIOSPackageDetails 
        )  
    $OutputMessage = "Dell Not implemented"
    $ExitCode = 0
    $Output = @{
        "Message" = $OutputMessage
        "ExitCode" = $ExitCode
    }
    Return $Output
}#endfunction
#Endregion Functions

#Region Script

# Read in DAT XML
[xml]$BIOSPackages = Invoke-WebRequest -Uri $DATUri -UseBasicParsing

# Sort BIOS Packages into variable
$BIOSPackageDetails = $BIOSPackages.ArrayOfCMPackage.CMPackage

# Adding and verifying Toast Application and Protocol Handler
Add-NotificationApp -AppID $AppID -AppDisplayName $AppDisplayName -IconUri $IconUri | Out-Null
Add-ToastRebootProtocolHandler | Out-Null

#Verify Toast Media folder exists
if (-not (Test-Path $ToastMediafolder)){
    New-Item -Path $ToastMediafolder -ItemType Directory | Out-Null
}

# Validate applicability
switch -Wildcard ($Manufacturer) { 
    {($PSItem -match "HP") -or ($PSItem -match "Hewlett-Packard")}{
        Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "Validated HP hardware check"
        $HPPreReq = [boolean](Get-InstalledModule | Where-Object {$_.Name -match "HPCMSL"} -ErrorAction SilentlyContinue -Verbose:$false)
        if ($HPPreReq){
            # Import module
            Import-Module HP.ClientManagement
            # Get matching identifier from baseboard
            $SystemID = Get-HPDeviceProductID
            $SupportedModel = $BIOSPackageDetails | Where-Object {$_.Description -match $SystemID}
            if (-not ([string]::IsNullOrEmpty($SupportedModel))) {
                [version]$BIOSApprovedVersion = ($BIOSPackageDetails | Where-Object {$_.Description -match $SystemID} | Sort-Object Version -Descending  | Select-Object -First 1 -Unique -ExpandProperty Version).Split(" ")[0] 
                $OEM = "HP"
                Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "$($SupportedModel.Description) succesfully matched on SKU $($SystemID)"
            } 
            else {
                Write-EventLog -LogName $EventLogName -EntryType Warning -EventId 8002 -Source $EventLogSource -Message "Model with SKU value $($SystemID) not found in XML source. Exiting script"
                Write-Output "Model with SKU value $($SystemID) not found in XML source. Exiting script"
                Exit 0
            }       
        } else { 
            # HP Prereq is missing. Exit script
            Write-EventLog -LogName $EventLogName -EntryType Warning -EventId 8002 -Source $EventLogSource -Message "HP CMSL Powershell Module is missing. Remediation not possible."
            Write-Output "HP Prereq missing. HPCMSL Powershell Module is missing. Remediation not possible."
            Exit 0
        }
    }
    {($PSItem -match "Lenovo")}{
        Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message  "Validated Lenovo hardware check"
        $LenovoPreReq = $true
        if ($LenovoPreReq){
            # Get matching identifier from baseboard
            $SystemID = "Something"
            $SupportedModel = $BIOSPackageDetails | Where-Object {$_.Description -match $SystemID}
            if (-not ([string]::IsNullOrEmpty($SupportedModel))) {
                [version]$BIOSApprovedVersion = ($BIOSPackageDetails | Where-Object {$_.Description -match $SystemID} | Sort-Object Version -Descending  | Select-Object -First 1 -Unique -ExpandProperty Version).Split(" ")[0] 
                $OEM = "Lenovo"
            } 
            else {
                Write-EventLog -LogName $EventLogName -EntryType Warning -EventId 8001 -Source $EventLogSource -Message "Model $ComputerModel with SKU value $SystemSKU not found in XML source"
            }
        }
    }
    {($PSItem -match "Dell")}{
        Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message  "Validated Dell hardware check"
        if ($DellPreReq){
            # Get matching identifier from baseboard
            $SystemID = "Something"
            $SupportedModel = $BIOSPackageDetails | Where-Object {$_.Description -match $SystemID}
            if (-not ([string]::IsNullOrEmpty($SupportedModel))) {
                [version]$BIOSApprovedVersion = ($BIOSPackageDetails | Where-Object {$_.Description -match $SystemID} | Sort-Object Version -Descending  | Select-Object -First 1 -Unique -ExpandProperty Version).Split(" ")[0] 
                $OEM = "DELL"
            } 
            else {
                Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message  "Model $ComputerModel with SKU value $SystemSKU not found in XML source"
            }       
        }
    }
    default {
        Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message  "Incompatible Hardware. $($Manufacturer) not supported"
        Write-Output "Incompatible Hardware. $($Manufacturer) not supported"
        Exit 0
    }
}

# Checking if registry entries for BIOS Update management exits and set to 0 if they don't exists
if (-NOT(Test-Path -Path "$RegPath\")) {
    New-Item -Path "$RegPath" -Force
    New-ItemProperty -Path "$RegPath" -Name 'BIOSUpdateInprogress' -Value 0 -PropertyType 'DWORD'
    New-ItemProperty -Path "$RegPath" -Name 'BIOSUpdateAttempts' -Value 0 -PropertyType 'DWORD'
    New-ItemProperty -Path "$RegPath" -Name 'BIOSUpdateTime' -Value "" -PropertyType 'String'
    New-ItemProperty -Path "$RegPath" -Name 'BIOSDeployedVersion' -Value "" -PropertyType 'String'
}

# Check if BIOS Update is in Progress
$BiosUpdateinProgress = Get-ItemPropertyValue -Path $RegPath -Name "BIOSUpdateInprogress"
if ($BiosUpdateinProgress -ne 0){
    Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "BIOS Update already in Progress"
    # Check if computer has restarted since last try 
    [DateTime]$BIOSUpdateTime = Get-ItemPropertyValue -Path "$RegPath" -Name 'BIOSUpdateTime'
    $LastBootime = Get-Date (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime)
    if ($BIOSUpdateTime -gt $LastBootime){
        Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "Computer pending reboot after BIOS staging. Checking for user session"
        # Computer not restarted - Invoke remediation to notify user to reboot
        if (Test-UserSession){
            #User is logged on - send toast to user to perform the reboot
            Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "User session found - notify user to reboot with toast"
            Invoke-ToastNotification -ToastSettings $ToastSettings -AppID $AppID -Scenario $Scenario
            Write-Output  "Computer pending reboot after BIOS staging. User toast invoked"
        } else {
            #No user logged on - enforcing a reboot to finalize BIOS flashing                
            Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "No user currenty logged on - restarting computer to finalize BIOS flashing"
            Write-Output  "Computer pending reboot after BIOS staging. No users session found - restarting"
            $RestartCommand = 'C:\Windows\System32\shutdown.exe'
            $RestartArguments = '-r -t 60 -c "Your computer will be restarted in 1 minute to complete the BIOS Update process."'
            Start-Process $RestartCommand -ArgumentList $RestartArguments -NoNewWindow
        }
        Exit 0
    }
    else {
        # Step 4 Computer restarted - Check BIOS Version
        Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "Computer has restarted after flashing - validating bios version"
        #Check BIOS Version - if not updated - Check counter - if not met threshold exit 1 - if treshold exit 0 
        $TestBiosCommand = "Test-BIOSVersion$($OEM) -BIOSApprovedVersion $($BIOSApprovedVersion) -SystemID $($SystemID)"
        $BIOSCheck = Invoke-Expression $TestBiosCommand
        
        #If updated OK - Cleanup
        if ($BIOSCheck.ExitCode -eq 0){
            Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "Update Completed"
            Set-ItemProperty -Path "$RegPath" -Name 'BIOSUpdateInprogress' -Value 0
            Set-ItemProperty -Path "$RegPath" -Name 'BIOSUpdateAttempts' -Value 0 
            Set-ItemProperty -Path "$RegPath" -Name 'BIOSUpdateTime' -Value "" 
            Set-ItemProperty -Path "$RegPath" -Name 'BIOSDeployedVersion' -Value "" 
            Write-Output "$($BIOSCheck.Message)"
            Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "$($BIOSCheck.Message)"
            Exit 0
        }
        else {
            #Step 5 Computer restarted - BIOS not updated - Check counter
            [int]$Attempts = Get-ItemPropertyValue -Path $RegPath -Name 'BIOSUpdateAttempts'
            Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "Attempt $($Attempts): BIOS not current after flashing and reboot"
            if ($Attempts -gt 3){
                # Give up after 3 attempts
                Write-EventLog -LogName $EventLogName -EntryType Warning -EventId 8002 -Source $EventLogSource -Message "Update not completed after reboot - giving up after $($Attempts) attempts"
                Write-Output "Update not completed after reboot - giving up after $($Attempts) attempts"
                Exit 0     
            } 
            else {
                Write-EventLog -LogName $EventLogName -EntryType Warning -EventId 8002 -Source $EventLogSource -Message "Checking for active users sessions"
                # Checking for user session                
                if (Test-UserSession){
                    #User is logged on - send toast to user to perform the reboot
                    Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "User session found - notify user to reboot with toast"
                    Invoke-ToastNotification -ToastSettings $ToastSettings -AppID $AppID -Scenario $Scenario
                    Write-Output  "Computer pending reboot after BIOS staging. User toast invoked"
                } else {
                    #No user logged on - enforcing a reboot to finalize BIOS flashing                
                    Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "No user currenty logged on - restarting computer to finalize BIOS flashing"
                    Write-Output  "Computer pending reboot after BIOS staging. No users session found - restarting"
                    $RestartCommand = 'C:\Windows\System32\shutdown.exe'
                    $RestartArguments = '-r -t 60 -c "Your computer will be restarted in 1 minute to complete the BIOS Update process."'
                    Start-Process $RestartCommand -ArgumentList $RestartArguments -NoNewWindow
                }
                Exit 0
            }         
        }
    }
}
else {
    # Step 6 BIOS Update not in progress - Check BIOS Version
    Write-Output "Validate bios version"
    $UpdateBIOSCommand = "Invoke-BIOSUpdate$($OEM) -BIOSApprovedVersion $($BIOSApprovedVersion) -SystemID $($SystemID)"
    $BIOSUpdate = Invoke-Expression $UpdateBIOSCommand

    if ($BIOSUpdate.ExitCode -eq 1){
        Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "$($BIOSCheck.Message)"
        Write-Output "$($BIOSUpdate.Message)"
        Exit 1
    }
    else {
        Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "$($BIOSCheck.Message)"
        Write-Output "$($BIOSUpdate.Message)"
        Exit 0
    } 
}
#EndRegion Script

