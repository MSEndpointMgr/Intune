#region functions
# Function to get all Installed Application
function Get-InstalledApplications() {
    param(
        [string]$UserSid
        )
    
    New-PSDrive -PSProvider Registry -Name "HKU" -Root HKEY_USERS | Out-Null
    $regpath = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*")
    $regpath += "HKU:\$UserSid\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    if (-not ([IntPtr]::Size -eq 4)) 
    {
        $regpath += "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $regpath += "HKU:\$UserSid\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    }
    $propertyNames = 'DisplayName','DisplayVersion','Publisher', 'UninstallString'
    $Apps = Get-ItemProperty $regpath -Name $propertyNames -ErrorAction SilentlyContinue | .{process{if($_.DisplayName) { $_ } }} | Select-Object DisplayName, DisplayVersion, Publisher, UninstallString, PSPath | Sort-Object DisplayName   
    Remove-PSDrive -Name "HKU" | Out-Null
    Return $Apps
}
# Function to create the authorization signature
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}
# Function to create and post the request
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode

}
#endregion functions

#region script
#region initialize
# Replace with your Workspace ID
$CustomerId = ""  

# Replace with your Primary Key
$SharedKey = ""

#Control if you want to collect App or Device Inventory or both (True = Collect)
$CollectAppInventory = $true
$CollectDeviceInventory = $true

#endregion initialize
#region DEVICEINVENTORY
if ($CollectDeviceInventory){
    #Set Name of Log
    $DeviceLog = "DeviceInventory"

    #Get Intune DeviceID and ManagedDeviceName
    if(@(Get-ChildItem HKLM:SOFTWARE\Microsoft\Enrollments\ -Recurse | Where-Object {$_.PSChildName -eq 'MS DM Server'}))
    {
    $MSDMServerInfo = Get-ChildItem HKLM:SOFTWARE\Microsoft\Enrollments\ -Recurse | Where-Object {$_.PSChildName -eq 'MS DM Server'}
    $ManagedDeviceInfo = Get-ItemProperty -LiteralPath "Registry::$($MSDMServerInfo)"
    }
    $ManagedDeviceName = $ManagedDeviceInfo.EntDeviceName
    $ManagedDeviceID = $ManagedDeviceInfo.EntDMID

    #Get the AzureAD Device ID
    $command = (dsregcmd.exe /status) | Select-String ("DeviceID : ")
    $output = $command.ToString().trim() -split " : "
    $AADDeviceID = $output[1]

    #Get Windows Update Service Settings
    $DefaultAUService = (New-Object -ComObject "Microsoft.Update.ServiceManager").Services | Where-Object {$_.isDefaultAUService -eq $True} | Select-Object Name
    $AUMeteredNetwork =  (Get-ItemProperty -Path HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings\).AllowAutoWindowsUpdateDownloadOverMeteredNetwork
    if ($AUMeteredNetwork -eq "0"){
        $AUMetered = "false"
    } else {$AUMetered = "true"}

    #Get Device Location
    $ComputerPublicIP = (Invoke-WebRequest -UseBasicParsing -uri "http://ifconfig.me/ip").Content
    $Computerlocation = Invoke-RestMethod -Method Get -Uri "http://ip-api.com/json/$ComputerPublicIP"
    $ComputerCountry = $Computerlocation.country
    $ComputerCity = $Computerlocation.city

    # Get Computer Inventory Information 
    $ComputerInfo = Get-computerInfo
    $ComputerName = $ComputerInfo.CsName
    $ComputerModel = $ComputerInfo.CsModel
    $ComputerManufacturer = $ComputerInfo.CsManufacturer
    $ComputerUptime = [int]($ComputerInfo.OsUptime).Days
    $ComputerLastBoot = $ComputerInfo.OsLastBootUpTime
    $ComputerInstallDate = $ComputerInfo.OsInstallDate
    $ComputerWindowsVersion = $ComputerInfo.WindowsVersion
    $ComputerSystemSkuNumber = $ComputerInfo.CsSystemSKUNumber
    $ComputerSerialNr = $ComputerInfo.BiosSeralNumber   
    $ComputerBiosVersion = $ComputerInfo.BiosSMBIOSBIOSVersion
    $ComputerBiosDate = $ComputerInfo.BiosReleaseDate
    $ComputerFirmwareType = $ComputerInfo.BiosFirmwareType
    $ComputerPhysicalMemory = [Math]::Round(($ComputerInfo.CsTotalPhysicalMemory/ 1GB))
    $ComputerOSBuild = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name CurrentBuild).CurrentBuild
    $ComputerOSRevision = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR).UBR
    $ComputerCPU = Get-CimInstance win32_processor  | Select-Object Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors
    $ComputerProcessorManufacturer = $ComputerCPU.Manufacturer
    $ComputerProcessorName = $ComputerCPU.Name
    $ComputerNumberOfCores = $ComputerCPU.NumberOfCores
    $ComputerNumberOfLogicalProcessors = $ComputerCPU.NumberOfLogicalProcessors
    $TPMValues = Get-Tpm -ErrorAction SilentlyContinue | Select-Object -Property TPMReady, TPMPresent, TPMEnabled, TPMActivated, ManagedAuthLevel
    $BitLockerInfo = Get-BitLockerVolume -MountPoint C: | Select-Object -Property *
    $ComputerTPMReady = $TPMValues.TPMReady
    $ComputerTPMPresent = $TPMValues.TPMPresent
    $ComputerTPMEnabled = $TPMValues.TPMEnabled
    $ComputerTPMActivated = $TPMValues.TPMActivated
    $ComputerBitlockerCipher = $BitLockerInfo.EncryptionMethod
    $ComputerBitlockerStatus = $BitLockerInfo.VolumeStatus
    $ComputerBitlockerProtection = $BitLockerInfo.ProtectionStatus
    $CurrentNetAdapter = Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and  $_.Name -notmatch "vEthernet"} 
    $IPConfiguration = Get-NetIPConfiguration -InterfaceIndex $CurrentNetAdapter[0].ifIndex
    $ComputerNetInterfaceDescription = $CurrentNetAdapter.InterfaceDescription
    $ComputerNetProfileName = $IPConfiguration.NetProfile.Name 
    $ComputerNetIPv4Adress = $IPConfiguration.IPv4Address.IPAddress
    $ComputerNetInterfaceAlias = $CurrentNetAdapter.InterfaceAlias
    $ComputerNetIPv4DefaultGateway = $IPConfiguration.IPv4DefaultGateway.NextHop
    $ComputerDefaultAUService = $DefaultAUService.Name
    $ComputerAUMetered = $AUMetered
    #$timestamp = Get-Date -Format "yyyy-MM-DDThh:mm:ssZ" 

    # Create JSON to Upload to Log Analytics
    $Inventory = New-Object System.Object
    $Inventory | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force   
    $Inventory | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force   
    $Inventory | Add-Member -MemberType NoteProperty -Name "AADDeviceID" -Value "$AADDeviceID" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force       
    $Inventory | Add-Member -MemberType NoteProperty -Name "Model" -Value "$ComputerModel" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "Manufacturer" -Value "$ComputerManufacturer" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "ComputerUpTime" -Value "$ComputerUptime" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "LastBoot" -Value "$ComputerLastBoot" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "InstallDate" -Value "$ComputerInstallDate" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "WindowsVersion" -Value "$ComputerWindowsVersion" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "DefaultAUService" -Value "$ComputerDefaultAUService" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "AUMetered" -Value "$ComputerAUMetered" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "SystemSkuNumber" -Value "$ComputerSystemSkuNumber" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "SerialNumber" -Value "$ComputerSerialNr" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "BiosVersion" -Value "$ComputerBiosVersion" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "BiosDate" -Value "$ComputerBiosDate" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "FirmwareType" -Value "$ComputerFirmwareType" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "Memory" -Value "$ComputerPhysicalMemory" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "OSBuild" -Value "$ComputerOSBuild" -Force 
    $Inventory | Add-Member -MemberType NoteProperty -Name "OSRevision" -Value "$ComputerOSRevision" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "CPUManufacturer" -Value "$ComputerProcessorManufacturer" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "CPUName" -Value "$ComputerProcessorName" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "CPUCores" -Value "$ComputerNumberOfCores" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "CPULogical" -Value "$ComputerNumberOfLogicalProcessors" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "TPMReady" -Value "$ComputerTPMReady" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "TPMPresent" -Value "$ComputerTPMPresent" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "TPMEnabled" -Value "$ComputerTPMEnabled" -Force 
    $Inventory | Add-Member -MemberType NoteProperty -Name "TPMActived" -Value "$ComputerTPMActivated" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "BitlockerCipher" -Value "$ComputerBitlockerCipher" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "BitlockerVolumeStatus" -Value "$ComputerBitlockerStatus" -Force
    $Inventory | Add-Member -MemberType NoteProperty -Name "BitlockerProtectionStatus" -Value "$ComputerBitlockerProtection" -Force 
    $Inventory | Add-Member -MemberType NoteProperty -Name "NetInterfaceDescription" -Value "$ComputerNetInterfaceDescription" -Force 
    $Inventory | Add-Member -MemberType NoteProperty -Name "NetProfileName" -Value "$ComputerNetProfileName" -Force 
    $Inventory | Add-Member -MemberType NoteProperty -Name "NetIPv4Adress" -Value "$ComputerNetIPv4Adress" -Force 
    $Inventory | Add-Member -MemberType NoteProperty -Name "NetInterfaceAlias" -Value "$ComputerNetInterfaceAlias" -Force 
    $Inventory | Add-Member -MemberType NoteProperty -Name "NetIPv4DefaultGateway" -Value "$ComputerNetIPv4DefaultGateway" -Force  
    $Inventory | Add-Member -MemberType NoteProperty -Name "ComputerContry" -Value "$ComputerCountry" -Force 
    $Inventory | Add-Member -MemberType NoteProperty -Name "ComputerCity" -Value "$ComputerCity" -Force  

    $Devicejson = $Inventory | ConvertTo-Json

    # Submit the data to the API endpoint
    $ResponseDeviceInventory = Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($Devicejson)) -logType $DeviceLog 
}#endregion DEVICEINVENTORY

#region APPINVENTORY
if ($CollectAppInventory){
    $AppLog = "AppInventory"

    #Get SID of current interactive users
    $CurrentLoggedOnUser = (Get-WmiObject -Class win32_computersystem).UserName
    $AdObj = New-Object System.Security.Principal.NTAccount($CurrentLoggedOnUser)
    $strSID = $AdObj.Translate([System.Security.Principal.SecurityIdentifier])
    $UserSid = $strSID.Value
    #Get Apps for system and current user
    $MyApps = Get-InstalledApplications -UserSid $UserSid
    $UniqueApps = ($MyApps | Group-Object Displayname | Where-Object {$_.Count -eq 1} ).Group
    $DuplicatedApps = ($MyApps | Group-Object Displayname | Where-Object {$_.Count -gt 1} ).Group 
    $NewestDuplicateApp = ($DuplicatedApps | Group-Object DisplayName) | ForEach-Object {$_.Group | Sort-Object [version]DisplayVersion -Descending | Select-Object -First 1 }
    $CleanAppList = $UniqueApps + $NewestDuplicateApp | Sort-Object DisplayName

    $AppArray = @()
    foreach ($App in $CleanAppList){
        $tempapp = new-object -TypeName PSObject
        $tempapp | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force   
        $tempapp | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force   
        $tempapp | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force   
        $tempapp | Add-Member -MemberType NoteProperty -Name "AADDeviceID" -Value "$AADDeviceID" -Force
        $tempapp | Add-Member -MemberType NoteProperty -Name "AppName" -Value $App.DisplayName -Force
        $tempapp | Add-Member -MemberType NoteProperty -Name "AppVersion" -Value $App.DisplayVersion -Force
        $tempapp | Add-Member -MemberType NoteProperty -Name "AppPublisher" -Value $App.Publisher -Force
        $tempapp | Add-Member -MemberType NoteProperty -Name "AppUninstallString" -Value $App.UninstallString -Force
        $tempapp | Add-Member -MemberType NoteProperty -Name "AppUninstallRegPath" -Value $app.PSPath.Split("::")[-1]
        $AppArray += $tempapp
    }    

    $Appjson = $AppArray | ConvertTo-Json

    # Submit the data to the API endpoint
    $ResponseAppInventory =  Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($Appjson)) -logType $AppLog 
}#endregion APPINVENTORY

#Report back status
$date = get-date -Format "dd-MM HH:mm"
$OutputMessage = "InventoryDate:$date "
if($CollectDeviceInventory){
    if($ResponseDeviceInventory -eq 200){
        
        $OutputMessage = $OutPutMessage + "AppInventory:OK "
    }
    else{
        $OutputMessage = $OutPutMessage + "AppInventory:Fail "
    }
}
if($CollectAppInventory){
    if($ResponseAppInventory -eq 200){
        
        $OutputMessage = $OutPutMessage + "DeviceInventory:OK "
    }
    else{
        $OutputMessage = $OutPutMessage + "DeviceInventory:Fail "
    }
}
Write-Output $OutputMessage
Exit 0
#endregion script