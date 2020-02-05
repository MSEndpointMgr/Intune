# Define the Azure Storage blob URL for where the VcRedist.json file can be accessed
$VcRedistJSONUri = "https://<AzureStorageBlobUrl>"

try {
    # Construct initial table for detection values for all Visual C++ applications populated from JSON file
    $VcRedistTable = New-Object -TypeName "System.Collections.Hashtable"
    $VcRedistMetaData = Invoke-RestMethod -Uri $VcRedistJSONUri -ErrorAction Stop
    foreach ($VcRedistItem in $VcRedistMetaData.VCRedist) {
        $KeyName = -join($VcRedistItem.Version.Replace("-", ""), $VcRedistItem.Architecture)
        $VcRedistTable.Add($KeyName, $false)
    }
}
catch [System.Exception] {
    # Error catched but output is not being redirected, as it would confuse the Win32 app detection model
}

# Construct list for holding detected Visual C++ applications from registry lookup
$VcRedistUninstallList = New-Object -TypeName "System.Collections.ArrayList"

# Define Uninstall registry paths for both 32-bit and 64-bit
$UninstallNativePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
$UninstallWOW6432Path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"

# Add all uninstall registry entries to list from native path
$UninstallItemList = New-Object -TypeName "System.Collections.ArrayList"
$UninstallNativeItems = Get-ChildItem -Path $UninstallNativePath -ErrorAction SilentlyContinue
if ($UninstallNativeItems -ne $null) {
    $UninstallItemList.AddRange($UninstallNativeItems) | Out-Null
}

# Add all uninstall registry entries to list from Wow6432Node path
$UninstallWOW6432Items = Get-ChildItem -Path $UninstallWOW6432Path -ErrorAction SilentlyContinue
if ($UninstallWOW6432Items -ne $null) {
    $UninstallItemList.AddRange($UninstallWOW6432Items) | Out-Null
}

# Determine the detection rules for applicable Visual C++ application installations for operating system architecture
$Is64BitOperatingSystem = [System.Environment]::Is64BitOperatingSystem
if ($Is64BitOperatingSystem -eq $true) {
    # Construct new detection table to hold detection values for all Visual C++ applications
    $VcRedistDetectionTable = New-Object -TypeName "System.Collections.Hashtable"
    foreach ($VcRedistTableItem in $VcRedistTable.Keys) {
        $VcRedistDetectionTable.Add($VcRedistTableItem, $VcRedistTable[$VcRedistTableItem])
    }
}
else {
    # Construct new detection table to hold detection values for all Visual C++ applications
    $VcRedistDetectionTable = New-Object -TypeName "System.Collections.Hashtable"
    foreach ($VcRedistTableItem in $VcRedistTable.Keys) {
        if ($VcRedistTableItem -match "x86") {
            $VcRedistDetectionTable.Add($VcRedistTableItem, $VcRedistTable[$VcRedistTableItem])
        }
    }
}

# Process each uninstall registry item from list
foreach ($VcRedistItem in $UninstallItemList) {
    try {
        $DisplayName = Get-ItemPropertyValue -Path $VcRedistItem.PSPath -Name "DisplayName" -ErrorAction Stop
        if (($DisplayName -match "^Microsoft Visual C\+\+\D*(?<Year>(\d|-){4,9}).*Redistributable.*(?<Architecture>(x86|x64)).*") -or ($DisplayName -match "^Microsoft Visual C\+\+\D*(?<Year>(\d|-){4,9}).*(?<Architecture>(x86|x64)).*Redistributable.*")) {
            $PSObject = [PSCustomObject]@{
                "DisplayName" = $DisplayName
                "Version" = (Get-ItemPropertyValue -Path $VcRedistItem.PSPath -Name "DisplayVersion")
                "Architecture" = $Matches.Architecture
                "Year" = $Matches.Year.Replace("-", "")
                "Path" = $VcRedistItem.PSPath
            }
            $VcRedistUninstallList.Add($PSObject) | Out-Null
        }
    }
    catch [System.Exception] {
        # Error catched but output is not being redirected, as it would confuse the Win32 app detection model
    }
}

# Set detection value in hash-table for each detected Visual C++ application
foreach ($VcRedistApp in $VcRedistUninstallList) {
    $DetectionItemName = -join($VcRedistApp.Year, $VcRedistApp.Architecture)
    if ($VcRedistDetectionTable.Keys -contains $DetectionItemName) {
        $VcRedistDetectionTable[$DetectionItemName] = $true
    }
}

# Handle final detection logic, return only if all desired Visual C++ applications was found
if ($VcRedistDetectionTable.Values -notcontains $false) {
    Write-Output -InputObject "Application detected"
}