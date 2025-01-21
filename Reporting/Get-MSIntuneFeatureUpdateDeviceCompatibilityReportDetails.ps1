# Authentication (requires MSGraphRequest module)
$Global:AuthenticationHeader = Get-AccessToken -TenantID "<tenant_id" -ClientID "<client_id>" -RedirectUri "http://localhost"

# Params - Mandatory
$ReportName = "MEMUpgradeCompatibility"
$AssetType = @("Application", "Driver") # Application, Driver, Other
$RiskStatus = "MediumRisk" # LowRisk, MediumRisk, HighRisk
$OperatingSystemName = "Windows 11"
$OperatingSystemVersion = "23H2"

# Functions
function ConvertTo-Base64String {
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the string to be encoded as Base64.")]
        [ValidateNotNullOrEmpty()]
        [string]$Value
    )
    Process {
        # Encode string from parameter input
        $EncodedString = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Value))

        # Handle return value
        return $EncodedString
    }
}

function ConvertFrom-Base64String {
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the string to be decoded from Base64 to a human-readable string.")]
        [ValidateNotNullOrEmpty()]
        [string]$Value
    )
    Process {
        # Decode string from parameter input
        $DecodedString = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Value))

        # Handle return value
        return $DecodedString
    }
}

# Report filter table names
$ReportFilterTableNames = @{
    MEMUpgradeCompatibility = "MEMUpgradeReadinessTargetOS"
}

# Report table identifiers for cached report configurations request body
$ReportTableIdentifiers = @{
    MEMUpgradeCompatibility = "MEMUpgradeReadinessOrgAppAndDriverV2_00000000-0000-0000-0000-000000000001"
}

# Asset type table
$ReportAssetTypeTableValues = @{
    "All" = 0
    "Application" = 1
    "Driver" = 2
    "Other" = 3
}

# Report readiness status table
$ReportReadinessStatusTableValues = @{
    "LowRisk" = 0
    "MediumRisk" = 1
    "HighRisk" = 2
}

# Target operating system filtering request body table
$ReportFiltersBodyTable = @{
    name = $ReportFilterTableNames[$ReportName]
    select = $null
    skip = 0
    top = 100
    filter = [string]::Empty
    orderBy = @("DisplayName desc")
}

# Invoke request to retrieve available target operating system filter values
$ReportFiltersUri = "deviceManagement/reports/getReportFilters"
$ReportFiltersResponse = Invoke-MSGraphOperation -Post -APIVersion "Beta" -Resource $ReportFiltersUri -Body ($ReportFiltersBodyTable | ConvertTo-Json)
if ($ReportFiltersResponse.Values.Count -ge 1) {
    # Construct array list for all report filter values
    $ReportFilterValuesList = New-Object -TypeName "System.Collections.ArrayList"
    
    # Construct a new custom object for each report filter value returned from request
    foreach ($ReportFilterValue in $ReportFiltersResponse.Values) {
        $PSObject = [PSCustomObject]@{
            ID = $ReportFilterValue[0]
            DisplayName = $ReportFilterValue[1]
        }
        $ReportFilterValuesList.Add($PSObject) | Out-Null
    }

    # Select target operating system filter value from list based on parameter input
    $TargetOperatingSystemFilter = $ReportFilterValuesList | Where-Object { ($PSItem.DisplayName -like "*$($OperatingSystemName)*") -and ($PSItem.DisplayName -like "*$($OperatingSystemVersion)*") }
}

# Convert target operating system filter display name to an url encoded and Base64 encoded string
$FilterPickerEncodedString = ConvertTo-Base64String -Value ([System.Uri]::EscapeDataString($TargetOperatingSystemFilter.DisplayName))

# Construct filter string dynamically depending on parameter input
$CachedReportConfigurationsFilterString = "(ReadinessStatus eq '$($ReportReadinessStatusTableValues[$RiskStatus])') and (TargetOS eq '$($TargetOperatingSystemFilter.ID)')"
if ($AssetType -ne $null) {
    if ($AssetType.Count -eq 1) {
        $CachedReportConfigurationsFilterString = $CachedReportConfigurationsFilterString + " and (AssetType eq '$($ReportAssetTypeTableValues[$AssetType])')"
    }
    else {
        $CachedReportConfigurationsFilterString = $CachedReportConfigurationsFilterString + " and ("
        for ($i = 0; $i -lt $AssetType.Count; $i++) {
            if ($i -gt 0) {
                $CachedReportConfigurationsFilterString = $CachedReportConfigurationsFilterString + " or "
            }
            $CachedReportConfigurationsFilterString = $CachedReportConfigurationsFilterString + "AssetType eq '$($ReportAssetTypeTableValues[$AssetType[$i]])'"
        }
        $CachedReportConfigurationsFilterString = $CachedReportConfigurationsFilterString + ")"
    }
}

$CachedReportConfigurationsBodyTable = @{
    id = $ReportTableIdentifiers[$ReportName]
    filter = $CachedReportConfigurationsFilterString
    metadata = "TargetOS=>filterPicker=$($FilterPickerEncodedString)"
    orderBy = @()
    select = @("AssetType", "AssetName", "AssetVendor", "AssetVersion", "DeviceIssuesCount", "ReadinessStatus", "IssueTypes")
}

# Invoke request for cached report configurations, mimicing the 'Generate' button within the Intune portal
$CachedReportConfigurationsUri = "deviceManagement/reports/cachedReportConfigurations"
$CachedReportConfigurationsResponse = Invoke-MSGraphOperation -Post -APIVersion "Beta" -Resource $CachedReportConfigurationsUri -Body ($CachedReportConfigurationsBodyTable | ConvertTo-Json)
$CachedReportConfigurationsResponse

# Invoke request and await for status change from inProgress to completed
$CachedReportConfigurationsStatusUri = "deviceManagement/reports/cachedReportConfigurations('$($CachedReportConfigurationsResponse.id)')"
$CachedReportConfigurationsStatusResponse = Invoke-MSGraphOperation -Get -APIVersion "Beta" -Resource $CachedReportConfigurationsStatusUri
while ($CachedReportConfigurationsStatusResponse.status -like "inProgress") {
    $CachedReportConfigurationsStatusResponse = Invoke-MSGraphOperation -Get -APIVersion "Beta" -Resource $CachedReportConfigurationsStatusUri
    Start-Sleep -Seconds 1
}

# Cached report request body table for device readiness
$CachedReportAssetsBodyTable = @{
    id = $CachedReportConfigurationsResponse.id
    skip = 0
    top = 50
    search = [string]::Empty # Search for specific assets
    orderBy = @()
    select = @("AssetType", "AssetName", "AssetVendor", "AssetVersion", "DeviceIssuesCount", "ReadinessStatus", "IssueTypes")
    filter = [string]::Empty
}

# Construct array list for all asset values
$AssetList = New-Object -TypeName "System.Collections.Generic.List[System.Object]"

# Invoke request to get data from cached report device readiness
$CachedReportAssetsUri = "deviceManagement/reports/getCachedReport"
$CachedReportAssetsResponse = Invoke-MSGraphOperation -Post -APIVersion "Beta" -Resource $CachedReportAssetsUri -Body ($CachedReportAssetsBodyTable | ConvertTo-Json)
foreach ($CachedReportAsset in $CachedReportAssetsResponse.Values) {
    # Construct a new custom object for each asset value returned from request, using the schema to dynamically add properties
    $Asset = New-Object -TypeName "PSObject"
    for ($i = 0; $i -lt $CachedReportAssetsResponse.Values[0].Count; $i++) {
        $AssetSchemaCurrent = $CachedReportAssetsResponse.Schema[$i].Column
        $Asset | Add-Member -MemberType "NoteProperty" -Name $AssetSchemaCurrent -Value $CachedReportAsset[$i]
    }

    # Update the AssetType property to a human-readable string
    $Asset.AssetType = ($ReportAssetTypeTableValues.GetEnumerator() | Where-Object { $PSItem.Value -eq $Asset.AssetType }).Name

    # Update the ReadinessStatus property to a human-readable string
    $Asset.ReadinessStatus = ($ReportReadinessStatusTableValues.GetEnumerator() | Where-Object { $PSItem.Value -eq $Asset.ReadinessStatus }).Name

    # Add the asset to the list
    $AssetList.Add($Asset)
}
$AssetList | Select-Object -First 2 | Format-Table -AutoSize


# Construct array list for all asset values
$AffectedDevicesList = New-Object -TypeName "System.Collections.Generic.List[System.Object]"

# Retrieve affected devices for specific asset
$AffectedDevicesFilterReportBodyTable = @{
    name = "MEMUpgradeReadinessOprDevicesPerAsset"
    filter = "(TargetOS eq 'NI23H2') and (AssetType eq '2') and (AssetName eq 'Logitech BRIO (usbvideo.sys)') and (AssetVendor eq 'Logitech') and (AssetVersion eq '1.0.85.0')"
    orderBy = @("AssetName asc")
    select = @("DeviceName", "DeviceManufacturer", "DeviceModel", "OSVersion", "IssueTypes")
    top = 40
    skip = 0
}
$ReportFiltersUri = "deviceManagement/reports/getReportFilters"
$ReportFiltersResponse = Invoke-MSGraphOperation -Post -APIVersion "Beta" -Resource $ReportFiltersUri -Body ($AffectedDevicesFilterReportBodyTable | ConvertTo-Json)

foreach ($AffectedDevice in $ReportFiltersResponse.Values) {
    # Construct a new custom object for each asset value returned from request, using the schema to dynamically add properties
    $Device = New-Object -TypeName "PSObject"
    for ($i = 0; $i -lt $ReportFiltersResponse.Values[0].Count; $i++) {
        $DeviceSchemaCurrent = $ReportFiltersResponse.Schema[$i].Column
        $Device | Add-Member -MemberType "NoteProperty" -Name $DeviceSchemaCurrent -Value $AffectedDevice[$i]
    }

    # Add the device to the list
    $AffectedDevicesList.Add($Device)
}
$AffectedDevicesList | Format-Table -AutoSize
