<#
.SYNOPSIS
    Automatically detect the current location using Location Services in Windows 10 and call the Azure Maps API to determine and set the Windows time zone based on current location data.

.DESCRIPTION
    This script will automatically set the Windows time zone based on current location data. It does so by detecting the current position (latitude and longitude) from Location services
    in Windows 10 and then calls the Azure Maps API to determine correct Windows time zone based of the current position. If Location Services is not enabled in Windows 10, it will automatically
    be enabled and ensuring the service is running.

.PARAMETER AzureMapsSharedKey
    Specify the Azure Maps API shared key available under the Authentication blade of the resource in Azure.

.NOTES
    FileName:    Set-WindowsTimeZone.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2020-05-19
    Updated:     2020-12-22

    Version history:
    1.0.0 - (2020-05-19) - Script created
    1.0.1 - (2020-05-23) - Added registry key presence check for lfsvc configuration and better handling of selecting a single Windows time zone when multiple objects with different territories where returned (thanks to @jgkps for reporting)
    1.0.2 - (2020-09-10) - Improved registry key handling for enabling location services
    1.0.3 - (2020-12-22) - Added support for TLS 1.2 to disable location services once script has completed
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [parameter(Mandatory = $false, HelpMessage = "Specify the Azure Maps API shared key available under the Authentication blade of the resource in Azure.")]
    [ValidateNotNullOrEmpty()]
    [string]$AzureMapsSharedKey = "<ENTER_YOUR_SHARED_KEY_HERE>"
)
Begin {
    # Enable TLS 1.2 support for downloading modules from PSGallery
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
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
            [string]$Severity
        )
        # Determine log file location
        $LogFilePath = Join-Path -Path (Join-Path -Path $env:windir -ChildPath "Temp") -ChildPath "Set-WindowsTimeZone.log"
        
        # Construct time stamp for log entry
        if (-not(Test-Path -Path 'variable:global:TimezoneBias')) {
            [string]$global:TimezoneBias = [System.TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalMinutes
            if ($TimezoneBias -match "^-") {
                $TimezoneBias = $TimezoneBias.Replace('-', '+')
            }
            else {
                $TimezoneBias = '-' + $TimezoneBias
            }
        }
        $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), $TimezoneBias)
        
        # Construct date for log entry
        $Date = (Get-Date -Format "MM-dd-yyyy")
        
        # Construct context for log entry
        $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        
        # Construct final log entry
        $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""WindowsTimeZone"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
        
        # Add value to log file
        try {
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to append log entry to Set-WindowsTimeZone.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    }

    function Get-GeoCoordinate {
        # Construct return value object
        $Coordinates = [PSCustomObject]@{
            Latitude = $null
            Longitude = $null
        }

        Write-LogEntry -Value "Attempting to start resolving the current device coordinates" -Severity 1
        $GeoCoordinateWatcher = New-Object -TypeName "System.Device.Location.GeoCoordinateWatcher"
        $GeoCoordinateWatcher.Start()

        # Wait until watcher resolves current location coordinates
        $GeoCounter = 0
        while (($GeoCoordinateWatcher.Status -notlike "Ready") -and ($GeoCoordinateWatcher.Permission -notlike "Denied") -and ($GeoCounter -le 60)) {
            Start-Sleep -Seconds 1
            $GeoCounter++
        }

        # Break operation and return empty object since permission was denied
        if ($GeoCoordinateWatcher.Permission -like "Denied") {
            Write-LogEntry -Value "Permission was denied accessing coordinates from location services" -Severity 3

            # Stop and dispose of the GeCoordinateWatcher object
            $GeoCoordinateWatcher.Stop()
            $GeoCoordinateWatcher.Dispose()

            # Handle return error
            return $Coordinates
        }

        # Set coordinates for return value
        $Coordinates.Latitude = ($GeoCoordinateWatcher.Position.Location.Latitude).ToString().Replace(",", ".")
        $Coordinates.Longitude = ($GeoCoordinateWatcher.Position.Location.Longitude).ToString().Replace(",", ".")

        # Stop and dispose of the GeCoordinateWatcher object
        $GeoCoordinateWatcher.Stop()
        $GeoCoordinateWatcher.Dispose()

        # Handle return value
        return $Coordinates
    }

    function New-RegistryKey {
        param(
            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string]$Path
        )
        try {
            Write-LogEntry -Value "Checking presence of registry key: $($Path)" -Severity 1
            if (-not(Test-Path -Path $Path)) {
                Write-LogEntry -Value "Attempting to create registry key: $($Path)" -Severity 1
                New-Item -Path $Path -ItemType "Directory" -Force -ErrorAction Stop | Out-Null
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value "Failed to create registry key '$($Path)'. Error message: $($_.Exception.Message)" -Severity 3
        }
    }

    function Set-RegistryValue {
        param(
            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string]$Path,
    
            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string]$Name,        
    
            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string]$Value,

            [parameter(Mandatory=$false)]
            [ValidateNotNullOrEmpty()]
            [ValidateSet("String", "ExpandString", "Binary", "DWord", "MultiString", "Qword")]
            [string]$Type = "String"
        )
        try {
            Write-LogEntry -Value "Checking presence of registry value '$($Name)' in registry key: $($Path)" -Severity 1
            $RegistryValue = Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($RegistryValue -ne $null) {
                Write-LogEntry -Value "Setting registry value '$($Name)' to: $($Value)" -Severity 1
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -ErrorAction Stop
            }
            else {
                New-RegistryKey -Path $Path -ErrorAction Stop
                Write-LogEntry -Value "Setting registry value '$($Name)' to: $($Value)" -Severity 1
                New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force -ErrorAction Stop | Out-Null
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value "Failed to create or update registry value '$($Name)' in '$($Path)'. Error message: $($_.Exception.Message)" -Severity 3
        }
    }

    function Enable-LocationServices {
        $AppsAccessLocation = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
        Set-RegistryValue -Path $AppsAccessLocation -Name "LetAppsAccessLocation" -Value 0 -Type "DWord"

        $LocationConsentKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
        Set-RegistryValue -Path $LocationConsentKey -Name "Value" -Value "Allow" -Type "String"

        $SensorPermissionStateKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
        Set-RegistryValue -Path $SensorPermissionStateKey -Name "SensorPermissionState" -Value 1 -Type "DWord"

        $LocationServiceConfigurationKey = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
        Set-RegistryValue -Path $LocationServiceConfigurationKey -Name "Status" -Value 1 -Type "DWord"

        $LocationService = Get-Service -Name "lfsvc"
        Write-LogEntry -Value "Checking location service 'lfsvc' for status: Running" -Severity 1
        if ($LocationService.Status -notlike "Running") {
            Write-LogEntry -Value "Location service is not running, attempting to start service" -Severity 1
            Start-Service -Name "lfsvc"
        }
    }

    function Disable-LocationServices {
        $LocationConsentKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
        Set-RegistryValue -Path $LocationConsentKey -Name "Value" -Value "Deny" -Type "String"

        $SensorPermissionStateKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
        Set-RegistryValue -Path $SensorPermissionStateKey -Name "SensorPermissionState" -Value 0 -Type "DWord"

        $LocationServiceConfigurationKey = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
        Set-RegistryValue -Path $LocationServiceConfigurationKey -Name "Status" -Value 0 -Type "DWord"
    }

    Write-LogEntry -Value "Starting to determine the desired Windows time zone configuration" -Severity 1

    try {
        # Load required assembly and construct a GeCoordinateWatcher object
        Write-LogEntry -Value "Attempting to load required 'System.Device' assembly" -Severity 1
        Add-Type -AssemblyName "System.Device" -ErrorAction Stop

        try {
            # Ensure Location Services in Windows is enabled and service is running
            Enable-LocationServices

            # Retrieve the latitude and longitude values
            $GeoCoordinates = Get-GeoCoordinate
            if (($GeoCoordinates.Latitude -ne $null) -and ($GeoCoordinates.Longitude -ne $null)) {
                Write-LogEntry -Value "Successfully resolved current device coordinates" -Severity 1
                Write-LogEntry -Value "Detected latitude: $($GeoCoordinates.Latitude)" -Severity 1
                Write-LogEntry -Value "Detected longitude: $($GeoCoordinates.Longitude)" -Severity 1

                # Construct query string for Azure Maps API request
                $AzureMapsQuery = -join@($GeoCoordinates.Latitude, ",", $GeoCoordinates.Longitude)

                try {
                    # Call Azure Maps timezone/byCoordinates API to retrieve IANA time zone id
                    Write-LogEntry -Value "Attempting to determine IANA time zone id from Azure MAPS API using query: $($AzureMapsQuery)" -Severity 1
                    $AzureMapsTimeZoneURI = "https://atlas.microsoft.com/timezone/byCoordinates/json?subscription-key=$($AzureMapsSharedKey)&api-version=1.0&options=all&query=$($AzureMapsQuery)"
                    $AzureMapsTimeZoneResponse = Invoke-RestMethod -Uri $AzureMapsTimeZoneURI -Method "Get" -ErrorAction Stop
                    if ($AzureMapsTimeZoneResponse -ne $null) {
                        $IANATimeZoneValue = $AzureMapsTimeZoneResponse.TimeZones.Id
                        Write-LogEntry -Value "Successfully retrieved IANA time zone id from current position data: $($IANATimeZoneValue)" -Severity 1

                        try {
                            # Call Azure Maps timezone/enumWindows API to retrieve the Windows time zone id
                            Write-LogEntry -Value "Attempting to Azure Maps API to enumerate Windows time zone ids" -Severity 1
                            $AzureMapsWindowsEnumURI = "https://atlas.microsoft.com/timezone/enumWindows/json?subscription-key=$($AzureMapsSharedKey)&api-version=1.0"
                            $AzureMapsWindowsEnumResponse = Invoke-RestMethod -Uri $AzureMapsWindowsEnumURI -Method "Get" -ErrorAction Stop
                            if ($AzureMapsWindowsEnumResponse -ne $null) {
                                $TimeZoneID = $AzureMapsWindowsEnumResponse | Where-Object { ($PSItem.IanaIds -like $IANATimeZoneValue) -and ($PSItem.Territory.Length -eq 2) } | Select-Object -ExpandProperty WindowsId
                                Write-LogEntry -Value "Successfully determined the Windows time zone id: $($TimeZoneID)" -Severity 1

                                try {
                                    # Set the time zone
                                    Write-LogEntry -Value "Attempting to configure the Windows time zone id with value: $($TimeZoneID)" -Severity 1
                                    Set-TimeZone -Id $TimeZoneID -ErrorAction Stop
                                    Write-LogEntry -Value "Successfully configured the Windows time zone" -Severity 1
                                }
                                catch [System.Exception] {
                                    Write-LogEntry -Value "Failed to set Windows time zone. Error message: $($PSItem.Exception.Message)" -Severity 3
                                }
                            }
                            else {
                                Write-LogEntry -Value "Invalid response from Azure Maps call enumerating Windows time zone ids" -Severity 3
                            }
                        }
                        catch [System.Exception] {
                            Write-LogEntry -Value "Failed to call Azure Maps API to enumerate Windows time zone ids. Error message: $($PSItem.Exception.Message)" -Severity 3
                        }
                    }
                    else {
                        Write-LogEntry -Value "Invalid response from Azure Maps query when attempting to retrieve the IANA time zone id" -Severity 3
                    }
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Failed to retrieve the IANA time zone id based on current position data from Azure Maps. Error message: $($PSItem.Exception.Message)" -Severity 3
                }
            }
            else {
                Write-LogEntry -Value "Unable to determine current device coordinates from location services, breaking operation" -Severity 3
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value "Failed to determine Windows time zone. Error message: $($PSItem.Exception.Message)" -Severity 3
        }
    }
    catch [System.Exception] {
        Write-LogEntry -Value "Failed to load required 'System.Device' assembly, breaking operation" -Severity 3
    }
}
End {
    # Set Location Services to disabled to let other policy configuration manage the state
    Disable-LocationServices
}