<#
.SYNOPSIS
    BIOS Control detection script for MSEndpointMgr Intune MBM
.DESCRIPTION
    This proactive remediation script is part of the Intune version of Modern BIOS management. More information can be found at https://msendpointmgr.com 
    NB: Only edit variables in the Declarations region of the script. 
    The following variables MUST be set: 
    1. DATUri - Url path to BIOSPackages.xml 
.EXAMPLE
	Invoke-IntuneBIOSUpdateDetect.ps1 - Run as SYSTEM 
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
#Region Initialisations
# Set Error Action to Silently Continue
$Script:ErrorActionPreference = "SilentlyContinue"
# Enable TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Script:ExitCode = 0
#Endregion Initialisations

#Region Decalarations
# Create and define Eventlog for logging - edit with caution
$Script:EventLogName = 'MSEndpointMgr'
$Script:EventLogSource = 'MSEndpointMgrBIOSMgmt'
New-EventLog -LogName $EventLogName -Source $EventLogSource -ErrorAction SilentlyContinue

# Define path to DAT provisioned XML
$Script:DATUri = "<TO BE SET>"

# Get manufacturer 
$Script:Manufacturer = (Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty Manufacturer).Trim()

# Registry path for status messages - Edit with caution 
$Script:RegPath = 'HKLM:\SOFTWARE\MSEndpointMgr\BIOSUpdateManagemement'

# Defining BIOSUpdate Status Variables - Do not edit
$Script:BIOSUpdateInprogress = $null
$Script:BIOSUpdateAttempts = $null
$Script:BIOSUpdateTime = $null
$Script:BIOSDeployedVersion = $null
#EndRegion Declarations 
#Region Functions

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

#endregion Functions

#region Script
# Read in DAT XML
[xml]$BIOSPackages = Invoke-WebRequest -Uri $DATUri -UseBasicParsing

# Sort BIOS Packages into variable
$BIOSPackageDetails = $BIOSPackages.ArrayOfCMPackage.CMPackage

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
        } 
        else { 
            # HP Prereq is missing. Exit script
            Write-EventLog -LogName $EventLogName -EntryType Warning -EventId 8002 -Source $EventLogSource -Message "HP CMSL Powershell Module is missing. Remediation not possible."
            Write-Output "HP Prereq missing. HPCMSL Powershell Module is missing. Remediation not possible."
            Exit 0
        }
    }
    {($PSItem -match "Lenovo")}{
        Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "Validated Lenovo hardware check"
        $LenovoPreReq = $false
        if ($LenovoPreReq){
            # Get matching identifier from baseboard
            $SystemID = "Something"
            $SupportedModel = $BIOSPackageDetails | Where-Object {$_.Description -match $SystemID}
            if (-not ([string]::IsNullOrEmpty($SupportedModel))) {
                [version]$BIOSApprovedVersion = ($BIOSPackageDetails | Where-Object {$_.Description -match $SystemID} | Sort-Object Version -Descending  | Select-Object -First 1 -Unique -ExpandProperty Version).Split(" ")[0] 
                $OEM = "Lenovo"
            } 
            else {
                Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "Model $ComputerModel with SKU value $SystemSKU not found in XML source"
            }
        }
        else {
        Write-EventLog -LogName $EventLogName -EntryType Warning -EventId 8002 -Source $EventLogSource -Message "$($Manufacturer) not implemented"
        Write-output "$($Manufacturer) not implemented"
        Exit 0
        }
    }
    {($PSItem -match "Dell")}{
        Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "Validated Dell hardware check"
        $DellPreReq = $false
        if ($DellPreReq){
            # Get matching identifier from baseboard
            $SystemID = "Something"
            $SupportedModel = $BIOSPackageDetails | Where-Object {$_.Description -match $SystemID}
            if (-not ([string]::IsNullOrEmpty($SupportedModel))) {
                [version]$BIOSApprovedVersion = ($BIOSPackageDetails | Where-Object {$_.Description -match $SystemID} | Sort-Object Version -Descending  | Select-Object -First 1 -Unique -ExpandProperty Version).Split(" ")[0] 
                $OEM = "Dell"
            } 
            else {
                Write-EventLog -LogName $EventLogName -EntryType Warning -EventId 8002 -Source $EventLogSource -Message "Model with SKU value $($SystemID) not found in XML source. Exiting script"
                Write-Output "Model with SKU value $($SystemID) not found in XML source. Exiting script"
                Exit 0
            }       
        }
        else {
            Write-EventLog -LogName $EventLogName -EntryType Warning -EventId 8002 -Source $EventLogSource -Message "$($Manufacturer) not implemented"
            Write-output "$($Manufacturer) not implemented"
            Exit 0
        }

    }
    default {
                Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "Incompatible Hardware. $($Manufacturer) not supported"
                Write-output "Incompatible Hardware. $($Manufacturer) not supported"
                Exit 0
    }
}

# Checking if registry entries for BIOS Update management exits and set to 0 if they don't exists
if (-NOT(Test-Path -Path "$RegPath\")) {
    New-Item -Path "$RegPath" -Force | Out-Null
    New-ItemProperty -Path "$RegPath" -Name 'BIOSUpdateInprogress' -Value 0 -PropertyType 'DWORD' -Force | Out-Null
    New-ItemProperty -Path "$RegPath" -Name 'BIOSUpdateAttempts' -Value 0 -PropertyType 'DWORD' -Force | Out-Null
    New-ItemProperty -Path "$RegPath" -Name 'BIOSUpdateTime' -Value "" -PropertyType 'String' -Force | Out-Null
    New-ItemProperty -Path "$RegPath" -Name 'BIOSDeployedVersion' -Value "" -PropertyType 'String' -Force | Out-Null
}

# Check if BIOS Update is in Progress
$BiosUpdateinProgress = Get-ItemPropertyValue -Path "$($RegPath)\" -Name BIOSUpdateInprogress
if ($BiosUpdateinProgress -ne 0){
    Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "BIOS Update is in Progress"
    # Check if computer has restarted since last try 
    [DateTime]$BIOSUpdateTime = Get-ItemPropertyValue -Path "$RegPath" -Name 'BIOSUpdateTime'
    $LastBootime = Get-Date (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime)
    if ($BIOSUpdateTime -gt $LastBootime){
        # Computer not restarted - Invoke remediation to notify user to reboot
        Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "BIOSUpdateTime is newer than last reboot, pending first reboot"
        Exit 1
    }
    else {
        # Step 4 Computer restarted - Check BIOS Version
        Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "Computer has restarted - validate bios version"
        $TestBiosCommand = "Test-BIOSVersion$($OEM) -BIOSApprovedVersion $($BIOSApprovedVersion) -SystemID $($SystemID)"
        $BIOSCheck = Invoke-Expression $TestBiosCommand

        if ($BIOSCheck.ExitCode -eq 0){
            Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "Update Complete - Clean up in registry"
            Set-ItemProperty -Path "$RegPath" -Name 'BIOSUpdateInprogress' -Value 0
            Set-ItemProperty -Path "$RegPath" -Name 'BIOSUpdateAttempts' -Value 0 
            Set-ItemProperty -Path "$RegPath" -Name 'BIOSUpdateTime' -Value "" 
            Set-ItemProperty -Path "$RegPath" -Name 'BIOSDeployedVersion' -Value "" 
            Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "$($BIOSCheck.Message)"
            Write-Output "$($BIOSCheck.Message)"
            Exit 0
        }
        else {
            #Step 5 Computer restarted - BIOS not updated - Invoke remediation if threshold not met
            [int]$Attempts = Get-ItemPropertyValue -Path $RegPath -Name 'BIOSUpdateAttempts'
            if ($Attempts -gt 3){
                Write-EventLog -LogName $EventLogName -EntryType Warning -EventId 8002 -Source $EventLogSource -Message "Update not completed after reboot - giving up after $($Attempts) attempts"
                Write-Output "Update not completed after reboot - giving up after $($Attempts) attempts"
                Exit 0     
            } else {
                Set-ItemProperty -Path $RegPath -Name 'BIOSUpdateAttempts' -Value $Attempts
                Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "Update not completed after reboot - Attempts: $($Attempts) - Call remediation script"            
                Write-Output "$($BIOSCheck.Message)"
                #$Attempts++
                Exit 1
            }
        }
    }
} else {
    # Step 6 BIOS Update not in progress - Check BIOS Version
    Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "Validate bios version"
    $TestBiosCommand = "Test-BIOSVersion$($OEM) -BIOSApprovedVersion $($BIOSApprovedVersion) -SystemID $($SystemID)"
    $BIOSCheck = Invoke-Expression $TestBiosCommand

    if ($BIOSCheck.ExitCode -eq 1){
        Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "$($BIOSCheck.Message)"
        Write-Output "$($BIOSCheck.Message)"
        Exit 1
    }
    else {
        Write-EventLog -LogName $EventLogName -EntryType Information -EventId 8001 -Source $EventLogSource -Message "$($BIOSCheck.Message)"
        Write-Output "$($BIOSCheck.Message)"
        Exit 0
    } 
}

#endregion script












