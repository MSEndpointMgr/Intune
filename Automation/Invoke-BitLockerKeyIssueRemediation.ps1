<#
.SYNOPSIS
    This script retrieves the Bitlocker keys from the enterprise API and optionally deletes the x oldest keys if the total count exceeds the specified
    threshold value or the maximum of 200 keys.

.DESCRIPTION
This script retrieves BitLocker recovery keys from the enterprise API and deletes the oldest keys if the total count exceeds a threshold. 
The script also enforces BitLocker encryption on the OS drive if no keys are found and the FVE policy is enforced, and backs up BitLocker keys to Entra.
It does not require authetnication to Graph as it uses the MS-Organization-Access certificate to access the enterprise API.

Created on:   2025-03-13
Updated on:   2025-03-20
Created by:   Ben Whitmore / Rudy Ooms @PatchMyPC
Contributors: Maurice Daly
Filename:     Invoke-BitLockerKeyIssueDetection.ps1

    ---------------------------------------------------------------------------------
LEGAL DISCLAIMER

The PowerShell script provided is shared with the community as-is
The author and co-author(s) make no warranties or guarantees regarding its functionality, reliability, or suitability for any specific purpose
Please note that the script may need to be modified or adapted to fit your specific environment or requirements
It is recommended to thoroughly test the script in a non-production environment before using it in a live or critical system
The author and co-author(s) cannot be held responsible for any damages, losses, or adverse effects that may arise from the use of this script
You assume all risks and responsibilities associated with its usage
---------------------------------------------------------------------------------

.NOTES
    Requires admin privileges and an MS-Organization-Access certificate. When running as a remediation script, the script should be run as SYSTEM.
#>
# requires variables

# Logging directory
$LogDirectory = "$env:SystemDrive\ProgramData\Microsoft\IntuneManagementExtension\Logs"

# Configuration
$KeysToDeleteCount = 10
$KeyHighWaterMark = 20
$KeyCriticalWaterMark = 200

# endregion Variables

# region Functions

function global:Write-LogEntry {
    param
    (
        [Parameter(Mandatory = $true,
            HelpMessage = 'Value added to the log file.')]
        [ValidateNotNullOrEmpty()]
        [string]$Value,
        [Parameter(Mandatory = $false,
            HelpMessage = 'Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.')]
        [ValidateSet('1', '2', '3')]
        [ValidateNotNullOrEmpty()]
        [string]$Severity = '1',
        [Parameter(Mandatory = $false,
            HelpMessage = 'Name of the log file that the entry will written to.')]
        [ValidateNotNullOrEmpty()]
        [string]$LogFileName = "PMPC-BitLockerMaintenance.log",
        [switch]$UpdateUI
    )
	
    # Determine log file location
    $script:LogFilePath = Join-Path -Path $LogDirectory -ChildPath $LogFileName
	
    # Construct time stamp for log entry
    $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), " ", (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
	
    # Construct date for log entry
    $Date = (Get-Date -Format "MM-dd-yyyy")
	
    # Construct context for log entry
    $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
	
    # Construct final log entry
    $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""PMPC-BitLockerMaintenance"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
	
    # Add value to log file
    try {
        #Write-Output "$($Value)"
        Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
    } catch [System.Exception] {
        Write-Warning -Message "Unable to append log entry to PMPC-BitLockerMaintenance.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
    }
}

function Invoke-BitLockerKeyRemoval {
    # Get BitLocker recovery keys from manage-bde for all volumes
    $BitLockerKeys = Get-BitLockerVolume | Where-Object { $_.KeyProtector -ne $null } | Select-Object -ExpandProperty KeyProtector
    $BitLockerKeyProtectorIds = $BitLockerKeys | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" } | Select-Object -ExpandProperty KeyProtectorId
    # Remove {} from $BitLockerKeyProtectors
    $BitLockerKeyProtectorIds = $BitLockerKeyProtectors -replace '[{}]', ''

    # Remove all BitLocker keys which are not in the $BitLockerKeyProtectors
    $KeyIdsToDelete = $Results | Where-Object { $_.KeyId -notin $BitLockerKeyProtectorIds } | Select-Object -ExpandProperty KeyId -Unique

    # Delete BitLocker keys if the $keysToDelete count is greater than 0
    if ($KeyIdsToDelete.Count -gt 0) {
        Write-LogEntry -Value "[BitLocker Key Deletion] - Removing $($KeysToDelete.Count) BitLocker keys" -Severity 1
        try {           

            # Create a foreach loop to delete keys in batches of 15
            $BatchCount = 15
            $TotalBatchCount = $KeyIdsToDelete.Count
            $BatchMarker = 0

            # Check if the number of keys to delete is greater than the initial batch size
            # Create a while loop to delete keys in batches of 15
            while ($BatchMarker -lt $TotalBatchCount) {
                # Determine the number of keys to delete in this batch
                $RemainingKeys = $TotalBatchCount - $BatchMarker
                $KeysToDeleteCount = if ($RemainingKeys -lt $BatchCount) { $RemainingKeys } else { $BatchCount }

                # Get the keys to delete for this batch
                $KeysToDelete = $KeyIdsToDelete[$BatchMarker..($BatchMarker + $KeysToDeleteCount - 1)]

                # Create the body for the API request
                $DeleteBody = @{ "kids" = $KeysToDelete } | ConvertTo-Json -Compress
                $DeleteResponse = Invoke-WebRequest -Uri $BitLockerDeleteURL -Method Delete -Headers $Headers -Certificate $Certificate -Body $DeleteBody -ContentType "application/json" -UseBasicParsing

                if ($DeleteResponse.StatusCode -eq "200") {
                    Write-LogEntry -Value "- Successfully deleted $($KeysToDelete.Count) BitLocker Recovery Keys" -Severity 1

                    # Increment the batch marker by the number of keys processed
                    $BatchMarker += $KeysToDeleteCount
                } else {
                    Write-LogEntry -Value "[Error] - Error deleting BitLocker keys: $($DeleteResponse.StatusCode)" -Severity 3; exit 1
                }
            }

            # Check if the response status code is 200
            if ($DeleteResponse.StatusCode -eq "200") {
                Write-LogEntry -Value "- Successfully deleted $($KeyIdsToDelete.Count) BitLocker Recovery Keys" -Severity 1
                
                # Resume the BitLocker encryption process
                Write-LogEntry -Value "[BitLocker Protection] - Resuming BitLocker encryption on volumes in a degraded state or where protection is disabled." -Severity 1
                $BitLockerVolumes = Get-BitLockerVolume | Where-Object { $_.VolumeStatus -eq "Degraded" -or $_.ProtectionStatus -eq "Off" }
                if ($BitLockerVolumes) {
                    foreach ($Volume in $BitLockerVolumes) {
                        try {
                            Write-LogEntry -Value "- Resuming BitLocker encryption on volume: $($Volume.MountPoint)" -Severity 1
                            Resume-BitLocker -MountPoint $Volume.MountPoint
                        } catch {
                            Write-LogEntry -Value "[Error] - Failed to resume BitLocker encryption on volume: $($Volume.MountPoint). Error: $($_.Exception.Message)" -Severity 2
                        }
                    }
                } else {
                    Write-LogEntry -Value "- No BitLocker volumes found in a degraded state." -Severity 1
                }

                # Check if there are any BitLocker volumes with key protectors
                $BitLockerVolumes = Get-BitLockerVolume | Where-Object { $_.KeyProtector -ne $null }

                # Force BitLocker key escrow to Entra
                if ($BitLockerVolumes) {
                    Write-LogEntry -Value "[BitLocker Key Escrow] - Backing up BitLocker keys to Entra" -Severity 1
                    foreach ($Volume in $BitLockerVolumes) {
                        Write-LogEntry -Value "- Processing volume: $($Volume.MountPoint)" -Severity 1

                        # Get all key protectors for the volume
                        $KeyProtectors = $Volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }

                        # Backup each key protector to Entra
                        foreach ($KeyProtector in $KeyProtectors) {
                            try {
                                Write-LogEntry -Value "- Backing up key protector with ID: $($KeyProtector.KeyProtectorId)" -Severity 1 
                                BackupToAAD-BitLockerKeyProtector -MountPoint $Volume.MountPoint -KeyProtectorId $KeyProtector.KeyProtectorId
                                Write-LogEntry -Value "- Successfully backed up key protector with ID: $($KeyProtector.KeyProtectorId)" -Severity 1
                            } catch {
                                Write-LogEntry -Value "- Failed to back up key protector with ID: $($KeyProtector.KeyProtectorId). Error: $($_.Exception.Message)" -Severity 3; exit 1
                            }
                        }
                    }
                    Write-LogEntry -Value "[BitLocker Key Escrow] - Successfully backed up BitLocker keys to Entra" -Severity 1; exit 0
                } else {
                    Write-LogEntry -Value "[Warning] - No BitLocker volumes with key protectors found." -Severity 2; exit 0
                }  
            } else {
                Write-LogEntry -Value "[Error] - Error deleting BitLocker keys: $($DeleteResponse.StatusCode)" -Severity 3; exit 1
            }   
        } catch {
            Write-LogEntry -Value "[Error] - Failed to delete BitLocker Recovery Keys. Error: $_" -Severity 3; exit 1
        }
    } else {
        Write-LogEntry -Value "- No BitLocker keys to delete." -Severity 1; exit 0
    }
}
# endregion functions

# region script
Write-LogEntry -Value "[BitLocker Key Maintenance] - Starting key remediation process" -Severity 1
Write-LogEntry -Value "- Obtaining certificate for BitLocker key retrieval" -Severity 1

try {
    # Retrieve the MS-Organization-Access certificate
    $Certificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -like "*MS-Organization-Access*" } | Select-Object -First 1
} catch {
    Write-LogEntry -Value "[Certificate Error] - MS-Organization-Access certificate not found. $($_.Exception.Message)]" -Severity 3; exit 1
}

# If the certificate has been found, proceed
if ($Certificate) {
    Write-LogEntry -Value "[Certificate] - MS-Organization-Access certificate found." -Severity 1
    # Extract Device ID from the certificate subject
    Write-LogEntry -Value "- Attempting to extract Device ID from the certificate subject" -Severity 1
    if ($Certificate.Subject -match "CN=([a-f0-9\-]+)") {
        $DeviceId = $matches[1]

        # Construct API request details
        $BitLockerUrl = "https://enterpriseregistration.windows.net/manage/common/bitlocker/$DeviceId"
        $BitLockerDeleteURL = "https://enterpriseregistration.windows.net/manage/common/bitlocker/$deviceId"
        $Headers = @{
            "User-Agent"              = "BitLocker/10.0.27783 (Windows)"
            "Accept"                  = "application/json"
            "ocp-adrs-client-name"    = "Windows"
            "ocp-adrs-client-version" = "10.0.27783"
        }

        $Results = @()

        if (-not([string]::IsNullOrEmpty($DeviceId))) {
            Write-LogEntry -Value "- Device ID extracted from certificate subject: $DeviceId" -Severity 1
        } else {
            Write-LogEntry -Value "[Error] - Unable to extract Device ID from the certificate." -Severity 3; exit 1
        }
    }
} else {
    Write-LogEntry -Value "[Certificate Error] - MS-Organization-Access certificate not found." -Severity 3; exit 1
}

# Retrieve BitLocker key details
try {
    Write-LogEntry -Value "[BitLocker API] - Retrieving BitLocker key details from enterprise API" -Severity 1
    $Response = Invoke-WebRequest -Uri $BitLockerUrl -Method GET -Headers $Headers -Certificate $Certificate -UseBasicParsing
    if ($Response.StatusCode -eq "200") {
        Write-LogEntry -Value "- Successfully queried API URI ($BitLockerUrl) with status code $($Reponse.StatusCode)" -Severity 1
        Write-LogEntry -Value "- Parsing BitLocker key details" -Severity 1
        $KeyData = $Response.Content | ConvertFrom-Json
        if ($KeyData.keys) {
            foreach ($Key in $KeyData.keys) {
                $Results += [PSCustomObject]@{
                    KeyId        = $Key.kid
                    CreationTime = $Key.creationtime
                    VolumeType   = $Key.volumetype
                }
            }
        } else {
            Write-LogEntry -Value "- No BitLocker keys found for this device. Flagging for remediation to enforce BitLocker encryption" -Severity 1; exit 1
        }
    } else {
        Write-LogEntry -Value "[Error] - Error retrieving communicating with API URI ($BitLockerUrl): $($Response.StatusCode)" -Severity 3; exit 1
    }


} catch {
    Write-LogEntry -Value "[Error] - Error retrieving BitLocker key details: $($_.Exception.Message)" -Severity 3; exit 1
}

# Process results
if ($Results.Count -gt 0) {
    Write-LogEntry -Value "- BitLocker key details retrieved successfully" -Severity 1
    Write-LogEntry -Value "- Found $($Results.Count) BitLocker keys" -Severity 1
    Write-LogEntry -Value "- Checking key count against configured thresholds" -Severity 1
    if ($Results.Count -ge $KeyHighWaterMark) {
        if ($Results.Count -ge $KeyCriticalWaterMark) {
            Write-LogEntry -Value "[Critical] - Number of BitLocker keys exceeds the configured max value of $KeyCriticalWaterMark" -Severity 3
            # Call the function to delete the oldest keys
            Invoke-BitLockerKeyRemoval
        } else {
            Write-LogEntry -Value "[Warning] - Number of BitLocker keys exceeds the configured max value of $KeyHighWaterMark" -Severity 2
            # Call the function to delete the oldest keys
            Invoke-BitLockerKeyRemoval
        }
    } else {
        Write-LogEntry -Value "[Healthy State] - Key count is $($Results.Count), which is less than $KeyHighWaterMark. No action required." -Severity 1; exit 0
    }
} else {
    # Check if BitLocker encryption should be enforced from the FVE registry key
    if ((Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE") -eq $true) {
        # Check if the OSEncrpytionType is set to 1
        $OSEncryptionType = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSEncryptionType" -ErrorAction SilentlyContinue
        if ($OSEncryptionType.OSEncryptionType -eq 1) {
            Write-LogEntry -Value "[Warning] - BitLocker policy enforced, however, no keys are found. Enforcing BitLokcer on OS drive" -Severity 2
            Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAES256 -UsedSpaceOnly -SkipHardwareTest -TpmProtector | Out-Null
            Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAES256 -UsedSpaceOnly -SkipHardwareTest -RecoveryPasswordProtector | Out-Null
            BackupToAAD-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $BitLockerVolume.KeyProtector[1].KeyProtectorId -ErrorAction SilentlyContinue
        } else {
            Write-LogEntry -Value "[Healthy State] - BitLocker policy not enforced for OS drive." -Severity 1; exit 0
        }
    } else {
        Write-LogEntry -Value "[Healthy State] - No BitLocker keys found and BitLocker encryption is not enforced. No action required." -Severity 1; exit 0
    }
}

# endregion script



