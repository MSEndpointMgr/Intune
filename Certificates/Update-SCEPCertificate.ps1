<#
.SYNOPSIS
    Remove existing SCEP device certificate and enroll a new until subject name matches desired configuration.

.DESCRIPTION
    Remove existing SCEP device certificate and enroll a new until subject name matches desired configuration.

.NOTES
    FileName:    Update-SCEPCertificate.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2019-12-21
    Updated:     2020-04-24

    Version history:
    1.0.0 - (2019-12-21) Script created
    1.0.1 - (2020-04-24) Added to check for certificate with subject names matching CN=WIN in addition to CN=DESKTOP and CN=LAPTOP
#>
Process {
    # Functions
    function Write-CMLogEntry {
        param (
            [parameter(Mandatory=$true, HelpMessage="Value added to the log file.")]
            [ValidateNotNullOrEmpty()]
            [string]$Value,
            
            [parameter(Mandatory=$true, HelpMessage="Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
            [ValidateNotNullOrEmpty()]
            [ValidateSet("1", "2", "3")]
            [string]$Severity,
            
            [parameter(Mandatory=$false, HelpMessage="Name of the log file that the entry will written to.")]
            [ValidateNotNullOrEmpty()]
            [string]$FileName = "SCEPCertificateUpdate.log"
        )
        # Determine log file location
        $WindowsTempLocation = (Join-Path -Path $env:windir -ChildPath "Temp")
        $LogFilePath = Join-Path -Path $WindowsTempLocation -ChildPath $FileName
        
        # Construct time stamp for log entry
        $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), "+", (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
        
        # Construct date for log entry
        $Date = (Get-Date -Format "MM-dd-yyyy")
        
        # Construct context for log entry
        $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        
        # Construct final log entry
        $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""SCEPCertificateUpdate"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
        
        # Add value to log file and if specified console output
        try {
            if ($Script:PSBoundParameters["Verbose"]) {
                # Write either verbose or warning output to console
                switch ($Severity) {
                    1 {
                        Write-Verbose -Message $Value
                    }
                    default {
                        Write-Warning -Message $Value
                    }
                }

                # Write output to log file
                Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
            }
            else {
                # Write output to log file
                Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
            }
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to append log entry to SCEPCertificateUpdate.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    }

    function Get-SCEPCertificate {
        do {
            $SCEPCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { ($_.Subject -match "CN=DESKTOP") -or ($_.Subject -match "CN=LAPTOP") -or ($_.Subject -match "CN=WIN") }
            if ($SCEPCertificate -eq $null) {
                Write-CMLogEntry -Value "Unable to locate SCEP certificate, waiting 10 seconds before checking again" -Severity 2
                Start-Sleep -Seconds 10
            }
            else {
                Write-CMLogEntry -Value "Successfully located SCEP certificate with subject: $($SCEPCertificate.Subject)" -Severity 1
                return $SCEPCertificate
            }
        }
        until ($SCEPCertificate -ne $null)
    }

    function Remove-SCEPCertificate {
        param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [System.Object]$InputObject
        )
        # Remove SCEP issued certificate
        Write-CMLogEntry -Value "Attempting to remove certificate with subject name: $($InputObject.Subject)" -Severity 1
        Remove-Item -Path $InputObject.PSPath -Force
    }

    function Test-SCEPCertificate {
        param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string[]]$Subject
        )
        # Force a manual MDM policy sync
        Write-CMLogEntry -Value "Triggering manual MDM policy sync" -Severity 1
        Get-ScheduledTask | Where-Object { $_.TaskName -eq "PushLaunch" } | Start-ScheduledTask

        # Check if new SCEP issued certificate was successfully installed
        Write-CMLogEntry -Value "Attempting to check if SCEP certificate was successfully installed after a manual MDM policy sync" -Severity 1
        do {
            $SCEPCertificateInstallEvent = Get-WinEvent -LogName "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin" | Where-Object { ($_.Id -like "39") -and ($_.TimeCreated -ge (Get-Date).AddMinutes(-1)) }
        }
        until ($SCEPCertificateInstallEvent -ne $null)
        Write-CMLogEntry -Value "SCEP certificate was successfully installed after a manual MDM policy sync, proceeding to validate it's subject name" -Severity 1

        # Attempt to locate SCEP issued certificate where the subject name matches either 'DESKTOP', 'LAPTOP' or 'WIN'
        $SubjectNames = $Subject -join "|"
        $SCEPCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Subject -match $SubjectNames }
        if ($SCEPCertificate -eq $null) {
            Write-CMLogEntry -Value "SCEP certificate subject name does not match, returning failure" -Severity 3
            return $false
        }
        else {
            Write-CMLogEntry -Value "SCEP certificate subject name matches desired input, returning success" -Severity 1
            return $true
        }
    }

    # Define the desired subject name matching patterns for a successful SCEP certificate installation
    $SubjectNames = @("CN=CL", "CN=CORP")

    # Attempt to locate and wait for SCEP issued certificate where the subject name matches either 'DESKTOP', 'LAPTOP' or 'WIN'
    $SCEPCertificateItem = Get-SCEPCertificate
    if ($SCEPCertificateItem -ne $null) {
        # Remove existing SCEP issues certificate with subject name matching either 'DESKTOP', 'LAPTOP' or 'WIN'
        Remove-SCEPCertificate -InputObject $SCEPCertificateItem

        # Validate that new certificate was installed and it contains the correct subject name
        do {
            $SCEPResult = Test-SCEPCertificate -Subject $SubjectNames
            if ($SCEPResult -eq $false) {
                # SCEP certificate installed did not match desired subject named, remove it and attempt to enroll a new
                Write-CMLogEntry -Value "Failed to validate SCEP certificate subject name, removing existing SCEP certificate" -Severity 3
                Remove-SCEPCertificate -InputObject (Get-SCEPCertificate)
            }
            else {
                Write-CMLogEntry -Value "Successfully validated desired SCEP certificate was successfully installed" -Severity 1
            }
        }
        until ($SCEPResult -eq $true)
    }
}