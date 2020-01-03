<#
.SYNOPSIS
    Enable BitLocker with both TPM and recovery password key protectors on Windows 10 devices.

.DESCRIPTION
    Enable BitLocker with both TPM and recovery password key protectors on Windows 10 devices.

.PARAMETER EncryptionMethod
    Define the encryption method to be used when enabling BitLocker.

.NOTES
    FileName:    Enable-BitLockerEncryption.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2019-10-29
    Updated:     2020-01-03

    Version history:
    1.0.0 - (2019-10-29) Script created
    1.0.1 - (2020-01-03) Added functionality to check if TPM chip is owned and take ownership if it's not
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [parameter(Mandatory=$false, HelpMessage="Define the encryption method to be used when enabling BitLocker.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("Aes128", "Aes256", "XtsAes128", "XtsAes256")]
    [string]$EncryptionMethod = "XtsAes256"
)
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
		$LogFilePath = Join-Path -Path (Join-Path -Path $env:windir -ChildPath "Temp") -ChildPath "Enable-BitLockerEncryption.log"
		
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
		$LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""BitLockerEncryption"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
		
		# Add value to log file
		try {
			Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
		}
		catch [System.Exception] {
			Write-Warning -Message "Unable to append log entry to Enable-BitLockerEncryption.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
		}
    }
    
    function Invoke-Executable {
        param (
            [parameter(Mandatory = $true, HelpMessage = "Specify the file name or path of the executable to be invoked, including the extension")]
            [ValidateNotNullOrEmpty()]
            [string]$FilePath,

            [parameter(Mandatory = $false, HelpMessage = "Specify arguments that will be passed to the executable")]
            [ValidateNotNull()]
            [string]$Arguments
        )
        
        # Construct a hash-table for default parameter splatting
        $SplatArgs = @{
            FilePath = $FilePath
            NoNewWindow = $true
            Passthru = $true
            RedirectStandardOutput = "null.txt"
            ErrorAction = "Stop"
        }
        
        # Add ArgumentList param if present
        if (-not ([System.String]::IsNullOrEmpty($Arguments))) {
            $SplatArgs.Add("ArgumentList", $Arguments)
        }
        
        # Invoke executable and wait for process to exit
        try {
            $Invocation = Start-Process @SplatArgs
            $Handle = $Invocation.Handle
            $Invocation.WaitForExit()
    
            # Remove redirected output file
            Remove-Item -Path (Join-Path -Path $PSScriptRoot -ChildPath "null.txt") -Force
    
        }
        catch [System.Exception] {
            Write-Warning -Message $_.Exception.Message; break
        }
        
        return $Invocation.ExitCode
    }    

    # Check if we're running as a 64-bit process or not
    if (-not[System.Environment]::Is64BitProcess) {
        # Get the sysnative path for powershell.exe
        $SysNativePowerShell = Join-Path -Path ($PSHOME.ToLower().Replace("syswow64", "sysnative")) -ChildPath "powershell.exe"

        # Construct new ProcessStartInfo object to restart powershell.exe as a 64-bit process and re-run scipt
        $ProcessStartInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
        $ProcessStartInfo.FileName = $SysNativePowerShell
        $ProcessStartInfo.Arguments = "-ExecutionPolicy Bypass -File ""$($PSCommandPath)"""
        $ProcessStartInfo.RedirectStandardOutput = $true
        $ProcessStartInfo.RedirectStandardError = $true
        $ProcessStartInfo.UseShellExecute = $false
        $ProcessStartInfo.WindowStyle = "Hidden"
        $ProcessStartInfo.CreateNoWindow = $true

        # Instatiate the new 64-bit process
        $Process = [System.Diagnostics.Process]::Start($ProcessStartInfo)

        # Read standard error output to determine if the 64-bit script process somehow failed
        $ErrorOutput = $Process.StandardError.ReadToEnd()
        if ($ErrorOutput) {
            Write-Error -Message $ErrorOutput
        }
    }
    else {
        try {
            # Import required module for managing BitLocker
            Import-Module -Name "BitLocker" -DisableNameChecking -Verbose:$false -ErrorAction Stop

            try {
                # Check if TPM chip is currently owned, if not take ownership
                $TPMClass = Get-WmiObject -Namespace "root\cimv2\Security\MicrosoftTPM" -Class "Win32_TPM"
                $IsTPMOwned = $TPMClass.IsOwned().IsOwned
                if ($IsTPMOwned -eq $false) {
                    Write-LogEntry -Value "TPM chip is currently not owned, value from WMI class method 'IsOwned' was: $($IsTPMOwned)" -Severity 1
                    
                    # Generate a random pass phrase to be used when taking ownership of TPM chip
                    $NewPassPhrase = (New-Guid).Guid.Replace("-", "").SubString(0, 14)

                    # Construct owner auth encoded string
                    $NewOwnerAuth = $TPMClass.ConvertToOwnerAuth($NewPassPhrase).OwnerAuth

                    # Attempt to take ownership of TPM chip
                    $Invocation = $TPMClass.TakeOwnership($NewOwnerAuth)
                    if ($Invocation.ReturnValue -eq 0) {
                        Write-LogEntry -Value "TPM chip ownership was successfully taken" -Severity 1
                    }
                    else {
                        Write-LogEntry -Value "Failed to take ownership of TPM chip, return value from invocation: $($Invocation.ReturnValue)" -Severity 3
                    }
                }
                else {
                    Write-LogEntry -Value "TPM chip is currently owned, will not attempt to take ownership" -Severity 1
                }
            }
            catch [System.Exception] {
                Write-LogEntry -Value "An error occurred while taking ownership of TPM chip. Error message: $($_.Exception.Message)" -Severity 3
            }

            try {
                # Retrieve the current encryption status of the operating system drive
                Write-LogEntry -Value "Attempting to retrieve the current encryption status of the operating system drive" -Severity 1
                $BitLockerOSVolume = Get-BitLockerVolume -MountPoint $env:SystemRoot -ErrorAction Stop

                if ($BitLockerOSVolume -ne $null) {
                    # Determine whether BitLocker is turned on or off
                    if (($BitLockerOSVolume.VolumeStatus -like "FullyDecrypted") -or ($BitLockerOSVolume.KeyProtector.Count -eq 0)) {
                        Write-LogEntry -Value "Current encryption status of the operating system drive was detected as: $($BitLockerOSVolume.VolumeStatus)" -Severity 1

                        try {
                            # Enable BitLocker with TPM key protector
                            Write-LogEntry -Value "Attempting to enable BitLocker protection with TPM key protector for mount point: $($env:SystemRoot)" -Severity 1
                            Enable-BitLocker -MountPoint $BitLockerOSVolume.MountPoint -TpmProtector -UsedSpaceOnly -EncryptionMethod $EncryptionMethod -SkipHardwareTest -ErrorAction Stop
                        }
                        catch [System.Exception] {
                            Write-LogEntry -Value "An error occurred while enabling BitLocker with TPM key protector for mount point '$($env:SystemRoot)'. Error message: $($_.Exception.Message)" -Severity 3
                        }

                        try {
                            # Enable BitLocker with recovery password key protector
                            Write-LogEntry -Value "Attempting to enable BitLocker protection with recovery password key protector for mount point: $($env:SystemRoot)" -Severity 1
                            Enable-BitLocker -MountPoint $BitLockerOSVolume.MountPoint -RecoveryPasswordProtector -UsedSpaceOnly -EncryptionMethod $EncryptionMethod -SkipHardwareTest -ErrorAction Stop
                        }
                        catch [System.Exception] {
                            Write-LogEntry -Value "An error occurred while enabling BitLocker with recovery password key protector for mount point '$($env:SystemRoot)'. Error message: $($_.Exception.Message)" -Severity 3
                        }
                    }
                    elseif (($BitLockerOSVolume.VolumeStatus -like "FullyEncrypted") -or ($BitLockerOSVolume.VolumeStatus -like "UsedSpaceOnly")) {
                        Write-LogEntry -Value "Current encryption status of the operating system drive was detected as: $($BitLockerOSVolume.VolumeStatus)" -Severity 1
                        Write-LogEntry -Value "Validating that all desired key protectors are enabled" -Severity 1

                        # Validate that not only the TPM protector is enabled, add recovery password protector
                        if ($BitLockerOSVolume.KeyProtector.Count -lt 2) {
                            if ($BitLockerOSVolume.KeyProtector.KeyProtectorType -like "Tpm") {
                                Write-LogEntry -Value "Recovery password key protector is not present" -Severity 1

                                try {
                                    # Enable BitLocker with TPM key protector
                                    Write-LogEntry -Value "Attempting to enable BitLocker protection with recovery password key protector for mount point: $($env:SystemRoot)" -Severity 1
                                    Enable-BitLocker -MountPoint $BitLockerOSVolume.MountPoint -RecoveryPasswordProtector -UsedSpaceOnly -EncryptionMethod $EncryptionMethod -SkipHardwareTest -ErrorAction Stop
                                }
                                catch [System.Exception] {
                                    Write-LogEntry -Value "An error occurred while enabling BitLocker with TPM key protector for mount point '$($env:SystemRoot)'. Error message: $($_.Exception.Message)" -Severity 3
                                }
                            }

                            if ($BitLockerOSVolume.KeyProtector.KeyProtectorType -like "RecoveryPassword") {
                                Write-LogEntry -Value "TPM key protector is not present" -Severity 1

                                try {
                                    # Add BitLocker recovery password key protector
                                    Write-LogEntry -Value "Attempting to enable BitLocker protection with TPM key protector for mount point: $($env:SystemRoot)" -Severity 1
                                    Enable-BitLocker -MountPoint $BitLockerOSVolume.MountPoint -TpmProtector -UsedSpaceOnly -EncryptionMethod $EncryptionMethod -SkipHardwareTest -ErrorAction Stop
                                }
                                catch [System.Exception] {
                                    Write-LogEntry -Value "An error occurred while enabling BitLocker with recovery password key protector for mount point '$($env:SystemRoot)'. Error message: $($_.Exception.Message)" -Severity 3
                                }
                            }                            
                        }
                        else {
                            # BitLocker is in wait state
                            Invoke-Executable -FilePath "manage-bde.exe" -Arguments "-On $($BitLockerOSVolume.MountPoint) -UsedSpaceOnly"
                        }                        
                    }
                    else {
                        Write-LogEntry -Value "Current encryption status of the operating system drive was detected as: $($BitLockerOSVolume.VolumeStatus)" -Severity 1
                    }

                    # Validate that previous configuration was successful and all key protectors have been enabled and encryption is on
                    $BitLockerOSVolume = Get-BitLockerVolume -MountPoint $env:SystemRoot

                    # Wait for encryption to complete
                    if ($BitLockerOSVolume.VolumeStatus -like "EncryptionInProgress") {
                        do {
                            $BitLockerOSVolume = Get-BitLockerVolume -MountPoint $env:SystemRoot
                            Write-LogEntry -Value "Current encryption percentage progress: $($BitLockerOSVolume.EncryptionPercentage)" -Severity 1
                            Write-LogEntry -Value "Waiting for BitLocker encryption progress to complete, sleeping for 15 seconds" -Severity 1
                            Start-Sleep -Seconds 15
                        }
                        until ($BitLockerOSVolume.EncryptionPercentage -eq 100)
                        Write-LogEntry -Value "Encryption of operating system drive has now completed" -Severity 1
                    }

                    if (($BitLockerOSVolume.VolumeStatus -like "FullyEncrypted") -and ($BitLockerOSVolume.KeyProtector.Count -eq 2)) {
                        try {
                            # Attempt to backup recovery password to Azure AD device
                            Write-LogEntry -Value "Attempting to backup recovery password to Azure AD device object" -Severity 1
                            $RecoveryPasswordKeyProtector = $BitLockerOSVolume.KeyProtector | Where-Object { $_.KeyProtectorType -like "RecoveryPassword" }
                            if ($RecoveryPasswordKeyProtector -ne $null) {
                                BackupToAAD-BitLockerKeyProtector -MountPoint $BitLockerOSVolume.MountPoint -KeyProtectorId $RecoveryPasswordKeyProtector.KeyProtectorId -ErrorAction Stop
                                Write-LogEntry -Value "Successfully backed up recovery password details" -Severity 1
                            }
                            else {
                                Write-LogEntry -Value "Unable to determine proper recovery password key protector for backing up of recovery password details" -Severity 2
                            }
                        }
                        catch [System.Exception] {
                            Write-LogEntry -Value "An error occurred while attempting to backup recovery password to Azure AD. Error message: $($_.Exception.Message)" -Severity 3
                        }
                    }
                    else {
                        Write-LogEntry -Value "Validation of current encryption status for operating system drive was not successful" -Severity 2
                        Write-LogEntry -Value "Current volume status for mount point '$($BitLockerOSVolume.MountPoint)': $($BitLockerOSVolume.VolumeStatus)" -Severity 2
                        Write-LogEntry -Value "Count of enabled key protectors for volume: $($BitLockerOSVolume.KeyProtector.Count)" -Severity 2
                    }
                }
                else {
                    Write-LogEntry -Value "Current encryption status query returned an empty result, this was not expected at this point" -Severity 2
                }
            }
            catch [System.Exception] {
                Write-LogEntry -Value "An error occurred while retrieving the current encryption status of operating system drive. Error message: $($_.Exception.Message)" -Severity 3
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value "An error occurred while importing the BitLocker module. Error message: $($_.Exception.Message)" -Severity 3
        }
    }
}