<#
.SYNOPSIS
    Download and install the latest set of drivers and driver software from HP repository online using HP Image Assistant for current client device

.DESCRIPTION
    This script will download and install the latest matching drivers and driver software from HP repository online using HP Image Assistant that will
    analyze what's required for the current client device it's running on.

.PARAMETER RunMode
    Select run mode for this script, either Stage or Execute.

.PARAMETER HPIASoftpaqNumber
    Specify the HP Image Assistant softpaq number.

.EXAMPLE
    .\Invoke-HPDriverUpdate.ps1 -RunMode "Stage"

.NOTES
    FileName:    Invoke-HPDriverUpdate.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2020-08-12
    Updated:     2020-08-12

    Version history:
    1.0.0 - (2020-08-12) Script created
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [parameter(Mandatory = $true, HelpMessage = "Select run mode for this script, either Stage or Execute.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("Stage","Execute")]
    [string]$RunMode,

    [parameter(Mandatory = $false, HelpMessage = "Specify the HP Image Assistant softpaq number.")]
    [ValidateNotNullOrEmpty()]
    [string]$HPIASoftpaqNumber = "sp103654"
)
Begin {
    # Enable TLS 1.2 support for downloading modules from PSGallery
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
Process {
    # Functions
    function Write-LogEntry {
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
			[string]$FileName = "HPDriverUpdate.log"
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
		$LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""HPDriverUpdate"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
		
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
            }

            # Write output to log file
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
		}
		catch [System.Exception] {
			Write-Warning -Message "Unable to append log entry to HPDriverUpdate.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
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
            [string]$Value
        )
        try {
            $RegistryValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($RegistryValue -ne $null) {
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -ErrorAction Stop
            }
            else {
                if (-not(Test-Path -Path $Path)) {
                    New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop | Out-Null
                }
                New-ItemProperty -Path $Path -Name $Name -PropertyType String -Value $Value -Force -ErrorAction Stop
            }
        }
        catch [System.Exception] {
            Write-Warning -Message "Failed to create or update registry value '$($Name)' in '$($Path)'. Error message: $($_.Exception.Message)"
        }
    }

    function Invoke-Executable {
        param (
            [parameter(Mandatory = $true, HelpMessage = "Specify the file name or path of the executable to be invoked, including the extension.")]
            [ValidateNotNullOrEmpty()]
            [string]$FilePath,
    
            [parameter(Mandatory = $false, HelpMessage = "Specify arguments that will be passed to the executable.")]
            [ValidateNotNull()]
            [string]$Arguments
        )
        
        # Construct a hash-table for default parameter splatting
        $SplatArgs = @{
            FilePath = $FilePath
            NoNewWindow = $true
            Passthru = $true
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
        }
        catch [System.Exception] {
            Write-Warning -Message $_.Exception.Message; break
        }
        
        # Handle return value with exitcode from process
        return $Invocation.ExitCode
    }

    # Validate that script is executed on HP hardware
    $Manufacturer = (Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty Manufacturer).Trim()
    switch -Wildcard ($Manufacturer) {
        "*HP*" {
            Write-LogEntry -Value "Validated HP hardware check, allowed to continue" -Severity 1
        }
        "*Hewlett-Packard*" {
            Write-LogEntry -Value "Validated HP hardware check, allowed to continue" -Severity 1
        }
        default {
            Write-LogEntry -Value "Unsupported hardware detected, HP hardware is required for this script to operate" -Severity 3; exit 1
        }
    }

    switch ($RunMode) {
        "Stage" {
            # Stage script in system root directory for ActiveSetup
            try {
                $WindowsTempPath = Join-Path -Path $env:SystemRoot -ChildPath "Temp"
                Write-LogEntry -Value "Attempting to stage '$($MyInvocation.MyCommand.Definition)' to: $($WindowsTempPath)" -Severity 1
                Copy-Item $MyInvocation.MyCommand.Definition -Destination $WindowsTempPath -Force -ErrorAction Stop
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Unable to stage script in Windows\Temp directory for execution. Error message: $($_.Exception.Message)" -Severity 3; exit 1
            }

            try {
                # Install latest NuGet package provider
                Write-LogEntry -Value "Attempting to install latest NuGet package provider" -Severity 1
                $PackageProvider = Install-PackageProvider -Name "NuGet" -Force -ErrorAction Stop -Verbose:$false

                # Attempt to get the installed PowerShellGet module
                Write-LogEntry -Value "Attempting to locate installed PowerShellGet module" -Severity 1
                $PowerShellGetInstalledModule = Get-InstalledModule -Name "PowerShellGet" -ErrorAction SilentlyContinue -Verbose:$false
                if ($PowerShellGetInstalledModule -ne $null) {
                    try {
                        # Attempt to locate the latest available version of the PowerShellGet module from repository
                        Write-LogEntry -Value "Attempting to request the latest PowerShellGet module version from repository" -Severity 1
                        $PowerShellGetLatestModule = Find-Module -Name "PowerShellGet" -ErrorAction Stop -Verbose:$false
                        if ($PowerShellGetLatestModule -ne $null) {
                            if ($PowerShellGetInstalledModule.Version -lt $PowerShellGetLatestModule.Version) {
                                try {
                                    # Newer module detected, attempt to update
                                    Write-LogEntry -Value "Newer version detected, attempting to update the PowerShellGet module from repository" -Severity 1
                                    Update-Module -Name "PowerShellGet" -Scope "AllUsers" -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
                                }
                                catch [System.Exception] {
                                    Write-LogEntry -Value "Failed to update the PowerShellGet module. Error message: $($_.Exception.Message)" -Severity 3 ; exit 1
                                }
                            }
                        }
                        else {
                            Write-LogEntry -Value "Location request for the latest available version of the PowerShellGet module failed, can't continue" -Severity 3; exit 1
                        }
                    }
                    catch [System.Exception] {
                        Write-LogEntry -Value "Failed to retrieve the latest available version of the PowerShellGet module, can't continue. Error message: $($_.Exception.Message)" -Severity 3; exit 1
                    }
                }
                else {
                    try {
                        # PowerShellGet module was not found, attempt to install from repository
                        Write-LogEntry -Value "PowerShellGet module was not found, attempting to install from repository" -Severity 1
                        Install-Module -Name "PowerShellGet" -Scope "AllUsers" -Force -AllowClobber -ErrorAction Stop -Verbose:$false
                    }
                    catch [System.Exception] {
                        Write-LogEntry -Value "Unable to install PowerShellGet module from repository. Error message: $($_.Exception.Message)" -Severity 3; exit 1
                    }
                }

                try {
                    # Invoke executing script again in Execute run mode after package provider and modules have been installed/updated
                    Write-LogEntry -Value "Re-launching the PowerShell instance in Execute mode to overcome a bug with PowerShellGet" -Severity 1
                    $Invocation = Invoke-Executable -FilePath "powershell.exe" -Arguments "-ExecutionPolicy Bypass -NoProfile -File $($env:SystemRoot)\Temp\$($MyInvocation.MyCommand.Name) -RunMode Execute"
                    if ($Invocation -ne 0) {
                        Write-LogEntry -Value "Re-launched PowerShell instance failed with exit code: $($Invocation)" -Severity 3
                    }
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Failed to restart executing script in Execute run mode. Error message: $($_.Exception.Message)" -Severity 3; exit 1
                }
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Unable to install latest NuGet package provider. Error message: $($_.Exception.Message)" -Severity 3; exit 1
            }            
        }
        "Execute" {
            try {
                # Install HP Client Management Script Library
                Write-LogEntry -Value "Attempting to install HPCMSL module from repository" -Severity 1
                Install-Module -Name "HPCMSL" -AcceptLicense -Force -ErrorAction Stop -Verbose:$false

                # Create HPIA directory for HP Image Assistant extraction
                $HPImageAssistantExtractPath = Join-Path -Path $env:SystemRoot -ChildPath "Temp\HPIA"
                if (-not(Test-Path -Path $HPImageAssistantExtractPath)) {
                    Write-LogEntry -Value "Creating directory for HP Image Assistant extraction: $($HPImageAssistantExtractPath)" -Severity 1
                    New-Item -Path $HPImageAssistantExtractPath -ItemType "Directory" -Force | Out-Null
                }

                # Create HP logs for HP Image Assistant
                $HPImageAssistantReportPath = Join-Path -Path $env:SystemRoot -ChildPath "Temp\HPIALogs"
                if (-not(Test-Path -Path $HPImageAssistantReportPath)) {
                    Write-LogEntry -Value "Creating directory for HP Image Assistant report logs: $($HPImageAssistantReportPath)" -Severity 1
                    New-Item -Path $HPImageAssistantReportPath -ItemType "Directory" -Force | Out-Null
                }

                # Create HP Drivers directory for driver content
                $SoftpaqDownloadPath = Join-Path -Path $env:SystemRoot -ChildPath "Temp\HPDrivers"
                if (-not(Test-Path -Path $SoftpaqDownloadPath)) {
                    Write-LogEntry -Value "Creating directory for softpaq downloads: $($SoftpaqDownloadPath)" -Severity 1
                    New-Item -Path $SoftpaqDownloadPath -ItemType "Directory" -Force | Out-Null
                }

                # Set current working directory to HPIA directory
                Write-LogEntry -Value "Switching working directory to: $($env:SystemRoot)\Temp" -Severity 1
                Set-Location -Path (Join-Path -Path $env:SystemRoot -ChildPath "Temp")

                try {
                    # Download HP Image Assistant softpaq and extract it to Temp directory
                    Write-LogEntry -Value "Attempting to download and extract HP Image Assistant to: $($HPImageAssistantExtractPath)" -Severity 1
                    Get-Softpaq -Number $HPIASoftpaqNumber -Extract -DestinationPath $HPImageAssistantExtractPath -Overwrite "yes" -Verbose -ErrorAction Stop

                    try {
                        # Invoke HP Image Assistant to install drivers and driver software
                        $HPImageAssistantExecutablePath = Join-Path -Path $env:SystemRoot -ChildPath "Temp\HPIA\HPImageAssistant.exe"
                        Write-LogEntry -Value "Attempting to execute HP Image Assistant to install drivers and driver software, this might take some time" -Severity 1
                        $Invocation = Invoke-Executable -FilePath $HPImageAssistantExecutablePath -Arguments "/Operation:Analyze /Action:Install /Selection:All /Silent /Category:Drivers,Software /ReportFolder:$($HPImageAssistantReportPath) /SoftpaqDownloadFolder:$($SoftpaqDownloadPath)" -ErrorAction Stop

                        # Add a registry key for Win32 app detection rule based on HP Image Assistant exit code
                        switch ($Invocation) {
                            0 {
                                Write-LogEntry -Value "HP Image Assistant returned successful exit code: $($Invocation)" -Severity 1
                                Set-RegistryValue -Path "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "ExecutionResult" -Value "Success" -ErrorAction Stop
                            }
                            256 { # The analysis returned no recommendations
                                Write-LogEntry -Value "HP Image Assistant returned there were no recommendations for this system, exit code: $($Invocation)" -Severity 1
                                Set-RegistryValue -Path "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "ExecutionResult" -Value "Success" -ErrorAction Stop
                            }
                            3010 { # Softpaqs installations are successful, but at least one requires a restart
                                Write-LogEntry -Value "HP Image Assistant returned successful exit code: $($Invocation)" -Severity 1
                                Set-RegistryValue -Path "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "ExecutionResult" -Value "Success" -ErrorAction Stop
                            }
                            3020 { # One or more Softpaq's failed to install
                                Write-LogEntry -Value "HP Image Assistant did not install one or more softpaqs successfully, examine the Readme*.html file in: $($HPImageAssistantReportPath)" -Severity 2
                                Write-LogEntry -Value "HP Image Assistant returned successful exit code: $($Invocation)" -Severity 1
                                Set-RegistryValue -Path "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "ExecutionResult" -Value "Success" -ErrorAction Stop
                            }
                            default {
                                Write-LogEntry -Value "HP Image Assistant returned unhandled exit code: $($Invocation)" -Severity 3
                                Set-RegistryValue -Path "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "ExecutionResult" -Value "Failed" -ErrorAction Stop
                            }
                        }

                        # Cleanup downloaded softpaq executable that was extracted
                        Write-LogEntry -Value "Attempting to cleanup directory for downloaded softpaqs: $($SoftpaqDownloadPath)" -Severity 1
                        Remove-Item -Path $SoftpaqDownloadPath -Force -Recurse -Confirm:$false

                        # Cleanup extracted HPIA directory
                        Write-LogEntry -Value "Attempting to cleanup extracted HP Image Assistant directory: $($HPImageAssistantExtractPath)" -Severity 1
                        Remove-Item -Path $HPImageAssistantExtractPath -Force -Recurse -Confirm:$false

                        # Cleanup downloaded HP Image Assistant softpaq
                        $HPImageAssistantSoftpaqExecutable = Join-Path -Path $env:SystemRoot -ChildPath "Temp\$($HPIASoftpaqNumber).exe"
                        Write-LogEntry -Value "Attempting to remove downloaded HP Image Assistant softpaq executable: $($HPImageAssistantSoftpaqExecutable)" -Severity 1
                        Remove-Item -Path $HPImageAssistantSoftpaqExecutable -Force -Confirm:$false
                    }
                    catch [System.Exception] {
                        Write-LogEntry -Value "Failed to run HP Image Assistant to install drivers and driver software. Error message: $($_.Exception.Message)" -Severity 3; exit 1
                    }
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Failed to download and extract HP Image Assistant softpaq. Error message: $($_.Exception.Message)" -Severity 3; exit 1
                }
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Unable to install HPCMSL module from repository. Error message: $($_.Exception.Message)" -Severity 3; exit 1
            }
        }
    }   
}