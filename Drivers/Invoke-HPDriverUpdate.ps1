<#
.SYNOPSIS
    Download and install the latest set of drivers and driver software from HP repository online using HP Image Assistant for current client device.

.DESCRIPTION
    This script will download and install the latest matching drivers and driver software from HP repository online using HP Image Assistant that will
    analyze what's required for the current client device it's running on.

.PARAMETER RunMode
    Select run mode for this script, either Stage or Execute.

.PARAMETER HPIAAction
    Specify the HP Image Assistant action to perform, e.g. Download or Install.

.EXAMPLE
    .\Invoke-HPDriverUpdate.ps1 -RunMode "Stage"

.NOTES
    FileName:    Invoke-HPDriverUpdate.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2020-08-12
    Updated:     2021-04-07

    Version history:
    1.0.0 - (2020-08-12) Script created
    1.0.1 - (2020-09-15) Added a fix for registering default PSGallery repository if not already registered
    1.0.2 - (2020-09-28) Added a new parameter HPIAAction that controls whether to Download or Install applicable drivers
    1.0.3 - (2021-04-07) Replaced Get-Softpaq cmdlet with a hard-coded softpaq number with the newly added Install-HPImageAssistant cmdlet in the HPCMSL module
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [parameter(Mandatory = $true, HelpMessage = "Select run mode for this script, either Stage or Execute.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("Stage", "Execute")]
    [string]$RunMode,

    [parameter(Mandatory = $false, HelpMessage = "Specify the HP Image Assistant action to perform, e.g. Download or Install.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("Download", "Install")]
    [string]$HPIAAction = "Install"
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

    function Start-PowerShellSysNative {
        param (
            [parameter(Mandatory = $false, HelpMessage = "Specify arguments that will be passed to the sysnative PowerShell process.")]
            [ValidateNotNull()]
            [string]$Arguments
        )

        # Get the sysnative path for powershell.exe
        $SysNativePowerShell = Join-Path -Path ($PSHOME.ToLower().Replace("syswow64", "sysnative")) -ChildPath "powershell.exe"

        # Construct new ProcessStartInfo object to restart powershell.exe as a 64-bit process and re-run scipt
        $ProcessStartInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
        $ProcessStartInfo.FileName = $SysNativePowerShell
        $ProcessStartInfo.Arguments = $Arguments
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

    # Stage script in system root directory for ActiveSetup
    $WindowsTempPath = Join-Path -Path $env:SystemRoot -ChildPath "Temp"
    if (-not(Test-Path -Path (Join-Path -Path $WindowsTempPath -ChildPath $MyInvocation.MyCommand.Name))) {
        Write-LogEntry -Value "Attempting to stage '$($MyInvocation.MyCommand.Definition)' to: $($WindowsTempPath)" -Severity 1
        Copy-Item $MyInvocation.MyCommand.Definition -Destination $WindowsTempPath -Force
    }
    else {
        Write-LogEntry -Value "Found existing script file '$($MyInvocation.MyCommand.Definition)' in '$($WindowsTempPath)', will not attempt to stage again" -Severity 1
    }

    # Check if we're running as a 64-bit process or not, if not restart as a 64-bit process
    if (-not[System.Environment]::Is64BitProcess) {
        Write-LogEntry -Value "Re-launching the PowerShell instance as a 64-bit process in Stage mode since it was originally launched as a 32-bit process" -Severity 1
        Start-PowerShellSysNative -Arguments "-ExecutionPolicy Bypass -File $($env:SystemRoot)\Temp\$($MyInvocation.MyCommand.Name) -RunMode Stage"
    }
    else {
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
                Write-LogEntry -Value "Current script host process is running in 64-bit: $([System.Environment]::Is64BitProcess)" -Severity 1

                try {
                    # Install latest NuGet package provider
                    Write-LogEntry -Value "Attempting to install latest NuGet package provider" -Severity 1
                    $PackageProvider = Install-PackageProvider -Name "NuGet" -Force -ErrorAction Stop -Verbose:$false
    
                    # Ensure default PSGallery repository is registered
                    Register-PSRepository -Default -ErrorAction SilentlyContinue

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
                            Write-LogEntry -Value "PowerShellGet module was not found, will attempting to install it and it's dependencies from repository" -Severity 1
                            Write-LogEntry -Value "Attempting to install PackageManagement module from repository" -Severity 1
                            Install-Module -Name "PackageManagement" -Force -Scope AllUsers -AllowClobber -ErrorAction Stop -Verbose:$false
                            Write-LogEntry -Value "Attempting to install PowerShellGet module from repository" -Severity 1
                            Install-Module -Name "PowerShellGet" -Force -Scope AllUsers -AllowClobber -ErrorAction Stop -Verbose:$false
                        }
                        catch [System.Exception] {
                            Write-LogEntry -Value "Unable to install PowerShellGet module from repository. Error message: $($_.Exception.Message)" -Severity 3; exit 1
                        }
                    }
    
                    try {
                        # Invoke executing script again in Execute run mode after package provider and modules have been installed/updated
                        Write-LogEntry -Value "Re-launching the PowerShell instance in Execute mode to overcome a bug with PowerShellGet" -Severity 1
                        Start-PowerShellSysNative -Arguments "-ExecutionPolicy Bypass -File $($env:SystemRoot)\Temp\$($MyInvocation.MyCommand.Name) -RunMode Execute"
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
                        Install-HPImageAssistant -Extract -DestinationPath $HPImageAssistantExtractPath -Quiet -ErrorAction Stop
    
                        try {
                            # Invoke HP Image Assistant to install drivers and driver software
                            $HPImageAssistantExecutablePath = Join-Path -Path $env:SystemRoot -ChildPath "Temp\HPIA\HPImageAssistant.exe"
                            switch ($HPIAAction) {
                                "Download" {
                                    Write-LogEntry -Value "Attempting to execute HP Image Assistant to download drivers including driver software, this might take some time" -Severity 1

                                    # Prepare arguments for HP Image Assistant download mode
                                    $HPImageAssistantArguments = "/Operation:Analyze /Action:Download /Selection:All /Silent /Category:Drivers,Software /ReportFolder:$($HPImageAssistantReportPath) /SoftpaqDownloadFolder:$($SoftpaqDownloadPath)"

                                    # Set HP Image Assistant operational mode in registry
                                    Set-RegistryValue -Path "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "OperationalMode" -Value "Download" -ErrorAction Stop
                                }
                                "Install" {
                                    Write-LogEntry -Value "Attempting to execute HP Image Assistant to download and install drivers including driver software, this might take some time" -Severity 1

                                    # Prepare arguments for HP Image Assistant install mode
                                    $HPImageAssistantArguments = "/Operation:Analyze /Action:Install /Selection:All /Silent /Category:Drivers,Software /ReportFolder:$($HPImageAssistantReportPath) /SoftpaqDownloadFolder:$($SoftpaqDownloadPath)"

                                    # Set HP Image Assistant operational mode in registry
                                    Set-RegistryValue -Path "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "OperationalMode" -Value "Install" -ErrorAction Stop
                                }
                            }

                            # Invoke HP Image Assistant
                            $Invocation = Invoke-Executable -FilePath $HPImageAssistantExecutablePath -Arguments $HPImageAssistantArguments -ErrorAction Stop
    
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
    
                            if ($HPIAAction -like "Install") {
                                # Cleanup downloaded softpaq executable that was extracted
                                Write-LogEntry -Value "Attempting to cleanup directory for downloaded softpaqs: $($SoftpaqDownloadPath)" -Severity 1
                                Remove-Item -Path $SoftpaqDownloadPath -Force -Recurse -Confirm:$false
                            }
    
                            # Cleanup extracted HPIA directory
                            Write-LogEntry -Value "Attempting to cleanup extracted HP Image Assistant directory: $($HPImageAssistantExtractPath)" -Severity 1
                            Remove-Item -Path $HPImageAssistantExtractPath -Force -Recurse -Confirm:$false
    
                            # Remove script from Temp directory
                            Write-LogEntry -Value "Attempting to self-destruct executing script file: $($MyInvocation.MyCommand.Definition)" -Severity 1
                            Remove-Item -Path $MyInvocation.MyCommand.Definition -Force -Confirm:$false
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
}