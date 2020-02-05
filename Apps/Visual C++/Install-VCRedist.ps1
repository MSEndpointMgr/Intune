<#
.SYNOPSIS
    Install Visual C++ Redistributable applications defined in the specified JSON master file.

.DESCRIPTION
    Install Visual C++ Redistributable applications defined in the specified JSON master file.

.PARAMETER URL
    Specify the Azure Storage blob URL where JSON file is accessible from.

.EXAMPLE
    # Install all Visual C++ Redistributable applications defined in a JSON file published at a given URL:
    .\Install-VisualCRedist.ps1 -URL "https://<AzureStorageBlobUrl>"

.NOTES
    FileName:    Install-VisualCRedist.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2020-02-05
    Updated:     2020-02-05

    Version history:
    1.0.0 - (2020-02-05) Script created
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [parameter(Mandatory = $false, HelpMessage = "Specify the Azure Storage blob URL where JSON file is accessible from.")]
    [ValidateNotNullOrEmpty()]
    [string]$URL = "https://<AzureStorageBlobUrl>"
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
            [string]$Severity,

            [parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will written to.")]
            [ValidateNotNullOrEmpty()]
            [string]$FileName = "VisualCRedist.log"
        )
        # Determine log file location
        $LogFilePath = Join-Path -Path $env:SystemRoot -ChildPath (Join-Path -Path "Temp" -ChildPath $FileName)
        
        # Construct time stamp for log entry
        $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), "+", (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
        
        # Construct date for log entry
        $Date = (Get-Date -Format "MM-dd-yyyy")
        
        # Construct context for log entry
        $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        
        # Construct final log entry
        $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""VisualCRedist"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
        
        # Add value to log file
        try {
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to append log entry to VisualCRedist.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
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

    Write-LogEntry -Value "Starting installation of Visual C++ applications" -Severity 1
    
    try {
        # Load JSON meta data from Azure Storage blob file    
        Write-LogEntry -Value "Loading meta data from URL: $($URL)" -Severity 1
        $VcRedistMetaData = Invoke-RestMethod -Uri $URL -ErrorAction Stop
    }
    catch [System.Exception] {
        Write-Warning -Message "Failed to access JSON file. Error message: $($_.Exception.Message)"; break
    }

    # Set install root path based on current working directory
    $InstallRootPath = Join-Path -Path $PSScriptRoot -ChildPath "Source"

    # Get current architecture of operating system
    $Is64BitOperatingSystem = [System.Environment]::Is64BitOperatingSystem

    # Process each item from JSON meta data
    foreach ($VcRedistItem in $VcRedistMetaData.VCRedist) {
        if (($Is64BitOperatingSystem -eq $false) -and ($VcRedistItem.Architecture -like "x64")) {
            Write-LogEntry -Value "Skipping installation of '$($VcRedistItem.Architecture)' for '$($VcRedistItem.DisplayName)' on a non 64-bit operating system" -Severity 2
        }
        else {
            Write-LogEntry -Value "Processing item for installation: $($VcRedistItem.DisplayName)" -Severity 1

            # Determine execution path for current item
            $FileExecutionPath = Join-Path -Path $InstallRootPath -ChildPath (Join-Path -Path $VcRedistItem.Version -ChildPath (Join-Path -Path $VcRedistItem.Architecture -ChildPath $VcRedistItem.FileName))
            Write-LogEntry -Value "Determined file execution path for current item: $($FileExecutionPath)" -Severity 1
    
            # Install current executable
            if (Test-Path -Path $FileExecutionPath) {
                Write-LogEntry -Value "Starting installation of: $($VcRedistItem.DisplayName)" -Severity 1
                $Invocation = Invoke-Executable -FilePath $FileExecutionPath -Arguments $VcRedistItem.Parameters
    
                switch ($Invocation) {
                    0 {
                        Write-LogEntry -Value "Successfully installed application" -Severity 1
                    }
                    3010 {
                        Write-LogEntry -Value "Successfully installed application, but a restart is required" -Severity 1
                    }
                    default {
                        Write-LogEntry -Value "Failed to install application, exit code: $($Invocation)" -Severity 3
                    }
                }
            }
            else {
                Write-LogEntry -Value "Unable to detect file executable for: $($VcRedistItem.DisplayName)" -Severity 3
                Write-LogEntry -Value "Expected file could not be found: $($FileExecutionPath)" -Severity 3
            }
        }
    }
}