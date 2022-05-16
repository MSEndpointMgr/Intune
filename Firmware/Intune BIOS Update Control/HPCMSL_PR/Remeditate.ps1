#HP HPCMLS Remediation Script 
#Created by: 
#Jan Ketil Skanke & Maurice Daly 
#MSEndpointMgr.com 
#Start-PowerShellSysNative is inspired by @NickolajA's method to install the HPCMLS module 
#Fixed an issue with version 1.6.5 - added -SkipPublisherCheck as HP has changed their root cert from this version. 

#Start remediate
#This remediation must run in system context and in 64bit powershell. 
function Start-PowerShellSysNative {
    param (
        [parameter(Mandatory = $false, HelpMessage = "Specify arguments that will be passed to the sysnative PowerShell process.")]
        [ValidateNotNull()]
        [string]$Arguments
    )

    # Get the sysnative path for powershell.exe
    $SysNativePowerShell = Join-Path -Path ($PSHOME.ToLower().Replace("syswow64", "sysnative")) -ChildPath "powershell.exe"

    # Construct new ProcessStartInfo object to run scriptblock in fresh process
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
}#endfunction

 # Enable TLS 1.2 support for downloading modules from PSGallery (Required)
 [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Validate that script is executed on HP hardware
$Manufacturer = (Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty Manufacturer).Trim()
switch -Wildcard ($Manufacturer) {
    "*HP*" {
        Write-output "Validated HP hardware check" 
    }
    "*Hewlett-Packard*" {
        Write-output "Validated HP hardware check" 
    }
    default {
        Write-output "Not running on HP Hardware, Script not applicable"; exit 0
    }
}

# Install latest NuGet package provider
try {
Write-Output "Attempting to install latest NuGet package provider"
$PackageProvider = Install-PackageProvider -Name "NuGet" -Force -ErrorAction Stop -Verbose:$false
}
catch [System.Exception] {
    Write-output "Unable to install latest NuGet package provider. Error message: $($_.Exception.Message)"; exit 1
}   

# Install the latest PowershellGet Module 
if ($PackageProvider.Version -ge "2.8.5"){
    $PowerShellGetInstalledModule = Get-InstalledModule -Name "PowerShellGet" -ErrorAction SilentlyContinue -Verbose:$false
    if ($PowerShellGetInstalledModule -ne $null) {
        try {
            # Attempt to locate the latest available version of the PowerShellGet module from repository
            Write-Output "Attempting to request the latest PowerShellGet module version from repository" 
            $PowerShellGetLatestModule = Find-Module -Name "PowerShellGet" -ErrorAction Stop -Verbose:$false
            if ($PowerShellGetLatestModule -ne $null) {
                if ($PowerShellGetInstalledModule.Version -lt $PowerShellGetLatestModule.Version) {
                    try {
                        # Newer module detected, attempt to update
                        Write-Output "Newer version detected, attempting to update the PowerShellGet module from repository" 
                        Update-Module -Name "PowerShellGet" -Scope "AllUsers" -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
                    }
                    catch [System.Exception] {
                        Write-Output "Failed to update the PowerShellGet module. Error message: $($_.Exception.Message)"; exit 1
                    }
                }
            }
            else {
                Write-Output "Location request for the latest available version of the PowerShellGet module failed, can't continue"; exit 1
            }
        }
        catch [System.Exception] {
            Write-Output "Failed to retrieve the latest available version of the PowerShellGet module, can't continue. Error message: $($_.Exception.Message)" ; exit 1
        }
    } else {
        try {
            # PowerShellGet module was not found, attempt to install from repository
            Write-Output "PowerShellGet module was not found, attempting to install it including dependencies from repository" 
            Write-Output "Attempting to install PackageManagement module from repository" 
            Install-Module -Name "PackageManagement" -Force -Scope AllUsers -AllowClobber -ErrorAction Stop -Verbose:$false
            Write-Output "Attempting to install PowerShellGet module from repository" 
            Install-Module -Name "PowerShellGet" -Force -Scope AllUsers -AllowClobber -ErrorAction Stop -Verbose:$false
        }
        catch [System.Exception] {
            Write-Output "Unable to install PowerShellGet module from repository. Error message: $($_.Exception.Message)"; exit 1
        }
    }
    
    #Install the latest HPCMSL Module
    $HPInstalledModule = Get-InstalledModule | Where-Object {$_.Name -match "HPCMSL"} -ErrorAction SilentlyContinue -Verbose:$false
    if ($HPInstalledModule -ne $null) {
        $HPGetLatestModule = Find-Module -Name "HPCMSL" -ErrorAction Stop -Verbose:$false
        if ($HPInstalledModule.Version -lt $HPGetLatestModule.Version) {
            Write-Output "Newer HPCMSL version detected, updating from repository"
            $scriptBlock = {
                try {
                    # Install HP Client Management Script Library
                    Write-Output -Value "Attempting to install HPCMSL module from repository" 
                    Install-Module -Name "HPCMSL" -AcceptLicense -Force -SkipPublisherCheck -ErrorAction Stop -Verbose:$false
                } 
                catch [System.Exception] {
                    Write-OutPut -Value "Unable to install HPCMSL module from repository. Error message: $($_.Exception.Message)"; exit 1
                }
            } 
            Start-PowerShellSysNative -Arguments "-ExecutionPolicy Bypass $($scriptBlock)"
        } else {
            Write-Output "HPCMSL Module is up to date"; exit 0
        }
    } else {
        Write-Output "HPCMSL Module is missing, try to install from repository"
        $scriptBlock = {
            try {
                # Install HP Client Management Script Library
                Write-Output -Value "Attempting to install HPCMSL module from repository" 
                Install-Module -Name "HPCMSL" -AcceptLicense -Force -ErrorAction Stop -Verbose:$false
            } 
            catch [System.Exception] {
                Write-OutPut -Value "Unable to install HPCMSL module from repository. Error message: $($_.Exception.Message)"; exit 1
            }
        } 
        Start-PowerShellSysNative -Arguments "-ExecutionPolicy Bypass $($scriptBlock)"
    }
}