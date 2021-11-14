#HP HPCMLS Detection Script 
#Created by: 
#Jan Ketil Skanke & Maurice Daly 
#MSEndpointMgr.com 

#Start Detection
#Validate that script is executed on HP hardware
$Manufacturer = (Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty Manufacturer).Trim()
switch -Wildcard ($Manufacturer) {
    "*HP*" {
        Write-output "Validated HP hardware check" 
    }
    "*Hewlett-Packard*" {
        Write-output "Validated HP hardware check" 
    }
    default {
        Write-output "Not running on HP Hardware, Remediation not applicable"; exit 0
    }
}
$ProviderInstalled = $false
$Providers = Get-PackageProvider -ListAvailable 
if ($Providers.Name -notcontains "NuGet") {
    Write-Output "Required provider missing"; exit 1
}elseif (((Get-PackageProvider -Name "NuGet").version) -le ([Version]"2.8.5")) {
    Write-Output "Provider must be updated"; exit 1
}else {
    Write-Output "Provider OK, Checking for modules" 
    $ProviderInstalled = $true
}

if ($ProviderInstalled) {
    $PowerShellGetInstalledModule = Get-InstalledModule -Name "PowerShellGet" -ErrorAction SilentlyContinue -Verbose:$false
    if ($PowerShellGetInstalledModule -ne $null) {
        try {
            # Attempt to locate the latest available version of the PowerShellGet module from repository
            Write-Output "Attempting to request the latest PowerShellGet module version from repository" 
            $PowerShellGetLatestModule = Find-Module -Name "PowerShellGet" -ErrorAction Stop -Verbose:$false
            if ($PowerShellGetLatestModule -ne $null) {
                if ($PowerShellGetInstalledModule.Version -lt $PowerShellGetLatestModule.Version) {
                    Write-Output "Newer PowerShellGet version detected, update from repository is needed";exit 1
                } else {
                    Write-Output "PowershellGet is Ready"
                    $HPInstalledModule = Get-InstalledModule | Where-Object {$_.Name -match "HPCMSL"} -ErrorAction SilentlyContinue -Verbose:$false
                    if ($HPInstalledModule -ne $null) {
                        $HPGetLatestModule = Find-Module -Name "HPCMSL" -ErrorAction Stop -Verbose:$false
                        if ($HPInstalledModule.Version -lt $HPGetLatestModule.Version) {
                            Write-Output "Newer HPCMSL version detected, update from repository is needed";exit 1
                        } else {
                            Write-Output "HPCMSL Module is up to date"; exit 0
                        }
                    } else {
                        Write-Output "HPCMSL Module is missing"; exit 1
                    }
                }
            } else {
                Write-Output "Location request for the latest available version of the PowerShellGet module failed, can't continue"; exit 1
            }
        }
        catch [System.Exception] {
            Write-Output "Failed to retrieve the latest available version of the PowerShellGet module, can't continue. Error message: $($_.Exception.Message)" ; exit 1
        }
    } else {
        Write-Output "PowershellGet module is missing"; exit 1
    }
}
