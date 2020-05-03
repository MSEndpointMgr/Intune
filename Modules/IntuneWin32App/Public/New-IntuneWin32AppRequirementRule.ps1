function New-IntuneWin32AppRequirementRule {
    <#
    .SYNOPSIS
        Construct a new requirement rule as an optional requirement for Add-IntuneWin32App cmdlet.

    .DESCRIPTION
        Construct a new requirement rule as an optional requirement for Add-IntuneWin32App cmdlet.

    .PARAMETER Architecture
        Specify the architecture as a requirement for the Win32 app.

    .PARAMETER MinimumSupportedOperatingSystem
        Specify the minimum supported operating system version as a requirement for the Win32 app.

    .PARAMETER MinimumFreeDiskSpaceInMB
        Specify the minimum free disk space in MB as a requirement for the Win32 app.

    .PARAMETER MinimumMemoryInMB
        Specify the minimum required memory in MB as a requirement for the Win32 app.

    .PARAMETER MinimumNumberOfProcessors
        Specify the minimum number of required logical processors as a requirement for the Win32 app.

    .PARAMETER MinimumCPUSpeedInMHz
        Specify the minimum CPU speed in Mhz (as an integer) as a requirement for the Win32 app.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-27
        Updated:     2020-01-27

        Version history:
        1.0.0 - (2020-01-27) Function created
    #>    
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the architecture as a requirement for the Win32 app.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("x64", "x86", "All")]
        [string]$Architecture,

        [parameter(Mandatory = $true, HelpMessage = "Specify the minimum supported operating system version as a requirement for the Win32 app.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("1607", "1703", "1709", "1803", "1809", "1903")]
        [string]$MinimumSupportedOperatingSystem,

        [parameter(Mandatory = $false, HelpMessage = "Specify the minimum free disk space in MB as a requirement for the Win32 app.")]
        [ValidateNotNullOrEmpty()]
        [int]$MinimumFreeDiskSpaceInMB,

        [parameter(Mandatory = $false, HelpMessage = "Specify the minimum required memory in MB as a requirement for the Win32 app.")]
        [ValidateNotNullOrEmpty()]
        [int]$MinimumMemoryInMB,

        [parameter(Mandatory = $false, HelpMessage = "Specify the minimum number of required logical processors as a requirement for the Win32 app.")]
        [ValidateNotNullOrEmpty()]
        [int]$MinimumNumberOfProcessors,

        [parameter(Mandatory = $false, HelpMessage = "Specify the minimum CPU speed in Mhz (as an integer) as a requirement for the Win32 app.")]
        [ValidateNotNullOrEmpty()]
        [int]$MinimumCPUSpeedInMHz
    )
    # Construct table for supported architectures
    $ArchitectureTable = @{
        "x64" = "x64"
        "x86" = "x86"
        "All" = "x64,x86"
    }

    # Construct table for supported operating systems
    $OperatingSystemTable = @{
        "1607" = "v10_1607"
        "1703" = "v10_1703"
        "1709" = "v10_1709"
        "1803" = "v10_1803"
        "1809" = "v10_1809"
        "1903" = "v10_1903"
        "1909" = "v10_1909"
    }

    # Construct ordered hash-table with least amount of required properties for default requirement rule
    $RequirementRule = [ordered]@{
        "applicableArchitectures" = $ArchitectureTable[$Architecture]
        "minimumSupportedOperatingSystem" = @{
            $OperatingSystemTable[$MinimumSupportedOperatingSystem] = $true
        }
    }

    # Add additional requirement rule details if specified on command line
    if ($PSBoundParameters["MinimumFreeDiskSpaceInMB"]) {
        $RequirementRule.Add("minimumFreeDiskSpaceInMB", $MinimumFreeDiskSpaceInMB)
    }
    if ($PSBoundParameters["MinimumMemoryInMB"]) {
        $RequirementRule.Add("minimumMemoryInMB", $MinimumMemoryInMB)
    }
    if ($PSBoundParameters["MinimumNumberOfProcessors"]) {
        $RequirementRule.Add("minimumNumberOfProcessors", $MinimumNumberOfProcessors)
    }
    if ($PSBoundParameters["MinimumCPUSpeedInMHz"]) {
        $RequirementRule.Add("minimumCpuSpeedInMHz", $MinimumCPUSpeedInMHz)
    }

    return $RequirementRule
}