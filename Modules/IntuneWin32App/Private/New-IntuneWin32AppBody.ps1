function New-IntuneWin32AppBody {
    <#
    .SYNOPSIS
        Retrieves meta data from the detection.xml file inside the packaged Win32 application .intunewin file.

    .DESCRIPTION
        Retrieves meta data from the detection.xml file inside the packaged Win32 application .intunewin file.

    .PARAMETER FilePath
        Specify an existing local path to where the win32 app .intunewin file is located.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
        1.0.1 - (2020-01-27) Added support for RequirementRule parameter input
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Define that the Win32 application body will be MSI based.")]
        [switch]$MSI,

        [parameter(Mandatory = $true, ParameterSetName = "EXE", HelpMessage = "Define that the Win32 application body will be File based.")]
        [switch]$EXE,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify a display name for the Win32 application body.")]
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify a description for the Win32 application body.")]
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [string]$Description,        

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify a publisher name for the Win32 application body.")]
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [string]$Publisher,

        [parameter(Mandatory = $false, ParameterSetName = "MSI", HelpMessage = "Specify a developer name for the Win32 application body.")]
        [parameter(Mandatory = $false, ParameterSetName = "EXE")]
        [string]$Developer = [string]::Empty,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the file name (e.g. name.intunewin) for the Win32 application body.")]
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [string]$FileName,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the setup file name (e.g. setup.exe) for the Win32 application body.")]
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [string]$SetupFileName,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the installation experience for the Win32 application body.")]
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("system", "user")]
        [string]$InstallExperience,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the installation experience for the Win32 application body.")]
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("allow", "basedOnReturnCode", "suppress", "force")]
        [string]$RestartBehavior,

        [parameter(Mandatory = $false, ParameterSetName = "MSI", HelpMessage = "Specify the requirement rules for the Win32 application body.")]
        [parameter(Mandatory = $false, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Specialized.OrderedDictionary]$RequirementRule,

        [parameter(Mandatory = $false, ParameterSetName = "MSI", HelpMessage = "Provide a Base64 encoded string as icon for the Win32 application body.")]
        [parameter(Mandatory = $false, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        [string]$Icon,

        [parameter(Mandatory = $true, ParameterSetName = "EXE", HelpMessage = "Specify the install command line for the Win32 application body.")]
        [ValidateNotNullOrEmpty()]
        [string]$InstallCommandLine,

        [parameter(Mandatory = $true, ParameterSetName = "EXE", HelpMessage = "Specify the uninstall command line for the Win32 application body.")]
        [ValidateNotNullOrEmpty()]
        [string]$UninstallCommandLine,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the MSI installation purpose for the Win32 application body.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("DualPurpose", "PerMachine", "PerUser")]
        [string]$MSIInstallPurpose,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the MSI product code for the Win32 application body.")]
        [ValidateNotNullOrEmpty()]
        [string]$MSIProductCode,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the MSI product name for the Win32 application body.")]
        [ValidateNotNullOrEmpty()]
        [string]$MSIProductName,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the MSI product version for the Win32 application body.")]
        [ValidateNotNullOrEmpty()]
        [string]$MSIProductVersion,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the MSI requires reboot value for the Win32 application body.")]
        [ValidateNotNullOrEmpty()]
        [bool]$MSIRequiresReboot,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the MSI upgrade code for the Win32 application body.")]
        [ValidateNotNullOrEmpty()]
        [string]$MSIUpgradeCode
    )
    # Determine values for requirement rules
    if ($PSBoundParameters["RequirementRule"]) {
        $ApplicableArchitectures = $RequirementRule["applicableArchitectures"]
        $MinimumSupportedOperatingSystem = $RequirementRule["minimumSupportedOperatingSystem"]
    }
    else {
        $ApplicableArchitectures = "x64,x86"
        $MinimumSupportedOperatingSystem = @{
            "v10_1607" = $true
        }
    }

    switch ($PSCmdlet.ParameterSetName) {
        "MSI" {
            $Win32AppBody = [ordered]@{
                "@odata.type" = "#microsoft.graph.win32LobApp"
                "applicableArchitectures" = $ApplicableArchitectures
                "description" = $Description
                "developer" = $Developer
                "displayName" = $DisplayName
                "fileName" = $FileName
                "setupFilePath" = $SetupFileName
                "installCommandLine" = "msiexec.exe /i `"$SetupFileName`""
                "uninstallCommandLine" = "msiexec.exe /x `"$MSIProductCode`""
                "installExperience" = @{
                    "runAsAccount" = $InstallExperience
                    "deviceRestartBehavior" = $RestartBehavior
                }
                "informationUrl" = $null
                "isFeatured" = $false
                "minimumSupportedOperatingSystem" = $MinimumSupportedOperatingSystem
                "msiInformation" = @{
                    "packageType" = $MSIInstallPurpose
                    "productCode" = $MSIProductCode
                    "productName" = $MSIProductName
                    "productVersion" = $MSIProductVersion
                    "publisher" = $MSIPublisher
                    "requiresReboot" = $MSIRequiresReboot
                    "upgradeCode" = $MSIUpgradeCode
                };
                "notes" = ""
                "owner" = ""
                "privacyInformationUrl" = $null
                "publisher" = $Publisher
                "runAs32bit" = $false
            }

            # Add icon property if pass on command line
            if ($PSBoundParameters["Icon"]) {
                $Win32AppBody.Add("largeIcon", @{
                    "type" = "image/png"
                    "value" = $Icon
                })
            }
        }
        "EXE" {
            $Win32AppBody = [ordered]@{
                "@odata.type" = "#microsoft.graph.win32LobApp"
                "applicableArchitectures" = "x64,x86"
                "description" = $Description
                "developer" = $Developer
                "displayName" = $DisplayName
                "fileName" = $FileName
                "setupFilePath" = $SetupFileName
                "installCommandLine" = $InstallCommandLine
                "uninstallCommandLine" = $UninstallCommandLine
                "installExperience" = @{
                    "runAsAccount" = $InstallExperience
                    "deviceRestartBehavior" = $RestartBehavior
                }
                "informationUrl" = $null
                "isFeatured" = $false
                "minimumSupportedOperatingSystem" = @{
                    "v10_1607" = $true
                }
                "msiInformation" = $null
                "notes" = ""
                "owner" = ""
                "privacyInformationUrl" = $null
                "publisher" = $Publisher
                "runAs32bit" = $false
            }

            # Add icon property if pass on command line
            if ($PSBoundParameters["Icon"]) {
                $Win32AppBody.Add("largeIcon", @{
                    "type" = "image/png"
                    "value" = $Icon
                })
            }
        }
    }

    # Handle return value with constructed Win32 application body
    return $Win32AppBody
}