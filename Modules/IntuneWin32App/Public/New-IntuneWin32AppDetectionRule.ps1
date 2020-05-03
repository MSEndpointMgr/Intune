function New-IntuneWin32AppDetectionRule {
    <#
    .SYNOPSIS
        Construct a new detection rule required for Add-IntuneWin32App cmdlet.

    .DESCRIPTION
        Construct a new detection rule required for Add-IntuneWin32App cmdlet.

    .PARAMETER MSI
        Define that the detection rule will be MSI based.

    .PARAMETER File
        Define that the detection rule will be File based.

    .PARAMETER Registry
        Define that the detection rule will be Registry based.

    .PARAMETER PowerShellScript
        Define that the detection rule will be PowerShell script based.

    .PARAMETER MSIProductCode
        Specify the MSI product code for the application.

    .PARAMETER MSIProductVersionOperator
        Specify the MSI product version operator. Supported values are: notConfigured, equal, notEqual, greaterThanOrEqual, greaterThan, lessThanOrEqual or lessThan.

    .PARAMETER MSIProductVersion
        Specify the MSI product version, e.g. 1.0.0.

    .PARAMETER FilePath
        Specify the path for a folder or file.

    .PARAMETER FileOrFolderName
        Specify the folder or file name.

    .PARAMETER FileDetectionType
        Specify the file detection type. Supported values are: notConfigured, exists, modifiedDate, createdDate, version or sizeInMB.

    .PARAMETER FileDetectionValue
        Specify the file detection value.

    .PARAMETER Check32BitOn64System
        Specify if detection should check for 32-bit on 64-bit systems.

    .PARAMETER RegistryKeyPath
        Specify the registry key path, e.g. 'HKEY_LOCAL_MACHINE\SOFTWARE\Program'.

    .PARAMETER RegistryDetectionType
        Specify the registry detection type. Supported values are: exists, doesNotExist, string, integer or version.

    .PARAMETER RegistryValueName
        Specify the registry value name.

    .PARAMETER Check32BitRegOn64System
        Specify if detection should check for 32-bit on 64-bit system.

    .PARAMETER ScriptFile
        Specify the full path to the PowerShell detection script, e.g. 'C:\Scripts\Detection.ps1'.

    .PARAMETER EnforceSignatureCheck
        Specify if PowerShell script signature check should be enforced.

    .PARAMETER RunAs32Bit
        Specify is PowerShell script should be executed as a 32-bit process.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Define that the detection rule will be MSI based.")]
        [switch]$MSI,

        [parameter(Mandatory = $true, ParameterSetName = "File", HelpMessage = "Define that the detection rule will be File based.")]
        [switch]$File,

        [parameter(Mandatory = $true, ParameterSetName = "Registry", HelpMessage = "Define that the detection rule will be Registry based.")]
        [switch]$Registry,

        [parameter(Mandatory = $true, ParameterSetName = "PowerShell", HelpMessage = "Define that the detection rule will be PowerShell script based.")]
        [switch]$PowerShellScript,

        [parameter(Mandatory = $true, ParameterSetName = "MSI", HelpMessage = "Specify the MSI product code for the application.")]
        [ValidateNotNullOrEmpty()]
        [string]$MSIProductCode,

        [parameter(Mandatory = $false, ParameterSetName = "MSI", HelpMessage = "Specify the MSI product version operator. Supported values are: notConfigured, equal, notEqual, greaterThanOrEqual, greaterThan, lessThanOrEqual or lessThan.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("notConfigured", "equal", "notEqual", "greaterThanOrEqual", "greaterThan", "lessThanOrEqual", "lessThan")]
        [string]$MSIProductVersionOperator = "notConfigured",

        [parameter(Mandatory = $false, ParameterSetName = "MSI", HelpMessage = "Specify the MSI product version, e.g. 1.0.0.")]
        [ValidateNotNullOrEmpty()]
        [string]$MSIProductVersion = [string]::Empty,

        [parameter(Mandatory = $true, ParameterSetName = "File", HelpMessage = "Specify the path for a folder or file.")]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [parameter(Mandatory = $true, ParameterSetName = "File", HelpMessage = "Specify the folder or file name.")]
        [ValidateNotNullOrEmpty()]
        [string]$FileOrFolderName,

        [parameter(Mandatory = $false, ParameterSetName = "File", HelpMessage = "Specify the file detection type. Supported values are: notConfigured, exists, modifiedDate, createdDate, version or sizeInMB.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("notConfigured", "exists", "modifiedDate", "createdDate", "version", "sizeInMB")]
        [string]$FileDetectionType = "notConfigured",

        [parameter(Mandatory = $false, ParameterSetName = "File", HelpMessage = "Specify the file detection value.")]
        [ValidateNotNullOrEmpty()]
        [string]$FileDetectionValue = [string]::Empty,

        [parameter(Mandatory = $false, ParameterSetName = "File", HelpMessage = "Specify if detection should check for 32-bit on 64-bit systems.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("True", "False")]
        [string]$Check32BitOn64System = "False",

        [parameter(Mandatory = $true, ParameterSetName = "Registry", HelpMessage = "Specify the registry key path, e.g. 'HKEY_LOCAL_MACHINE\SOFTWARE\Program'.")]
        [ValidateNotNullOrEmpty()]
        [string]$RegistryKeyPath,
       
        [parameter(Mandatory = $true, ParameterSetName = "Registry", HelpMessage = "Specify the registry detection type. Supported values are: exists, doesNotExist, string, integer or version.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("exists", "doesNotExist", "string", "integer", "version")]
        [string]$RegistryDetectionType,
       
        [parameter(Mandatory = $false, ParameterSetName = "Registry", HelpMessage = "Specify the registry value name.")]
        [ValidateNotNullOrEmpty()]
        [string]$RegistryValueName,
       
        [parameter(Mandatory = $false, ParameterSetName = "Registry", HelpMessage = "Specify if detection should check for 32-bit on 64-bit system.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("True","False")]
        [string]$Check32BitRegOn64System = "False",

        [parameter(Mandatory = $true, ParameterSetName = "PowerShell", HelpMessage = "Specify the full path to the PowerShell detection script, e.g. 'C:\Scripts\Detection.ps1'.")]
        [ValidateNotNullOrEmpty()]
        [string]$ScriptFile,
       
        [parameter(Mandatory = $false, ParameterSetName = "PowerShell", HelpMessage = "Specify if PowerShell script signature check should be enforced.")]
        [ValidateNotNullOrEmpty()]
        [bool]$EnforceSignatureCheck = $false,
       
        [parameter(Mandatory = $false, ParameterSetName = "PowerShell", HelpMessage = "Specify is PowerShell script should be executed as a 32-bit process.")]
        [ValidateNotNullOrEmpty()]
        [bool]$RunAs32Bit = $false
    )
    # Handle initial value for return
    $DetectionRule = $null

    # Determine detection rule generation method based upon parameter set name
    switch ($PSCmdlet.ParameterSetName) {
        "MSI" {
            $DetectionRule = [ordered]@{
                "@odata.type" = "#microsoft.graph.win32LobAppProductCodeDetection"
                "productCode" = $MSIProductCode
                "productVersionOperator" = $MSIProductVersionOperator
                "productVersion" = $MSIProductVersion
            }
        }
        "File" {
            # NOTE: Currently only supports detection method type as "File or folder exists", other methods will be implemented in a future release
            $DetectionRule = [ordered]@{
                "@odata.type" = "#microsoft.graph.win32LobAppFileSystemDetection"
                "check32BitOn64System" = $Check32BitOn64System
                "detectionType" = $FileDetectionType
                "detectionValue" = $FileDetectionValue
                "fileOrFolderName" = $FileOrFolderName
                "operator" = "notConfigured"
                "path" = $FilePath
            }
        }
        "Registry" {
            # NOTE: Currently only supports detection method type as "Key/Value exists", other methods will be implemented in a future release
            $DetectionRule = [ordered]@{
                "@odata.type" = "#microsoft.graph.win32LobAppRegistryDetection"
                "check32BitOn64System" = $Check32BitRegOn64System
                "detectionType" = "exists"
                "detectionValue" = ""
                "keyPath" = $RegistryKeyPath
                "operator" = "notConfigured"
            }

            # Handle valueName property value depending on parameter input
            if ($PSBoundParameters["RegistryValueName"]) {
                $DetectionRule.Add("valueName", $RegistryValueName)
            }
            else {
                $DetectionRule.Add("valueName", [string]::Empty)
            }
        }
        "PowerShell" {
            # Detect if passed script file exists
            if (Test-Path -Path $ScriptFile) {
                # Convert script file contents to base64 string
                $ScriptContent = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("$($ScriptFile)"))

                # Construct detection rule ordered table
                $DetectionRule = [ordered]@{
                    "@odata.type" = "#microsoft.graph.win32LobAppPowerShellScriptDetection"
                    "enforceSignatureCheck" = $EnforceSignatureCheck
                    "runAs32Bit" = $RunAs32Bit
                    "scriptContent" = $ScriptContent
                }
            }
            else {
                Write-Warning -Message "Unable to detect the presence of specified script file"
            }
        }
    }
    
    # Handle return value with constructed detection rule
    return $DetectionRule
}