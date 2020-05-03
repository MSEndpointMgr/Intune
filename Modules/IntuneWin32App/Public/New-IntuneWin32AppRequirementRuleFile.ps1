function New-IntuneWin32AppRequirementRuleFile {
    <#
    .SYNOPSIS
        Create a new Requirement rule object to be used for the Add-IntuneWin32App function.

    .DESCRIPTION
        Create a new Requirement rule object to be used for the Add-IntuneWin32App function.

    .PARAMETER Existence
        Define that the detection rule will be existence based, e.g. if a file or folder exists or does not exist.

    .PARAMETER DateModified
        Define that the detection rule will be based on a file or folders date modified value.

    .PARAMETER DateCreated
        Define that the detection rule will be based on when a file or folder was created.

    .PARAMETER Path
        Specify a path that will be combined with what's passed for the FileOrFolder parameter, e.g. C:\Windows\Temp.

    .PARAMETER FileOrFolder
        Specify a file or folder name that will be combined with what's passed for the Path parameter, e.g. File.exe.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-04-29
        Updated:     2020-04-29

        Version history:
        1.0.0 - (2020-04-29) Function created
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [parameter(Mandatory = $true, ParameterSetName = "Existence", HelpMessage = "Define that the detection rule will be existence based, e.g. if a file or folder exists or does not exist.")]
        [switch]$Existence,

        [parameter(Mandatory = $true, ParameterSetName = "DateModified", HelpMessage = "Define that the detection rule will be based on a file or folders date modified value.")]
        [switch]$DateModified,

        [parameter(Mandatory = $true, ParameterSetName = "DateCreated", HelpMessage = "Define that the detection rule will be based on when a file or folder was created.")]
        [switch]$DateCreated,
        
        [parameter(Mandatory = $true, ParameterSetName = "Existence", HelpMessage = "Specify a path that will be combined with what's passed for the FileOrFolder parameter, e.g. C:\Windows\Temp.")]
        [parameter(Mandatory = $true, ParameterSetName = "DateModified")]
        [parameter(Mandatory = $true, ParameterSetName = "DateCreated")]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [parameter(Mandatory = $true, ParameterSetName = "Existence", HelpMessage = "Specify a file or folder name that will be combined with what's passed for the Path parameter, e.g. File.exe.")]
        [parameter(Mandatory = $true, ParameterSetName = "DateModified")]
        [parameter(Mandatory = $true, ParameterSetName = "DateCreated")]
        [ValidateNotNullOrEmpty()]
        [string]$FileOrFolder,

        [parameter(Mandatory = $false, ParameterSetName = "Existence", HelpMessage = "Decide whether environment variables should be expanded in 32-bit context on 64-bit environments.")]
        [parameter(Mandatory = $false, ParameterSetName = "DateModified")]
        [parameter(Mandatory = $false, ParameterSetName = "DateCreated")]
        [ValidateNotNullOrEmpty()]
        [bool]$Check32BitOn64System = $false,

        [parameter(Mandatory = $true, ParameterSetName = "Existence", HelpMessage = "Specify the detection type of an file or folder, if it either exists or doesn't exist.")]
        [ValidateSet("exists", "doesNotExist")]
        [ValidateNotNullOrEmpty()]
        [string]$DetectionType,

        [parameter(Mandatory = $true, ParameterSetName = "DateModified", HelpMessage = "Specify the date operator. Supported values are: notConfigured, equal, notEqual, greaterThanOrEqual, greaterThan, lessThanOrEqual or lessThan.")]
        [parameter(Mandatory = $true, ParameterSetName = "DateCreated")]
        [ValidateSet("equal", "notEqual", "greaterThanOrEqual", "greaterThan", "lessThanOrEqual", "lessThan")]
        [ValidateNotNullOrEmpty()]
        [string]$DateOperator,

        [parameter(Mandatory = $true, ParameterSetName = "DateModified", HelpMessage = "Specify a datetime object as the value.")]
        [parameter(Mandatory = $true, ParameterSetName = "DateCreated")]
        [ValidateNotNullOrEmpty()]
        [datetime]$DateValue
    )
    Process {
        switch ($PSCmdlet.ParameterSetName) {
            "Existence" {
                # Construct ordered hash-table with least amount of required properties for default requirement rule
                $RequirementRuleFile = [ordered]@{
                    "@odata.type" = "#microsoft.graph.win32LobAppFileSystemRequirement"
                    "operator" = "notConfigured"
                    "detectionValue" = $null
                    "path" = $Path
                    "fileOrFolderName" = $FileOrFolder
                    "check32BitOn64System" = $Check32BitOn64System
                    "detectionType" = $DetectionType
                }
            }
            "DateModified" {
                # Convert input datetime object to ISO 8601 string
                $DateValueString = ConvertTo-JSONDate -InputObject $DateValue

                # Construct ordered hash-table with least amount of required properties for default requirement rule
                $RequirementRuleFile = [ordered]@{
                    "@odata.type" = "#microsoft.graph.win32LobAppFileSystemRequirement"
                    "operator" = $DateOperator
                    "detectionValue" = $DateValueString
                    "path" = $Path
                    "fileOrFolderName" = $FileOrFolder
                    "check32BitOn64System" = $Check32BitOn64System
                    "detectionType" = "modifiedDate"
                }
            }
            "DateCreated" {

            }
        }

        # Handle return value with constructed requirement rule for file
        return $RequirementRuleFile
    }
}