function New-IntuneWin32AppReturnCode {
    <#
    .SYNOPSIS
        Return a hash-table with a specified return code.

    .DESCRIPTION
        Return a hash-table with a specified return code.

    .PARAMETER ReturnCode
        Specify the return code value for the Win32 application body.

    .PARAMETER Type
        Specify the type for the return code value for the Win32 application body. Supported values are: success, softReboot, hardReboot or retry.

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
        [parameter(Mandatory = $true, HelpMessage = "Specify the return code value for the Win32 application body.")]
        [ValidateNotNullOrEmpty()]
        [int]$ReturnCode,

        [parameter(Mandatory = $true, HelpMessage = "Specify the type for the return code value for the Win32 application body. Supported values are: success, softReboot, hardReboot or retry.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("success", "softReboot", "hardReboot", "retry")]
        [string]$Type
    )
    $ReturnCodeTable = @{
        "returnCode" = $ReturnCode
        "type" = $Type
    }

    return $ReturnCodeTable
}