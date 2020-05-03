function Get-IntuneWin32AppDefaultReturnCode {
    <#
    .SYNOPSIS
        Return an array of default return codes.

    .DESCRIPTION
        Return an array of default return codes.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>
    $ReturnCodeArray = @()
    $ReturnCodeArray += @{ "returnCode" = 0; "type" = "success" }
    $ReturnCodeArray += @{ "returnCode" = 1707; "type" = "success" }
    $ReturnCodeArray += @{ "returnCode" = 3010; "type" = "softReboot" }
    $ReturnCodeArray += @{ "returnCode" = 1641; "type" = "hardReboot" }
    $ReturnCodeArray += @{ "returnCode" = 1618; "type" = "retry" }
    
    return $ReturnCodeArray
}