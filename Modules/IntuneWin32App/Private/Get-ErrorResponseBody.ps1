function Get-ErrorResponseBody {
    <#
    .SYNOPSIS
        Get error details from Graph invocation.

    .DESCRIPTION
        Get error details from Graph invocation.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>      
    param(   
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Exception]$Exception
    )
    # Read the error stream
    $ErrorResponseStream = $Exception.Response.GetResponseStream()
    $StreamReader = New-Object System.IO.StreamReader($ErrorResponseStream)
    $StreamReader.BaseStream.Position = 0
    $StreamReader.DiscardBufferedData()
    $ResponseBody = $StreamReader.ReadToEnd()

    # Handle return object
    return $ResponseBody
}