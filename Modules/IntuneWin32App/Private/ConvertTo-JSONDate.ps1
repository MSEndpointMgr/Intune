function ConvertTo-JSONDate {
    <#
    .SYNOPSIS
        Converts a DateTime object to a ISO 8601 date time string properly formatted for usage with Intune Graph API.

    .DESCRIPTION
        Converts a DateTime object to a ISO 8601 date time string properly formatted for usage with Intune Graph API.

    .PARAMETER InputObject
        Specify a DateTime object.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-05-03
        Updated:     2020-05-03

        Version history:
        1.0.0 - (2020-05-03) Function created
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [parameter(Mandatory = $true, ValueFromPipeline = $true, HelpMessage = "Specify a DateTime object.")]
        [ValidateNotNullOrEmpty()]
        [datetime]$InputObject
    )
    # Convert input datetime object to ISO 8601
    $DateTimeString = Get-Date -Year $InputObject.Year -Month $InputObject.Month -Day $InputObject.Day -Hour $InputObject.Hour -Second $InputObject.Second -UFormat '+%Y-%m-%dT%H:%M:%S.000Z'

    # Return converted datetime object as a string
    return $DateTimeString
}