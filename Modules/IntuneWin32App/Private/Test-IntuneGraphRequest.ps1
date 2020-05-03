function Test-IntuneGraphRequest {
    <#
    .SYNOPSIS
        Test if a certain resource is available in Intune Graph API.

    .DESCRIPTION
        Test if a certain resource is available in Intune Graph API.

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
        [ValidateSet("Beta", "v1.0")]
        [string]$APIVersion,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Resource
    )
    try {
        # Construct full URI
        $GraphURI = "https://graph.microsoft.com/$($APIVersion)/deviceAppManagement/$($Resource)"

        # Call Graph API and get JSON response
        $GraphResponse = Invoke-RestMethod -Uri $GraphURI -Headers $AuthToken -Method "GET" -ErrorAction Stop -Verbose:$false
        if ($GraphResponse -ne $null) {
            return $true
        }
    }
    catch [System.Exception] {
        return $false
    }
}