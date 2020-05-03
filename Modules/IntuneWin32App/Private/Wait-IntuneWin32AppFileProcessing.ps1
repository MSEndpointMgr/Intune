function Wait-IntuneWin32AppFileProcessing {
    <#
    .SYNOPSIS
        Wait for contentVersions/files resource processing.

    .DESCRIPTION
        Wait for contentVersions/files resource processing.

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
        [string]$Stage,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Resource
    )
    do {
        $GraphRequest = Invoke-IntuneGraphRequest -APIVersion "Beta" -Resource $Resource -Method "GET"
        switch ($GraphRequest.uploadState) {
            "$($Stage)Pending" {
                Write-Verbose -Message "Intune service request for operation '$($Stage)' is in pending state, sleeping for 10 seconds"
                Start-Sleep -Seconds 10
            }
            "$($Stage)Failed" {
                Write-Warning -Message "Intune service request for operation '$($Stage)' failed"
                return $GraphRequest
            }
            "$($Stage)TimedOut" {
                Write-Warning -Message "Intune service request for operation '$($Stage)' timed out"
                return $GraphRequest
            }
        }
    }
    until ($GraphRequest.uploadState -like "$($Stage)Success")
    Write-Verbose -Message "Intune service request for operation '$($Stage)' was successful with uploadState: $($GraphRequest.uploadState)"

    return $GraphRequest
}