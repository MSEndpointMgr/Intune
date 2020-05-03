function Invoke-AzureStorageBlobUploadRenew {
    <#
    .SYNOPSIS
        Renew the SAS URI.

    .DESCRIPTION
        Renew the SAS URI.

        This is a modified function that was originally developed by Dave Falkus and is available here:
        https://github.com/microsoftgraph/powershell-intune-samples/blob/master/LOB_Application/Win32_Application_Add.ps1

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
        [string]$Resource
    )
    $RenewSASURIRequest = Invoke-IntuneGraphRequest -APIVersion "Beta" -Resource "$($Resource)/renewUpload" -Method "POST" -Body ""
    $FilesProcessingRequest = Wait-IntuneWin32AppFileProcessing -Stage "AzureStorageUriRenewal" -Resource $Resource
}