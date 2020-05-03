function Invoke-AzureStorageBlobUploadFinalize {
    <#
    .SYNOPSIS
        Finalize upload of chunks of the .intunewin file into Azure Storage blob container.

    .DESCRIPTION
        Finalize upload of chunks of the .intunewin file into Azure Storage blob container.

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
        [string]$StorageUri,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Object]$ChunkID
    )
    $Uri = "$($StorageUri)&comp=blocklist"
	$Request = "PUT $($Uri)"
	$XML = '<?xml version="1.0" encoding="utf-8"?><BlockList>'
	foreach ($Chunk in $ChunkID) {
		$XML += "<Latest>$($Chunk)</Latest>"
	}
	$XML += '</BlockList>'

	try {
		Invoke-RestMethod -Uri $Uri -Method "Put" -Body $XML -ErrorAction Stop
	}
	catch {
		Write-Warning -Message "Failed to finalize Azure Storage blob upload. Error message: $($_.Exception.Message)"
	}
}