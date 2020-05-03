function Invoke-AzureStorageBlobUploadChunk {
    <#
    .SYNOPSIS
        Upload a chunk of the .intunewin file into Azure Storage blob container.

    .DESCRIPTION
        Upload a chunk of the .intunewin file into Azure Storage blob container.

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
        [System.Object]$ChunkID,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Object]$Bytes
    )
	$Uri = "$($StorageUri)&comp=block&blockid=$($ChunkID)"
	$Request = "PUT $($Uri)"
	$ISOEncoding = [System.Text.Encoding]::GetEncoding("iso-8859-1")
	$EncodedBytes = $ISOEncoding.GetString($Bytes)
	$Headers = @{
		"x-ms-blob-type" = "BlockBlob"
	}

	try	{
		$WebResponse = Invoke-WebRequest $Uri -Method "Put" -Headers $Headers -Body $EncodedBytes
	}
	catch {
        Write-Warning -Message "Failed to upload chunk to Azure Storage blob. Error message: $($_.Exception.Message)"
	} 
}