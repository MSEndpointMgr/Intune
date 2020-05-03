function Invoke-AzureStorageBlobUpload {
    <#
    .SYNOPSIS
        Upload and commit .intunewin file into Azure Storage blob container.

    .DESCRIPTION
        Upload and commit .intunewin file into Azure Storage blob container.

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
        [string]$FilePath,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Resource
    )
    $ChunkSizeInBytes = 1024l * 1024l * 6l;

    # Start the timer for SAS URI renewal
    $SASRenewalTimer = [System.Diagnostics.Stopwatch]::StartNew()

    # Find the file size and open the file
    $FileSize = (Get-Item -Path $FilePath).Length
    $ChunkCount = [System.Math]::Ceiling($FileSize / $ChunkSizeInBytes)
    $BinaryReader = New-Object -TypeName System.IO.BinaryReader([System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open))
    $Position = $BinaryReader.BaseStream.Seek(0, [System.IO.SeekOrigin]::Begin)

    # Upload each chunk. Check whether a SAS URI renewal is required after each chunk is uploaded and renew if needed
    $ChunkIDs = @()
    for ($Chunk = 0; $Chunk -lt $ChunkCount; $Chunk++) {
        $ChunkID = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($Chunk.ToString("0000")))
        $ChunkIDs += $ChunkID
        $Start = $Chunk * $ChunkSizeInBytes
        $Length = [System.Math]::Min($ChunkSizeInBytes, $FileSize - $Start)
        $Bytes = $BinaryReader.ReadBytes($Length)
        $CurrentChunk = $Chunk + 1

        Write-Progress -Activity "Uploading File to Azure Storage blob" -Status "Uploading chunk $CurrentChunk of $ChunkCount" -PercentComplete ($CurrentChunk / $ChunkCount * 100)
        $UploadResponse = Invoke-AzureStorageBlobUploadChunk -StorageUri $StorageUri -ChunkID $ChunkID -Bytes $Bytes
        if (($CurrentChunk -lt $ChunkCount) -and ($SASRenewalTimer.ElapsedMilliseconds -ge 450000)) {
            Invoke-AzureStorageBlobUploadRenew -Resource $Resource
            $SASRenewalTimer.Restart()
        }
    }

    # Complete write status progress bar
    Write-Progress -Completed -Activity "Uploading File to Azure Storage blob"

    # Finalize the upload of the content file to Azure Storage blob
    Invoke-AzureStorageBlobUploadFinalize -StorageUri $StorageUri -ChunkID $ChunkIDs

    # Close and dispose binary reader object
    $BinaryReader.Close()
    $BinaryReader.Dispose()
}