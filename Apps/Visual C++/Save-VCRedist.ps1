<#
.SYNOPSIS
    Download Visual C++ Redistributable executables defined in the specified JSON master file.

.DESCRIPTION
    Download Visual C++ Redistributable executables defined in the specified JSON master file.
    All files will be downloaded into a folder named Source that will be created automatically in the executing directory of the script.

.PARAMETER URL
    Specify the Azure Storage blob URL where JSON file is accessible from.

.EXAMPLE
    # Download all Visual C++ Redistributable executables defined in a JSON file published at a given URL:
    .\Save-VCRedist.ps1 -URL "https://<AzureStorageBlobUrl>"

.NOTES
    FileName:    Save-VisualCRedist.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2020-02-05
    Updated:     2020-02-05

    Version history:
    1.0.0 - (2020-02-05) Script created
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [parameter(Mandatory = $false, HelpMessage = "Specify the Azure Storage blob URL where JSON file is accessible from.")]
    [ValidateNotNullOrEmpty()]
    [string]$URL = "https://<AzureStorageBlobUrl>"
)
Process {
    # Functions
    function Start-DownloadFile {
        param(
            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string]$URL,
    
            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string]$Path,
    
            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string]$Name
        )
        Begin {
            # Construct WebClient object
            $WebClient = New-Object -TypeName System.Net.WebClient
        }
        Process {
            # Create path if it doesn't exist
            if (-not(Test-Path -Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force | Out-Null
            }
    
            # Start download of file
            $WebClient.DownloadFile($URL, (Join-Path -Path $Path -ChildPath $Name))
        }
        End {
            # Dispose of the WebClient object
            $WebClient.Dispose()
        }
    }

    try {
        # Load JSON meta data from Azure Storage blob file    
        Write-Verbose -Message "Loading meta data from URL: $($URL)"
        $VcRedistMetaData = Invoke-RestMethod -Uri $URL -ErrorAction Stop
    }
    catch [System.Exception] {
        Write-Warning -Message "Failed to access JSON file. Error message: $($_.Exception.Message)"; break
    }

    # Set download path based on current working directory
    $DownloadRootPath = Join-Path -Path $PSScriptRoot -ChildPath "Source"    

    # Process each item from JSON meta data
    foreach ($VcRedistItem in $VcRedistMetaData.VCRedist) {
        Write-Verbose -Message "Processing item: $($VcRedistItem.DisplayName)"

        # Determine download path for current item
        $DownloadPath = Join-Path -Path $DownloadRootPath -ChildPath (Join-Path -Path $VcRedistItem.Version -ChildPath $VcRedistItem.Architecture)
        Write-Verbose -Message "Determined download path for current item: $($DownloadPath)"

        # Create download path if it doesn't exist
        if (-not(Test-Path -Path $DownloadPath)) {
            New-Item -Path $DownloadPath -ItemType Directory -Force | Out-Null
        }

        # Start download of current item
        Start-DownloadFile -Path $DownloadPath -URL $VcRedistItem.URL -Name $VcRedistItem.FileName
        Write-Verbose -Message "Successfully downloaded: $($VcRedistItem.DisplayName)"
    }
}