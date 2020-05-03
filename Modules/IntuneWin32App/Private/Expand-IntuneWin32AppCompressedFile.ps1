function Expand-IntuneWin32AppCompressedFile {
    <#
    .SYNOPSIS
        Expands a named file from inside the packaged Win32 application .intunewin file to a directory named as input from FolderName parameter.

    .DESCRIPTION
        Expands a named file from inside the packaged Win32 application .intunewin file to a directory named as input from FolderName parameter.

    .PARAMETER FilePath
        Specify an existing local path to where the win32 app .intunewin file is located.

    .PARAMETER FileName
        Specify the file name inside of the Win32 app .intunewin file to be expanded.

    .PARAMETER FolderName
        Specify the name of the extraction folder.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify an existing local path to where the win32 app .intunewin file is located.")]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^[A-Za-z]{1}:\\\w+\\\w+")]
        [ValidateScript({
            # Check if path contains any invalid characters
            if ((Split-Path -Path $_ -Leaf).IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
                Write-Warning -Message "$(Split-Path -Path $_ -Leaf) contains invalid characters"; break
            }
            else {
            # Check if file extension is intunewin
                if ([System.IO.Path]::GetExtension((Split-Path -Path $_ -Leaf)) -like ".intunewin") {
                    return $true
                }
                else {
                    Write-Warning -Message "$(Split-Path -Path $_ -Leaf) contains unsupported file extension. Supported extension is '.intunewin'"; break
                }
            }
        })]
        [string]$FilePath,

        [parameter(Mandatory = $true, HelpMessage = "Specify the file name inside of the Win32 app .intunewin file to be expanded.")]
        [ValidateNotNullOrEmpty()]
        [string]$FileName,

        [parameter(Mandatory = $true, HelpMessage = "Specify the name of the extraction folder.")]
        [ValidateNotNullOrEmpty()]
        [string]$FolderName
    )
    Begin {
        # Load System.IO.Compression assembly for managing compressed files
        try {
            $ClassImport = Add-Type -AssemblyName "System.IO.Compression.FileSystem" -ErrorAction Stop -Verbose:$false
        }
        catch [System.Exception] {
            Write-Warning -Message "An error occurred while loading System.IO.Compression.FileSystem assembly. Error message: $($_.Exception.Message)"; break
        }
    }
    Process {
        try {
            # Attemp to open compressed .intunewin archive file from parameter input
            $IntuneWin32AppFile = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
    
            # Construct extraction directory in the same location of the .intunewin file
            $ExtractionFolderPath = Join-Path -Path (Split-Path -Path $FilePath -Parent) -ChildPath $FolderName
            if (-not(Test-Path -Path ($ExtractionFolderPath))) {
                New-Item -Path $ExtractionFolderPath -ItemType Directory -Force | Out-Null
            }

            # Attempt to extract named file from .intunewin file
            try {
                if ($IntuneWin32AppFile -ne $null) {
                    # Determine the detection.xml file inside zip archive
                    $IntuneWin32AppFile.Entries | Where-Object { $_.Name -like $FileName } | ForEach-Object {
                        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, (Join-Path -Path $ExtractionFolderPath -ChildPath $FileName), $true)
                    }
                    $IntuneWin32AppFile.Dispose()
    
                    # Handle return value with XML content from detection.xml
                    return (Join-Path -Path $ExtractionFolderPath -ChildPath $FileName)
                }
            }
            catch [System.Exception] {
                Write-Warning -Message "An error occurred while extracing '$($FileName)' from '$($FilePath)' file. Error message: $($_.Exception.Message)"
            }
        }
        catch [System.Exception] {
            Write-Warning -Message "An error occurred while attempting to open compressed '$($FilePath)' file. Error message: $($_.Exception.Message)"
        }
    }
}