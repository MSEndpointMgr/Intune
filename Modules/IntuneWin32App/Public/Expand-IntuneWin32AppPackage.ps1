function Expand-IntuneWin32AppPackage {
    <#
    .SYNOPSIS
        Decode an existing .intunewin file already packaged as a Win32 application and allow it's contents to be extracted.

    .DESCRIPTION
        Decode an existing .intunewin file already packaged as a Win32 application and allow it's contents to be extracted.

    .PARAMETER FilePath
        Specify the full path of the locally available packaged Win32 application, e.g. 'C:\Temp\AppName.intunewin'.

    .PARAMETER Force
        Specify parameter to overwrite existing files already in working directory.

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
        [parameter(Mandatory = $true, HelpMessage = "Specify the full path of the locally available packaged Win32 application, e.g. 'C:\Temp\AppName.intunewin'.")]
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

        [parameter(Mandatory = $false, HelpMessage = "Specify parameter to overwrite existing files already in working directory.")]
        [switch]$Force
    )
    Begin {
        # Load System.IO.Compression assembly for managing compressed files
        try {
            $ClassImport = Add-Type -AssemblyName "System.IO.Compression.FileSystem" -ErrorAction Stop -Verbose:$false
        }
        catch [System.Exception] {
            Write-Warning -Message "An error occurred while loading System.IO.Compression.FileSystem assembly. Error message: $($_.Exception.Message)"; break
        }

        # Set script variable for error action preference
        $ErrorActionPreference = "Stop"        
    }
    Process {
        if (Test-Path -Path $FilePath) {
            try {
                # Read Win32 app meta data
                Write-Verbose -Message "Attempting to gather required Win32 app meta data from file: $($FilePath)"
                $IntuneWinMetaData = Get-IntuneWin32AppMetaData -FilePath $FilePath -ErrorAction Stop
                if ($IntuneWinMetaData -ne $null) {
                    # Retrieve Base64 encoded encryption key
                    $Base64Key = $IntuneWinMetaData.ApplicationInfo.EncryptionInfo.EncryptionKey
                    Write-Verbose -Message "Found Base64 encoded encryption key from meta data: $($Base64Key)"

                    # Retrieve Base64 encoded initialization vector
                    $Base64IV = $IntuneWinMetaData.ApplicationInfo.EncryptionInfo.InitializationVector
                    Write-Verbose -Message "Found Base64 encoded initialization vector from meta data: $($Base64IV)"

                    try {
                        # Extract encoded .intunewin from Contents folder
                        Write-Verbose -Message "Attempting to extract encoded .intunewin file from inside Contents folder of the Win32 application package"
                        $ExtractedIntuneWinFile = $FilePath + ".extracted"
                        $ZipFile = [System.IO.Compression.ZipFile]::OpenRead($IntuneWinFile)
                        $IntuneWinFileName = Split-Path -Path $FilePath -Leaf
                        $ZipFile.Entries | Where-Object { $_.Name -like $IntuneWinFileName } | ForEach-Object {
                            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, $ExtractedIntuneWinFile, $true)
                        }

                        # Dispose of ZipFile from memory
                        $ZipFile.Dispose()

                        try {
                            # Convert Base64 encryption info to bytes
                            Write-Verbose -Message "Attempting to convert Base64 encoded encryption key and initialization vector secure strings"
                            $Key = [System.Convert]::FromBase64String($Base64Key)
                            $IV = [System.Convert]::FromBase64String($Base64IV)

                            try {
                                # Open target filestream for read/write
                                $TargetFilePath = $FilePath + ".decoded"
                                $TargetFilePathName = Split-Path -Path $TargetFilePath -Leaf
                                if (Test-Path -Path $TargetFilePath) {
                                    if ($PSBoundParameters["Force"]) {
                                        try {
                                            Remove-Item -Path $TargetFilePath -Force -ErrorAction Stop
                                        }
                                        catch [System.Exception] {
                                            Write-Warning -Message "An error occurred while removing existing decoded file: $($TargetFilePathName). Error message: $($_.Exception.Message)"; break
                                        }
                                    }
                                    else {
                                        Write-Warning -Message "Existing file '$($TargetFilePathName)' already exists, use Force parameter to overwrite"; break
                                    }
                                }

                                Write-Verbose -Message "Attempting to create a new decoded .intunewin file: $($TargetFilePath)"
                                [System.IO.FileStream]$FileStreamTarget = [System.IO.File]::Open($TargetFilePath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)

                                try {
                                    # Create AES decryptor
                                    Write-Verbose -Message "Attempting to construct new AES decryptor with encryption key and initialization vector"
                                    $AES = [System.Security.Cryptography.Aes]::Create()
                                    [System.Security.Cryptography.ICryptoTransform]$Decryptor = $AES.CreateDecryptor($Key, $IV)

                                    try {
                                        # Open source filestream for read-only
                                        Write-Verbose -Message "Attepmting to open extracted .intunewin file: $($ExtractedIntuneWinFile)"
                                        [System.IO.FileStream]$FileStreamSource = [System.IO.File]::Open($ExtractedIntuneWinFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
                                        $FileStreamSourceSeek = $FileStreamSource.Seek(48l, [System.IO.SeekOrigin]::Begin)

                                        try {
                                            # Construct new CryptoStream
                                            Write-Verbose -Message "Attempting to create CryptoStream and write decoded chunks of data to file: $($TargetFilePath)"
                                            [System.Security.Cryptography.CryptoStream]$CryptoStream = New-Object -TypeName System.Security.Cryptography.CryptoStream -ArgumentList @($FileStreamTarget, $Decryptor, [System.Security.Cryptography.CryptoStreamMode]::Write) -ErrorAction Stop

                                            # Write all chunks of data to decoded target file
                                            $buffer = New-Object byte[](2097152)
                                            while ($BytesRead = $FileStreamSource.Read($buffer, 0, 2097152)) {
                                                $CryptoStream.Write($buffer, 0, $BytesRead)
                                                $CryptoStream.Flush()
                                            }

                                            # Flush final block in cryptostream
                                            $CryptoStream.FlushFinalBlock()
                                            Write-Verbose -Message "Successfully decoded '$($IntuneWinFileName)' Win32 app package file to: $($TargetFilePath)"
                                        }
                                        catch [System.Exception] {
                                            Write-Warning -Message "An error occurred while creating a CryptoStream and writing decoded chunks of data to file: $($TargetFilePath). Error message: $($_.Exception.Message)"
                                        }
                                    }
                                    catch [System.Exception] {
                                        Write-Warning -Message "An error occurred while opening extracted .intunewin file '$($ExtractedIntuneWinFile)'. Error message: $($_.Exception.Message)"
                                    }
                                }
                                catch [System.Exception] {
                                    Write-Warning -Message "An error occurred while creating AES decryptor. Error message: $($_.Exception.Message)"
                                }
                            }
                            catch [System.Exception] {
                                Write-Warning -Message "An error occurred while creating a new decoded .intunewin file: $($TargetFilePath). Error message: $($_.Exception.Message)"
                            }
                        }
                        catch [System.Exception] {
                            Write-Warning -Message "An error occurred while converting Base64 encoded encryption key and initialization vector secure strings. Error message: $($_.Exception.Message)"
                        }
                    }
                    catch [System.Exception] {
                        Write-Warning -Message "An error occurred while extracing encoded .intunewin file from inside Contents folder of the Win32 application package. Error message: $($_.Exception.Message)"
                    }
                }
            }
            catch [System.Exception] {
                Write-Warning -Message "An error occurred while gathering Win32 app meta data. Error message: $($_.Exception.Message)"
            }
        }
        else {
            Write-Warning -Message "Unable to locate specified .intunewin file"
        }
    }
    End {
        # Dispose of objects and release locks
        if ($CryptoStream -ne $null) {
            $CryptoStream.Dispose()
        }
        if ($FileStreamSource -ne $null) {
            $FileStreamSource.Dispose()
        }
        if ($Decryptor -ne $null) {
            $Decryptor.Dispose()
        }
        if ($FileStreamTarget -ne $null) {
            $FileStreamTarget.Dispose()
        }
        if ($AES -ne $null) {
            $AES.Dispose()
        }

        # Remove extracted intunewin file
        if (Test-Path -Path $ExtractedIntuneWinFile) {
            Remove-Item -Path $ExtractedIntuneWinFile -Force
        }        
    }
}