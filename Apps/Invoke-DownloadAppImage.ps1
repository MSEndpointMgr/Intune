<#
.SYNOPSIS
    Download an app image for a specific app in the App Store.

.DESCRIPTION
    This script can download the app image for a specific app available in the App Store.

.PARAMETER AppName
    Specify the app name to search for within the App Store.

.PARAMETER Path
    Path to a folder where the app image will be downloaded to.

.EXAMPLE
    Download the app image from 'Microsoft Word' app in the App Store:
    .\Invoke-DownloadAppImage.ps1 -AppName "Microsoft Word" -Path "C:\Temp"

.NOTES
    Script name: Invoke-DownloadAppImage.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2016-03-17
    Updated:     N/A
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [parameter(Mandatory=$true, ParameterSetName="AppName", HelpMessage="Specify the app name to search for within the App Store.")]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern("^[A-Za-z\s]*$")]
    [string]$AppName,

    [parameter(Mandatory=$true, ParameterSetName="Url", HelpMessage="Specify the URL pointing to the app in the App Store.")]
    [ValidateNotNullOrEmpty()]
    [string]$URL,

    [parameter(Mandatory=$true, ParameterSetName="AppName", HelpMessage="Path to a folder where the app image will be downloaded to.")]
    [parameter(Mandatory=$true, ParameterSetName="Url")]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern("^[A-Za-z]{1}:\\\w+")]
    [ValidateScript({
	    # Check if path contains any invalid characters
	    if ((Split-Path -Path $_ -Leaf).IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
		    Throw "$(Split-Path -Path $_ -Leaf) contains invalid characters"
	    }
	    else {
		    # Check if the whole path exists
		    if (Test-Path -Path $_ -PathType Container) {
				    return $true
		    }
		    else {
			    Throw "Unable to locate part of or the whole specified path, specify a valid path"
		    }
	    }
    })]
    [string]$Path
)
Process {
    # Amend app name for usage in search url
    $StoreAppName = ($AppName -replace " ", "+").ToLower()

    switch ($PSCmdlet.ParameterSetName) {
        "AppName" {
            # Invoke web request to get unique app link
            $SearchURL = "https://itunes.apple.com/search?term=$($StoreAppName)&entity=software&limit=1"
            $SearchWebRequest = Invoke-WebRequest -Uri $SearchURL
            $AppLink = (ConvertFrom-Json -InputObject $SearchWebRequest).Results | Select-Object -ExpandProperty trackViewUrl
        }
        "Url" {
            $AppLink = $URL
        }
    }

    # Invoke web request to get app image information
    if ($AppLink -ne $null) {
        $WebRequest = Invoke-WebRequest -Uri $AppLink
        $AppIcon = $WebRequest.Images | Where-Object { ($_.Width -eq 175) -and ($_.Class -like "artwork") }
        if ($AppIcon -ne $null) {
            # Download app image to specified path
            $WebClient = New-Object System.Net.WebClient
            $WebClient.DownloadFile($AppIcon."src-swap", "$($Path)\$($AppIcon.alt).jpg")
            $AppImage = [PSCustomObject]@{
                ImageName = $AppIcon.alt
                ImagePath = "$($Path)\$($AppIcon.alt).jpg"
            }
            Write-Output -InputObject $AppImage
        }
    }
    else {
        Write-Warning -Message "Unable to determine app link for specified app: $($AppName)"
    }
}
End {
    # Dispose of the WebClient object
    $WebClient.Dispose()
}