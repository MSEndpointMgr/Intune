<#
.SYNOPSIS
    Search the iTunes or Google Play stores for the app links

.DESCRIPTION
    This script can search for any app available in either iTunes or Google Play store

.PARAMETER Store
    Specify which Store to search within

.PARAMETER AppName
    Specify the app name to search for within the Store

.PARAMETER Limit
    Limit search results to the specified number (only valid for iTunes Store)

.EXAMPLE
    .\Get-StoreAppInformation.ps1 -Store iTunes -AppName "Microsoft Word" -Limit 1

.NOTES
    FileName:    Get-StoreAppInformation.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2015-08-19
    Updated:     2019-05-14

    Version history:
    1.0.0 - (2015-08-19) Script created    
    1.0.1 - (2019-05-14) Added BundleId property returned from store search
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [parameter(Mandatory=$true, HelpMessage="Specify which Store to search within")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("iTunes","GooglePlay")]
    [string]$Store,

    [parameter(Mandatory=$true, HelpMessage="Specify the app name to search for within the Store")]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern("^[A-Za-z\s]*$")]
    [string]$AppName,

    [parameter(Mandatory=$false, HelpMessage="Limit search results to the specified number (only valid for iTunes Store)")]
    [ValidateNotNullOrEmpty()]
    [string]$Limit = "1"
)
Begin {
    # Construct URL determined on parameter input
    switch ($Store) {
        "iTunes" { 
            $StoreAppName = ($AppName -replace " ", "+").ToLower()
            $SearchURL = "https://itunes.apple.com/search?"
            $URL = $SearchURL + "term=$($StoreAppName)" + "&entity=software&limit=$($Limit)"
        }
        "GooglePlay" {
            $StoreAppName = ($AppName -replace " ", "%20").ToLower()
            $SearchURL = "https://play.google.com/store/search?"
            $URL = $SearchURL + "q=$($StoreAppName)&c=apps&hl=en"
        }
    }
}
Process {
    # Search in selected Store for app information
    switch ($Store) {
        "iTunes" { 
            $WebRequest = Invoke-WebRequest -Uri $URL
            $WebRequestObject = ConvertFrom-Json -InputObject $WebRequest
            if ($WebRequestObject.Results -ne $null) {
                foreach ($Object in $WebRequestObject.Results) {
                    $PSObject = [PSCustomObject]@{
                        "AppName" = $Object.trackCensoredName
                        "StoreLink" = $Object.trackViewUrl
                        "BundleId" = $Object.bundleId
                    }
                    Write-Output -InputObject $PSObject
                }
            }
        }
        "GooglePlay" {
            $WebRequest = Invoke-WebRequest -Uri $URL
            $WebRequestObject = $WebRequest.Links | Where-Object { $_.innerText -like "*$($AppName)*" }
            if ($WebRequestObject -ne $null) {
                foreach ($Object in $WebRequestObject) {
                    $PSObject = [PSCustomObject]@{
                        "AppName" = $Object.innerText
                        "StoreLink" = "https://play.google.com" + $Object.href
                        "BundleId" = ($Object.href).Split("=")[1]
                    }
                    Write-Output -InputObject $PSObject
                }
            }
        }
    }
}