<#
.Synopsis
Check information about the Intune MDM certificate and the associated OIDs.

Created on:   2024-09-16
Created by:   Ben Whitmore @MSEndpointMgr
Filename:     Get-MDMInformation.ps1

.Description
This script checks the local machine certificate store for certificates issued by the Microsoft Intune MDM Device CA.
It validates the certificate chain and checks if the private key is present and exportable.
The script also looks for specific OIDs in the certificate extensions and converts the byte arrays to GUIDs.
The output includes the certificate name, thumbprint, issuer, chain trust status, private key presence, private key exportability status and the reassembled GUIDs from the byte arrays.

---------------------------------------------------------------------------------
LEGAL DISCLAIMER

The PowerShell script provided is shared with the community as-is
The author and co-author(s) make no warranties or guarantees regarding its functionality, reliability, or suitability for any specific purpose
Please note that the script may need to be modified or adapted to fit your specific environment or requirements
It is recommended to thoroughly test the script in a non-production environment before using it in a live or critical system
The author and co-author(s) cannot be held responsible for any damages, losses, or adverse effects that may arise from the use of this script
You assume all risks and responsibilities associated with its usage
---------------------------------------------------------------------------------

.PARAMETER mdmIntermediateIssuer
The issuer of the mdm certificate. Default is 'CN=Microsoft Intune MDM Device CA'.

.PARAMETER mdmRootIssuer
The issuer of the mdm root certificate. Default is 'CN=Microsoft Intune Root Certification Authority'.

.EXAMPLE
.\Get-MDMInformation.ps1

#>
param (
    [string]$mdmIntermediateIssuer = 'CN=Microsoft Intune MDM Device CA',
    [string]$mdmRootIssuer = 'CN=Microsoft Intune Root Certification Authority'
)

# Function to validate if the certificate chain is valid and from the correct issuer
function Test-CertificateIssuer {
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert,
        [string]$expectedIntermediateIssuer,
        [string]$expectedRootIssuer
    )

    # Create a new instance of the x509Chain class to build and validate the certificate chain
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck # Disable revocation check

    if ($chain.Build($cert)) {
    
        # Store variables for the intermediate and root certificate validation
        $intermediateIssuerValid = $false
        $rootIssuerValid = $false

        # Validate each certificate in the chain
        foreach ($element in $chain.ChainElements) {
            $subject = $element.Certificate.Subject
            $issuer = $element.Certificate.Issuer

            # Check if the certificate is the root certificate (self-signed)
            if ($subject -eq $issuer) {

                # Validate the root certificate issuer
                if ($issuer -eq $expectedRootIssuer) {
                    $rootIssuerValid = $true
                }
            }
            elseif ($issuer -eq $expectedIntermediateIssuer) {

                # Validate the intermediate issuer
                $intermediateIssuerValid = $true
            }
        }

        # Return true only if both the intermediate and root issuers are valid
        return $intermediateIssuerValid -and $rootIssuerValid
    }
    else {
        return $false
    }
}

# Function to check if the current user is an administrator
function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Combined function to check private key exportability and get KSP, including TPM detection
function Get-PrivateKeyInfo {
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert
    )

    if (Test-IsAdmin) {
        # Test if the private key is exportable
        try {
            $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $null)
            $isExportable = $true
        }
        catch {
            $isExportable = $false
        }

        # Use Start-Process to run certutil and capture only the provider information. Certutil is more reliable than the .NET classes for this information.
        try {
            $certUtilOutput = & certutil.exe -store my $cert.Thumbprint | Select-String -Pattern 'Provider'

            # Extract the provider value from the output and clean it
            $provider = $certUtilOutput -replace 'Provider\s*=\s*', '' -replace '^\s+', ''

            # Store provider in variable
            $ksp = $provider
        }
        catch {
            $ksp = ("Error retrieving KSP: {0}" -f $_)
        }
    }
    else {
        $isExportable = 'Insufficient privileges to test (Requires Admin)'
        $ksp = 'Insufficient privileges to test (Requires Admin)'
    }

    return [PSCustomObject]@{
        Exportable = $isExportable
        KspName    = $ksp
    }
}

function Convert-BitStringToGuid {
    param (
        [byte[]]$bitstring,
        [string]$oid
    )
    
    # Convert the byte array to a hexadecimal string
    $hexString = [System.BitConverter]::ToString($bitstring)

    # Split the string into individual hex pairs
    $hexArray = $hexString.Split('-')

    # Reorder the array based on the OID
    if ($oid -eq '1.2.840.113556.5.4') {

        # Intune MDM Device ID (4-byte little-endian, 2-byte little-endian, 2-byte little-endian, 2-byte little-endian, rest big-endian)
        $guidArray = @(
            $hexArray[3], $hexArray[2], $hexArray[1], $hexArray[0], '-'
            $hexArray[5], $hexArray[4], '-'
            $hexArray[7], $hexArray[6], '-'
            $hexArray[8], $hexArray[9], '-'
            $hexArray[10..15]
        )
    }
    elseif ($oid -eq '1.2.840.113556.5.14') {

        # Entra ID Tenant ID (4-byte little-endian, 2-byte little-endian, 2-byte little-endian, 2-byte big-endian, rest big-endian)
        $guidArray = @(
            $hexArray[5], $hexArray[4], $hexArray[3], $hexArray[2], '-'
            $hexArray[7], $hexArray[6], '-'
            $hexArray[9], $hexArray[8], '-'
            $hexArray[10], $hexArray[11], '-'
            $hexArray[12..17]
        )
    }

    # Join the array and return the formatted GUID
    return $guidArray -join ''
}

# Convert byte array to hexadecimal string
function ConvertToHexString($byteArray) {
    return ($byteArray | ForEach-Object { $_.ToString('x2') }) -join ' '
}

# Open the LocalMachine certificate store (or User store - sometimes the MDM certificate is located here depending on the enrollment method)
$x509Store = New-Object System.Security.Cryptography.X509Certificates.X509Store([System.Security.Cryptography.X509Certificates.StoreName]::My, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
$x509Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

# Initialize array to hold the results
$certResults = @()

# Loop through certificates and check the criteria
foreach ($cert in $x509Store.Certificates) {

    # Only process if the certificate issuer is correct
    if ($cert.Issuer -eq $mdmIntermediateIssuer) {

        # Is the private key present?
        $hasPrivateKey = $cert.HasPrivateKey

        # Retrieve private key exportability and KSP information
        $privateKeyInfo = Get-PrivateKeyInfo -cert $cert

        # Validate the chain and check the issuer
        $chainTrusted = Test-CertificateIssuer -cert $cert -expectedIntermediateIssuer $mdmIntermediateIssuer -expectedRootIssuer $mdmRootIssuer

        # Variables to hold OID data
        $mdmDeviceIdBitString = $null
        $entraTenantIdBitString = $null
        $mdmDeviceIdGuid = $null
        $entraTenantIdGuid = $null
        $mdmCertOidBitString = $null
        $mdmCertOidHex = $null

        # Loop through extensions to find the specific OIDs
        foreach ($extension in $cert.Extensions) {
            if ($extension.Oid.Value -eq '1.2.840.113556.5.4') {

                # OID for Intune MDM Device ID
                $mdmDeviceIdBitString = $extension.RawData
                $mdmDeviceIdGuid = Convert-BitStringToGuid -bitstring $mdmDeviceIdBitString -oid $extension.Oid.Value
            }
            elseif ($extension.Oid.Value -eq '1.2.840.113556.5.14') {

                # OID for Entra Tenant ID
                $entraTenantIdBitString = $extension.RawData
                $entraTenantIdGuid = Convert-BitStringToGuid -bitstring $entraTenantIdBitString -oid $extension.Oid.Value
            }
            elseif ($extension.Oid.Value -eq '1.2.840.113556.5.6') {

                # OID for MDM certificate
                $mdmCertOidBitString = $extension.RawData
                $mdmCertOid = 'This is an MDM certificate'
                $mdmCertOidFound = $true
            }
        }

        # Create an object for the certificate details
        $certObject = [PSCustomObject]@{
            CertificateName                              = $cert.Subject
            CertificateThumbprint                        = $cert.Thumbprint
            CertificateIssuer                            = $cert.Issuer
            CertificateChainTrusted                      = $chainTrusted
            PrivateKeyPresent                            = $hasPrivateKey
            PrivateKeyExportable                         = $privateKeyInfo.Exportable
            KeyStorageProvider                           = $privateKeyInfo.KspName
            IntuneMDMDeviceIDOID_1_2_840_113556_5_4      = if ($mdmDeviceIdBitString) { ConvertToHexString $mdmDeviceIdBitString } else { 'Not Found' }
            IntuneMDMDeviceIDReassembled                 = if ($mdmDeviceIdGuid) { $mdmDeviceIdGuid } else { 'Not Found' }
            EntraTenantIDOID_1_2_840_113556_5_14         = if ($entraTenantIdBitString) { ConvertToHexString $entraTenantIdBitString } else { 'Not Found' }
            EntraTenantIDReassembled                     = if ($entraTenantIdGuid) { $entraTenantIdGuid } else { 'Not Found' }
            MDMCertOID_1_2_840_113556_5_6                = if ($mdmCertOidFound) { $mdmCertOid } else { 'This is not a valid MDM certificate' }
        }

        # Add object to results array
        $certResults += $certObject
    }
}

# Output the array of certificate details
return $certResults

# Close the store when done
$x509Store.Close()
