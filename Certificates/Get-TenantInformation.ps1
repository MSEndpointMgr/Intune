<#
.Synopsis
Check information on the MDM and EntraID certificate using the associated OIDs.

Created on:   2024-09-16
Created by:   Ben Whitmore @MSEndpointMgr
Thanks to:    Bryan Dam @PatchMyPC
Filename:     Get-TenantInformation.ps1

.Description
This script performs an extensive check on certificates issued by the MDM Device CA and EntraID, by searching across all user profiles as well as the LocalMachine\My certificate store. It retrieves and validates the certificates associated with MDM and EntraID using their respective OIDs (Object Identifiers).

The script performs the following tasks:
1. **Certificate Search**:
   - It first checks the **LocalMachine\My** store for the certificates issued by the MDM Device CA or EntraID Intermediate Issuer.
   - If the certificates are not found in the LocalMachine store, it then checks the **user profile paths** (`C:\Users\<username>\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates`) for the certificates. (Including the SYSTEM profile)

2. **Certificate Validation**:
   - For each certificate, the script checks the **issuer** and **validates the certificate chain**. It ensures that the certificate is correctly signed by the expected intermediate and root authorities.
   - It checks if the certificate contains a **private key** and whether the private key is **exportable**.

3. **OID Processing**:
   - The script processes the **certificate extensions** to extract specific Object Identifiers (OIDs). It then converts the associated **byte arrays** to **GUIDs** for further validation.

4. **Output**:
   - For each matched certificate, the script outputs:
     - The **certificate name**, **thumbprint**, **issuer**, and the **trust status** of the certificate chain.
     - Whether the certificate contains a **private key** and if it is **exportable**.
     - The **Key Storage Provider (KSP)** name associated with the private key.
     - The **reassembled GUIDs** from specific OIDs found in the certificate extensions.

This script helps automate the process of verifying certificates from the MDM and EntraID, ensuring that both the certificates and their private keys are valid and properly configured, especially in environments with multiple user profiles.

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

.PARAMETER entraIDIntermediateIssuer
The issuer of the entraID certificate. Default is 'MS-Organization-Access'.

.PARAMETER certToCheck
The type of certificate to check. Default is 'Both'. Valid values are 'MDM', 'EntraID', 'Both'.

.PARAMETER mdmOids
A hashtable to define the OIDs for the MDM certificate.

.PARAMETER entraIDOids
A hashtable to define the OIDs for the EntraID certificate.

.EXAMPLE
.\Get-TenantInformation.ps1
#>

[CmdletBinding()]
param (
    [ValidateSet('MDM', 'EntraID', 'Both')]
    [string]$CertToCheck = 'Both',

    [string]$MDMIntermediateIssuer = 'CN=Microsoft Intune MDM Device CA',
    [string]$MDMRootIssuer = 'CN=Microsoft Intune Root Certification Authority',
    [string]$EntraIDIntermediateIssuer = 'MS-Organization-Access',

    # Hashtable to define OIDs for MDM and EntraID
    [Hashtable]$MDMOIDs = @{
        '1.2.840.113556.5.4'  = 'MDMDeviceID'
        '1.2.840.113556.5.6'  = 'MDMTenantID'
        '1.2.840.113556.5.14' = 'EntraTenantID'
    },
    [Hashtable]$EntraIDOIDs = @{
        '1.2.840.113556.1.5.284.2' = 'EntraDeviceID'
        '1.2.840.113556.1.5.284.3' = 'EntraDeviceID'
        '1.2.840.113556.1.5.284.5' = 'EntraTenantID'
        '1.2.840.113556.1.5.284.7' = 'EntraJoinType'
        '1.2.840.113556.1.5.284.8' = 'EntraTenantRegion'
    }
)

$VerbosePreference = 'Continue'

# Function to convert a byte array into a hexadecimal string
function ConvertToHexString($byteArray) {
    return ($byteArray | ForEach-Object { $_.ToString('x2') }) -join ' '
}

# Function to convert bitstring to GUID based on OID
function Convert-BitStringToGuid {
    param (
        [byte[]]$bitstring,
        [string]$oid
    )

    # Check if the bitstring is null or empty
    if (-not $bitstring) {
        Write-Verbose "The OID $oid has no value (bitstring is null or empty)."
        return "Null"
    }

    # Convert the byte array to a hexadecimal string
    $hexString = [System.BitConverter]::ToString($bitstring)

    # Split the string into individual hex pairs
    $hexArray = $hexString.Split('-')

    # Reorder the array based on the OID
    $guidArray = @()

    switch ($oid) {
        '1.2.840.113556.5.4' {

            # MDM Device ID (4-byte little-endian, 2-byte little-endian, 2-byte little-endian, rest big-endian)
            Write-Verbose "OID = MDM Device ID OID"
            Write-Verbose "Hex Array: $($hexArray -join '')"
            $guidArray = @(
                $hexArray[3], $hexArray[2], $hexArray[1], $hexArray[0], '-'
                $hexArray[5], $hexArray[4], '-'
                $hexArray[7], $hexArray[6], '-'
                $hexArray[8], $hexArray[9], '-'
                $hexArray[10..15]
            )
            Write-Verbose "Intune MDM Device ID: $($guidArray -join '')"
        }
        '1.2.840.113556.5.6' {

            # MDM Tenant ID (4-byte little-endian, 2-byte little-endian, 2-byte little-endian, rest big-endian)
            Write-Verbose "OID = MDM Tenant ID OID"
            Write-Verbose "Hex Array: $($hexArray -join '')"
            $guidArray = @(
                $hexArray[5], $hexArray[4], $hexArray[3], $hexArray[2], '-'
                $hexArray[7], $hexArray[6], '-'
                $hexArray[8], $hexArray[9], '-'
                $hexArray[10..15]
            )
            Write-Verbose "Intune Tenant ID: $($guidArray -join '')"
        }
        '1.2.840.113556.5.14' {

            # Entra ID Tenant ID (4-byte little-endian, 2-byte little-endian, 2-byte little-endian, rest big-endian)
            Write-Verbose "OID = Entra Tenant ID OID"
            Write-Verbose "Hex Array: $($hexArray -join '')"
            $guidArray = @(
                $hexArray[5], $hexArray[4], $hexArray[3], $hexArray[2], '-'
                $hexArray[7], $hexArray[6], '-'
                $hexArray[9], $hexArray[8], '-'
                $hexArray[10], $hexArray[11], '-'
                $hexArray[12..17]
            )
            Write-Verbose "Entra Tenant ID: $($guidArray -join '')"
        }
        { $_ -eq '1.2.840.113556.1.5.284.2' -or $_ -eq '1.2.840.113556.1.5.284.3' } {

            # Entra ID Device ID (4-byte little-endian, 2-byte little-endian, 2-byte little-endian, rest big-endian)
            Write-Verbose "OID = Entra Device ID OID"
            Write-Verbose "Hex Array: $($hexArray -join '')"
            $guidArray = @(
                $hexArray[6], $hexArray[5], $hexArray[4], $hexArray[3], '-'
                $hexArray[8], $hexArray[7], '-'
                $hexArray[10], $hexArray[9], '-'
                $hexArray[11], $hexArray[12], '-'
                $hexArray[13..18]
            )
            Write-Verbose "Entra Device ID: $($guidArray -join '')"
        }
        '1.2.840.113556.1.5.284.5' {

            # Entra ID Device ID (4-byte little-endian, 2-byte little-endian, 2-byte little-endian, rest big-endian)
            Write-Verbose "OID = Entra Tenant ID OID"
            Write-Verbose "Hex Array: $($hexArray -join '')"
            $guidArray = @(
                $hexArray[6], $hexArray[5], $hexArray[4], $hexArray[3], '-'
                $hexArray[8], $hexArray[7], '-'
                $hexArray[10], $hexArray[9], '-'
                $hexArray[11], $hexArray[12], '-'
                $hexArray[13..18]
            )
            Write-Verbose "Entra Tenant ID: $($guidArray -join '')"
        }
        '1.2.840.113556.1.5.284.7' {

            # Join Type (assumed to be a character representing the join type, we don't assemble a GUID here)
            $joinType = [char]([convert]::toint16($hexArray[3], 16))
            Write-Verbose "OID = Entra Join Type OID"
            Write-Verbose "Hex Array: $($hexArray -join '')"
            $guidArray = if ($joinType -eq '0') {
                Write-Verbose "Entra Registered `(0`)"
                "Entra Registered `(0`)"
            }
            elseif ($joinType -eq '1') {
                Write-Verbose "Entra Joined `(1`)"
                "Entra Joined `(1`)"
            }
            else {
                Write-Verbose "Unknown `($($joinType)`)"
                "Unknown `($($joinType)`)"
            }
        }
        '1.2.840.113556.1.5.284.8' {

            # Tenant Region (assumes two 2-byte little-endian values)
            Write-Verbose "OID = Entra Tenant Region OID"
            Write-Verbose "Hex Array: $($hexArray -join '')"
            $guidArray = [char]([convert]::toint16($hexArray[3], 16)), [char]([convert]::toint16($hexArray[4], 16))
            Write-Verbose "Entra Tenant Region: $($guidArray -join '')"
        }
        default {
            Write-Debug "Unknown OID: $oid"
        }
    }

    # Return the GUID as a string
    return $guidArray -join ''
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
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert,
        [string]$certFilePath  # Optional parameter for certificate file path (only used for user profile)
    )

    if (Test-IsAdmin) {

        # Test if the private key is exportable
        try {
            if ($cert) {
                
                # Test exportability for the certificate object
                $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $null)
                $isExportable = $true
            } else {
                $isExportable = $false
            }
        }
        catch {
            $isExportable = $false
        }

        # Use certutil if the certificate is from LocalMachine store
        if ($certFilePath) {
            try {
                # If it's a certificate file path (from user profile), use certutil on the file path
                $certUtilOutput = & certutil.exe -dump $certFilePath | Select-String -Pattern 'Provider'

                # Extract the provider value from the output and clean it
                $provider = $certUtilOutput -replace 'Provider\s*=\s*', '' -replace '^\s+', ''
                $ksp = $provider
            }
            catch {
                $ksp = ("Error retrieving KSP: {0}" -f $_)
            }
        }
        elseif ($cert) {
            # If it's from LocalMachine store, use certutil directly on the certificate object
            try {
                $certUtilOutput = & certutil.exe -store my $cert.Thumbprint | Select-String -Pattern 'Provider'

                # Extract the provider value from the output and clean it
                $provider = $certUtilOutput -replace 'Provider\s*=\s*', '' -replace '^\s+', ''
                $ksp = $provider
            }
            catch {
                $ksp = ("Error retrieving KSP: {0}" -f $_)
            }
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

# Function to get certificate file path or handle LocalMachine\My store
function Get-CertificateFilePath {
    param (
        [string]$thumbprint,
        [string]$profilePath
    )

    # First, check if the certificate exists in the user profile path
    $certFilePath = Join-Path -Path $profilePath -ChildPath "$thumbprint"

    if (Test-Path $certFilePath) {
        Write-Verbose "Certificate found in user profile path: $certFilePath"
        return $certFilePath
    }

    # If not found in user profile, check the LocalMachine\My store
    Write-Verbose "Certificate not found in user profile. Checking LocalMachine store."

    # Search for the certificate in the LocalMachine\My store by thumbprint
    $localMachineStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $localMachineStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

    # Get the certificate from LocalMachine store by thumbprint
    $cert = $localMachineStore.Certificates | Where-Object { $_.Thumbprint -eq $thumbprint }

    if ($cert) {
        Write-Verbose "Certificate found in LocalMachine store: $($cert[0].Subject)"
        return $cert[0]
    } else {
        Write-Error "Certificate with thumbprint $thumbprint not found in either user profile or LocalMachine store."
        return $null
    }
}

# Main function to retrieve and process certificates
function Get-CertificateInformation {
    param (
        [string]$MDMIntermediateIssuer,
        [string]$MDMRootIssuer,
        [string]$EntraIDIntermediateIssuer,
        [string]$CertToCheck,
        [Hashtable]$MDMOIDs,
        [Hashtable]$EntraIDOIDs
    )

    $certResults = @()

    # Check LocalMachine store first
    $certificateStore = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    Write-Verbose "`nChecking certificates in LocalMachine store"

    $localMachineStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", $certificateStore)
    $localMachineStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

    foreach ($cert in $localMachineStore.Certificates) {
        switch ($CertToCheck) {
            'Both' {

                # Process EntraID Certificate first
                if ($cert.Issuer.Contains($EntraIDIntermediateIssuer)) {
                    Write-Verbose "`nFound EntraID Certificate in the LocalMachine\My store"
                    Write-Verbose "Processing EntraID Certificate"
                    $certObject = Invoke-CertificateProcessing -cert $cert -EntraIDIntermediateIssuerCN $EntraIDIntermediateIssuer -CertificateTest "EntraID" -OidList $EntraIDOIDs -CertificateLocation "LocalMachine\My"
                    $certResults += $certObject
                }

                # Process MDM Certificate second
                if ($cert.Issuer.Contains($MDMIntermediateIssuer)) {
                    Write-Verbose "`nFound MDM Certificate in the LocalMachine\My store"
                    Write-Verbose "Processing MDM Certificate"
                    $certObject = Invoke-CertificateProcessing -cert $cert -MDMIntermediateIssuerCN $MDMIntermediateIssuer -MDMRootIssuer $MDMRootIssuer -CertificateTest "MDM" -OidList $MDMOIDs -CertificateLocation "LocalMachine\My"
                    $certResults += $certObject
                }
            }
            'MDM' {

                # Process MDM Certificate
                if ($cert.Issuer.Contains($MDMIntermediateIssuer)) {
                    Write-Verbose "`nFound MDM Certificate in the LocalMachine\My store"
                    Write-Verbose "Processing MDM Certificate"
                    $certObject = Invoke-CertificateProcessing -cert $cert -MDMIntermediateIssuerCN $MDMIntermediateIssuer -MDMRootIssuer $MDMRootIssuer -CertificateTest "MDM" -OidList $MDMOIDs -CertificateLocation "LocalMachine\My"
                    $certResults += $certObject
                }
            }
            'EntraID' {

                # Process EntraID Certificate
                if ($cert.Issuer.Contains($EntraIDIntermediateIssuer)) {
                    Write-Verbose "`nFound EntraID Certificate in the LocalMachine\My store"
                    Write-Verbose "Processing EntraID Certificate"
                    $certObject = Invoke-CertificateProcessing -cert $cert -EntraIDIntermediateIssuerCN $EntraIDIntermediateIssuer -CertificateTest "EntraID" -OidList $EntraIDOIDs -CertificateLocation "LocalMachine\My"
                    $certResults += $certObject
                }
            }
        }
    }
    $localMachineStore.Close()

    # Check User and SYSTEM store next if no certificates were found in LocalMachine
    if (-not $certResults) {

        # Define paths for User and System certificates
        $certPaths = @{}

        # Get all user profile directories, including only valid user profiles
        $userProfiles = Get-CIMInstance -ClassName Win32_UserProfile | Where-Object { (($_.LocalPath -like "C:\Users\*") -and $_.LocalPath -notlike "C:\Windows\ServiceProfiles\*") -or $_.LocalPath -eq 'C:\Windows\system32\config\systemprofile'
        }

        # Add user profile paths to the certPaths hashtable
        foreach ($userProfile in $userProfiles) {
            $certificatePath = Join-Path -Path $userProfile.LocalPath -ChildPath 'AppData\Roaming\Microsoft\SystemCertificates\My\Certificates'
    
            # Add the user profile path to the certPaths hashtable
            $certPaths["$certificatePath"] = $certificatePath
        }

        # Loop through User and System profiles for certificates
        foreach ($profile in $certPaths.GetEnumerator()) {
            $profileName = $profile.Key
            $profilePath = $profile.Value

            if (Test-Path $profilePath) {
                Write-Verbose "`nChecking certificates in $profileName profile ($profilePath)"

                $certFiles = Get-ChildItem -Path $profilePath
                foreach ($certFile in $certFiles) {
                    try {

                        # Attempt to load the certificate, regardless of extension
                        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certFile.FullName)

                        switch ($CertToCheck) {
                            'Both' {

                                # Process EntraID Certificate first
                                if ($cert.Issuer.Contains($EntraIDIntermediateIssuer)) {
                                    Write-Verbose "`nProcessing EntraID Certificate"
                                    Write-Verbose "`nFound EntraID Certificate in the $profileName store"
                                    $certObject = Invoke-CertificateProcessing -cert $cert -EntraIDIntermediateIssuerCN $EntraIDIntermediateIssuer -CertificateTest "EntraID" -CertificateType "File" -OidList $EntraIDOIDs -CertificateLocation $profileName
                                    $certResults += $certObject
                                }

                                # Process MDM Certificate second
                                if ($cert.Issuer.Contains($MDMIntermediateIssuer)) {
                                    Write-Verbose "`nProcessing MDM Certificate"
                                    Write-Verbose "`nFound MDM Certificate in the $profileName store"
                                    $certObject = Invoke-CertificateProcessing -cert $cert -expectedMDMIntermediateIssuerCN $MDMIntermediateIssuer -expectedMDMRootIssuer $MDMRootIssuer -CertificateTest "MDM" -CertificateType "File" -OidList $MDMOIDs -CertificateLocation $profileName
                                    $certResults += $certObject
                                }
                            }
                            'MDM' {

                                # Process MDM Certificate
                                if ($cert.Issuer.Contains($MDMIntermediateIssuer)) {
                                    Write-Verbose "`nProcessing MDM Certificate"
                                    Write-Verbose "`nFound MDM Certificate in the $profileName store"
                                    $certObject = Invoke-CertificateProcessing -cert $cert -expectedMDMIntermediateIssuerCN $MDMIntermediateIssuer -expectedMDMRootIssuer $MDMRootIssuer -CertificateTest "MDM" -CertificateType "File" -OidList $MDMOIDs -CertificateLocation $profileName
                                    $certResults += $certObject
                                }
                            }
                            'EntraID' {

                                # Process EntraID Certificate
                                if ($cert.Issuer.Contains($EntraIDIntermediateIssuer)) {
                                    Write-Verbose "`nProcessing EntraID Certificate"
                                    Write-Verbose "`nFound EntraID Certificate in the $profileName store"
                                    $certObject = Invoke-CertificateProcessing -cert $cert -EntraIDIntermediateIssuerCN $EntraIDIntermediateIssuer -CertificateTest "EntraID" -CertificateType "File" -OidList $EntraIDOIDs -CertificateLocation $profileName
                                    $certResults += $certObject
                                }
                            }
                        }
                    }
                    catch {
                        Write-Error $_.Exception.Message
                        Write-Verbose "Skipping invalid certificate file: $($certFile.Name)"
                    }
                }
            }
            else {
                Write-Verbose "`nThe directory $profilePath does not exist."
            }
        }
    }

    return $certResults
}

# Function to test the certificate issuer
function Test-CertificateIssuer {
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert,
        [string]$expectedIntermediateIssuer,
        [string]$expectedRootIssuer
    )

    # Create a new instance of the x509Chain class to build and validate the certificate chain
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck

    Write-Verbose "Building certificate chain for certificate: $($cert.Subject)"

    # Build the certificate chain
    if ($chain.Build($cert)) {
        Write-Verbose "Certificate chain successfully built."

        # Store variables for the intermediate and root certificate validation
        $intermediateIssuerValid = $false
        $rootIssuerValid = $false

        # Validate each certificate in the chain
        foreach ($element in $chain.ChainElements) {
            $subject = $element.Certificate.Subject
            $issuer = $element.Certificate.Issuer

            Write-Verbose "Checking chain element: Subject = $subject, Issuer = $issuer"

            # Check if the certificate is the root certificate (self-signed)
            if ($subject -eq $issuer) {
                Write-Verbose "This certificate is self-signed. Verifying if it's the root certificate."

                # If it's self-signed, it should be the root certificate
                if ($issuer -eq $expectedRootIssuer) {
                    Write-Verbose "Root certificate found and valid."
                    $rootIssuerValid = $true
                }
            }
            elseif ($issuer -eq $expectedIntermediateIssuer) {

                # Validate the intermediate issuer
                Write-Verbose "Intermediate certificate found and valid."
                $intermediateIssuerValid = $true
            }
            else {
                Write-Verbose "This certificate is neither the root nor the expected intermediate certificate."
            }
        }

        # If the certificate chain contains the intermediate and root issuer, return true
        if ($intermediateIssuerValid -and $rootIssuerValid) {
            Write-Verbose "Both intermediate and root certificates are valid. Certificate chain is valid."
            return $true
        }
        else {
            Write-Verbose "One or both of the intermediate and root certificates are invalid. Certificate chain is not valid."
            return $false
        }
    }
    else {

        # Return false if the chain validation fails
        Write-Verbose "Certificate chain could not be built or validated."
        return $false
    }
}

# Function to process certificates
function Invoke-CertificateProcessing {
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert,
        [string]$MDMIntermediateIssuerCN,
        [string]$MDMRootIssuer,
        [string]$EntraIDIntermediateIssuerCN,
        [string]$CertificateLocation,
        [string]$CertificateTest,
        [hashtable]$OidList,
        [string]$Certificate
    )

    Write-Verbose "Processing $CertificateTest Certificate"

    $properties = [ordered] @{
        CertificateTest       = $CertificateTest
        CertificateLocation   = $CertificateLocation
        CertificateName       = $cert.Subject
        CertificateThumbprint = $cert.Thumbprint
        CertificateIssuer     = $cert.Issuer
    }

    # Initialize a chain object and build the certificate chain
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.Build($cert) | Out-Null

    # Check if the certificate chain is longer than just the cert itself
    $certChainPresent = $false

    if ($chain.ChainElements.Count -gt 1) {
        $certChainPresent = $true
        Write-Verbose "Certificate chain found on the device."
    }
    else {
        Write-Verbose "Certificate chain not fully present on the device."
    }

    $properties["CertChainPresent"] = $certChainPresent

    # Validate the certificate chain depending on the certificate type
    if ($CertificateTest -eq 'MDM') {
        Write-Verbose "Validating MDM certificate chain."
        $chainValid = Test-CertificateIssuer -cert $cert -expectedIntermediateIssuer $MDMIntermediateIssuerCN -expectedRootIssuer $MDMRootIssuer
        if ($chainValid) {
            $properties["CertChainValidated"] = $true
            Write-Verbose "MDM certificate chain validated successfully."
        }
        else {
            $properties["CertChainValidated"] = $false
            Write-Verbose "MDM certificate chain validation failed."
        }
    }
    elseif ($CertificateTest -eq 'EntraID') {
        Write-Verbose "Validating EntraID certificate chain."
        $chainValid = Test-CertificateIssuer -cert $cert -expectedIntermediateIssuer $EntraIDIntermediateIssuerCN -expectedRootIssuer $MDMRootIssuer
        if ($chainValid) {
            $properties["CertChainValidated"] = $true
            Write-Verbose "EntraID certificate chain validated successfully."
        }
        else {
            $properties["CertChainValidated"] = $false
            Write-Verbose "EntraID certificate chain validation failed."
        }
    }

        # Determine if the cert is from LocalMachine or UserProfile, and call Get-PrivateKeyInfo accordingly
        $certFilePath = $null

        # Check if the cert is from a user profile path (not from LocalMachine store)
        if ($CertificateLocation -ne "LocalMachine\My") {
            $certFilePath = Join-Path -Path $CertificateLocation -ChildPath "$($cert.Thumbprint)"
        }

    # Check if the certificate has a private key and if it is exportable
    $hasPrivateKey = $cert.HasPrivateKey

    if ($hasPrivateKey){

    # Call Get-PrivateKeyInfo with either the cert object (for LocalMachine store) or the file path (for user profile)
    $privateKeyInfo = Get-PrivateKeyInfo -cert $cert -certFilePath $certFilePath

    $properties["PrivateKeyPresent"] = $hasPrivateKey
    $properties["PrivateKeyExportable"] = $privateKeyInfo.Exportable
    $properties["KeyStorageProvider"] = $privateKeyInfo.KspName

    } else {
        $properties["PrivateKeyPresent"] = $hasPrivateKey
        $properties["PrivateKeyExportable"] = $false
        $properties["KeyStorageProvider"] = $false
    }

    # Process OIDs based on the certificate type and OID list passed in
    foreach ($extension in $cert.Extensions) {
        if ($OidList.ContainsKey($extension.Oid.Value)) {
            Write-Verbose "Processing OID: $($extension.Oid.Value)"
            $oidName = $OidList[$extension.Oid.Value]

            # Convert RawData to Hex String and reassemble if necessary
            $properties[$oidName] = ConvertToHexString $extension.RawData
            $properties["${oidName}"] = Convert-BitStringToGuid -bitstring $extension.RawData -oid $extension.Oid.Value
        }
    }

    return [PSCustomObject]$properties
}

# Execute the main function with Verbose logging enabled
Get-CertificateInformation `
    -MDMIntermediateIssuer $MDMIntermediateIssuer `
    -MDMRootIssuer $MDMRootIssuer `
    -EntraIDIntermediateIssuer $EntraIDIntermediateIssuer `
    -CertToCheck $CertToCheck `
    -MDMOIDs $MDMOIDs `
    -EntraIDOIDs $EntraIDOIDs