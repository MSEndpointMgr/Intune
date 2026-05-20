<#
.Synopsis
Check information on the MDM and EntraID certificate using the associated OIDs.

Created on:   19th May 2026
Created by:   Ben Whitmore
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
   - It records the validity period of the leaf certificate and the issuing intermediate.

3. **OID Processing**:
   - The script processes the **certificate extensions** to extract specific Object Identifiers (OIDs). For GUID-shaped extensions it strips the ASN.1 OCTET STRING wrapper and uses [System.Guid]::new() on the 16-byte payload, which applies the Windows mixed-endian layout (Data1/Data2/Data3 little-endian, Data4 big-endian).

4. **Output**:
   - For each matched certificate, the script outputs:
     - The **certificate name**, **thumbprint**, **issuer**, **validity period**, and the **trust status** of the certificate chain.
     - The **issuing intermediate certificate subject and validity period**.
     - Whether the certificate contains a **private key** and if it is **exportable**.
     - The **Key Storage Provider (KSP)** name associated with the private key.
     - The **decoded value** and **raw hex** for each known OID extension.

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

.PARAMETER intuneDeviceManagementIntermediateIssuer
The issuer of the Intune Device Management certificate. Default is 'CN=Microsoft Intune Device Management Device CA'.

.PARAMETER intuneDeviceManagementOids
A hashtable to define the OIDs for the Intune Device Management certificate.

.EXAMPLE
.\Get-TenantInformation.ps1
#>

[CmdletBinding()]
param (
    [ValidateSet('MDM', 'EntraID', 'IntuneDeviceManagement', 'Both')]
    [string]$CertToCheck = 'Both',

    [string]$MDMIntermediateIssuer = 'CN=Microsoft Intune MDM Device CA',
    [string]$MDMRootIssuer = 'CN=Microsoft Intune Root Certification Authority',
    [string]$EntraIDIntermediateIssuer = 'MS-Organization-Access',

    [Hashtable]$MDMOIDs = @{
        '1.2.840.113556.5.4'  = 'MDMDeviceID'
        '1.2.840.113556.5.6'  = 'IntuneAccountID'
        '1.2.840.113556.5.14' = 'EntraTenantID'
    },
    [Hashtable]$EntraIDOIDs = @{
        '1.2.840.113556.1.5.284.2' = 'EntraDeviceID'
        '1.2.840.113556.1.5.284.3' = 'EntraDeviceID'
        '1.2.840.113556.1.5.284.5' = 'EntraTenantID'
        '1.2.840.113556.1.5.284.7' = 'EntraJoinType'
        '1.2.840.113556.1.5.284.8' = 'EntraTenantRegion'
    },

    [string]$IntuneDeviceManagementIntermediateIssuer = 'CN=Microsoft Intune Device Management Device CA',

    [Hashtable]$IntuneDeviceManagementOIDs = @{
        '1.2.840.113556.5.4'  = 'EntDMID'
        '1.2.840.113556.5.11' = 'IntuneUserID'
        '1.2.840.113556.5.14' = 'EntraTenantID'
        '1.2.840.113556.5.25' = 'IntuneDeviceMgmtID'
    }
)

$VerbosePreference = 'Continue'

function ConvertToHexString($byteArray) {
    return ($byteArray | ForEach-Object { $_.ToString('x2') }) -join ' '
}

# Strip an ASN.1 OCTET STRING wrapper, if present, and return the inner 16 GUID bytes.
# Handles three observed shapes:
#   - 16 bytes : no wrapper (e.g. OID 1.2.840.113556.5.4)
#   - 18 bytes : short-form wrapper '04 10' + 16 bytes (e.g. OIDs 5.6, 5.14)
#   - 19 bytes : long-form wrapper  '04 81 10' + 16 bytes (e.g. OIDs 1.5.284.2/3/5)
function Get-GuidPayloadBytes {
    param ([byte[]]$RawData)

    switch ($RawData.Length) {
        16 { return $RawData }
        18 {
            if ($RawData[0] -eq 0x04 -and $RawData[1] -eq 0x10) { return $RawData[2..17] }
            throw "Expected ASN.1 OCTET STRING header '04 10' for 18-byte extension; got $($RawData[0..1] -join ' ')"
        }
        19 {
            if ($RawData[0] -eq 0x04 -and $RawData[1] -eq 0x81 -and $RawData[2] -eq 0x10) { return $RawData[3..18] }
            throw "Expected ASN.1 OCTET STRING header '04 81 10' for 19-byte extension; got $($RawData[0..2] -join ' ')"
        }
        default {
            throw "Unexpected raw extension length for GUID OID: $($RawData.Length) bytes"
        }
    }
}

function Convert-BitStringToGuid {
    param (
        [byte[]]$bitstring,
        [string]$oid
    )

    if (-not $bitstring) {
        Write-Verbose "The OID $oid has no value (bitstring is null or empty)."
        return "Null"
    }

    Write-Verbose "OID = $oid"
    Write-Verbose "Raw bytes: $([System.BitConverter]::ToString($bitstring))"

    switch ($oid) {
        '1.2.840.113556.1.5.284.7' {

            # Join Type - single ASCII character at offset 3 (after 04 81 01 wrapper).
            # 0 = Entra Registered, 1 = Entra Joined
            $joinType = [char]$bitstring[3]
            $result = switch ($joinType) {
                '0'     { "Entra Registered (0)" }
                '1'     { "Entra Joined (1)" }
                default { "Unknown ($joinType)" }
            }
            Write-Verbose "Decoded: $result"
            return $result
        }
        '1.2.840.113556.1.5.284.8' {

            # Tenant Region - two ASCII characters at offsets 3,4 (after 04 81 02 wrapper)
            $region = [string]::new([char[]]@($bitstring[3], $bitstring[4]))
            Write-Verbose "Decoded: $region"
            return $region
        }
        default {

            # ASN.1 INTEGER (tag 0x02): decode as a small integer value
            if ($bitstring.Length -ge 3 -and $bitstring[0] -eq 0x02) {
                try {
                    $intLength = $bitstring[1]
                    $intValue = 0
                    for ($i = 0; $i -lt $intLength; $i++) {
                        $intValue = ($intValue -shl 8) -bor $bitstring[2 + $i]
                    }
                    Write-Verbose "Decoded INTEGER: $intValue"
                    return $intValue.ToString()
                }
                catch {
                    Write-Verbose "Could not decode as INTEGER: $($_.Exception.Message)"
                    return "Decode failed: $($_.Exception.Message)"
                }
            }

            # GUID-shaped OIDs: strip the ASN.1 wrapper and let .NET parse the 16-byte payload
            try {
                $guidBytes = Get-GuidPayloadBytes -RawData $bitstring
                $guid = [Guid]::new([byte[]]$guidBytes).ToString().ToUpper()
                Write-Verbose "Decoded GUID: $guid"
                return $guid
            }
            catch {
                Write-Verbose "Could not decode as GUID: $($_.Exception.Message)"
                return "Decode failed: $($_.Exception.Message)"
            }
        }
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
        [string]$IntuneDeviceManagementIntermediateIssuer,
        [string]$CertToCheck,
        [Hashtable]$MDMOIDs,
        [Hashtable]$EntraIDOIDs,
        [Hashtable]$IntuneDeviceManagementOIDs
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

                # Process Intune Device Management Certificate third
                if ($cert.Issuer.Contains($IntuneDeviceManagementIntermediateIssuer)) {
                    Write-Verbose "`nFound Intune Device Management Certificate in the LocalMachine\My store"
                    Write-Verbose "Processing Intune Device Management Certificate"
                    $certObject = Invoke-CertificateProcessing -cert $cert -IntuneDeviceManagementIntermediateIssuerCN $IntuneDeviceManagementIntermediateIssuer -MDMRootIssuer $MDMRootIssuer -CertificateTest "IntuneDeviceManagement" -OidList $IntuneDeviceManagementOIDs -CertificateLocation "LocalMachine\My"
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
            'IntuneDeviceManagement' {

                # Process Intune Device Management Certificate
                if ($cert.Issuer.Contains($IntuneDeviceManagementIntermediateIssuer)) {
                    Write-Verbose "`nFound Intune Device Management Certificate in the LocalMachine\My store"
                    Write-Verbose "Processing Intune Device Management Certificate"
                    $certObject = Invoke-CertificateProcessing -cert $cert -IntuneDeviceManagementIntermediateIssuerCN $IntuneDeviceManagementIntermediateIssuer -MDMRootIssuer $MDMRootIssuer -CertificateTest "IntuneDeviceManagement" -OidList $IntuneDeviceManagementOIDs -CertificateLocation "LocalMachine\My"
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

                                # Process Intune Device Management Certificate third
                                if ($cert.Issuer.Contains($IntuneDeviceManagementIntermediateIssuer)) {
                                    Write-Verbose "`nProcessing Intune Device Management Certificate"
                                    Write-Verbose "`nFound Intune Device Management Certificate in the $profileName store"
                                    $certObject = Invoke-CertificateProcessing -cert $cert -IntuneDeviceManagementIntermediateIssuerCN $IntuneDeviceManagementIntermediateIssuer -MDMRootIssuer $MDMRootIssuer -CertificateTest "IntuneDeviceManagement" -CertificateType "File" -OidList $IntuneDeviceManagementOIDs -CertificateLocation $profileName
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
                            'IntuneDeviceManagement' {

                                # Process Intune Device Management Certificate
                                if ($cert.Issuer.Contains($IntuneDeviceManagementIntermediateIssuer)) {
                                    Write-Verbose "`nProcessing Intune Device Management Certificate"
                                    Write-Verbose "`nFound Intune Device Management Certificate in the $profileName store"
                                    $certObject = Invoke-CertificateProcessing -cert $cert -IntuneDeviceManagementIntermediateIssuerCN $IntuneDeviceManagementIntermediateIssuer -MDMRootIssuer $MDMRootIssuer -CertificateTest "IntuneDeviceManagement" -CertificateType "File" -OidList $IntuneDeviceManagementOIDs -CertificateLocation $profileName
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
        [string]$IntuneDeviceManagementIntermediateIssuerCN,
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

    # Validity window of the leaf certificate
    $now = Get-Date
    $properties["CertNotBefore"]       = $cert.NotBefore
    $properties["CertNotAfter"]        = $cert.NotAfter
    $properties["CertDaysUntilExpiry"] = [int]($cert.NotAfter - $now).TotalDays

    # Initialize a chain object and build the certificate chain
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.Build($cert) | Out-Null

    # Check if the certificate chain is longer than just the cert itself
    $certChainPresent = $false

    if ($chain.ChainElements.Count -gt 1) {
        $certChainPresent = $true
        Write-Verbose "Certificate chain found on the device."

        # Record the issuing intermediate (chain element [1]) details
        $intermediate = $chain.ChainElements[1].Certificate
        $properties["IssuerCertSubject"]           = $intermediate.Subject
        $properties["IssuerCertThumbprint"]        = $intermediate.Thumbprint
        $properties["IssuerCertNotBefore"]         = $intermediate.NotBefore
        $properties["IssuerCertNotAfter"]          = $intermediate.NotAfter
        $properties["IssuerCertDaysUntilExpiry"]   = [int]($intermediate.NotAfter - $now).TotalDays
    }
    else {
        Write-Verbose "Certificate chain not fully present on the device."
        $properties["IssuerCertSubject"]           = $null
        $properties["IssuerCertThumbprint"]        = $null
        $properties["IssuerCertNotBefore"]         = $null
        $properties["IssuerCertNotAfter"]          = $null
        $properties["IssuerCertDaysUntilExpiry"]   = $null
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
    elseif ($CertificateTest -eq 'IntuneDeviceManagement') {
        Write-Verbose "Validating Intune Device Management certificate chain."
        $chainValid = Test-CertificateIssuer -cert $cert -expectedIntermediateIssuer $IntuneDeviceManagementIntermediateIssuerCN -expectedRootIssuer $MDMRootIssuer
        if ($chainValid) {
            $properties["CertChainValidated"] = $true
            Write-Verbose "Intune Device Management certificate chain validated successfully."
        }
        else {
            $properties["CertChainValidated"] = $false
            Write-Verbose "Intune Device Management certificate chain validation failed."
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

    # Process OIDs based on the certificate type and OID list passed in.
    foreach ($extension in $cert.Extensions) {
        if ($OidList.ContainsKey($extension.Oid.Value)) {
            Write-Verbose "Processing OID: $($extension.Oid.Value)"
            $oidName = $OidList[$extension.Oid.Value]

            $properties[$oidName]        = Convert-BitStringToGuid -bitstring $extension.RawData -oid $extension.Oid.Value
            # $properties["${oidName}Raw"] = ConvertToHexString $extension.RawData
        }
    }

    return [PSCustomObject]$properties
}

# Execute the main function with Verbose logging enabled
Get-CertificateInformation `
    -MDMIntermediateIssuer $MDMIntermediateIssuer `
    -MDMRootIssuer $MDMRootIssuer `
    -EntraIDIntermediateIssuer $EntraIDIntermediateIssuer `
    -IntuneDeviceManagementIntermediateIssuer $IntuneDeviceManagementIntermediateIssuer `
    -CertToCheck $CertToCheck `
    -MDMOIDs $MDMOIDs `
    -EntraIDOIDs $EntraIDOIDs `
    -IntuneDeviceManagementOIDs $IntuneDeviceManagementOIDs