<#
.SYNOPSIS
    Prepare a Windows server for SCEP certificate distribution using NDES for Microsoft Intune.

.DESCRIPTION
    This script will prepare and configure a Windows server for SCEP certificate distribution using NDES for Microsoft Intune.
    For running this script, permissions to set service principal names are required including local administrator privileges on the server where the script is executed on.

.PARAMETER CertificateAuthorityConfig
    Define the Certificate Authority configuration using the following format: <IssuingCAFQDN>\<CACommonName>.

.PARAMETER NDESTemplateName
    Define the name of the certificate template that will be used by NDES to issue certificates to mobile devices. Don't specify the display name.
    
.PARAMETER NDESExternalFQDN
    Define the external FQDN of the NDES service published through an application proxy, e.g. ndes-tenantname.msappproxy.net.

.PARAMETER RegistrationAuthorityName
    Define the Registration Authority name information used by NDES.

.PARAMETER RegistrationAuthorityCompany
    Define the Registration Authority company information used by NDES.
    
.PARAMETER RegistrationAuthorityDepartment
    Define the Registration Authority department information used by NDES.

.PARAMETER RegistrationAuthorityCity
    Define the Registration Authority city information used by NDES.

.EXAMPLE
    # Install and configure NDES with verbose output:
    .\Install-MSIntuneNDESServer.ps1 -CertificateAuthorityConfig "CA01.domain.com\DOMAIN-CA01-CA" -NDESTemplateName "NDESIntune" -NDESExternalFQDN "ndes-tenantname.msappproxy.net" -RegistrationAuthorityName "Name" -RegistrationAuthorityCompany "CompanyName" -RegistrationAuthorityDepartment "Department" -RegistrationAuthorityCity "City" -Verbose

.NOTES
    FileName:    Install-MSIntuneNDESServer.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2018-06-17
    Updated:     2018-06-17
    
    Version history:
    1.0.0 - (2018-06-17) Script created
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [parameter(Mandatory=$true, HelpMessage="Define the Certificate Authority configuration using the following format: <IssuingCAFQDN>\<CACommonName>.")]
    [ValidateNotNullOrEmpty()]
    [string]$CertificateAuthorityConfig,    

    [parameter(Mandatory=$true, HelpMessage="Define the name of the certificate template that will be used by NDES to issue certificates to mobile devices. Don't specify the display name.")]
    [ValidateNotNullOrEmpty()]
    [string]$NDESTemplateName,

    [parameter(Mandatory=$true, HelpMessage="Define the external FQDN of the NDES service published through an application proxy, e.g. ndes-tenantname.msappproxy.net.")]
    [ValidateNotNullOrEmpty()]
    [string]$NDESExternalFQDN,

    [parameter(Mandatory=$true, HelpMessage="Define the Registration Authority name information used by NDES.")]
    [ValidateNotNullOrEmpty()]
    [string]$RegistrationAuthorityName,

    [parameter(Mandatory=$true, HelpMessage="Define the Registration Authority company information used by NDES.")]
    [ValidateNotNullOrEmpty()]
    [string]$RegistrationAuthorityCompany,
    
    [parameter(Mandatory=$true, HelpMessage="Define the Registration Authority department information used by NDES.")]
    [ValidateNotNullOrEmpty()]
    [string]$RegistrationAuthorityDepartment,

    [parameter(Mandatory=$true, HelpMessage="Define the Registration Authority city information used by NDES.")]
    [ValidateNotNullOrEmpty()]
    [string]$RegistrationAuthorityCity
)
Begin {
    # Ensure that running PowerShell version is 5.1
    #Requires -Version 5.1

    # Init verbose logging for environment gathering process phase
    Write-Verbose -Message "Initiating environment gathering process phase"

    # Add additional variables required for installation and configuration
    Write-Verbose -Message "- Configuring additional variables required for installation and configuration"
    $ServerFQDN = -join($env:COMPUTERNAME, ".", $env:USERDNSDOMAIN.ToLower())
    Write-Verbose -Message "- Variable ServerFQDN has been assigned value: $($ServerFQDN)"
    $ServerNTAccountName = -join($env:USERDOMAIN.ToUpper(), "\", $env:COMPUTERNAME, "$")
    Write-Verbose -Message "- Variable ServerNTAccountName has been assigned value: $($ServerNTAccountName)"

    # Get Server Authentication certificate for IIS binding
    try {
        $ServerAuthenticationCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction Stop | Where-Object { ($_.Subject -match $NDESExternalFQDN) -and ($_.Extensions["2.5.29.37"].EnhancedKeyUsages.FriendlyName.Contains("Server Authentication")) }
        if ($ServerAuthenticationCertificate -eq $null) {
            Write-Warning -Message "Unable to locate required Server Authentication certificate matching external NDES FQDN"; break
        }
        else {
            Write-Verbose -Message "- Successfully located required Server Authentication certificate matching external NDES FQDN"
        }
    }
    catch [System.Exception] {
        Write-Warning -Message "An error occurred while attempting to locate required Server Authentication certificate matching external NDES FQDN"; break
    }

    # Get Client Authentication certifcate for Intune Certificate Connector
    try {
        $ClientAuthenticationCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction Stop | Where-Object { ($_.Subject -match $ServerFQDN) -and ($_.Extensions["2.5.29.37"].EnhancedKeyUsages.FriendlyName.Contains("Client Authentication")) }
        if ($ClientAuthenticationCertificate -eq $null) {
            Write-Warning -Message "Unable to locate required Client Authentication certificate matching internal NDES server FQDN"; break
        }
        else {
            Write-Verbose -Message "- Successfully located required Client Authentication certificate matching internal NDES server FQDN"
        }
    }
    catch [System.Exception] {
        Write-Warning -Message "An error occurred while attempting to locate required Client Authentication certificate matching internal NDES server FQDN"; break
    }

    # Completed verbose logging for environment gathering process phase
    Write-Verbose -Message "Completed environment gathering process phase"
}
Process {
    # Functions
    function Test-PSCredential {
        param (
            [parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [System.Management.Automation.PSCredential]$Credential
        )
        Process {
            $ErrorActionPreference = "Stop"
            try {
                Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
                $ContextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
                $PrincipalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $ContextType, $env:USERDNSDOMAIN.ToLower()
                $ContextOptions = [System.DirectoryServices.AccountManagement.ContextOptions]::Negotiate            
                if (-not($PrincipalContext.ValidateCredentials($Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password)) -eq $true) {
                    return $false
                }
                else {
                    return $true
                }
            }
            catch [System.Exception] {
                if (-not($PrincipalContext.ValidateCredentials($Credential.GetNetworkCredential().UserName, $Credential.GetNetworkCredential().Password, $ContextOptions)) -eq $true) {
                    return $false
                } 
                else {
                    return $true
                }
            }
        }
    }

    # Configure main script error action preference
    $ErrorActionPreference = "Stop"    

    # Initiate main script function
    Write-Verbose -Message "Initiating main script engine to install and configure NDES on server: $($env:COMPUTERNAME)"

    # Init verbose logging for credentials phase
    Write-Verbose -Message "Initiating credentials gathering process phase"

    # Get local administrator credential
    Write-Verbose -Message "- Prompting for credential input for Enterprise Administrator domain credential"
    $AdministratorPSCredential = (Get-Credential -Message "Specify a Enterprise Administrator domain credential with the following formatting 'DOMAIN\useraccount'")
    if (-not(Test-PSCredential -Credential $AdministratorPSCredential)) {
        Write-Warning -Message "Unable to validate specified Enterprise Administrator domain credentials"; break
    }
    else {
        # Validate local administrator privileges
        Write-Verbose -Message "- Given credentials was validated successfully, checking for Enterprise Administrator privileges for current user"
        if (-not([Security.Principal.WindowsIdentity]::GetCurrent().Groups | Select-String -Pattern "S-1-5-32-544")) {
            Write-Warning -Message "Current user context is not a local administrator on this server"; break
        }
    }

    # Get service account credential
    Write-Verbose -Message "- Prompting for credential input for NDES service account domain credential"
    $NDESServiceAccountCredential = (Get-Credential -Message "Specify the NDES service account domain credential with the following formatting 'DOMAIN\useraccount'")
    if (-not(Test-PSCredential -Credential $NDESServiceAccountCredential)) {
        Write-Warning -Message "Unable to validate specified NDES service account domain credentials"; break
    }
    $NDESServiceAccountName = -join($NDESServiceAccountCredential.GetNetworkCredential().Domain, "\" ,$NDESServiceAccountCredential.GetNetworkCredential().UserName)
    $NDESServiceAccountPassword = $NDESServiceAccountCredential.GetNetworkCredential().SecurePassword
    Write-Verbose -Message "- Successfully gathered NDES service account credentials"

    # Completed verbose logging for credentials phase
    Write-Verbose -Message "Completed credentials gathering process phase"

    # Init verbose logging for pre-configuration phase
    Write-Verbose -Message "Initiating pre-configuration phase"
    
    # Give computer account read permissions on Client Authentication certificate private key
    try {
        Write-Verbose -Message "- Attempting to give the NDES server computer account permissions on the Client Authentication certificate private key"
        $ClientAuthenticationKeyContainerName = $ClientAuthenticationCertificate.PrivateKey.CspKeyContainerInfo.KeyContainerName
        $ClientAuthenticationKeyFilePath = Join-Path -Path $env:ProgramData -ChildPath "Microsoft\Crypto\RSA\MachineKeys\$($ClientAuthenticationKeyContainerName)"
        Write-Verbose -Message "- Retrieving existing access rules for private key container"
        $ClientAuthenticationACL = Get-Acl -Path $ClientAuthenticationKeyFilePath

        # Check if existing ACL exist matching computer account with read permissions
        $ServerAccessRule = $ClientAuthenticationACL.Access | Where-Object { ($_.IdentityReference -like $ServerNTAccountName) -and ($_.FileSystemRights -match "Read") }
        if ($ServerAccessRule -eq $null) {
            Write-Verbose -Message "- Could not find existing access rule for computer account with read permission on private key, attempting to delegate permissions"
            $NTAccountUser = New-Object -TypeName System.Security.Principal.NTAccount($ServerNTAccountName) -ErrorAction Stop
            $FileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule($NTAccountUser, "Read", "None", "None", "Allow") -ErrorAction Stop
            $ClientAuthenticationACL.AddAccessRule($FileSystemAccessRule)
            Set-Acl -Path $ClientAuthenticationKeyFilePath -AclObject $ClientAuthenticationACL -ErrorAction Stop
            Write-Verbose -Message "- Successfully delegated the NDES server computer account permissions on the Client Authentication certificate private key"
        }
        else {
            Write-Verbose -Message "- Found an existing access rule for computer account with read permission on private key, will skip configuration"
        }
    }
    catch [System.Exception] {
        Write-Warning -Message "An error occurred while attempting to give the NDES server computer account permissions on the Client Authentication certificate private key"; break
    }

    try {
        # Configure service account SPN for local server
        Write-Verbose -Message "- Attempting to configure service princal names for NDES service account: $($NDESServiceAccountName)"
        Write-Verbose -Message "- Configuring service principal name HTTP/$($ServerFQDN) on $($NDESServiceAccountName)"
        $ServerFQDNInvocation = Invoke-Expression -Command "cmd.exe /c setspn.exe -s HTTP/$($ServerFQDN) $($NDESServiceAccountName)" -ErrorAction Stop
        if ($ServerFQDNInvocation -match "Updated object") {
            Write-Verbose -Message "- Successfully configured service principal name for NDES service account"    
        }
        Write-Verbose -Message "- Configuring service principal name HTTP/$($env:COMPUTERNAME) on $($NDESServiceAccountName)"
        $ServerInvocation = Invoke-Expression -Command "cmd.exe /c setspn.exe -s HTTP/$($env:COMPUTERNAME) $($NDESServiceAccountName)" -ErrorAction Stop
        if ($ServerInvocation -match "Updated object") {
            Write-Verbose -Message "- Successfully configured service principal name for NDES service account"    
        }        
        Write-Verbose -Message "- Successfully configured service principal names for NDES service account"
    }
    catch [System.Exception] {
        Write-Warning -Message "Failed to configure service princal names for NDES service account"; break
    }

    # Completed verbose logging for pre-configuration phase
    Write-Verbose -Message "Completed pre-configuration phase"

    # Init verbose logging for Windows feature installation phase
    Write-Verbose -Message "Initiating Windows feature installation phase"    

    # Install required Windows features for NDES
    $NDESWindowsFeatures = @("ADCS-Device-Enrollment", "Web-Filtering", "Web-Asp-Net", "NET-Framework-Core", "NET-HTTP-Activation", "Web-Asp-Net45", "NET-Framework-45-Core", "NET-Framework-45-ASPNET", "NET-WCF-HTTP-Activation45", "Web-Metabase", "Web-WMI", "Web-Mgmt-Console", "NET-Non-HTTP-Activ")
    foreach ($WindowsFeature in $NDESWindowsFeatures) {
        Write-Verbose -Message "- Checking installation state for feature: $($WindowsFeature)"
        if (((Get-WindowsFeature -Name $WindowsFeature -Verbose:$false).InstallState -ne "Installed")) {
            Write-Verbose -Message "- Attempting to install Windows feature: $($WindowsFeature)"
            Add-WindowsFeature -Name $WindowsFeature -ErrorAction Stop -Verbose:$false | Out-Null
            Write-Verbose -Message "- Successfully installed Windows feature: $($WindowsFeature)"
        }
        else {
            Write-Verbose -Message "- Windows feature is already installed: $($WindowsFeature)"
        }
    }

    # Completed verbose logging for Windows feature installation phase
    Write-Verbose -Message "Completed Windows feature installation phase"

    # Init verbose logging for NDES server role installation phase
    Write-Verbose -Message "Initiating NDES server role installation phase"

    # Add NDES service account to the IIS_IUSRS group
    try {
        Write-Verbose -Message "- Checking if NDES service account is a member of the IIS_IUSRS group"
        $IISIUSRSMembers = Get-LocalGroupMember -Group "IIS_IUSRS" -Member $NDESServiceAccountName -ErrorAction SilentlyContinue
        if ($IISIUSRSMembers -eq $null) {
            Write-Verbose -Message "- Attempting to add NDES service account to the IIS_IUSRS group"
            Add-LocalGroupMember -Group "IIS_IUSRS" -Member $NDESServiceAccountName -ErrorAction Stop
            Write-Verbose -Message "- Successfully added NDES service account to the IIS_IUSRS group"
        }
        else {
            Write-Verbose -Message "- NDES service account is already a member of the IIS_IUSRS group"
        }
    }
    catch [System.Exception] {
        Write-Warning -Message "An error occurred when attempting to add NDES service account to the IIS_IUSRS group"; break
    }    

    # Set NDES install parameters
    $InstallNDESParams = @{
        "Credential" = $AdministratorPSCredential
        "CAConfig" = $CertificateAuthorityConfig
        "RAName" = $RegistrationAuthorityName
        "RACompany" = $RegistrationAuthorityCompany
        "RADepartment" = $RegistrationAuthorityDepartment
        "RACity" = $RegistrationAuthorityCity
        "ServiceAccountName" = $NDESServiceAccountName
        "ServiceAccountPassword" = $NDESServiceAccountPassword
    }

    # Install and configure NDES server role
    try {
        Write-Verbose -Message "- Starting NDES server role installation, this could take some time"
        Install-AdcsNetworkDeviceEnrollmentService @InstallNDESParams -Force -ErrorAction Stop -Verbose:$false | Out-Null
        Write-Verbose -Message "- Successfully installed and configured NDES server role"
    }
    catch [System.Exception] {
        Write-Warning -Message "An error occurred. Error message: $($_.Exception.Message)"; break
    }

    # Completed verbose logging for NDES server role installation phase
    Write-Verbose -Message "Completed NDES server role installation phase"

    # Init verbose logging for NDES server role post-installation phase
    Write-Verbose -Message "Initiating NDES server role post-installation phase"

    # Configure NDES certificate template in registry
    try {
        Write-Verbose -Message "- Attempting to configure EncryptionTemplate registry name with value: $($NDESTemplateName)"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP" -Name "EncryptionTemplate" -Value $NDESTemplateName -ErrorAction Stop
        Write-Verbose -Message "- Successfully configured EncryptionTemplate registry name"
        Write-Verbose -Message "- Attempting to configure GeneralPurposeTemplate registry name with value: $($NDESTemplateName)"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP" -Name "GeneralPurposeTemplate" -Value $NDESTemplateName -ErrorAction Stop
        Write-Verbose -Message "- Successfully configured GeneralPurposeTemplate registry name"
        Write-Verbose -Message "- Attempting to configure SignatureTemplate registry name with value: $($NDESTemplateName)"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP" -Name "SignatureTemplate" -Value $NDESTemplateName -ErrorAction Stop
        Write-Verbose -Message "- Successfully configured SignatureTemplate registry name"
    }
    catch [System.Exception] {
        Write-Warning -Message "An error occurred while configuring NDES certificate template in registry"; break
    }    

    # Completed verbose logging for NDES server role installation phase
    Write-Verbose -Message "Completed NDES server role post-installation phase"

    # Init verbose logging for IIS configuration phase
    Write-Verbose -Message "Initiating IIS configuration phase"

    # Import required IIS module
    try {
        Write-Verbose -Message "- Import required IIS module"
        Import-Module -Name "WebAdministration" -ErrorAction Stop -Verbose:$false
        Write-Verbose -Message "- Successfully imported required IIS module"
    }
    catch [System.Exception] {
        Write-Warning -Message "An error occurred while importing the required IIS module"; break
    }

    # Configure HTTP parameters in registry
    try {
        Write-Verbose -Message "- Attempting to configure HTTP parameters in registry, setting MaxFieldLength to value: 65534"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" -Name "MaxFieldLength" -Value 65534 -ErrorAction Stop
        Write-Verbose -Message "- Successfully configured HTTP parameter in registry for MaxFieldLength"
        Write-Verbose -Message "- Attempting to configure HTTP parameters in registry, setting MaxRequestBytes to value: 65534"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" -Name "MaxRequestBytes" -Value 65534 -ErrorAction Stop
        Write-Verbose -Message "- Successfully configured HTTP parameter in registry for MaxRequestBytes"
    }
    catch [System.Exception] {
        Write-Warning -Message "An error occurred while configuring HTTP parameters in registry"; break
    }    

    # Add new HTTPS binding for Default Web Site
    try {
        Write-Verbose -Message "- Attempting to create new HTTPS binding for Default Web Site"
        $HTTPSWebBinding = Get-WebBinding -Name "Default Web Site" -IPAddress "*" -Port 443 -ErrorAction Stop
        if ($HTTPSWebBinding -eq $null) {
            New-WebBinding -Name "Default Web Site" -IPAddress "*" -Port 443 -Protocol Https -ErrorAction Stop | Out-Null
            Write-Verbose -Message "- Successfully creating new HTTPS binding for Default Web Site"
            Write-Verbose -Message "- Attempting to set Server Authentication certificate for HTTPS binding"
            $ServerAuthenticationCertificate | New-Item -Path "IIS:\SslBindings\*!443" -ErrorAction Stop | Out-Null
            Write-Verbose -Message "- Successfully set Server Authentication certificate for HTTPS binding"
        }
        else {
            Write-Verbose -Message "- Existing HTTPS binding found for Default Web Site, attempting to set Server Authentication certificate"
            if (-not(Get-Item -Path "IIS:\SslBindings\*!443" -ErrorAction SilentlyContinue)) {
                $ServerAuthenticationCertificate | New-Item -Path "IIS:\SslBindings\*!443" -ErrorAction Stop | Out-Null
                Write-Verbose -Message "- Successfully set Server Authentication certificate for HTTPS binding"
            }
            else {
                Write-Verbose -Message "- Existing HTTPS binding already has a certificate selected, removing it"
                Remove-Item -Path "IIS:\SslBindings\*!443" -Force -ErrorAction Stop | Out-Null
                Write-Verbose -Message "- Successfully removed certificate for existing HTTPS binding"
                Write-Verbose -Message "- Attempting to set new Server Authentication certificate for HTTPS binding"
                $ServerAuthenticationCertificate | New-Item -Path "IIS:\SslBindings\*!443" -ErrorAction Stop | Out-Null
                Write-Verbose -Message "- Successfully set Server Authentication certificate for HTTPS binding"
            }
        }
    }
    catch [System.Exception] {
        Write-Warning -Message "An error occurred while attempting to create new or update existing HTTPS binding and set certificate selection for Default Web Site"; break
    }

    # Configure Default Web Site to require SSL
    try {
        Write-Verbose -Message "- Attempting to set Default Web Site to require SSL"
        Set-WebConfigurationProperty -PSPath "IIS:\" -Filter "/system.webServer/security/access" -Name "sslFlags" -Value "Ssl" -Location "Default Web Site" -ErrorAction Stop
        Write-Verbose -Message "- Successfully set Default Web Site to require SSL"
    }
    catch [System.Exception] {
        Write-Warning -Message "An error occurred while attempting to set Default Web Site to require SSL"; break
    }

    # Set Default Web Site request limits
    try {
        Write-Verbose -Message "- Attempting to set Default Web Site request filtering maximum URL length with value: 65534"
        Set-WebConfiguration -PSPath "IIS:\Sites\Default Web Site" -Filter "/system.webServer/security/requestFiltering/requestLimits/@maxUrl" -Value 65534 -ErrorAction Stop
        Write-Verbose -Message "- Successfully set Default Web Site request filtering maximum URL length"
        Write-Verbose -Message "- Attempting to set Default Web Site request filtering maximum query string with value: 65534"
        Set-WebConfiguration -PSPath "IIS:\Sites\Default Web Site" -Filter "/system.webServer/security/requestFiltering/requestLimits/@maxQueryString" -Value 65534 -ErrorAction Stop
        Write-Verbose -Message "- Successfully set Default Web Site request filtering maximum query string"
        Write-Verbose -Message "- Attempting to set Default Web Site request filtering for double escaping with value: False"
        Set-WebConfiguration -PSPath "IIS:\Sites\Default Web Site" -Filter "/system.webServer/security/requestFiltering/@allowDoubleEscaping" -Value "False" -ErrorAction Stop
        Write-Verbose -Message "- Successfully set Default Web Site request filtering for double escaping"
    }
    catch [System.Exception] {
        Write-Warning -Message "An error occurred while attempting to set Default Web Site request filtering configuration"; break
    }

    # Configure Default Web Site authentication
    try {
        # Enable anonymous authentication
        Write-Verbose -Message "- Attempting to set Default Web Site anonymous authentication to: Enabled"
        Set-WebConfiguration -Location "Default Web Site" -Filter "/system.webServer/security/authentication/anonymousAuthentication/@Enabled" -Value "True" -ErrorAction Stop
        Write-Verbose -Message "- Successfully set Default Web Site anonymous authentication"

        # Disable windows authentication
        Write-Verbose -Message "- Attempting to set Default Web Site Windows authentication to: Disabled"
        Set-WebConfiguration -Location "Default Web Site" -Filter "/system.webServer/security/authentication/windowsAuthentication/@Enabled" -Value "False" -ErrorAction Stop
        Write-Verbose -Message "- Successfully set Default Web Site Windows authentication"
    }
    catch [System.Exception] {
        Write-Warning -Message "An error occurred while attempting to set Default Web Site authentication configuration"; break
    }

    # Disable IE Enhanced Security Configuration for administrators
    try {
        Write-Verbose -Message "- Attempting to disable IE Enhanced Security Configuration for administrators"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0 -ErrorAction Stop
        Write-Verbose -Message "- Successfully disabled IE Enhanced Security Configuration for administrators"
    }
    catch [System.Exception] {
        Write-Warning -Message "An error occurred while attempting to disable IE Enhanced Security Configuration for administrators"; break
    }

    # Completed verbose logging for IIS configuration phase
    Write-Verbose -Message "Completed IIS configuration phase"
    Write-Verbose -Message "Successfully installed and configured this server with NDES for Intune Certificate Connector to be installed"
    Write-Verbose -Message "IMPORTANT: Restart the server at this point before installing the Intune Certificate Connector"
}