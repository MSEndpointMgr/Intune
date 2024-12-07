<#
.SYNOPSIS
    Set a specific Scope Tag for all or specific platforms, e.g. Windows and/or macOS (supported for iOS and Android as well) on the desired profiles types, e.g. DeviceConfigurations, SecurityBaselines and more.

.DESCRIPTION
    This script can perform multiple methods to manage Scope Tags on configuration profiles, such as:
    - Add
      - This method will add a specific Scope Tag to defined profile types, leaving existing Scope Tags still assigned
    - Remove
      - This method will remove a specific Scope Tag from defined profile types, leaving any other Scope Tag still assigned
    - Replace
      - This method will replace all existing Scope Tags on defined profile types, with the specific Scope Tag

    NOTE: The default method used by this script, when the Method parameter is not passed on the command line, is 'Add'.

    The following configuration profiles, policies and script item types are supported:
    - DeviceConfiguration
    - DeviceCompliance
    - SettingsCatalog
    - SecurityBaseline
    - EndpointSecurityAntivirus
    - EndpointSecurityDiskEncryption
    - EndpointSecurityFirewall
    - EndpointSecurityAttackSurfaceReduction
    - EndpointSecurityEndpointDetectionAndResponse
    - EndpointSecurityAccountProtection
    - DeviceManagementScripts
    - DeviceHealthScripts
    - WindowsFeatureUpdateProfiles
    - WindowsQualityUpdateProfiles
    - WindowsDriverUpdateProfiles
    - AssignmentFilters
    - DeviceShellScripts
    - DeviceCustomAttributeShellScripts
    - GroupPolicyConfigurations
    - DeviceEnrollmentConfigurations
    - WindowsAutopilotDeploymentProfiles
    - EnrollmentNotifications
    - DeviceEnrollmentStatusPage
    - IntuneBrandingProfiles
    - AppleVPPTokens
    - MicrosoftTunnelSites
    - MicrosoftTunnelConfigurations

    NOTE: By default, when the ProfileType parameter is not passed on the command line, all profile types are used.

.PARAMETER TenantID
    Specify the Azure AD tenant ID or the common name, e.g. 'tenant.onmicrosoft.com'.

.PARAMETER ClientID
    Specify the service principal (also known as an app registration) Client ID (also known as Application ID). If not specified, script will default to well known 'Microsoft Intune PowerShell' application.

.PARAMETER Platform
    Specify platform to scope the desired configuration profiles.

.PARAMETER ScopeTagName
    Specify the name of an existing Scope Tag that will be assigned to all specified profile types per platform.

.PARAMETER Include
    Specify a string pattern to match for the name or displayName property of each profile type, to include only the the matching profiles when adding a Scope Tag.

.PARAMETER Exclude
    Specify a string pattern to match for the name or displayName property of each profile type, to exclude adding a Scope Tag to the matching profiles.

.PARAMETER Method
    Specify 'Add' to append the specific Scope Tag, 'Replace' to replace all existing Scope Tags with the specific Scope Tag or 'Remove' to remove the specific Scope Tag.

.PARAMETER First
    Specify the amount of profile type items to limit the overall operation to, e.g. only the first 3 items.

.PARAMETER ProfileType
    Specify the profile type to include where the specified Scope Tag will be added. By default, all profile types are specified.

.PARAMETER ThrottleInSeconds
    Specify the time in seconds to wait in between multiple PATCH requests, when adding or removing Scope Tags.

.EXAMPLE
    # Add a scope tag named 'NewYork' to all Windows configuration profile types:
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'Windows' -ScopeTagName 'NewYork'

    # Add a scope tag named 'NewYork' to all Windows configuration profile types where the display name matches the 'NY' pattern:
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'Windows' -ScopeTagName 'NewYork' -Include 'NY'

    # Add a scope tag named 'NewYork' to all Windows and macOS configuration profile types where the display name matches the 'NY' pattern:
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'Windows', 'macOS' -ScopeTagName 'NewYork' -Include 'NY'

    # Add a scope tag named 'NewYork' to all Windows and macOS configuration profile types where the display name matches the 'NY' pattern and excludes any profiles matching 'LDN':
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'Windows', 'macOS' -ScopeTagName 'NewYork' -Include 'NY' -Exclude 'LDN'

    # Add a scope tag named 'NewYork' to all Linux configuration profile types where the display name matches the 'NY' pattern, but validate the alterations before hand using -WhatIf:
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'Linux' -ScopeTagName 'NewYork' -Include 'NY' -WhatIf

    # Add a scope tag named 'NewYork' to only the first 3 Windows configuration profile types where the display name matches the 'NY' pattern:
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'Windows' -ScopeTagName 'NewYork' -Include 'NY' -First 3

    # Remove a scope tag named 'London' from all iOS configuration profile types:
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'iOS' -ScopeTagName 'London' -Method 'Remove'

    # Remove a scope tag named 'London' from all iOS configuration profile types where the display name matches the 'LDN' pattern:
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'iOS' -ScopeTagName 'London' -Include 'LDN' -Method 'Remove'

    # Remove a scope tag named 'London' from only the first 3 iOS configuration profile types where the display name matches the 'LDN' pattern:
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'iOS' -ScopeTagName 'London' -Include 'LDN' -Method 'Remove' -First 3

    # Replace all existing scope tags with a scope tag named 'Stockholm' on all Windows configuration profile types:
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'Windows' -ScopeTagName 'Stockholm' -Method 'Replace'

    # Replace all existing scope tags with a scope tag named 'Stockholm' on all Windows configuration profile types where the display name matches the 'STH' pattern:
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'Windows' -ScopeTagName 'Stockholm' -Method 'Replace'

    # Replace all existing scope tags with a scope tag named 'Stockholm' for only the first 3 Windows configuration profile types where the display name matches the 'STH' pattern:
    .\Set-MSIntuneProfileTypeScopeTag.ps1 -TenantID 'tenant.onmicrosoft.com' -Platform 'Windows' -ScopeTagName 'Stockholm' -Method 'Replace' -First 3

.NOTES
    FileName:    Set-MSIntuneProfileTypeScopeTag.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2022-12-05
    Updated:     2023-02-16

    Version history:
    1.0.0 - (2022-12-05) Script created
    1.0.1 - (2023-02-16) Changed Pattern parameter to be named Include instead and added a new Exclude parameter
#>
#Requires -Modules MSGraphRequest
[CmdletBinding(SupportsShouldProcess)]
param(
    [parameter(Mandatory = $true, HelpMessage = "Specify the Azure AD tenant ID or the common name, e.g. 'tenant.onmicrosoft.com'.")]
    [ValidateNotNullOrEmpty()]
    [string]$TenantID = "ericsson.onmicrosoft.com",

    [parameter(Mandatory = $false, HelpMessage = "Specify the service principal (also known as an app registration) Client ID (also known as Application ID). If not specified, script will default to well known 'Microsoft Intune PowerShell' application.")]
    [ValidateNotNullOrEmpty()]
    [string]$ClientID,

    [parameter(Mandatory = $true, HelpMessage = "Specify platform to scope the desired configuration profiles.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("Windows", "macOS", "Linux", "iOS", "Android")]
    [string[]]$Platform,

    [parameter(Mandatory = $true, HelpMessage = "Specify the name of an existing Scope Tag that will be assigned to all specified profile types per platform.")]
    [ValidateNotNullOrEmpty()]
    [string]$ScopeTagName,

    [parameter(Mandatory = $false, HelpMessage = "Specify a string pattern to match for the name or displayName property of each profile type, to include only the the matching profiles when adding a Scope Tag.")]
    [ValidateNotNullOrEmpty()]
    [string]$Include,

    [parameter(Mandatory = $false, HelpMessage = "Specify a string pattern to match for the name or displayName property of each profile type, to exclude adding a Scope Tag to the matching profiles.")]
    [ValidateNotNullOrEmpty()]
    [string]$Exclude,

    [parameter(Mandatory = $false, HelpMessage = "Specify 'Add' to append the specific Scope Tag, 'Replace' to replace all existing Scope Tags with the specific Scope Tag or 'Remove' to remove the specific Scope Tag.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("Add", "Remove", "Replace")]
    [string]$Method = "Add",

    [parameter(Mandatory = $false, HelpMessage = "Specify the amount of profile type items to limit the overall operation to, e.g. only the first 3 items.")]
    [ValidateNotNullOrEmpty()]
    [int]$First,

    [parameter(Mandatory = $false, HelpMessage = "Specify the profile type to include where the specified Scope Tag will be added. By default, all profile types are specified.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("DeviceConfiguration", "DeviceCompliance", "SettingsCatalog", "SecurityBaseline", "EndpointSecurityAntivirus", "EndpointSecurityDiskEncryption", "EndpointSecurityFirewall", "EndpointSecurityAttackSurfaceReduction", "EndpointSecurityEndpointDetectionAndResponse", "EndpointSecurityAccountProtection", "DeviceManagementScripts", "DeviceHealthScripts", "WindowsFeatureUpdateProfiles", "WindowsQualityUpdateProfiles", "WindowsDriverUpdateProfiles", "AssignmentFilters", "DeviceShellScripts", "DeviceCustomAttributeShellScripts", "GroupPolicyConfigurations", "DeviceEnrollmentConfigurations", "WindowsAutopilotDeploymentProfiles", "EnrollmentNotifications", "DeviceEnrollmentStatusPage", "IntuneBrandingProfiles", "AppleVPPTokens", "MicrosoftTunnelSites", "MicrosoftTunnelConfigurations")]
    [string[]]$ProfileType = @("DeviceConfiguration", "DeviceCompliance", "SettingsCatalog", "SecurityBaseline", "EndpointSecurityAntivirus", "EndpointSecurityDiskEncryption", "EndpointSecurityFirewall", "EndpointSecurityAttackSurfaceReduction", "EndpointSecurityEndpointDetectionAndResponse", "EndpointSecurityAccountProtection", "DeviceManagementScripts", "DeviceHealthScripts", "WindowsFeatureUpdateProfiles", "WindowsQualityUpdateProfiles", "WindowsDriverUpdateProfiles", "AssignmentFilters", "DeviceShellScripts", "DeviceCustomAttributeShellScripts", "GroupPolicyConfigurations", "DeviceEnrollmentConfigurations", "WindowsAutopilotDeploymentProfiles", "EnrollmentNotifications", "DeviceEnrollmentStatusPage", "IntuneBrandingProfiles", "AppleVPPTokens", "MicrosoftTunnelSites", "MicrosoftTunnelConfigurations"),

    [parameter(Mandatory = $false, HelpMessage = "Specify the time in seconds to wait in between multiple PATCH requests, when adding or removing Scope Tags.")]
    [ValidateNotNullOrEmpty()]
    [ValidateRange(1,15)]
    [int]$ThrottleInSeconds = 3
)
Begin {
    # Use TLS 1.2 connection when invoking web requests
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
Process {
    try {
        # Retrieve access token
        if ($PSBoundParameters["ClientID"]) {
            Write-Verbose -Message "Requesting access token for tenant '$($TenantID)' with ClientID: $($ClientID)"
            $AuthToken = Get-AccessToken -TenantID $TenantID -ClientID $ClientID -ErrorAction "Stop"
        }
        else {
            Write-Verbose -Message "Requesting access token for tenant: $($TenantID)"
            $AuthToken = Get-AccessToken -TenantID $TenantID -ErrorAction "Stop"
        }

        # Ensure a Scope Tag exists by given name from parameter input
        $ScopeTagsUri = "deviceManagement/roleScopeTags?`$filter=displayName eq '$($ScopeTagName)'"
        $ScopeTag = Invoke-MSGraphOperation -Get -APIVersion "Beta" -Resource $ScopeTagsUri
        if ($ScopeTag -ne $null) {
            Write-Verbose -Message "Found Scope Tag with display name '$($ScopeTag.displayName)' and id: $($ScopeTag.id)"

            # Construct list of profiles where the specified Scope Tag should be added
            $ProfilesList = New-Object -TypeName "System.Collections.ArrayList"

            # Process each platform
            foreach ($PlatformItem in $Platform) {
                Write-Verbose -Message "Enumerating platform '$($PlatformItem)' specific profiles"

                # Define the platform data types used to filter objects returned from configuration profiles request
                switch ($PlatformItem) {
                    "Windows" {
                        $PlatformDataTypes = @("microsoft.graph.windows", "microsoft.graph.securityBaseline", "microsoft.graph.sharedPC")
                    }
                    "macOS" {
                        $PlatformDataTypes = @("microsoft.graph.macOS")
                    }
                    "iOS" {
                        $PlatformDataTypes = @("microsoft.graph.ios")
                    }
                    "Android" {
                        $PlatformDataTypes = @("microsoft.graph.android")
                    }
                }
                Write-Verbose -Message "Using platform specific data type filtering options: $($PlatformDataTypes -join ", ")"

                # Process all profile types
                foreach ($ProfileTypeItem in $ProfileType) {
                    Write-Verbose -Message "Current profile type: $($ProfileTypeItem)"

                    # Instantiate resource, uri and filter variables
                    $ResourceUri = $null
                    $FilterScript = $false

                    # Define request and filter variables for all platforms
                    switch ($ProfileTypeItem) {
                        "DeviceConfiguration" {
                            $Resource = "deviceConfigurations"
                            $ResourceUri = "deviceManagement/$($Resource)"
                            $FilterScript = $true
                        }
                        "AssignmentFilters" {
                            $Resource = "assignmentFilters"
                            $ResourceUri = "deviceManagement/$($Resource)"
                        }
                        "EnrollmentNotifications" {
                            $ResourceUri = "deviceManagement/deviceEnrollmentConfigurations?`$filter=deviceEnrollmentConfigurationType eq 'EnrollmentNotificationsConfiguration'"
                        }
                        "IntuneBrandingProfiles" {
                            $Resource = "intuneBrandingProfiles"
                            $ResourceUri = "deviceManagement/$($Resource)"
                        }
                    }

                    # Define request variables for Windows, macOS, iOS and Android specific profile types
                    if ($PlatformItem -match "Windows|macOS|iOS|Android") {
                        switch ($ProfileTypeItem) {
                            "DeviceCompliance" {
                                $Resource = "deviceCompliancePolicies"
                                $ResourceUri = "deviceManagement/$($Resource)"
                                $FilterScript = $true
                            }
                            "SettingsCatalog" {
                                $ResourceUri = "deviceManagement/configurationPolicies?`$filter=templateReference/templateFamily eq 'none'"
                            }
                        }
                    }

                    # Define request variables for Windows specific profile types in the Endpoint Protection
                    if ($PlatformItem -match "Windows|macOS|Linux") {
                        switch ($ProfileTypeItem) {
                            "EndpointSecurityAntivirus" {
                                $Resource = "endpointSecurityAntivirus"
                                $ResourceUri = "deviceManagement/configurationPolicies?`$filter=templateReference/TemplateFamily eq '$($Resource)'"
                            }
                            "EndpointSecurityDiskEncryption" {
                                $Resource = "endpointSecurityDiskEncryption"
                                $ResourceUri = "deviceManagement/configurationPolicies?`$filter=templateReference/TemplateFamily eq '$($Resource)'"
                            }
                            "EndpointSecurityFirewall" {
                                $Resource = "endpointSecurityFirewall"
                                $ResourceUri = "deviceManagement/configurationPolicies?`$filter=templateReference/TemplateFamily eq '$($Resource)'"
                            }
                            "EndpointSecurityAttackSurfaceReduction" {
                                $Resource = "endpointSecurityAttackSurfaceReduction"
                                $ResourceUri = "deviceManagement/configurationPolicies?`$filter=templateReference/TemplateFamily eq '$($Resource)'"
                            }
                            "EndpointSecurityEndpointDetectionAndResponse" {
                                $Resource = "endpointSecurityEndpointDetectionAndResponse"
                                $ResourceUri = "deviceManagement/configurationPolicies?`$filter=templateReference/TemplateFamily eq '$($Resource)'"
                            }
                            "EndpointSecurityAccountProtection" {
                                $Resource = "endpointSecurityAccountProtection"
                                $ResourceUri = "deviceManagement/configurationPolicies?`$filter=templateReference/TemplateFamily eq '$($Resource)'"
                            }
                        }
                    }

                    # Define request variables for macOS and iOS specific profile types
                    if ($PlatformItem -match "macOS|iOS") {
                        switch ($ProfileTypeItem) {
                            "AppleVPPTokens" {
                                $Resource = "vppTokens"
                                $ResourceUri = "deviceAppManagement/$($Resource)"
                            }
                        }
                    }

                    # Define request variables for Android and iOS specific profile types
                    if ($PlatformItem -match "Android|iOS") {
                        switch ($ProfileTypeItem) {
                            "MicrosoftTunnelSites" {
                                $Resource = "microsoftTunnelSites"
                                $ResourceUri = "deviceAppManagement/$($Resource)"
                            }
                            "MicrosoftTunnelConfigurations" {
                                $Resource = "microsoftTunnelConfigurations"
                                $ResourceUri = "deviceAppManagement/$($Resource)"
                            }
                        }
                    }

                    # Define request variables for Windows specific profile types
                    if ($PlatformItem -like "Windows") {
                        switch ($ProfileTypeItem) {
                            "SecurityBaseline" {
                                $ResourceUri = "deviceManagement/templates?`$filter=templateType eq 'securityBaseline'"
                            }
                            "GroupPolicyConfigurations" {
                                $Resource = "groupPolicyConfigurations"
                                $ResourceUri = "deviceManagement/$($Resource)"
                            }
                            "DeviceManagementScripts" {
                                $Resource = "deviceManagementScripts"
                                $ResourceUri = "deviceManagement/$($Resource)"
                            }
                            "DeviceHealthScripts" {
                                $Resource = "deviceHealthScripts"
                                $ResourceUri = "deviceManagement/$($Resource)"
                            }
                            "WindowsFeatureUpdateProfiles" {
                                $Resource = "windowsFeatureUpdateProfiles"
                                $ResourceUri = "deviceManagement/$($Resource)"
                            }
                            "WindowsQualityUpdateProfiles" {
                                $Resource = "windowsQualityUpdateProfiles"
                                $ResourceUri = "deviceManagement/$($Resource)"
                            }
                            "WindowsDriverUpdateProfiles" {
                                $Resource = "windowsDriverUpdateProfiles"
                                $ResourceUri = "deviceManagement/$($Resource)"
                            }
                            "DeviceEnrollmentStatusPage" {
                                $ResourceUri = "deviceManagement/deviceEnrollmentConfigurations?`$filter=deviceEnrollmentConfigurationType eq 'Windows10EnrollmentCompletionPageConfiguration'"
                            }
                            "WindowsAutopilotDeploymentProfiles" {
                                $Resource = "windowsAutopilotDeploymentProfiles"
                                $ResourceUri = "deviceManagement/$($Resource)"
                            }
                        }
                    }

                    # Define request variables for macOS specific profile types
                    if ($PlatformItem -eq "macOS") {
                        switch ($ProfileTypeItem) {
                            "DeviceShellScripts" {
                                $Resource = "deviceShellScripts"
                                $ResourceUri = "deviceManagement/$($Resource)"
                            }
                            "DeviceCustomAttributeShellScripts" {
                                $Resource = "deviceCustomAttributeShellScripts"
                                $ResourceUri = "deviceManagement/$($Resource)"
                            }
                        }
                    }

                    # Define request variables for Linux specific profile types
                    if ($PlatformItem -eq "Linux") {
                        switch ($ProfileTypeItem) {
                            "DeviceCompliance" {
                                $Resource = "compliancePolicies"
                                $ResourceUri = "deviceManagement/$($Resource)"
                            }
                        }
                    }

                    # Process current profile item type if matching resource uri was set in any of the previous switch statements
                    if ($ResourceUri -ne $null) {
                        try {
                            # Retrieve profiles for current profile type
                            switch ($ProfileTypeItem) {
                                "SecurityBaseline" {
                                    Write-Verbose -Message "Request will use Uri: $($ResourceUri)"
                                    $SecurityBaselineTemplates = Invoke-MSGraphOperation -Get -APIVersion "Beta" -Resource $ResourceUri -ErrorAction "Stop"
                                    $SecurityBaselineTemplatesCount = ($SecurityBaselineTemplates | Measure-Object).Count
                                    if ($SecurityBaselineTemplatesCount -ge 1) {
                                        $ResourceUri = "deviceManagement/intents?`$filter=templateId eq '$($SecurityBaselineTemplates.id -join "' or templateId eq '")'"
                                        Write-Verbose -Message "Request will use Uri: $($ResourceUri)"
                                        $Profiles = Invoke-MSGraphOperation -Get -APIVersion "Beta" -Resource $ResourceUri -ErrorAction "Stop"
                                    }
                                }
                                default {
                                    Write-Verbose -Message "Request will use Uri: $($ResourceUri)"
                                    $Profiles = Invoke-MSGraphOperation -Get -APIVersion "Beta" -Resource $ResourceUri -ErrorAction "Stop"
                                }
                            }
                            
                            # Measure profiles count from request and continue if greater than or equal to 1
                            $ProfilesCount = ($Profiles | Measure-Object).Count
                            if ($ProfilesCount -ge 1) {
                                Write-Verbose -Message "Found count of profiles: $($ProfilesCount)"
                                
                                # Apply additional filtering using specific platform data types
                                if ($FilterScript -eq $true) {
                                    Write-Verbose -Message "Applying platform filter script logic"
                                    $Profiles = $Profiles | Where-Object { $PSItem.'@odata.type' -match ($PlatformDataTypes -join "|") }
                                    $ProfilesCount = ($Profiles | Measure-Object).Count
                                    Write-Verbose -Message "Filtered count of profiles: $($ProfilesCount)"
                                }
    
                                # Process each profile returned from request and add required data to profile list
                                foreach ($Profile in $Profiles) {
                                    # Instantiate variables custom object to ensure it's reset for each current item in the loop
                                    $ScopeTagPropertyName = $null

                                    # Determine whether to use property name 'roleScopeTagIds' or 'roleScopeTag' as the Graph API schema is not consistent across profile types
                                    if ($Profile.PSObject.Properties -match "roleScopeTagIds") {
                                        $ScopeTagPropertyName = "roleScopeTagIds"
                                    }
                                    else {
                                        if ($Profile.PSObject.Properties -match "roleScopeTag") {
                                            $ScopeTagPropertyName = "roleScopeTags"
                                        }
                                    }

                                    # Determine whether to use property name 'displayName' or 'name' as the Graph API schema is not consistent across profile types
                                    if ($Profile.PSObject.Properties -match "displayName") {
                                        $DisplayNamePropertyName = "displayName"
                                    }
                                    else {
                                        if ($Profile.PSObject.Properties -match "name") {
                                            $DisplayNamePropertyName = "name"
                                        }
                                    }

                                    # Test if scope tags property is empty, an additional direct request could be required to determine the applied scope tags
                                    if (($Profile.$ScopeTagPropertyName | Measure-Object).Count -eq 0) {
                                        $Uri = -join@(($ResourceUri -split "\?")[0], "/", $Profile.id)
                                        $ScopeTagIds = (Invoke-MSGraphOperation -Get -APIVersion "Beta" -Resource $Uri).$ScopeTagPropertyName
                                    }
                                    else {
                                        $ScopeTagIds = $Profile.$ScopeTagPropertyName
                                    }
                                    
                                    $PSObject = [PSCustomObject]@{
                                        "@odata.type" = if ($Profile.'@odata.type' -ne $null) { $Profile.'@odata.type' } else { $null }
                                        "Id" = $Profile.id
                                        "DisplayName" = $Profile.$DisplayNamePropertyName
                                        "ScopeTagIds" = $ScopeTagIds
                                        "Uri" = ($ResourceUri -split "\?")[0]
                                        "Count" = ($ScopeTagIds | Measure-Object).Count
                                        "PropertyName" = $ScopeTagPropertyName
                                    }

                                    # Ensure ProfileList array doesn't contain duplicate entries with same profile id if executed for multiple platforms
                                    if ($Profile.id -notin $ProfilesList.id) {
                                        $ProfilesList.Add($PSObject) | Out-Null
                                    }
                                }
                            }
                            else {
                                Write-Warning -Message "Could not find profiles matching profile type '$($ProfileTypeItem)' for platform '$($PlatformItem)'"
                            }
    
                            # Write output of current list count after current ProfileTypeItem
                            Write-Verbose -Message "Current ProfileList count: $($ProfilesList.Count)"
                        }
                        catch [System.Exception] {
                            throw "$($MyInvocation.MyCommand): Failed to get profiles for type $($ProfileTypeItem) with error message: $($_.Exception.Message)"
                        }
                    }
                }
            }

            # Filter list by Include parameter input if present
            if ($PSBoundParameters["Include"]) {
                Write-Verbose -Message "Applying 'Include' filtering on profile types based on displayName property using pattern: $($Include)"
                $ProfilesList = $ProfilesList | Where-Object { $PSItem.displayName -match $Include }
            }

            # Filter list by Exclude parameter input if present
            if ($PSBoundParameters["Exclude"]) {
                Write-Verbose -Message "Applying 'Exclude' filtering on profile types based on displayName property using pattern: $($Exclude)"
                $ProfilesList = $ProfilesList | Where-Object { $PSItem.displayName -notmatch $Exclude }
            }

            # Filter list by First parameter input if present
            if ($PSBoundParameters["First"]) {
                $ProfilesList = $ProfilesList | Select-Object -First $First
            }

            if (($PSBoundParameters["Include"]) -or ($PSBoundParameters["Exclude"]) -or ($PSBoundParameters["First"])) {
                # Write output of current list count after filters have been applied
                Write-Verbose -Message "Filtered ProfileList count: $($ProfilesList.Count)"
            }

            # Construct output stream list of profile items that's been amended by the script
            $ProfilesListOutput = New-Object -TypeName "System.Collections.ArrayList"

            # Process each item in profiles list
            $ProcessedProfileItems = 0
            $ProfileItemsCount = ($ProfilesList | Measure-Object).Count
            foreach ($ProfileItem in $ProfilesList) {
                Write-Verbose -Message "Processing current profile item with name: '$($ProfileItem.DisplayName)'"

                # Increase processed profile item counter
                $ProcessedProfileItems++

                # Construct inital array list for the request body to contain scope tags to either be added, removed or replaced
                $ScopeTagsIdList = New-Object -TypeName "System.Collections.ArrayList"

                # Instantiate variable for current profile type item to be added as output
                $ProcessProfileTypeOutput = $false

                switch ($Method) {
                    "Add" {
                        # Test if Scope Tag id is already present for current profile
                        if ($ScopeTag.id -notin $ProfileItem.ScopeTagIds) {
                            Write-Verbose -Message "Scope Tag with ID '$($ScopeTag.id)' is not present in '$($ProfileItem.PropertyName)', constructing request body for PATCH operation"

                            # Add existing scope tags from current profile to list, and add scope tag from parameter input
                            $ScopeTagsIdList.AddRange($ProfileItem.ScopeTagIds) | Out-Null
                            $ScopeTagsIdList.Add($ScopeTag.id) | Out-Null
                            $BodyTable = @{
                                $ProfileItem.PropertyName = @($ScopeTagsIdList)
                            }

                            # Add data type property to request body, if required
                            if ($ProfileItem.'@odata.type' -ne $null) {
                                $BodyTable.Add('@odata.type', $ProfileItem.'@odata.type')
                            }

                            try {
                                # Invoke patch request and amend scope tag property
                                if ($PSCmdlet.ShouldProcess($ProfileItem.DisplayName, "$($Method) scope tag '$($ScopeTagName)'")) {
                                    $ProfileItemUri = -join@($ProfileItem.Uri, "/", $ProfileItem.Id)
                                    Write-Verbose -Message "Invoke request for PATCH operation for Uri: $($ProfileItemUri)"
                                    $Response = Invoke-MSGraphOperation -Patch -APIVersion "Beta" -Resource $ProfileItemUri -Body ($BodyTable | ConvertTo-Json) -ContentType "application/json" -Verbose:$false -ErrorAction "Stop"
                                    $ProcessProfileTypeOutput = $true
                                }
                            }
                            catch [System.Exception] {
                                Write-Warning -Message "Failed to perform PATCH operation. Error message: $($_.Exception.Message)"
                            }
                        }
                        else {
                            Write-Verbose -Message "Scope Tag with ID '$($ScopeTag.id)' is already present in '$($ProfileItem.PropertyName)' property value: $($ProfileItem.ScopeTagIds -join ", ")"
                        }
                    }
                    "Remove" {
                        # Test if Scope Tag id is in array of current profile
                        if ($ScopeTag.id -in $ProfileItem.ScopeTagIds) {
                            Write-Verbose -Message "Scope Tag with ID '$($ScopeTag.id)' is configured for profile '$($ProfileItem.PropertyName)' and will be removed"

                            # Amend array list and filtering out the specific ID from parameter input
                            $ScopeTagsIdList.AddRange($ProfileItem.ScopeTagIds) | Out-Null
                            $ScopeTagsIdList = $ScopeTagsIdList | Where-Object { $PSItem -ne $ScopeTag.id }
                            $BodyTable = @{
                                $ProfileItem.PropertyName = @($ScopeTagsIdList)
                            }

                            # Add data type property to request body, if required
                            if ($ProfileItem.'@odata.type' -ne $null) {
                                $BodyTable.Add('@odata.type', $ProfileItem.'@odata.type')
                            }

                            try {
                                # Invoke patch request and amend scope tag property
                                if ($PSCmdlet.ShouldProcess($ProfileItem.DisplayName, "$($Method) scope tag '$($ScopeTagName)'")) {
                                    $ProfileItemUri = -join@($ProfileItem.Uri, "/", $ProfileItem.Id)
                                    Write-Verbose -Message "Invoke request for PATCH operation for Uri: $($ProfileItemUri)"
                                    $Response = Invoke-MSGraphOperation -Patch -APIVersion "Beta" -Resource $ProfileItemUri -Body ($BodyTable | ConvertTo-Json) -ContentType "application/json" -Verbose:$false -ErrorAction "Stop"
                                    $ProcessProfileTypeOutput = $true
                                }
                            }
                            catch [System.Exception] {
                                Write-Warning -Message "Failed to perform PATCH operation. Error message: $($_.Exception.Message)"
                            }
                        }
                    }
                    "Replace" {
                        Write-Verbose -Message "Scope Tag with ID '$($ScopeTag.id)' will replace existing IDs '$($ProfileItem.ScopeTagIds -join ", ")', constructing request body for PATCH operation"

                        # Add scope tag to array list for replace operation
                        $ScopeTagsIdList.Add($ScopeTag.id) | Out-Null
                        $BodyTable = @{
                            $ProfileItem.PropertyName = @($ScopeTagsIdList)
                        }

                        # Add data type property to request body, if required
                        if ($ProfileItem.'@odata.type' -ne $null) {
                            $BodyTable.Add('@odata.type', $ProfileItem.'@odata.type')
                        }
                        
                        try {
                            # Invoke patch request and amend scope tag property
                            if ($PSCmdlet.ShouldProcess($ProfileItem.DisplayName, "$($Method) all scope tags with '$($ScopeTagName)'")) {
                                $ProfileItemUri = -join@($ProfileItem.Uri, "/", $ProfileItem.Id)
                                Write-Verbose -Message "Invoke request for PATCH operation for Uri: $($ProfileItemUri)"
                                $Response = Invoke-MSGraphOperation -Patch -APIVersion "Beta" -Resource $ProfileItemUri -Body ($BodyTable | ConvertTo-Json) -ContentType "application/json" -Verbose:$false -ErrorAction "Stop"
                                $ProcessProfileTypeOutput = $true
                            }
                        }
                        catch [System.Exception] {
                            Write-Warning -Message "Failed to perform PATCH operation. Error message: $($_.Exception.Message)"
                        }
                    }
                }

                # Add current profile type item to output array list, since it has been changed by the script in previous request
                if ($ProcessProfileTypeOutput -eq $true) {
                    # Construct output object for console
                    $PSObject = [PSCustomObject]@{
                        "@odata.type" = if ($ProfileItem.'@odata.type' -ne $null) { $ProfileItem.'@odata.type' } else { $null }
                        "id" = $ProfileItem.Id
                        "displayName" = $ProfileItem.DisplayName
                        "NewScopeTagIds" = @($ScopeTagsIdList)
                        "PreviousScopeTagIds" = @($ProfileItem.ScopeTagIds)
                    }
                    $ProfilesListOutput.Add($PSObject) | Out-Null
                }

                if ($ProcessedProfileItems -lt $ProfileItemsCount) {
                    # Handle throttling
                    Write-Verbose -Message ("Throttling requests, next request in $($ThrottleInSeconds) second{0}" -f $(if ($ThrottleInSeconds -eq 1) { [string]::Empty } else { "s" }))
                    Start-Sleep -Seconds $ThrottleInSeconds
                }
            }

            # Handle return value
            return $ProfilesListOutput
        }
        else {
            Write-Warning -Message "Could not find Scope Tag with specified display name: $($ScopeTagName)"
        }
    }
    catch [System.Exception] {
        Write-Warning -Message "Failed to get access token for tenant $($TenantID) with error message: $($_.Exception.Message)"
    }
}