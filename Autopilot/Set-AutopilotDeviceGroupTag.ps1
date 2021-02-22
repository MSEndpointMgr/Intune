<#
.SYNOPSIS
    Set the Group Tag of an explicit Autopilot device or an array of devices to a specific value.

.DESCRIPTION
    This script will set the Group Tag of an explicit Autopilot device or an array of devices. The serial number
    of a device, or multiple, are used as the device idenfier in the Autopilot service. All devices will get the 
    same static Group Tag value, used as input for the Value parameter.

.PARAMETER TenantID
    Specify the Azure AD tenant ID or the common name, e.g. 'tenant.onmicrosoft.com'.

.PARAMETER ClientID
    Specify the service principal (also known as an app registration) Client ID (also known as Application ID).

.PARAMETER SerialNumber
    Specify an explicit or an array of serial numbers, to be used as the identifier when querying the Autopilot service for devices.

.PARAMETER Value
    Specify the Group Tag value to be set for all identified devices.

.EXAMPLE
    # Update the Group Tag of a device with serial number '1234567', with a value of 'GroupTag1':
    .\Set-AutopilotDeviceGroupTag.ps1 -TenantID "tenant.onmicrosoft.com" -ClientID "<guid>" -SerialNumber "1234567" -Value "GroupTag1"

    # Update the Group Tag of a multiple devices in an array, with a value of 'GroupTag1':
    .\Set-AutopilotDeviceGroupTag.ps1 -TenantID "tenant.onmicrosoft.com" -ClientID "<guid>" -SerialNumber @("1234567", "2345678") -Value "GroupTag1"

.NOTES
    FileName:    Set-AutopilotDeviceGroupTag.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2021-02-21
    Updated:     2021-02-21

    Version history:
    1.0.0 - (2021-02-21) Script created
#>
#Requires -Modules "MSAL.PS"
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [parameter(Mandatory = $true, HelpMessage = "Specify the Azure AD tenant ID or the common name, e.g. 'tenant.onmicrosoft.com'.")]
    [ValidateNotNullOrEmpty()]
    [string]$TenantID,

    [parameter(Mandatory = $true, HelpMessage = "Specify the service principal (also known as an app registration) Client ID (also known as Application ID).")]
    [ValidateNotNullOrEmpty()]
    [string]$ClientID,

    [parameter(Mandatory = $true, HelpMessage = "Specify an explicit or an array of serial numbers, to be used as the identifier when querying the Autopilot service for devices.")]
    [ValidateNotNullOrEmpty()]
    [string[]]$SerialNumber,

    [parameter(Mandatory = $true, HelpMessage = "Specify the Group Tag value to be set for all identified devices.")]
    [ValidateNotNullOrEmpty()]
    [string]$Value
)
Begin {}
Process {
    # Functions
    function New-AuthenticationHeader {
        <#
        .SYNOPSIS
            Construct a required header hash-table based on the access token from Get-MsalToken cmdlet.

        .DESCRIPTION
            Construct a required header hash-table based on the access token from Get-MsalToken cmdlet.

        .PARAMETER AccessToken
            Pass the AuthenticationResult object returned from Get-MsalToken cmdlet.

        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2020-12-04
            Updated:     2020-12-04

            Version history:
            1.0.0 - (2020-12-04) Script created
        #>
        param(
            [parameter(Mandatory = $true, HelpMessage = "Pass the AuthenticationResult object returned from Get-MsalToken cmdlet.")]
            [ValidateNotNullOrEmpty()]
            [Microsoft.Identity.Client.AuthenticationResult]$AccessToken
        )
        Process {
            # Construct default header parameters
            $AuthenticationHeader = @{
                "Content-Type" = "application/json"
                "Authorization" = $AccessToken.CreateAuthorizationHeader()
                "ExpiresOn" = $AccessToken.ExpiresOn.LocalDateTime
            }
    
            # Amend header with additional required parameters for bitLocker/recoveryKeys resource query
            $AuthenticationHeader.Add("ocp-client-name", "My App")
            $AuthenticationHeader.Add("ocp-client-version", "1.0")
    
            # Handle return value
            return $AuthenticationHeader
        }
    }

    function Invoke-MSGraphOperation {
        <#
        .SYNOPSIS
            Perform a specific call to Intune Graph API, either as GET, POST, PATCH or DELETE methods.
            
        .DESCRIPTION
            Perform a specific call to Intune Graph API, either as GET, POST, PATCH or DELETE methods.
            This function handles nextLink objects including throttling based on retry-after value from Graph response.
            
        .PARAMETER Get
            Switch parameter used to specify the method operation as 'GET'.
            
        .PARAMETER Post
            Switch parameter used to specify the method operation as 'POST'.
            
        .PARAMETER Patch
            Switch parameter used to specify the method operation as 'PATCH'.
            
        .PARAMETER Put
            Switch parameter used to specify the method operation as 'PUT'.
            
        .PARAMETER Delete
            Switch parameter used to specify the method operation as 'DELETE'.
            
        .PARAMETER Resource
            Specify the full resource path, e.g. deviceManagement/auditEvents.
            
        .PARAMETER Headers
            Specify a hash-table as the header containing minimum the authentication token.
            
        .PARAMETER Body
            Specify the body construct.
            
        .PARAMETER APIVersion
            Specify to use either 'Beta' or 'v1.0' API version.
            
        .PARAMETER ContentType
            Specify the content type for the graph request.
            
        .NOTES
            Author:      Nickolaj Andersen & Jan Ketil Skanke
            Contact:     @JankeSkanke @NickolajA
            Created:     2020-10-11
            Updated:     2020-11-11
    
            Version history:
            1.0.0 - (2020-10-11) Function created
            1.0.1 - (2020-11-11) Verified
        #>    
        param(
            [parameter(Mandatory = $true, ParameterSetName = "GET", HelpMessage = "Switch parameter used to specify the method operation as 'GET'.")]
            [switch]$Get,
    
            [parameter(Mandatory = $true, ParameterSetName = "POST", HelpMessage = "Switch parameter used to specify the method operation as 'POST'.")]
            [switch]$Post,
    
            [parameter(Mandatory = $true, ParameterSetName = "PATCH", HelpMessage = "Switch parameter used to specify the method operation as 'PATCH'.")]
            [switch]$Patch,
    
            [parameter(Mandatory = $true, ParameterSetName = "PUT", HelpMessage = "Switch parameter used to specify the method operation as 'PUT'.")]
            [switch]$Put,
    
            [parameter(Mandatory = $true, ParameterSetName = "DELETE", HelpMessage = "Switch parameter used to specify the method operation as 'DELETE'.")]
            [switch]$Delete,
    
            [parameter(Mandatory = $true, ParameterSetName = "GET", HelpMessage = "Specify the full resource path, e.g. deviceManagement/auditEvents.")]
            [parameter(Mandatory = $true, ParameterSetName = "POST")]
            [parameter(Mandatory = $true, ParameterSetName = "PATCH")]
            [parameter(Mandatory = $true, ParameterSetName = "PUT")]
            [parameter(Mandatory = $true, ParameterSetName = "DELETE")]
            [ValidateNotNullOrEmpty()]
            [string]$Resource,
    
            [parameter(Mandatory = $true, ParameterSetName = "GET", HelpMessage = "Specify a hash-table as the header containing minimum the authentication token.")]
            [parameter(Mandatory = $true, ParameterSetName = "POST")]
            [parameter(Mandatory = $true, ParameterSetName = "PATCH")]
            [parameter(Mandatory = $true, ParameterSetName = "PUT")]
            [parameter(Mandatory = $true, ParameterSetName = "DELETE")]
            [ValidateNotNullOrEmpty()]
            [System.Collections.Hashtable]$Headers,
    
            [parameter(Mandatory = $false, ParameterSetName = "POST", HelpMessage = "Specify the body construct.")]
            [parameter(Mandatory = $true, ParameterSetName = "PATCH")]
            [parameter(Mandatory = $true, ParameterSetName = "PUT")]
            [ValidateNotNullOrEmpty()]
            [System.Object]$Body,
    
            [parameter(Mandatory = $false, ParameterSetName = "GET", HelpMessage = "Specify to use either 'Beta' or 'v1.0' API version.")]
            [parameter(Mandatory = $false, ParameterSetName = "POST")]
            [parameter(Mandatory = $false, ParameterSetName = "PATCH")]
            [parameter(Mandatory = $false, ParameterSetName = "PUT")]
            [parameter(Mandatory = $false, ParameterSetName = "DELETE")]
            [ValidateNotNullOrEmpty()]
            [ValidateSet("Beta", "v1.0")]
            [string]$APIVersion = "v1.0",
    
            [parameter(Mandatory = $false, ParameterSetName = "GET", HelpMessage = "Specify the content type for the graph request.")]
            [parameter(Mandatory = $false, ParameterSetName = "POST")]
            [parameter(Mandatory = $false, ParameterSetName = "PATCH")]
            [parameter(Mandatory = $false, ParameterSetName = "PUT")]
            [parameter(Mandatory = $false, ParameterSetName = "DELETE")]
            [ValidateNotNullOrEmpty()]
            [ValidateSet("application/json", "image/png")]
            [string]$ContentType = "application/json"
        )
        Begin {
            # Construct list as return value for handling both single and multiple instances in response from call
            $GraphResponseList = New-Object -TypeName "System.Collections.ArrayList"
    
            # Construct full URI
            $GraphURI = "https://graph.microsoft.com/$($APIVersion)/$($Resource)"
            Write-Verbose -Message "$($PSCmdlet.ParameterSetName) $($GraphURI)"
        }
        Process {
            # Call Graph API and get JSON response
            do {
                try {
                    # Construct table of default request parameters
                    $RequestParams = @{
                        "Uri" = $GraphURI
                        "Headers" = $Headers
                        "Method" = $PSCmdlet.ParameterSetName
                        "ErrorAction" = "Stop"
                        "Verbose" = $false
                    }
    
                    switch ($PSCmdlet.ParameterSetName) {
                        "POST" {
                            if ($PSBoundParameters["Body"]) {
                                $RequestParams.Add("Body", $Body)
                            }
                            if (-not([string]::IsNullOrEmpty($ContentType))) {
                                $RequestParams.Add("ContentType", $ContentType)
                            }
                        }
                        "PATCH" {
                            $RequestParams.Add("Body", $Body)
                            $RequestParams.Add("ContentType", $ContentType)
                        }
                        "PUT" {
                            $RequestParams.Add("Body", $Body)
                            $RequestParams.Add("ContentType", $ContentType)
                        }
                    }
    
                    # Invoke Graph request
                    $GraphResponse = Invoke-RestMethod @RequestParams
    
                    # Handle paging in response
                    if ($GraphResponse.'@odata.nextLink' -ne $null) {
                        $GraphResponseList.AddRange($GraphResponse.value) | Out-Null
                        $GraphURI = $GraphResponse.'@odata.nextLink'
                        Write-Verbose -Message "NextLink: $($GraphURI)"
                    }
                    else {
                        # NextLink from response was null, assuming last page but also handle if a single instance is returned
                        if (-not([string]::IsNullOrEmpty($GraphResponse.value))) {
                            $GraphResponseList.AddRange($GraphResponse.value) | Out-Null
                        }
                        else {
                            $GraphResponseList.Add($GraphResponse) | Out-Null
                        }
                        
                        # Set graph response as handled and stop processing loop
                        $GraphResponseProcess = $false
                    }
                }
                catch [System.Exception] {
                    # Capture current error
                    $ExceptionItem = $PSItem
    
                    # Read the response stream
                    $StreamReader = New-Object -TypeName "System.IO.StreamReader" -ArgumentList @($ExceptionItem.Exception.Response.GetResponseStream()) -ErrorAction SilentlyContinue
                    if ($StreamReader -ne $null) {
                        $StreamReader.BaseStream.Position = 0
                        $StreamReader.DiscardBufferedData()
                        $ResponseBody = ($StreamReader.ReadToEnd() | ConvertFrom-Json)
        
                        if ($ExceptionItem.Exception.Response.StatusCode -like "429") {
                            # Detected throttling based from response status code
                            $RetryInSeconds = $ExceptionItem.Exception.Response.Headers["Retry-After"]
        
                            if ($RetryInSeconds -ne $null) {
                                # Wait for given period of time specified in response headers
                                Write-Verbose -Message "Graph is throttling the request, will retry in '$($RetryInSeconds)' seconds"
                                Start-Sleep -Seconds $RetryInSeconds
                            }
                            else {
                                Write-Verbose -Message "Graph is throttling the request, will retry in default '300' seconds"
                                Start-Sleep -Seconds 300
                            }
                        }
                        else {
                            switch ($PSCmdlet.ParameterSetName) {
                                "GET" {
                                    # Output warning message that the request failed with error message description from response stream
                                    Write-Warning -Message "Graph request failed with status code '$($ExceptionItem.Exception.Response.StatusCode)'. Error message: $($ResponseBody.error.message)"
        
                                    # Set graph response as handled and stop processing loop
                                    $GraphResponseProcess = $false
                                }
                                default {
                                    # Construct new custom error record
                                    $SystemException = New-Object -TypeName "System.Management.Automation.RuntimeException" -ArgumentList ("{0}: {1}" -f $ResponseBody.error.code, $ResponseBody.error.message)
                                    $ErrorRecord = New-Object -TypeName "System.Management.Automation.ErrorRecord" -ArgumentList @($SystemException, $ErrorID, [System.Management.Automation.ErrorCategory]::NotImplemented, [string]::Empty)
        
                                    # Throw a terminating custom error record
                                    $PSCmdlet.ThrowTerminatingError($ErrorRecord)
                                }
                            }
        
                            # Set graph response as handled and stop processing loop
                            $GraphResponseProcess = $false
                        }
                    }
                    else {
                        Write-Warning -Message "Failed with message: $($ExceptionItem.Exception.Message)"
    
                        # Set graph response as handled and stop processing loop
                        $GraphResponseProcess = $false
                    }
                }
            }
            until ($GraphResponseProcess -eq $false)
    
            # Handle return value
            return $GraphResponseList
        }
    }
    
    function Get-AutopilotDevice {
    <#
        .SYNOPSIS
            Retrieve an Autopilot device identity based on serial number.
            
        .DESCRIPTION
            Retrieve an Autopilot device identity based on serial number.
            
        .PARAMETER SerialNumber
            Specify the serial number of the device.
            
        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2021-02-21
            Updated:     2021-02-21
    
            Version history:
            1.0.0 - (2021-02-21) Function created
        #>    
        param(
            [parameter(Mandatory = $true, HelpMessage = "Specify the serial number of the device.")]
            [ValidateNotNullOrEmpty()]
            [string]$SerialNumber
        )
        Process {
            # Retrieve the Windows Autopilot device identity by filtering on serialNumber property with passed parameter input
            $SerialNumberEncoded = [Uri]::EscapeDataString($SerialNumber)
            $ResourceURI = "deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$($SerialNumberEncoded)')"
            $GraphResponse = (Invoke-MSGraphOperation -Get -APIVersion "Beta" -Resource $ResourceURI -Headers $Script:AuthenticationHeader).value
    
            # Handle return response
            return $GraphResponse
        }    
    }
    
    function Set-AutopilotDevice {
        <#
        .SYNOPSIS
            Update the GroupTag for an Autopilot device identity.
            
        .DESCRIPTION
            Update the GroupTag for an Autopilot device identity.
            
        .PARAMETER Id
            Specify the Autopilot device identity id.
    
        .PARAMETER GroupTag
            Specify the Group Tag string value.
            
        .NOTES
            Author:      Nickolaj Andersen
            Contact:     @NickolajA
            Created:     2021-02-21
            Updated:     2021-02-21
    
            Version history:
            1.0.0 - (2021-02-21) Function created
        #>
        param(
            [parameter(Mandatory = $true, HelpMessage = "Specify the Autopilot device identity id.")]
            [ValidateNotNullOrEmpty()]
            [string]$Id,
    
            [parameter(Mandatory = $true, HelpMessage = "Specify the Group Tag string value.")]
            [ValidateNotNullOrEmpty()]
            [string]$GroupTag
        )
        Process {
            # Construct JSON post body content
            $BodyTable = @{
                "groupTag" = $GroupTag
            }
            $BodyJSON = ConvertTo-Json -InputObject $BodyTable
    
            # Update Autopilot device properties with new group tag string
            $ResourceURI = "deviceManagement/windowsAutopilotDeviceIdentities/$($Id)/UpdateDeviceProperties"
            $GraphResponse = Invoke-MSGraphOperation -Post -APIVersion "Beta" -Resource $ResourceURI -Headers $Script:AuthenticationHeader -Body $BodyJSON -ContentType "application/json"
    
            # Handle return response
            return $GraphResponse
        }    
    }

    try {
        # Determine the correct RedirectUri (also known as Reply URL) to use with MSAL.PS
        if ($ClientID -like "d1ddf0e4-d672-4dae-b554-9d5bdfd93547") {
            $RedirectUri = "urn:ietf:wg:oauth:2.0:oob"
        }
        else {
            $RedirectUri = [string]::Empty
        }

        # Get authentication token
        $AccessToken = Get-MsalToken -TenantId $TenantID -ClientId $ClientID -RedirectUri $RedirectUri -ErrorAction Stop

        try {
            # Construct authentication header
            $AuthenticationHeader = New-AuthenticationHeader -AccessToken $AccessToken -ErrorAction Stop

            try {
                # Construct list to hold all Autopilot device objects
                $AutopilotDevices = New-Object -TypeName "System.Collections.ArrayList"
                
                # Retrieve list of Autopilot devices based on parameter input from SerialNumber
                foreach ($SerialNumberItem in $SerialNumber) {
                    Write-Verbose -Message "Attempting to get Autopilot device with serial number: $($SerialNumberItem)"
                    $AutopilotDevice = Get-AutopilotDevice -SerialNumber $SerialNumberItem -ErrorAction Stop
                    if ($AutopilotDevice -ne $null) {
                        $AutopilotDevices.Add($AutopilotDevice) | Out-Null
                    }
                    else {
                        Write-Warning -Message "Unable to get Autopilot device with serial number: $($SerialNumberItem)"
                    }
                }

                # Set group tag for all identified Autopilot devices
                if ($AutopilotDevices.Count -ge 1) {
                    if ($PSCmdlet.ShouldProcess("$($AutopilotDevices.Count) Autopilot devices", "Set Group Tag")) {
                        foreach ($AutopilotDevice in $AutopilotDevices) {
                            try {
                                # Set group tag for current Autopilot device
                                Write-Verbose -Message "Setting Group Tag value '$($Value)' for Autopilot device: $($AutopilotDevice.serialNumber)"
                                Set-AutopilotDevice -Id $AutopilotDevice.id -GroupTag $Value -ErrorAction Stop

                                # Handle success output
                                $PSObject = [PSCustomObject]@{
                                    SerialNumber = $AutopilotDevice.serialNumber
                                    GroupTag = $Value
                                    Result = "Success"
                                }
                            }
                            catch [System.Exception] {
                                Write-Warning -Message "An error occurred while setting the Group Tag for Autopilot device with serial number '$($AutopilotDevices.serialNumber)'. Error message: $($PSItem.Exception.Message)"

                                # Handle failure output
                                $PSObject = [PSCustomObject]@{
                                    SerialNumber = $AutopilotDevice.serialNumber
                                    GroupTag = $Value
                                    Result = "Success"
                                }
                            }

                            # Handle current item output return
                            Write-Output -InputObject $PSObject
                        }
                    }
                }
            }
            catch [System.Exception] {
                Write-Warning -Message "An error occurred while retrieving all Autopilot devices matching serial number input. Error message: $($PSItem.Exception.Message)"
            }
        }
        catch [System.Exception] {
            Write-Warning -Message "An error occurred while constructing the authentication header. Error message: $($PSItem.Exception.Message)"
        }
    }
    catch [System.Exception] {
        Write-Warning -Message "An error occurred while attempting to retrieve an authentication token. Error message: $($PSItem.Exception.Message)"
    }
}
