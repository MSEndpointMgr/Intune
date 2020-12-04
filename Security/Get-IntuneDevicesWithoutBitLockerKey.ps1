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

        [parameter(Mandatory = $true, ParameterSetName = "POST", HelpMessage = "Specify the body construct.")]
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
                        $RequestParams.Add("Body", $Body)
                        $RequestParams.Add("ContentType", $ContentType)
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
                $ExceptionItem = $PSItem
                if ($ExceptionItem.Exception.Response.StatusCode -like "429") {
                    # Detected throttling based from response status code
                    $RetryInSeconds = $ExceptionItem.Exception.Response.Headers["Retry-After"]

                    # Wait for given period of time specified in response headers
                    Write-Verbose -Message "Graph is throttling the request, will retry in '$($RetryInSeconds)' seconds"
                    Start-Sleep -Seconds $RetryInSeconds
                }
                else {
                    # Read the response stream
                    $StreamReader = New-Object -TypeName "System.IO.StreamReader" -ArgumentList @($ExceptionItem.Exception.Response.GetResponseStream())
                    $StreamReader.BaseStream.Position = 0
                    $StreamReader.DiscardBufferedData()
                    $ResponseBody = ($StreamReader.ReadToEnd() | ConvertFrom-Json)
                    
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
        }
        until ($GraphResponseProcess -eq $false)

        # Handle return value
        return $GraphResponseList
    }
}

# Install PSIntuneAuth module
Install-Module -Name "PSIntuneAuth"

# Get authentication token
$AuthToken = Get-MSIntuneAuthToken -TenantName "<tenant_name>.onmicrosoft.com" -ClientID "<client_id>" -PromptBehavior "Always"

# Amend header with additional required parameters for bitLocker/recoveryKeys resource query
$AuthToken.Add("ocp-client-name", "My App")
$AuthToken.Add("ocp-client-version", "1.0")

# Retrieve all available BitLocker recovery keys, select only desired properties
$BitLockerRecoveryKeys = Invoke-MSGraphOperation -Get -APIVersion "Beta" -Resource "bitlocker/recoveryKeys?`$select=id,createdDateTime,deviceId" -Headers $AuthToken -Verbose

# Retrieve all managed Windows devices in Intune
$ManagedDevices = Invoke-MSGraphOperation -Get -APIVersion "v1.0" -Resource "deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows'&select=azureADDeviceId&`$select=azureADDeviceId,deviceName" -Headers $AuthToken -Verbose

# Select only managed devices that doesn't have a recovery key
$ManagedDevices | Where-Object { $PSItem.azureADDeviceId -notin $BitLockerRecoveryKeys.deviceId }