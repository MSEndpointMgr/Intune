function Add-IntuneWin32AppAssignment {
    <#
    .SYNOPSIS
        Add an assignment to a Win32 app.

    .DESCRIPTION
        Add an assignment to a Win32 app.

    .PARAMETER TenantName
        Specify the tenant name, e.g. domain.onmicrosoft.com.

    .PARAMETER DisplayName
        Specify the display name for a Win32 application.

    .PARAMETER ID
        Specify the ID for a Win32 application.

    .PARAMETER Target
        Specify the target of the assignment, either AllUsers, AllDevices or Group.

    .PARAMETER Intent
        Specify the intent of the assignment, either required or available.

    .PARAMETER GroupID
        Specify the ID for an Azure AD group.

    .PARAMETER Notification
        Specify the notification setting for the assignment of the Win32 app.

    .PARAMETER ApplicationID
        Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration.

    .PARAMETER PromptBehavior
        Set the prompt behavior when acquiring a token.

    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2020-01-04
        Updated:     2020-01-04

        Version history:
        1.0.0 - (2020-01-04) Function created
        1.0.1 - (2020-04-29) Added support for AllDevices target assignment type
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [parameter(Mandatory = $true, ParameterSetName = "DisplayName", HelpMessage = "Specify the tenant name, e.g. domain.onmicrosoft.com.")]
        [parameter(Mandatory = $true, ParameterSetName = "ID")]
        [ValidateNotNullOrEmpty()]
        [string]$TenantName,

        [parameter(Mandatory = $true, ParameterSetName = "DisplayName", HelpMessage = "Specify the display name for a Win32 application.")]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName,

        [parameter(Mandatory = $true, ParameterSetName = "ID", HelpMessage = "Specify the ID for a Win32 application.")]
        [ValidateNotNullOrEmpty()]
        [string]$ID,

        [parameter(Mandatory = $true, ParameterSetName = "DisplayName", HelpMessage = "Specify the target of the assignment, either AllUsers, AllDevices or Group.")]
        [parameter(Mandatory = $true, ParameterSetName = "ID")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("AllUsers", "AllDevices", "Group")]
        [string]$Target,

        [parameter(Mandatory = $false, ParameterSetName = "DisplayName", HelpMessage = "Specify the intent of the assignment, either required or available.")]
        [parameter(Mandatory = $false, ParameterSetName = "ID")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("required", "available")]
        [string]$Intent = "available",

        [parameter(Mandatory = $false, ParameterSetName = "DisplayName", HelpMessage = "Specify the ID for an Azure AD group.")]
        [parameter(Mandatory = $false, ParameterSetName = "ID")]
        [ValidateNotNullOrEmpty()]
        [string]$GroupID,

        [parameter(Mandatory = $false, ParameterSetName = "DisplayName", HelpMessage = "Specify the notification setting for the assignment of the Win32 app.")]
        [parameter(Mandatory = $false, ParameterSetName = "ID")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("showAll", "showReboot", "hideAll")]
        [string]$Notification = "showAll",
        
        [parameter(Mandatory = $false, ParameterSetName = "DisplayName", HelpMessage = "Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration.")]
        [parameter(Mandatory = $false, ParameterSetName = "ID")]
        [ValidateNotNullOrEmpty()]
        [string]$ApplicationID = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547",
    
        [parameter(Mandatory = $false, ParameterSetName = "DisplayName", HelpMessage = "Set the prompt behavior when acquiring a token.")]
        [parameter(Mandatory = $false, ParameterSetName = "ID")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Auto", "Always", "Never", "RefreshSession")]
        [string]$PromptBehavior = "Auto"        
    )
    Begin {
        # Ensure required auth token exists or retrieve a new one
        Get-AuthToken -TenantName $TenantName -ApplicationID $ApplicationID -PromptBehavior $PromptBehavior

        # Validate group identifier is passed as input if target is set to Group
        if ($Target -like "Group") {
            if (-not($PSBoundParameters["GroupID"])) {
                Write-Warning -Message "Validation failed for parameter input, target set to Group but GroupID parameter was not specified"
            }
        }
    }
    Process {
        switch ($PSCmdlet.ParameterSetName) {
            "DisplayName" {
                $MobileApps = Invoke-IntuneGraphRequest -APIVersion "Beta" -Resource "mobileApps" -Method "GET"
                if ($MobileApps.value.Count -ge 1) {
                    $Win32MobileApps = $MobileApps.value | Where-Object { $_.'@odata.type' -like "#microsoft.graph.win32LobApp" }
                    if ($Win32MobileApps -ne $null) {
                        $Win32App = $Win32MobileApps | Where-Object { $_.displayName -like $DisplayName }
                        if ($Win32App -ne $null) {
                            Write-Verbose -Message "Detected Win32 app with ID: $($Win32App.id)"
                            $Win32AppID = $Win32App.id
                        }
                        else {
                            Write-Warning -Message "Query for Win32 apps returned empty a result, no apps matching the specified search criteria was found"
                        }
                    }
                    else {
                        Write-Warning -Message "Query for Win32 apps returned empty a result, no apps matching type 'win32LobApp' was found in tenant"
                    }
                }
                else {
                    Write-Warning -Message "Query for mobileApps resources returned empty"
                }
            }
            "ID" {
                $Win32AppID = $ID
            }
        }

        if (-not([string]::IsNullOrEmpty($Win32AppID))) {
            # Determine target property body based on parameter input
            switch ($Target) {
                "AllUsers" {
                    $TargetAssignment = @{
                        "@odata.type" = "#microsoft.graph.allLicensedUsersAssignmentTarget"
                    }                    
                }
                "AllDevices" {
                    $TargetAssignment = @{
                        "@odata.type" = "#microsoft.graph.allDevicesAssignmentTarget"
                    }                    
                }
                "Group" {
                    $TargetAssignment = @{
                        "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                        "groupId" = $GroupID
                    }
                }
            }

            # Construct table for Win32 app assignment body
            $Win32AppAssignmentBody = [ordered]@{
                "@odata.type" = "#microsoft.graph.mobileAppAssignment"
                "intent" = $Intent
                "source" = "direct"
                "target" = $TargetAssignment
                "settings" = @{
                    "@odata.type" = "#microsoft.graph.win32LobAppAssignmentSettings"
                    "notifications" = $Notification
                    "restartSettings" = $null
                    "installTimeSettings" = $null
                }
            }

            try {
                # Attempt to call Graph and create new assignment for Win32 app
                $Win32AppAssignmentResponse = Invoke-IntuneGraphRequest -APIVersion "Beta" -Resource "mobileApps/$($Win32AppID)/assignments" -Method "POST" -Body ($Win32AppAssignmentBody | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop
                if ($Win32AppAssignmentResponse.id) {
                    Write-Verbose -Message "Successfully created Win32 app assignment with ID: $($Win32AppAssignmentResponse.id)"
                    Write-Output -InputObject $Win32AppAssignmentResponse
                }
            }
            catch [System.Exception] {
                Write-Warning -Message "An error occurred while creating a Win32 app assignment: $($TargetFilePath). Error message: $($_.Exception.Message)"
            }
        }
        else {
            Write-Warning -Message "Unable to determine the Win32 app identification for assignment"
        }
    }
}