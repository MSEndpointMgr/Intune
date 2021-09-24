<#
    .SYNOPSIS
    Automated script for delayed targeting based on a set timerange. 
    .DESCRIPTION
    Add devices to group X hours after enrolled to Intune to avoid certain scripts and packages to be targeted during provisioning. 
     .PARAMETERS
    TargetingGroupID: The ObjectID of the group you are maintainging in Azure AD
    .NOTES
        Author:      Jan Ketil Skanke 
        Contact:     @JankeSkanke
        Created:     2021-06-14 
        Updated:     2021-06-14
        Version history:
        1.0.0 - (2021-09-22 ) Production Ready version
#>  

function Get-MSIAccessTokenGraph{
    $resourceURL = "https://graph.microsoft.com/" 
    $response = [System.Text.Encoding]::Default.GetString((Invoke-WebRequest -UseBasicParsing -Uri "$($env:IDENTITY_ENDPOINT)?resource=$resourceURL" -Method 'GET' -Headers @{'X-IDENTITY-HEADER' = "$env:IDENTITY_HEADER"; 'Metadata' = 'True'}).RawContentStream.ToArray()) | ConvertFrom-Json 
    $accessToken = $response.access_token

    #Create Global Authentication Header
    $Global:AuthenticationHeader = @{
    "Content-Type" = "application/json"
    "Authorization" = "Bearer " + $accessToken
    }
return $AuthenticationHeader
}

$TargetingGroupID = "<ENTER YOUR GROUPS OBJECTID FROM AZURE AD>" # Or use a Automation Account Variable 
#Connect to AzAccount for AZOperations 
$Connecting = Connect-AzAccount -Identity 

#Connect to Graph for Graph Operations 
$Response = Get-MSIAccessTokenGraph

#Set timeslot to check for new devices to add 
$starttime = Get-Date((Get-Date).AddHours(-28)) -Format "yyyy-MM-ddTHH:mm:ssZ"
$endtime = Get-Date((Get-Date).AddHours(-4)) -Format "yyyy-MM-ddTHH:mm:ssZ"

# Fetch all newly deployed MTRs and process them (Change filter if your are not using for MTRs) 
$Devices = Invoke-MSGraphOperation -APIVersion Beta -Get -Resource "deviceManagement/manageddevices?filter=startswith(deviceName, 'MTR-') and ((enrolleddatetime+lt+$($endtime)) and (enrolleddatetime+gt+$($starttime)))"
#This line below can be used for the first run to add all targeted devices up until -x hours. 
#$Devices = Invoke-MSGraphOperation -APIVersion Beta -Get -Resource "deviceManagement/manageddevices?filter=startswith(deviceName, 'MTR-') and (enrolleddatetime+lt+$($endtime))"

# Fetch all devices currently in group 
$DeviceIDsInGroup = (Get-AzADGroupMember -GroupObjectId $TargetingGroupID).Id
if (-not([string]::IsNullOrEmpty($Devices))){
  foreach($device in $devices){
    $DeviceID = $device.azureADDeviceId
    $DirectoryObjectID = (Invoke-MSGraphOperation -APIVersion Beta -Get -Resource "devices?filter=deviceId+eq+`'$DeviceID`'").id
    if (-not ($DirectoryObjectID -in $DeviceIDsInGroup)){            
      try {
        Add-AzADGroupMember -MemberObjectId $DirectoryObjectID -TargetGroupObjectId $TargetingGroupID -ErrorAction Stop
        Write-Output "Added $($device.deviceName) with ID $($DirectoryObjectID) to group"
      } catch {
        Write-Output "Failed to add $($device.deviceName) to group. Message: $($_.Exception.Message)"
        }
        } else {
          Write-Output "$($device.deviceName) with ID $($DirectoryObjectID) already in group"
        }
    }
} else {
  Write-Output "No new devices to process this time, exiting script"
}
