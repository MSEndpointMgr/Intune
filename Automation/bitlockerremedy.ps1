Disable-AzContextAutosave –Scope Process
$connection = Get-AutomationConnection -Name AzureRunAsConnection
$certificate = Get-AutomationCertificate -Name AzureRunAsCertificate
$connectionResult = Connect-AzAccount -ServicePrincipal -Tenant $connection.TenantID -ApplicationId $connection.ApplicationID -CertificateThumbprint $connection.CertificateThumbprint
#write-output $connectionResult

$GraphConnection = Get-MsalToken -ClientCertificate $certificate -ClientId $connection.ApplicationID -TenantId  $connection.TenantID 
$Header =  @{Authorization = "Bearer $($GraphConnection.AccessToken)"}

#write-output $GraphConnection

[string]$WorkspaceID = Get-AutomationVariable -Name 'BitlockerRemedyWorkspaceID'

#Define my query objects 
$ExposedKeysQuery = @'
AuditLogs
| where OperationName == "Read BitLocker key" and TimeGenerated > ago(65m) 
| extend MyDetails = tostring(AdditionalDetails[0].value)
| extend userPrincipalName_ = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| parse MyDetails with * "key ID: '" MyRecoveryKeyID  "'. Backed up from device: '" MyDevice "'" *
| project MyDevice, MyRecoveryKeyID, userPrincipalName_, TimeGenerated
'@

$DeletedKeysQuery = @'
AuditLogs
| where OperationName == "Delete BitLocker key" and TimeGenerated > ago(65m) 
| extend MyRecoveryKeyID = tostring(TargetResources[0].displayName)
| project MyRecoveryKeyID, ActivityDateTime
'@

$IntuneKeyRolloverQuery = @'
IntuneAuditLogs 
| where OperationName == "rotateBitLockerKeys ManagedDevice" and TimeGenerated > ago(65m)  
| extend DeviceID = tostring(parse_json(tostring(parse_json(Properties).TargetObjectIds))[0])
| project DeviceID, ResultType
'@

#Query Log Analytics Audit Logs 
$AllKeyExposures = Invoke-AZOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $ExposedKeysQuery
$MyAutoKeyDeletion = Invoke-AZOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $DeletedKeysQuery
$MyIntuneRolloverActions = Invoke-AZOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $IntuneKeyRolloverQuery

$DeviceToRolloverIDs = @()
foreach($KeyExposure in $AllKeyExposures.Results){
    if ($KeyExposure.MyRecoveryKeyID -in $MyAutoKeyDeletion.Results.MyRecoveryKeyID){
        #Write-Output "Device $($KeyExposure.MyDevice) with key $($KeyExposure.MyRecoveryKeyID) has been replaced OK"
    }elseif ($KeyExposure -notin $MyAutoKeyDeletion.Results.MyRecoveryKeyID) {
        #Write-Output "Device $($KeyExposure.MyDevice) with key $($KeyExposure.MyRecoveryKeyID) needs a rollover"
        $DeviceToRolloverIDs += $KeyExposure.MyDevice
    }
}

if ([string]::IsNullOrEmpty($DeviceToRolloverIDs)){
    Write-Output "Query returned empty. Possibly issues with delay in query"
    } else {
    #Write-Output "Device to rollover IDs $DeviceToRolloverIDs"
    foreach($DeviceToRolloverID in $DeviceToRolloverIDs){
        #write-output $DeviceToRolloverID
        $GetManagedDeviceIDUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?filter=azureADDeviceID eq '$DeviceToRolloverID'"
        #Write-Output $GetManagedDeviceIDUri
        $ManagedDeviceResult = Invoke-RestMethod -Method GET -Uri $GetManagedDeviceIDUri -ContentType "application/json" -Headers $Header -ErrorAction Stop
        write-output "Evaluating $($ManagedDeviceResult.value.deviceName)"
        $ManagedDeviceID = $ManagedDeviceResult.value.id 
        if ($ManagedDeviceID -notin $MyIntuneRolloverActions.Results.DeviceID){
            $RolloverKeyUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$ManagedDeviceID/rotateBitLockerKeys"
            $RolloverKeyResult = Invoke-RestMethod -Method POST -Uri $RolloverKeyUri -ContentType "application/json" -Headers $Header -ErrorAction Stop
            write-output "Recovery Key Rollover invoked on $($ManagedDeviceResult.value.deviceName)"
            } else {
            Write-Output "Intune Rollover has already been performed on $($ManagedDeviceResult.value.deviceName), no action needed"
        }
    }
}
