<#
.SYNOPSIS
    Monitor all Apple Connectors like Push Notification Certificate, VPP and DEP tokens. 
    This script is written to be used in an Azure Automation runbook to monitor your Intune deployment connectors. 
.DESCRIPTION
    Monitor all Apple Connectors like Push Notification Certificate, VPP and DEP tokens. 

.VARIABLES
All variables must be defines in Azure Automation 
    TenantName 
        Specify the *.onmicrosoft.com name for your tenant. 
    AppID
        Specify the ClientID of the Azure AD App used for unattended authentication to MS Graph API
    AppSecret (encrypted)
        Specify the secret key for authentication to the Azure AD App used for unattended authentication to MS Graph (never write that in side the script it self)
    ApplicationID
        Specify the Application ID of the app registration in Azure AD. By default, the script will attempt to use well known Microsoft Intune PowerShell app registration.
    Uri
        The Uri for the webhook for the Microsoft Teams channel we are sending the alerts too. 

.EXAMPLE
    # Script runs unnatended from Azure Automation - all parameters should be defined in Automation account 
    Monitor-IntuneAppleConnectors.ps1

.NOTES
    FileName:    Monitor-IntuneAppleConnectors.ps1
    Author:      Jan Ketil Skanke
    Contact:     @JankeSkanke
    Created:     2020-01-04
    Updated:     2020-01-04

    Version history:
    1.0.0 - (2020-01-04) First release

    Required modules:
    "Microsoft.graph.intune"
#>
#Define Your Notification Ranges
$AppleMDMPushCertNotificationRange = '30'
$AppleVPPTokenNotificationRange = '30'
$AppleDEPTokenNotificationRange = '30'

# Grab variables frrom automation account - this must match your variable names in Azure Automation Account 
# Example $Uri = Get-AutomationVariable -Name "TeamsChannelUri" means the VariableTeamsChannelUri must exist in Azure Automation with the correct variable. 
$TenantName = Get-AutomationVariable -Name 'TenantName'
$AppID = Get-AutomationVariable -Name "msgraph-clientcred-appid"
$AppSecret = Get-AutomationVariable -Name "msgraph-clientcred-appsecret"
$Uri = Get-AutomationVariable -Name "TeamsChannelUri"
$Now = Get-Date
Function Send-TeamsAlerts {
    [cmdletbinding()]
    Param(
        [string]$uri,
        [string]$ConnectorName,
        [string]$ExpirationStatus,
        [string]$AppleId,
        [string]$ExpDateStr
        )
#Format Message Body for Message Card in Microsoft Teams 
$body = @"
{
    "@type": "MessageCard",
    "@context": "https://schema.org/extensions",
    "summary": "Intune Apple Notification",
    "themeColor": "ffff00",
    "title": "$ExpirationStatus",
    "sections": [
     {
            "activityTitle": "Warning message",
            "activitySubtitle": "$Now",
            "activityImage": "https://github.com/JankeSkanke/imagerepo/blob/master/warning.png?raw=true",
            "facts": [
                {
                    "name": "Connector:",
                    "value": "$ConnectorName"
                },
                {
                    "name": "Status:",
                    "value": "$ExpirationStatus"
                },
                {
                    "name": "AppleID:",
                    "value": "$AppleID"
                },
                {
                    "name": "Expiry Date:",
                    "value": "$ExpDateStr"
                }
            ],
            "text": "Must be renewed by IT Admin before the expiry date."
        }
    ]
}
"@
# Post Message Alert to Teams
Invoke-RestMethod -uri $uri -Method Post -body $body -ContentType 'application/json' | Out-Null
Write-Output $ExpirationStatus
}
#Import Modules
import-module "Microsoft.graph.intune"

# Connect to Intune MSGraph with Client Secret quietly by updating Graph Environment to use our own Azure AD APP and connecting with a ClientSecret 
Update-MSGraphEnvironment -SchemaVersion "beta" -AppId $AppId -AuthUrl "https://login.microsoftonline.com/$TenantName" -Quiet
Connect-MSGraph -ClientSecret $AppSecret -Quiet

# Checking Apple Push Notification Cert 
$ApplePushCert = Get-IntuneApplePushNotificationCertificate
$ApplePushCertExpDate = $ApplePushCert.expirationDateTime
$ApplePushIdentifier = $ApplePushCert.appleIdentifier
$APNExpDate = $ApplePushCertExpDate.ToShortDateString()
    
if ($ApplePushCertExpDate -lt (Get-Date)) {
    $APNExpirationStatus = "MS Intune: Apple MDM Push certificate has already expired"
    Send-TeamsAlerts -uri $uri -ConnectorName "Apple Push Notification Certificate" -ExpirationStatus $APNExpirationStatus -AppleId $ApplePushIdentifier -ExpDateStr $APNExpDate 
}
else {
    $AppleMDMPushCertDaysLeft = ($ApplePushCertExpDate - (Get-Date))
    if ($AppleMDMPushCertDaysLeft.Days -le $AppleMDMPushCertNotificationRange) {
    $APNExpirationStatus = "MSIntune: Apple MDM Push certificate expires in $($AppleMDMPushCertDaysLeft.Days) days"
    Send-TeamsAlerts -uri $uri -ConnectorName "Apple Push Notification Certificate" -ExpirationStatus $APNExpirationStatus -AppleId $ApplePushIdentifier -ExpDateStr $APNExpDate 
    }
    else {
    $APNExpirationStatus = "MSIntune: NOALERT"
    Write-Output "APN Certificate OK"
    }
}
    
# Checking Apple Volume Purchase Program tokens 
$AppleVPPToken = Get-DeviceAppManagement_VppTokens
    
if($AppleVPPToken.Count -ne '0'){
    foreach ($token in $AppleVPPToken){
        $AppleVPPExpDate = $token.expirationDateTime
        $AppleVPPIdentifier = $token.appleId
        $AppleVPPState = $token.state
        $VPPExpDateStr = $AppleVPPExpDate.ToShortDateString()
        if ($AppleVPPState -ne 'valid') {
            $VPPExpirationStatus = "MSIntune: Apple VPP Token is not valid, new token required"
            Send-TeamsAlerts -uri $uri -ConnectorName "VPP Token" -ExpirationStatus $VPPExpirationStatus -AppleId $AppleVPPIdentifier -ExpDateStr $VPPExpDateStr
        }
        else {
        $AppleVPPTokenDaysLeft = ($AppleVPPExpDate - (Get-Date))
            if ($AppleVPPTokenDaysLeft.Days -le $AppleVPPTokenNotificationRange) {$VPPExpirationStatus = "MSIntune: Apple VPP Token expires in $($AppleVPPTokenDaysLeft.Days) days"
            Send-TeamsAlerts -uri $uri -ConnectorName "VPP Token" -ExpirationStatus $VPPExpirationStatus -AppleId $AppleVPPIdentifier -ExpDateStr $VPPExpDateStr
            }
            else {$VPPExpirationStatus = "MSIntune: NOALERT"
            Write-Output "Apple VPP Token OK"
            }
        }
    }
}

# Checking DEP Token
$AppleDEPToken = (Invoke-MSGraphRequest -Url 'https://graph.microsoft.com/beta/deviceManagement/depOnboardingSettings' -HttpMethod GET).value
if ($AppleDeptoken.Count -ne '0'){ 
    foreach ($token in $AppleDEPToken){
        $AppleDEPExpDate = $token.tokenExpirationDateTime
        $AppleDepID = $token.appleIdentifier
        $AppleDEPTokenDaysLeft = ($AppleDEPExpDate - (Get-Date))
        $DEPExpDateStr = $AppleDEPExpDate.ToShortDateString()
        if ($AppleDEPTokenDaysLeft.Days -le $AppleDEPTokenNotificationRange) {
            $AppleDEPExpirationStatus = "MSIntune: Apple DEP Token expires in $($AppleDEPTokenDaysLeft.Days) days"
            Send-TeamsAlerts -uri $uri -ConnectorName "DEP Token" -ExpirationStatus $AppleDEPExpirationStatus -AppleId $AppleDEPId -ExpDateStr $DEPExpDateStr
        }
        else {
            $AppleDEPExpirationStatus = "MSIntune: NOALERT"
            Write-Output "Apple DEP Token OK" 
            }
    }
}
