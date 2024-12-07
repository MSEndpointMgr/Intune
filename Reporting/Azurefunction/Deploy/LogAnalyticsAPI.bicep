// Define parameters
@description('Provide a name for the Function App that consists of alphanumerics. Name must be globally unique in Azure and cannot start or end with a hyphen.')
param FunctionAppName string
@allowed([
  'Y1'
  'EP1'
  'EP2'
  'EP3'
])

@description('Select the desired App Service Plan of the Function App. Select Y1 for free consumption based deployment.')
param FunctionAppServicePlanSKU string = 'Y1'

@minLength(3)
@maxLength(24)
@description('Provide a name for the Key Vault. Name must be globally unique in Azure and between 3-24 characters, containing only 0-9, a-z, A-Z, and - characters.')
param KeyVaultName string

@description('Provide the name of the existing Log Analytics workspace that has your Intune Diagnostics/Inventory logs.')
param LogAnalyticsWorkspaceName string

//param firstResourceGroupLocationg string = resourceGroup().location
@description('Provide the name of the resource group for your excisting Intune Log Analytics Workspace')
param LogAnalyticsResourceGroup string

@description('Provide any tags required by your organization (optional)')
param Tags object = {}

// Define variables
var UniqueString = uniqueString(resourceGroup().id)
var FunctionAppNameNoDash = replace(FunctionAppName, '-', '')
var FunctionAppNameNoDashUnderScore = replace(FunctionAppNameNoDash, '_', '')
var StorageAccountName = toLower('${take(FunctionAppNameNoDashUnderScore, 17)}${take(UniqueString, 5)}sa')
var FunctionAppServicePlanName = '${FunctionAppName}-fa-plan'
var FunctionAppInsightsName = '${FunctionAppName}-fa-ai'

// Reference excisting Log Analytics Workspace
resource LogAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2020-10-01' existing = {
  name: LogAnalyticsWorkspaceName
  scope: resourceGroup(LogAnalyticsResourceGroup)
}

// Appending variables for secrets 
var WorkSpaceIDSecret = LogAnalyticsWorkspace.properties.customerId
var SharedKeySecret = LogAnalyticsWorkspace.listKeys().primarySharedKey

// Create storage account for Function App
resource storageaccount 'Microsoft.Storage/storageAccounts@2021-02-01' = {
  name: StorageAccountName
  location: resourceGroup().location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties:{
    supportsHttpsTrafficOnly: true
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    allowSharedKeyAccess: true
  }
  tags: Tags
}

// Create app service plan for Function App
resource appserviceplan 'Microsoft.Web/serverfarms@2021-01-15' = {
  name: FunctionAppServicePlanName
  location: resourceGroup().location
  kind: 'Windows'
  sku: {
    name: FunctionAppServicePlanSKU
  }
  tags: Tags
}

// Create application insights for Function App
resource FunctionAppInsightsComponents 'Microsoft.Insights/components@2020-02-02-preview' = {
  name: FunctionAppInsightsName
  location: resourceGroup().location
  kind: 'web'
  properties: {
    Application_Type: 'web'
  }
  tags: union(Tags, {
    'hidden-link:${resourceId('Microsoft.Web/sites', FunctionAppInsightsName)}': 'Resource'
  })
}

// Create function app
resource FunctionApp 'Microsoft.Web/sites@2020-12-01' = {
  name: FunctionAppName
  location: resourceGroup().location
  kind: 'functionapp'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appserviceplan.id
    containerSize: 1536
    httpsOnly: true
    siteConfig: {
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      powerShellVersion: '~7'
      scmType: 'None'
      appSettings: [
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageaccount.name};AccountKey=${storageaccount.listKeys().keys[0].value}'
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageaccount.name};AccountKey=${storageaccount.listKeys().keys[0].value}'
        }
        {
          name: 'WEBSITE_CONTENTSHARE'
          value: toLower('LogAnalyticsAPI')
        }
        {
          name: 'WEBSITE_RUN_FROM_PACKAGE'
          value: '1'
        }
        {
          name: 'AzureWebJobsDisableHomepage'
          value: 'true'
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~3'
        }
        {
          name: 'FUNCTIONS_WORKER_PROCESS_COUNT'
          value: '3'
        }
        {
          name: 'PSWorkerInProcConcurrencyUpperBound'
          value: '10'
        }
        {
          name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
          value: reference(FunctionAppInsightsComponents.id, '2020-02-02-preview').InstrumentationKey
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: reference(FunctionAppInsightsComponents.id, '2020-02-02-preview').ConnectionString
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'powershell'
        }
        {
          name: 'TenantID'
          value: subscription().tenantId
        }
        {
          name: 'CustomerID'
          value: '@Microsoft.KeyVault(VaultName=${KeyVaultName};SecretName=WorkSpaceID)'
        }
        {
          name: 'SharedKey'
          value: '@Microsoft.KeyVault(VaultName=${KeyVaultName};SecretName=SharedKey)'
        }
      ]
    }
  }
  tags: Tags
}

// Create Key Vault
resource KeyVault 'Microsoft.KeyVault/vaults@2019-09-01' = {
  name: KeyVaultName
  location: resourceGroup().location
  properties: {
    enabledForDeployment: false
    enabledForTemplateDeployment: false
    enabledForDiskEncryption: false
    tenantId: subscription().tenantId
    accessPolicies: [
      {
        tenantId: FunctionApp.identity.tenantId
        objectId: FunctionApp.identity.principalId
        permissions: {
          secrets: [
            'get'
            'list'
          ]
        }
      }
    ]
    sku: {
      name: 'standard'
      family: 'A'
    }
  }
  resource WorkspaceID 'secrets' = {
    name: 'WorkSpaceID'
    properties: {
    value: WorkSpaceIDSecret
    }
  }
  resource SharedKey 'secrets' = {
    name: 'SharedKey'
    properties: {
      value: SharedKeySecret
    }
  }
}

// Add ZipDeploy for Function App
resource FunctionAppZipDeploy 'Microsoft.Web/sites/extensions@2015-08-01' = {
  parent: FunctionApp
  name: 'ZipDeploy'
  properties: {
      packageUri: 'https://github.com/MSEndpointMgr/Intune/releases/download/v0.9/LogAnalyticsAPI.zip'
  }
}

