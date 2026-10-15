// HVMC-LabResult-Func - secure serverless deployment (Azure Functions Flex Consumption)
// Horizon Valley Medical Center | Author: Sabitha S Karanavar
//
// Identity : system-assigned managed identity; shared-key access disabled on both storage accounts
// IAM      : Storage Blob Data Reader on ONE container of the ePHI account; Blob Data Owner only on the
//            function's own runtime account (deployment package + host state)
// Network  : outbound via VNet integration (HVMC-Func-Subnet); inbound only via a private endpoint
//            (public network access disabled); storage reachable only through private endpoints
// Transport: HTTPS only, TLS 1.2 minimum, FTP/basic publishing credentials disabled
//
// Deploy (not run in this lab): az deployment group create -g HVMC-CloudSecurity-RG -f main.bicep

param location string = resourceGroup().location
param vnetName string = 'HVMC-Prod-VNet'
param funcSubnetPrefix string = '10.0.6.0/26'
param peSubnetPrefix string = '10.0.5.0/27'
param functionAppName string = 'hvmc-labresult-func'
param suffix string = uniqueString(resourceGroup().id)

var ephiAccountName = 'hvmcphi${suffix}'
var runtimeAccountName = 'hvmcfrt${suffix}'
var blobDataReader = '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'
var blobDataOwner = 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'

resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' existing = {
  name: vnetName
}

resource funcSubnet 'Microsoft.Network/virtualNetworks/subnets@2023-11-01' = {
  parent: vnet
  name: 'HVMC-Func-Subnet'
  properties: {
    addressPrefix: funcSubnetPrefix
    delegations: [ { name: 'flex', properties: { serviceName: 'Microsoft.App/environments' } } ]
  }
}

resource peSubnet 'Microsoft.Network/virtualNetworks/subnets@2023-11-01' = {
  parent: vnet
  name: 'HVMC-PE-Subnet'
  properties: {
    addressPrefix: peSubnetPrefix
    privateEndpointNetworkPolicies: 'Enabled'
  }
  dependsOn: [ funcSubnet ]          // subnets of one VNet must be updated one at a time
}

// ---------- storage: ePHI (data) and runtime (function host) - both private, keyless
var storageProps = {
  publicNetworkAccess: 'Disabled'
  allowSharedKeyAccess: false
  allowBlobPublicAccess: false
  minimumTlsVersion: 'TLS1_2'
  supportsHttpsTrafficOnly: true
  networkAcls: { defaultAction: 'Deny', bypass: 'None' }
}

resource ephi 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: ephiAccountName
  location: location
  sku: { name: 'Standard_ZRS' }
  kind: 'StorageV2'
  properties: storageProps
}

resource ephiBlob 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: ephi
  name: 'default'
  properties: {
    isVersioningEnabled: true
    deleteRetentionPolicy: { enabled: true, days: 30 }
  }
}

resource labResults 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: ephiBlob
  name: 'lab-results'
  properties: { publicAccess: 'None' }
}

resource runtime 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: runtimeAccountName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: storageProps
}

resource runtimeBlob 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: runtime
  name: 'default'
}

resource packages 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: runtimeBlob
  name: 'app-package'
  properties: { publicAccess: 'None' }
}

// ---------- private DNS + private endpoints
resource blobDns 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.blob.${environment().suffixes.storage}'
  location: 'global'
}

resource sitesDns 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.azurewebsites.net'
  location: 'global'
}

resource blobDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: blobDns
  name: 'hvmc-vnet'
  location: 'global'
  properties: { virtualNetwork: { id: vnet.id }, registrationEnabled: false }
}

resource sitesDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: sitesDns
  name: 'hvmc-vnet'
  location: 'global'
  properties: { virtualNetwork: { id: vnet.id }, registrationEnabled: false }
}

var endpoints = [
  { name: 'pe-ephi-blob', target: ephi.id, group: 'blob', zone: blobDns.id }
  { name: 'pe-runtime-blob', target: runtime.id, group: 'blob', zone: blobDns.id }
  { name: 'pe-func-sites', target: func.id, group: 'sites', zone: sitesDns.id }
]

resource pes 'Microsoft.Network/privateEndpoints@2023-11-01' = [for e in endpoints: {
  name: e.name
  location: location
  properties: {
    subnet: { id: peSubnet.id }
    privateLinkServiceConnections: [ { name: e.name, properties: { privateLinkServiceId: e.target, groupIds: [ e.group ] } } ]
  }
}]

resource peZones 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-11-01' = [for (e, i) in endpoints: {
  parent: pes[i]
  name: 'default'
  properties: { privateDnsZoneConfigs: [ { name: e.group, properties: { privateDnsZoneId: e.zone } } ] }
}]

// ---------- function app (Flex Consumption, Python 3.11)
resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: '${functionAppName}-plan'
  location: location
  kind: 'functionapp'
  sku: { name: 'FC1', tier: 'FlexConsumption' }
  properties: { reserved: true }
}

resource func 'Microsoft.Web/sites@2023-12-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    publicNetworkAccess: 'Disabled'
    virtualNetworkSubnetId: funcSubnet.id
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${runtime.properties.primaryEndpoints.blob}app-package'
          authentication: { type: 'SystemAssignedIdentity' }
        }
      }
      runtime: { name: 'python', version: '3.11' }
      scaleAndConcurrency: { maximumInstanceCount: 40, instanceMemoryMB: 2048 }
    }
    siteConfig: {
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      http20Enabled: true
      appSettings: [
        { name: 'AzureWebJobsStorage__accountName', value: runtime.name }
        { name: 'EPHI_ACCOUNT_URL', value: ephi.properties.primaryEndpoints.blob }
        { name: 'EPHI_CONTAINER', value: 'lab-results' }
      ]
    }
  }
}

resource noFtp 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  parent: func
  name: 'ftp'
  properties: { allow: false }
}

resource noScmBasic 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  parent: func
  name: 'scm'
  properties: { allow: false }
}

// ---------- IAM: least privilege
resource readLabResults 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: labResults                                         // one container, read-only
  name: guid(labResults.id, func.id, blobDataReader)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', blobDataReader)
    principalId: func.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource ownRuntime 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: runtime                                            // the function's own state account only
  name: guid(runtime.id, func.id, blobDataOwner)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', blobDataOwner)
    principalId: func.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

output functionPrincipalId string = func.identity.principalId
output ephiAccount string = ephi.name
