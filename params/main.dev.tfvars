workload_name             = "845FDA"
location                  = "westus2"
environment_name          = "dev"
system_abbreviation       = "iep"
environment_abbreviation  = "dev"
instance_number           = "005"
workload_description      = null
existing_log_analytics_id = null

deploy_private_networking = true
deploy_postgresql         = true

tags = {
  environment = "dev"
  workload    = "456TRF"
  managedBy   = "bicepparam"
}

resource_group_definitions = [
  {
    key                 = "network"
    workloadDescription = "network"
  },
  {
    key                    = "networkEdge"
    workloadDescription    = "network"
    subWorkloadDescription = "edge"
  },
  {
    key                 = "hosting"
    workloadDescription = "hosting"
  },
  {
    key                 = "data"
    workloadDescription = "data"
  },
  {
    key                 = "operations"
    workloadDescription = "operations"
  }
]

spoke_network_config = {
  workloadDescription = null
  ingressOption       = "frontDoor" //options are 'none', 'frontDoor', or 'applicationGateway'
  vnetAddressSpace    = "10.0.0.0/21"
  subnetPlan = [
    {
      key                            = "appService"
      nameSuffix                     = "appservice"
      cidr                           = "10.0.0.0/23"
      create                         = true
      purpose                        = "Primary App Service hosting and integration subnet sized to the full /23 platform plan."
      delegationProfile              = "appServicePlan"
      nsgProfile                     = "appService"
      routeProfile                   = "none"
      privateEndpointNetworkPolicies = "Enabled"
    },
    {
      key               = "applicationGateway"
      nameSuffix        = "appgateway"
      cidr              = "10.0.2.0/24"
      create            = true
      purpose           = "Dedicated regional ingress subnet for Application Gateway if that ingress path is used."
      delegationProfile = "none"
      nsgProfile        = "applicationGateway"
      routeProfile      = "none"
    },
    {
      key               = "apimEdge"
      nameSuffix        = "apim"
      cidr              = "10.0.3.0/24"
      create            = true
      purpose           = "Reserved edge/API subnet for APIM or similar edge services."
      delegationProfile = "none"
      nsgProfile        = "none"
      routeProfile      = "none"
    },
    {
      key                            = "privateEndpoints"
      nameSuffix                     = "privateendpoint"
      cidr                           = "10.0.4.0/24"
      create                         = true
      purpose                        = "Shared private endpoint subnet."
      delegationProfile              = "none"
      nsgProfile                     = "privateEndpoint"
      routeProfile                   = "none"
      privateEndpointNetworkPolicies = "Disabled"
    },
    {
      key               = "privateConnectivityReserve"
      nameSuffix        = "privateconnectivity"
      cidr              = "10.0.5.0/24"
      create            = false
      purpose           = "Reserved growth space for future private connectivity needs."
      delegationProfile = "none"
      nsgProfile        = "none"
      routeProfile      = "none"
    },
    {
      key               = "functions"
      nameSuffix        = "functions"
      cidr              = "10.0.6.0/24"
      create            = true
      purpose           = "Dedicated Functions subnet held in the active /21 platform plan."
      delegationProfile = "none"
      nsgProfile        = "none"
      routeProfile      = "none"
    },
    {
      key               = "logicApps"
      nameSuffix        = "logicapps"
      cidr              = "10.0.7.0/26"
      create            = true
      purpose           = "Dedicated Logic Apps subnet held in the active /21 platform plan."
      delegationProfile = "none"
      nsgProfile        = "none"
      routeProfile      = "none"
    },
    {
      key               = "postgresql"
      nameSuffix        = "postgresql"
      cidr              = "10.0.7.64/27"
      create            = true
      purpose           = "Delegated subnet for PostgreSQL Flexible Server private access."
      delegationProfile = "postgresqlFlexibleServer"
      nsgProfile        = "postgresql"
      routeProfile      = "none"
    },
    {
      key               = "futureDelegatedData"
      nameSuffix        = "futuredata"
      cidr              = "10.0.7.96/27"
      create            = false
      purpose           = "Reserved delegated data subnet for future services."
      delegationProfile = "none"
      nsgProfile        = "none"
      routeProfile      = "none"
    },
    {
      key               = "generalReserve"
      nameSuffix        = "reserve"
      cidr              = "10.0.7.128/25"
      create            = false
      purpose           = "General reserve block retained for future subnet planning flexibility."
      delegationProfile = "none"
      nsgProfile        = "none"
      routeProfile      = "none"
    }
  ]
  enableEgressLockdown              = false
  dnsServers                        = []
  disableBgpRoutePropagation        = true
  encryption                        = false
  encryptionEnforcement             = "AllowUnencrypted"
  flowTimeoutInMinutes              = 0
  enableVmProtection                = false
  enablePrivateEndpointVNetPolicies = "Disabled"
  roleAssignments                   = []
  diagnosticSettings                = []
  nsgDiagnosticSettings = [
    {
      name = "network-allLogs"
      logCategoriesAndGroups = [
        {
          categoryGroup = "allLogs"
        }
      ]
    }
  ]
}

service_plan_config = {
  workloadDescription       = "frontEnd"
  sku                       = "B1"
  skuCapacity               = 1
  zoneRedundant             = false
  kind                      = "windows"
  existingPlanId            = null
  elasticScaleEnabled       = false
  maximumElasticWorkerCount = 1
  perSiteScaling            = false
  isCustomMode              = false
  roleAssignments           = []
  diagnosticSettings        = []
}

app_service_config = {
  workloadDescription               = "frontEnd"
  workloadMode                      = "windowsWebApp"
  httpsOnly                         = true
  disableBasicPublishingCredentials = true
  publicNetworkAccess               = "Disabled"
  siteConfig = {
    alwaysOn        = false
    ftpsState       = "FtpsOnly"
    minTlsVersion   = "1.2"
    healthCheckPath = "/healthz"
    http20Enabled   = true
  }
  managedIdentities = {
    systemAssigned = true
  }
  enabled                        = true
  clientAffinityEnabled          = false
  appSettings                    = {}
  useSolutionApplicationInsights = false
  diagnosticSettings             = []
}

key_vault_config = {
  enablePurgeProtection            = false
  softDeleteRetentionInDays        = 90
  sku                              = "standard"
  enableVaultForDeployment         = true
  enableVaultForTemplateDeployment = true
  enableVaultForDiskEncryption     = true
  publicNetworkAccess              = "Disabled"
  networkAcls = {
    bypass        = "AzureServices"
    defaultAction = "Deny"
  }
  roleAssignments    = []
  diagnosticSettings = []
}

app_insights_config = {
  # Must be lowercase. The Terraform contract validates AzureRM-supported values directly.
  applicationType                 = "web"
  publicNetworkAccessForIngestion = "Enabled"
  publicNetworkAccessForQuery     = "Enabled"
  retentionInDays                 = 90
  samplingPercentage              = 100
  disableLocalAuth                = true
  disableIpMasking                = true
  forceCustomerStorageForProfiler = false
  roleAssignments                 = []
  diagnosticSettings              = []
}

postgresql_admin_group_config = {
  objectId    = "b58ff011-4384-42b9-b25c-26c5dfc26b06"
  displayName = "secgrp-iep-eus2-dev-pgsqladmin-001"
}

postgresql_config = {
  workloadDescription               = "postgresql"
  privateAccessMode                 = "delegatedSubnet"
  skuName                           = "Standard_B1ms"
  availabilityZone                  = null
  highAvailabilityZone              = null
  highAvailability                  = "Disabled"
  backupRetentionDays               = 7
  geoRedundantBackup                = "Disabled"
  storageSizeGB                     = 32
  autoGrow                          = "Enabled"
  version                           = "18"
  publicNetworkAccess               = "Disabled"
  grantAppServiceIdentityReaderRole = true
  databases = [
    {
      name = "appdb"
    }
  ]
  configurations     = []
  roleAssignments    = []
  diagnosticSettings = []
}

app_gateway_config = {
  sku                  = "WAF_v2"
  scaleMode            = "autoscale"
  autoscaleMinCapacity = 2
  autoscaleMaxCapacity = 10
  availabilityZones    = [1, 2, 3]
  managedIdentities = {
    systemAssigned = false
  }
  enableHttp2                   = true
  enableFips                    = false
  gatewayIPConfigurations       = []
  frontendIPConfigurations      = []
  frontendPorts                 = []
  backendAddressPools           = []
  backendHttpSettingsCollection = []
  probes                        = []
  httpListeners                 = []
  requestRoutingRules           = []
  roleAssignments               = []
  diagnosticSettings            = []
}

front_door_config = {
  managedIdentities = {
    systemAssigned = true
  }
  enableDefaultWafMethodBlock = true
  wafCustomRules              = []
  sku                         = "Premium_AzureFrontDoor"
  wafPolicySettings = {
    enabledState     = "Enabled"
    mode             = "Prevention"
    requestBodyCheck = "Enabled"
  }
  wafManagedRuleSets = [
    {
      ruleSetType    = "Microsoft_DefaultRuleSet"
      ruleSetVersion = "2.1"
      ruleSetAction  = "Block"
    },
    {
      ruleSetType    = "Microsoft_BotManagerRuleSet"
      ruleSetVersion = "1.0"
      ruleSetAction  = "Block"
    }
  ]
  roleAssignments                 = []
  originResponseTimeoutSeconds    = 120
  autoApprovePrivateEndpoint      = true
  afdPeAutoApproverIsolationScope = "Regional"
  originGroups = [
    {
      name = "app-default"
      healthProbeSettings = {
        probePath              = "/"
        probeIntervalInSeconds = 100
        probeRequestType       = "GET"
        probeProtocol          = "Https"
      }
      loadBalancingSettings = {
        sampleSize                      = 4
        successfulSamplesRequired       = 3
        additionalLatencyInMilliseconds = 50
      }
      sessionAffinityState                                  = "Disabled"
      trafficRestorationTimeToHealedOrNewEndpointsInMinutes = 10
      origins = [
        {
          name                        = "app-default"
          httpPort                    = 80
          httpsPort                   = 443
          priority                    = 1
          weight                      = 1000
          enabledState                = "Enabled"
          enforceCertificateNameCheck = true
          sharedPrivateLink = {
            requestMessage = "frontdoor"
            groupId        = "sites"
          }
        }
      ]
    }
  ]
  afdEndpoints = [
    {
      name         = "default"
      enabledState = "Enabled"
      routes = [
        {
          name                = "default"
          originGroupName     = "app-default"
          patternsToMatch     = ["/*"]
          forwardingProtocol  = "HttpsOnly"
          linkToDefaultDomain = "Enabled"
          httpsRedirect       = "Enabled"
          enabledState        = "Enabled"
          supportedProtocols  = ["Http", "Https"]
        }
      ]
    }
  ]
  securityPatternsToMatch = ["/*"]
  diagnosticSettings      = []
}

ase_config = {
  clusterSettings = [
    {
      name  = "DisableTls1.0"
      value = "1"
    }
  ]
  dedicatedHostCount                 = 0
  internalLoadBalancingMode          = "Web, Publishing"
  zoneRedundant                      = true
  allowNewPrivateEndpointConnections = true
  remoteDebugEnabled                 = false
  roleAssignments                    = []
  diagnosticSettings                 = []
}

log_analytics_config = {
  sku                                         = "PerGB2018"
  retentionInDays                             = 365
  enableLogAccessUsingOnlyResourcePermissions = false
  disableLocalAuth                            = true
  publicNetworkAccessForIngestion             = "Enabled"
  publicNetworkAccessForQuery                 = "Enabled"
  roleAssignments                             = []
  diagnosticSettings                          = []
}
