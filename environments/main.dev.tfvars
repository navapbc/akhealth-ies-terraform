workload_name             = "878RVZ"
location                  = "eastus2"
environment_name          = "dev"
system_abbreviation       = "iep"
environment_abbreviation  = "dev"
instance_number           = "002"
workload_description      = ""
existing_log_analytics_id = null

deploy_private_networking = true
deploy_postgresql         = true

tags = {
  environment = "dev"
  workload    = "456TRF"
  managedBy   = "terraform"
}

spoke_network_config = {
  ingressOption                     = "frontDoor"
  vnetAddressSpace                  = "10.240.0.0/20"
  appSvcSubnetAddressSpace          = "10.240.0.0/26"
  privateEndpointSubnetAddressSpace = "10.240.11.0/24"
  postgreSqlPrivateAccessConfig = {
    subnetAddressSpace = "10.240.10.0/28"
  }
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
}

service_plan_config = {
  sku                       = "B1"
  skuCapacity               = 1
  zoneRedundant             = false
  kind                      = "windows"
  existingPlanId            = ""
  elasticScaleEnabled       = false
  maximumElasticWorkerCount = 1
  perSiteScaling            = false
  isCustomMode              = false
  roleAssignments    = []
  diagnosticSettings = []
}

app_service_config = {
  kind                              = "app"
  httpsOnly                         = true
  clientCertEnabled                 = false
  disableBasicPublishingCredentials = true
  publicNetworkAccess               = "Disabled"
  redundancyMode                    = "None"
  scmSiteAlsoStopped                = false
  siteConfig = {
    alwaysOn        = false
    ftpsState       = "FtpsOnly"
    minTlsVersion   = "1.2"
    healthCheckPath = "/healthz"
    http20Enabled   = true
  }
  hyperV = false
  managedIdentities = {
    systemAssigned = true
  }
  enabled                           = true
  storageAccountRequired            = false
  reserved                          = false
  clientAffinityEnabled             = false
  clientAffinityProxyEnabled        = true
  clientAffinityPartitioningEnabled = false
  diagnosticSettings                = []
  slots                             = []
  configs                           = []
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
  tier                              = "Burstable"
  availabilityZone                  = -1
  highAvailabilityZone              = -1
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
  sku                         = "WAF_v2"
  capacity                    = 2
  autoscaleMinCapacity        = 2
  autoscaleMaxCapacity        = 10
  availabilityZones           = [1, 2, 3]
  sslPolicyType               = "Custom"
  sslPolicyName               = ""
  sslPolicyMinProtocolVersion = "TLSv1_2"
  sslPolicyCipherSuites       = []
  sslCertificates             = []
  managedIdentities = {
    systemAssigned = false
  }
  trustedRootCertificates       = []
  authenticationCertificates    = []
  customErrorConfigurations     = []
  enableHttp2                   = true
  enableFips                    = false
  enableRequestBuffering        = false
  enableResponseBuffering       = false
  loadDistributionPolicies      = []
  gatewayIPConfigurations       = []
  frontendIPConfigurations      = []
  frontendPorts                 = []
  backendAddressPools           = []
  backendHttpSettingsCollection = []
  probes                        = []
  httpListeners                 = []
  privateEndpoints              = []
  privateLinkConfigurations     = []
  redirectConfigurations        = []
  rewriteRuleSets               = []
  sslProfiles                   = []
  trustedClientCertificates     = []
  urlPathMaps                   = []
  backendSettingsCollection     = []
  listeners                     = []
  requestRoutingRules           = []
  routingRules                  = []
  roleAssignments               = []
  diagnosticSettings            = []
  wafPolicySettings = {
    mode                   = "Prevention"
    state                  = "Enabled"
    requestBodyCheck       = true
    maxRequestBodySizeInKb = 128
    fileUploadLimitInMb    = 100
  }
  wafManagedRuleSets = [
    {
      ruleSetType    = "OWASP"
      ruleSetVersion = "3.2"
    },
    {
      ruleSetType    = "Microsoft_BotManagerRuleSet"
      ruleSetVersion = "1.0"
    }
  ]
}

front_door_config = {
  managedIdentities = {
    systemAssigned = true
  }
  enableDefaultWafMethodBlock = true
  wafCustomRules              = { rules = [] }
  sku                         = "Premium_AzureFrontDoor"
  wafPolicySettings = {
    enabledState     = "Enabled"
    mode             = "Prevention"
    requestBodyCheck = "Enabled"
  }
  wafManagedRuleSets = [
    {
      ruleSetType        = "Microsoft_DefaultRuleSet"
      ruleSetVersion     = "2.1"
      ruleSetAction      = "Block"
      ruleGroupOverrides = []
    },
    {
      ruleSetType        = "Microsoft_BotManagerRuleSet"
      ruleSetVersion     = "1.0"
      ruleSetAction      = "Block"
      ruleGroupOverrides = []
    }
  ]
  customDomains                   = []
  ruleSets                        = []
  secrets                         = []
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
      name                              = "default"
      autoGeneratedDomainNameLabelScope = "TenantReuse"
      enabledState                      = "Enabled"
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
