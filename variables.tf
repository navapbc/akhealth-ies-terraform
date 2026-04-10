variable "workload_name" {
  type        = string
  default     = "appsvc"
  description = "Suffix used by the source Bicep template. Terraform uses system/environment inputs directly for naming."
}

variable "location" {
  type        = string
  description = "Azure region for the deployment."
}

variable "environment_name" {
  type        = string
  description = "Friendly environment name."
}

variable "system_abbreviation" {
  type        = string
  description = "Owning system abbreviation."
}

variable "environment_abbreviation" {
  type        = string
  description = "Lifecycle environment abbreviation."
}

variable "instance_number" {
  type        = string
  description = "Deterministic instance suffix."
}

variable "workload_description" {
  type        = string
  description = "Optional workload descriptor that participates in naming."
  default     = ""
}

variable "deploy_ase_v3" {
  type        = bool
  default     = false
  description = "Whether to deploy an App Service Environment v3."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to resources."
}

variable "existing_log_analytics_id" {
  type        = string
  default     = null
  description = "Optional existing Log Analytics workspace resource ID."
}

variable "deploy_private_networking" {
  type        = bool
  default     = true
  description = "Whether to deploy private endpoints and private DNS assets."
}

variable "deploy_postgresql" {
  type        = bool
  default     = false
  description = "Whether to deploy PostgreSQL Flexible Server."
}

variable "spoke_network_config" {
  type = object({
    vnetAddressSpace                  = string
    appSvcSubnetAddressSpace          = string
    privateEndpointSubnetAddressSpace = string
    applicationGatewayConfig = optional(object({
      subnetAddressSpace = string
    }))
    postgreSqlPrivateAccessConfig = optional(object({
      subnetAddressSpace = string
    }))
    hubPeeringConfig = optional(object({
      virtualNetworkResourceId  = string
      virtualNetworkName        = string
      resourceGroupName         = string
      subscriptionId            = string
      allowForwardedTraffic     = bool
      allowGatewayTransit       = bool
      allowVirtualNetworkAccess = bool
      doNotVerifyRemoteGateways = bool
      useRemoteGateways         = bool
      reversePeeringConfig = optional(object({
        allowForwardedTraffic     = bool
        allowGatewayTransit       = bool
        allowVirtualNetworkAccess = bool
        doNotVerifyRemoteGateways = bool
        useRemoteGateways         = bool
      }))
    }))
    egressFirewallConfig = optional(object({
      internalIp = string
    }))
    ingressOption                     = string
    enableEgressLockdown              = bool
    dnsServers                        = list(string)
    ddosProtectionPlanResourceId      = optional(string)
    disableBgpRoutePropagation        = bool
    encryption                        = bool
    encryptionEnforcement             = string
    flowTimeoutInMinutes              = number
    enableVmProtection                = bool
    enablePrivateEndpointVNetPolicies = string
    bgpCommunity                      = optional(string)
    lock = optional(object({
      kind  = string
      name  = optional(string)
      notes = optional(string)
    }))
    roleAssignments = optional(list(object({
      roleDefinitionIdOrName             = string
      principalId                        = string
      principalType                      = optional(string)
      description                        = optional(string)
      condition                          = optional(string)
      conditionVersion                   = optional(string)
      delegatedManagedIdentityResourceId = optional(string)
      name                               = optional(string)
    })), [])
    diagnosticSettings = optional(list(object({
      name                                = optional(string)
      workspaceResourceId                 = optional(string)
      logAnalyticsDestinationType         = optional(string)
      storageAccountResourceId            = optional(string)
      eventHubAuthorizationRuleResourceId = optional(string)
      eventHubName                        = optional(string)
      marketplacePartnerResourceId        = optional(string)
      logCategoriesAndGroups = optional(list(object({
        category      = optional(string)
        categoryGroup = optional(string)
      })), [])
      metricCategories = optional(list(object({
        category = string
        enabled  = optional(bool)
      })), [])
    })), [])
  })
  description = "Azure native spoke network configuration object."
}

variable "service_plan_config" {
  type = object({
    sku                       = string
    skuCapacity               = number
    zoneRedundant             = bool
    kind                      = string
    existingPlanId            = string
    workerTierName            = string
    elasticScaleEnabled       = bool
    maximumElasticWorkerCount = number
    perSiteScaling            = bool
    targetWorkerCount         = number
    targetWorkerSize          = number
    virtualNetworkSubnetId    = string
    isCustomMode              = bool
    rdpEnabled                = bool
    installScripts            = list(any)
    planDefaultIdentity       = optional(string)
    registryAdapters          = list(any)
    storageMounts             = list(any)
    managedIdentities = object({
      systemAssigned = bool
    })
    lock = optional(object({
      kind  = string
      name  = optional(string)
      notes = optional(string)
    }))
    roleAssignments = optional(list(object({
      roleDefinitionIdOrName             = string
      principalId                        = string
      principalType                      = optional(string)
      description                        = optional(string)
      condition                          = optional(string)
      conditionVersion                   = optional(string)
      delegatedManagedIdentityResourceId = optional(string)
      name                               = optional(string)
    })), [])
    diagnosticSettings = optional(list(object({
      name                                = optional(string)
      workspaceResourceId                 = optional(string)
      logAnalyticsDestinationType         = optional(string)
      storageAccountResourceId            = optional(string)
      eventHubAuthorizationRuleResourceId = optional(string)
      eventHubName                        = optional(string)
      marketplacePartnerResourceId        = optional(string)
      logCategoriesAndGroups = optional(list(object({
        category      = optional(string)
        categoryGroup = optional(string)
      })), [])
      metricCategories = optional(list(object({
        category = string
        enabled  = optional(bool)
      })), [])
    })), [])
  })
  description = "Azure native App Service Plan configuration object."
}

variable "app_service_config" {
  type = object({
    kind                              = string
    enabled                           = bool
    httpsOnly                         = bool
    clientAffinityEnabled             = bool
    clientCertEnabled                 = bool
    disableBasicPublishingCredentials = bool
    publicNetworkAccess               = optional(string)
    redundancyMode                    = string
    scmSiteAlsoStopped                = bool
    hyperV                            = bool
    storageAccountRequired            = bool
    reserved                          = bool
    clientAffinityProxyEnabled        = bool
    clientAffinityPartitioningEnabled = bool
    managedIdentities = optional(object({
      systemAssigned = bool
    }))
    keyVaultAccessIdentityResourceId = optional(string)
    outboundVnetRouting = optional(object({
      allTraffic = optional(bool)
    }))
    functionHostStorageAccount = optional(object({
      name = string
    }))
    siteConfig = object({
      alwaysOn          = optional(bool)
      ftpsState         = optional(string)
      healthCheckPath   = optional(string)
      http20Enabled     = optional(bool)
      minTlsVersion     = optional(string)
      localMySqlEnabled = optional(bool)
    })
    configs = optional(list(object({
      name                           = string
      properties                     = optional(map(string))
      useSolutionApplicationInsights = optional(bool)
    })), [])
    diagnosticSettings = optional(list(object({
      name                                = optional(string)
      workspaceResourceId                 = optional(string)
      logAnalyticsDestinationType         = optional(string)
      storageAccountResourceId            = optional(string)
      eventHubAuthorizationRuleResourceId = optional(string)
      eventHubName                        = optional(string)
      marketplacePartnerResourceId        = optional(string)
      logCategoriesAndGroups = optional(list(object({
        category      = optional(string)
        categoryGroup = optional(string)
      })), [])
      metricCategories = optional(list(object({
        category = string
        enabled  = optional(bool)
      })), [])
    })), [])
    roleAssignments = optional(list(object({
      roleDefinitionIdOrName             = string
      principalId                        = string
      principalType                      = optional(string)
      description                        = optional(string)
      condition                          = optional(string)
      conditionVersion                   = optional(string)
      delegatedManagedIdentityResourceId = optional(string)
      name                               = optional(string)
    })), [])
    slots = optional(list(any), [])
    lock = optional(object({
      kind  = string
      name  = optional(string)
      notes = optional(string)
    }))
  })
  description = "Azure native App Service configuration object."

  validation {
    condition = (
      !strcontains(lower(var.app_service_config.kind), "functionapp") ||
      var.app_service_config.functionHostStorageAccount != null
    )
    error_message = "app_service_config.functionHostStorageAccount must be provided explicitly when app_service_config.kind is a function app."
  }
}

variable "key_vault_config" {
  type = object({
    enablePurgeProtection     = bool
    softDeleteRetentionInDays = number
    secrets = optional(list(object({
      name        = string
      value       = string
      contentType = optional(string)
      attributes = optional(object({
        exp = optional(number)
        nbf = optional(number)
      }))
      tags = optional(map(string))
    })), [])
    keys = optional(list(object({
      name      = string
      kty       = optional(string)
      keySize   = optional(number)
      curveName = optional(string)
      keyOps    = optional(list(string))
      attributes = optional(object({
        exp = optional(number)
        nbf = optional(number)
      }))
      tags = optional(map(string))
    })), [])
    enableVaultForTemplateDeployment = bool
    enableVaultForDiskEncryption     = bool
    createMode                       = string
    sku                              = string
    enableVaultForDeployment         = bool
    networkAcls = object({
      bypass        = optional(string)
      defaultAction = optional(string)
      ipRules = optional(list(object({
        value = string
      })), [])
      virtualNetworkRules = optional(list(object({
        id = string
      })), [])
    })
    publicNetworkAccess = string
    lock = optional(object({
      kind  = string
      name  = optional(string)
      notes = optional(string)
    }))
    roleAssignments = optional(list(object({
      roleDefinitionIdOrName             = string
      principalId                        = string
      principalType                      = optional(string)
      description                        = optional(string)
      condition                          = optional(string)
      conditionVersion                   = optional(string)
      delegatedManagedIdentityResourceId = optional(string)
      name                               = optional(string)
    })), [])
    diagnosticSettings = optional(list(object({
      name                                = optional(string)
      workspaceResourceId                 = optional(string)
      logAnalyticsDestinationType         = optional(string)
      storageAccountResourceId            = optional(string)
      eventHubAuthorizationRuleResourceId = optional(string)
      eventHubName                        = optional(string)
      marketplacePartnerResourceId        = optional(string)
      logCategoriesAndGroups = optional(list(object({
        category      = optional(string)
        categoryGroup = optional(string)
      })), [])
      metricCategories = optional(list(object({
        category = string
        enabled  = optional(bool)
      })), [])
    })), [])
  })
  description = "Azure native Key Vault configuration object."
}

variable "app_insights_config" {
  type = object({
    applicationType                 = string
    publicNetworkAccessForIngestion = string
    publicNetworkAccessForQuery     = string
    retentionInDays                 = number
    samplingPercentage              = number
    disableLocalAuth                = bool
    disableIpMasking                = bool
    forceCustomerStorageForProfiler = bool
    linkedStorageAccountResourceId  = optional(string)
    flowType                        = optional(string)
    requestSource                   = optional(string)
    kind                            = string
    immediatePurgeDataOn30Days      = optional(bool)
    ingestionMode                   = optional(string)
    lock = optional(object({
      kind  = string
      name  = optional(string)
      notes = optional(string)
    }))
    roleAssignments = optional(list(object({
      roleDefinitionIdOrName             = string
      principalId                        = string
      principalType                      = optional(string)
      description                        = optional(string)
      condition                          = optional(string)
      conditionVersion                   = optional(string)
      delegatedManagedIdentityResourceId = optional(string)
      name                               = optional(string)
    })), [])
    diagnosticSettings = optional(list(object({
      name                                = optional(string)
      workspaceResourceId                 = optional(string)
      logAnalyticsDestinationType         = optional(string)
      storageAccountResourceId            = optional(string)
      eventHubAuthorizationRuleResourceId = optional(string)
      eventHubName                        = optional(string)
      marketplacePartnerResourceId        = optional(string)
      logCategoriesAndGroups = optional(list(object({
        category      = optional(string)
        categoryGroup = optional(string)
      })), [])
      metricCategories = optional(list(object({
        category = string
        enabled  = optional(bool)
      })), [])
    })), [])
  })
  description = "Azure native Application Insights configuration object."
}

variable "app_gateway_config" {
  type = object({
    sku                         = string
    capacity                    = number
    autoscaleMinCapacity        = number
    autoscaleMaxCapacity        = number
    availabilityZones           = list(number)
    sslPolicyType               = string
    sslPolicyName               = string
    sslPolicyMinProtocolVersion = string
    sslPolicyCipherSuites       = list(string)
    sslCertificates             = list(object({ name = string, properties = any }))
    managedIdentities = object({
      systemAssigned = bool
    })
    trustedRootCertificates       = list(object({ name = string, properties = any }))
    authenticationCertificates    = list(object({ name = string, properties = any }))
    customErrorConfigurations     = list(object({ properties = any }))
    enableHttp2                   = bool
    enableFips                    = bool
    enableRequestBuffering        = bool
    enableResponseBuffering       = bool
    loadDistributionPolicies      = list(object({ name = string, properties = any }))
    gatewayIPConfigurations       = list(object({ name = string, properties = object({ subnet = object({ id = string }) }) }))
    frontendIPConfigurations      = list(object({ name = string, properties = any }))
    frontendPorts                 = list(object({ name = string, properties = object({ port = number }) }))
    backendAddressPools           = list(object({ name = string, properties = any }))
    backendHttpSettingsCollection = list(object({ name = string, properties = any }))
    probes                        = list(object({ name = string, properties = any }))
    httpListeners                 = list(object({ name = string, properties = any }))
    privateEndpoints              = list(object({ name = string, properties = any }))
    privateLinkConfigurations     = list(object({ name = string, properties = any }))
    redirectConfigurations        = list(object({ name = string, properties = any }))
    rewriteRuleSets               = list(object({ name = string, properties = any }))
    sslProfiles                   = list(object({ name = string, properties = any }))
    trustedClientCertificates     = list(object({ name = string, properties = any }))
    urlPathMaps                   = list(object({ name = string, properties = any }))
    backendSettingsCollection     = list(object({ name = string, properties = any }))
    listeners                     = list(object({ name = string, properties = any }))
    requestRoutingRules           = list(object({ name = string, properties = any }))
    routingRules                  = list(object({ name = string, properties = any }))
    roleAssignments = optional(list(object({
      roleDefinitionIdOrName             = string
      principalId                        = string
      principalType                      = optional(string)
      description                        = optional(string)
      condition                          = optional(string)
      conditionVersion                   = optional(string)
      delegatedManagedIdentityResourceId = optional(string)
      name                               = optional(string)
    })), [])
    diagnosticSettings = optional(list(object({
      name                                = optional(string)
      workspaceResourceId                 = optional(string)
      logAnalyticsDestinationType         = optional(string)
      storageAccountResourceId            = optional(string)
      eventHubAuthorizationRuleResourceId = optional(string)
      eventHubName                        = optional(string)
      marketplacePartnerResourceId        = optional(string)
      logCategoriesAndGroups = optional(list(object({
        category      = optional(string)
        categoryGroup = optional(string)
      })), [])
      metricCategories = optional(list(object({
        category = string
        enabled  = optional(bool)
      })), [])
    })), [])
    lock = optional(object({
      kind  = string
      name  = optional(string)
      notes = optional(string)
    }))
    wafPolicySettings = object({
      mode                   = string
      state                  = string
      requestBodyCheck       = bool
      maxRequestBodySizeInKb = number
      fileUploadLimitInMb    = number
    })
    wafManagedRuleSets = list(object({
      ruleSetType    = string
      ruleSetVersion = string
    }))
  })
  description = "Azure native Application Gateway configuration object."
}

variable "front_door_config" {
  type = object({
    afdPeAutoApproverIsolationScope = string
    managedIdentities = object({
      systemAssigned = bool
    })
    enableDefaultWafMethodBlock = bool
    wafCustomRules = object({
      rules = optional(list(object({
        name                       = string
        action                     = string
        enabledState               = optional(string)
        priority                   = number
        ruleType                   = optional(string)
        type                       = optional(string)
        rateLimitDurationInMinutes = optional(number)
        rateLimitThreshold         = optional(number)
        matchConditions = optional(list(object({
          matchVariable      = optional(string)
          match_variable     = optional(string)
          operator           = string
          negateCondition    = optional(bool)
          negation_condition = optional(bool)
          matchValue         = optional(list(string))
          match_values       = optional(list(string))
          selector           = optional(string)
          transforms         = optional(list(string))
        })), [])
        conditions = optional(list(object({
          match_variable     = string
          operator           = string
          negation_condition = optional(bool)
          match_values       = optional(list(string))
        })), [])
      })), [])
    })
    customDomains = list(any)
    ruleSets      = list(any)
    secrets       = list(any)
    roleAssignments = optional(list(object({
      roleDefinitionIdOrName             = string
      principalId                        = string
      principalType                      = optional(string)
      description                        = optional(string)
      condition                          = optional(string)
      conditionVersion                   = optional(string)
      delegatedManagedIdentityResourceId = optional(string)
      name                               = optional(string)
    })), [])
    originResponseTimeoutSeconds = number
    autoApprovePrivateEndpoint   = bool
    sku                          = string
    wafPolicySettings = object({
      enabledState     = string
      mode             = string
      requestBodyCheck = string
    })
    wafManagedRuleSets = list(object({
      ruleSetType        = string
      ruleSetVersion     = string
      ruleSetAction      = optional(string)
      ruleGroupOverrides = optional(list(any), [])
    }))
    originGroups = list(object({
      name           = string
      authentication = optional(any)
      healthProbeSettings = optional(object({
        probePath              = optional(string)
        probeIntervalInSeconds = optional(number)
        probeRequestType       = optional(string)
        probeProtocol          = optional(string)
      }))
      loadBalancingSettings = object({
        sampleSize                      = number
        successfulSamplesRequired       = number
        additionalLatencyInMilliseconds = optional(number)
      })
      sessionAffinityState                                  = string
      trafficRestorationTimeToHealedOrNewEndpointsInMinutes = number
      origins = list(object({
        name                        = string
        enabledState                = string
        enforceCertificateNameCheck = bool
        httpPort                    = number
        httpsPort                   = number
        priority                    = number
        weight                      = number
        sharedPrivateLink = optional(object({
          requestMessage = string
          groupId        = string
        }))
      }))
    }))
    afdEndpoints = list(object({
      name = string
      routes = list(object({
        name                = string
        cacheConfiguration  = optional(any)
        customDomainNames   = optional(list(string))
        enabledState        = string
        forwardingProtocol  = string
        httpsRedirect       = string
        linkToDefaultDomain = string
        originGroupName     = string
        originPath          = optional(string)
        patternsToMatch     = list(string)
        ruleSets            = optional(list(string))
        supportedProtocols  = list(string)
      }))
      tags                              = optional(map(string))
      autoGeneratedDomainNameLabelScope = string
      enabledState                      = string
    }))
    securityPatternsToMatch = optional(list(string), ["/*"])
    lock = optional(object({
      kind  = string
      name  = optional(string)
      notes = optional(string)
    }))
    diagnosticSettings = optional(list(object({
      name                                = optional(string)
      workspaceResourceId                 = optional(string)
      logAnalyticsDestinationType         = optional(string)
      storageAccountResourceId            = optional(string)
      eventHubAuthorizationRuleResourceId = optional(string)
      eventHubName                        = optional(string)
      marketplacePartnerResourceId        = optional(string)
      logCategoriesAndGroups = optional(list(object({
        category      = optional(string)
        categoryGroup = optional(string)
      })), [])
      metricCategories = optional(list(object({
        category = string
        enabled  = optional(bool)
      })), [])
    })), [])
  })
  description = "Azure native Front Door configuration object."
}

variable "ase_config" {
  type = object({
    clusterSettings = list(object({
      name  = string
      value = string
    }))
    customDnsSuffix                    = string
    ipsslAddressCount                  = number
    multiSize                          = string
    customDnsSuffixCertificateUrl      = string
    dedicatedHostCount                 = number
    dnsSuffix                          = string
    frontEndScaleFactor                = number
    internalLoadBalancingMode          = string
    zoneRedundant                      = bool
    allowNewPrivateEndpointConnections = bool
    ftpEnabled                         = bool
    inboundIpAddressOverride           = string
    remoteDebugEnabled                 = bool
    upgradePreference                  = string
    lock = optional(object({
      kind  = string
      name  = optional(string)
      notes = optional(string)
    }))
    roleAssignments = optional(list(object({
      roleDefinitionIdOrName             = string
      principalId                        = string
      principalType                      = optional(string)
      description                        = optional(string)
      condition                          = optional(string)
      conditionVersion                   = optional(string)
      delegatedManagedIdentityResourceId = optional(string)
      name                               = optional(string)
    })), [])
    diagnosticSettings = optional(list(object({
      name                                = optional(string)
      workspaceResourceId                 = optional(string)
      logAnalyticsDestinationType         = optional(string)
      storageAccountResourceId            = optional(string)
      eventHubAuthorizationRuleResourceId = optional(string)
      eventHubName                        = optional(string)
      marketplacePartnerResourceId        = optional(string)
      logCategoriesAndGroups = optional(list(object({
        category      = optional(string)
        categoryGroup = optional(string)
      })), [])
      metricCategories = optional(list(object({
        category = string
        enabled  = optional(bool)
      })), [])
    })), [])
  })
  description = "Azure native App Service Environment configuration object."
}

variable "postgresql_admin_group_config" {
  type = object({
    objectId    = string
    displayName = string
  })
  description = "Microsoft Entra group used as PostgreSQL administrator."
}

variable "postgresql_config" {
  type = object({
    workloadDescription               = string
    privateAccessMode                 = string
    skuName                           = string
    tier                              = string
    availabilityZone                  = number
    highAvailabilityZone              = number
    highAvailability                  = string
    backupRetentionDays               = number
    geoRedundantBackup                = string
    storageSizeGB                     = number
    autoGrow                          = string
    version                           = string
    publicNetworkAccess               = string
    grantAppServiceIdentityReaderRole = bool
    databases = optional(list(object({
      name      = string
      collation = optional(string)
      charset   = optional(string)
    })), [])
    configurations = optional(list(object({
      name   = string
      source = optional(string)
      value  = optional(string)
    })), [])
    lock = optional(object({
      kind  = string
      name  = optional(string)
      notes = optional(string)
    }))
    roleAssignments = optional(list(object({
      roleDefinitionIdOrName             = string
      principalId                        = string
      principalType                      = optional(string)
      description                        = optional(string)
      condition                          = optional(string)
      conditionVersion                   = optional(string)
      delegatedManagedIdentityResourceId = optional(string)
      name                               = optional(string)
    })), [])
    diagnosticSettings = optional(list(object({
      name                                = optional(string)
      workspaceResourceId                 = optional(string)
      logAnalyticsDestinationType         = optional(string)
      storageAccountResourceId            = optional(string)
      eventHubAuthorizationRuleResourceId = optional(string)
      eventHubName                        = optional(string)
      marketplacePartnerResourceId        = optional(string)
      logCategoriesAndGroups = optional(list(object({
        category      = optional(string)
        categoryGroup = optional(string)
      })), [])
      metricCategories = optional(list(object({
        category = string
        enabled  = optional(bool)
      })), [])
    })), [])
  })
  description = "Azure native PostgreSQL Flexible Server configuration object."
}

variable "log_analytics_config" {
  type = object({
    sku                                         = string
    retentionInDays                             = number
    enableLogAccessUsingOnlyResourcePermissions = bool
    disableLocalAuth                            = bool
    publicNetworkAccessForIngestion             = string
    publicNetworkAccessForQuery                 = string
    lock = optional(object({
      kind  = string
      name  = optional(string)
      notes = optional(string)
    }))
    roleAssignments = optional(list(object({
      roleDefinitionIdOrName             = string
      principalId                        = string
      principalType                      = optional(string)
      description                        = optional(string)
      condition                          = optional(string)
      conditionVersion                   = optional(string)
      delegatedManagedIdentityResourceId = optional(string)
      name                               = optional(string)
    })), [])
    diagnosticSettings = optional(list(object({
      name                                = optional(string)
      workspaceResourceId                 = optional(string)
      logAnalyticsDestinationType         = optional(string)
      storageAccountResourceId            = optional(string)
      eventHubAuthorizationRuleResourceId = optional(string)
      eventHubName                        = optional(string)
      marketplacePartnerResourceId        = optional(string)
      logCategoriesAndGroups = optional(list(object({
        category      = optional(string)
        categoryGroup = optional(string)
      })), [])
      metricCategories = optional(list(object({
        category = string
        enabled  = optional(bool)
      })), [])
    })), [])
  })
  description = "Azure native Log Analytics configuration object."
}
