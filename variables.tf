variable "workload_name" {
  type        = string
  default     = "appsvc"
  description = "Suffix used by the source Bicep template. Terraform uses system/environment inputs directly for naming."
}

variable "location" {
  type        = string
  description = "Azure region for the deployment."

  validation {
    condition = contains([
      "eastus",
      "eastus2",
      "westus",
      "westus2",
      "westus3",
      "centralus",
      "northcentralus",
      "southcentralus",
      "westcentralus",
    ], var.location)
    error_message = "location must be one of the repo-supported Azure regions."
  }
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
  description = "Optional workload descriptor that participates in naming. Use null to omit it."
  default     = null

  validation {
    condition     = var.workload_description == null || trimspace(var.workload_description) != ""
    error_message = "workload_description must be null or a non-empty string."
  }
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

variable "resource_group_definitions" {
  type = list(object({
    key                    = string
    workloadDescription    = string
    subWorkloadDescription = optional(string)
  }))
  description = "Definitions of the solution-managed resource groups keyed by category."

  validation {
    condition = (
      length(var.resource_group_definitions) == length(distinct([
        for definition in var.resource_group_definitions :
        definition.key
      ])) &&
      length(setsubtract(
        toset([for definition in var.resource_group_definitions : definition.key]),
        toset(["network", "networkEdge", "hosting", "data", "operations"])
      )) == 0 &&
      length(setsubtract(
        toset(["network", "networkEdge", "hosting", "data", "operations"]),
        toset([for definition in var.resource_group_definitions : definition.key])
      )) == 0
    )
    error_message = "resource_group_definitions must contain exactly one entry for each required key: network, networkEdge, hosting, data, and operations."
  }

  validation {
    condition = alltrue([
      for definition in var.resource_group_definitions :
      trimspace(definition.workloadDescription) != "" &&
      (
        definition.subWorkloadDescription == null ||
        trimspace(definition.subWorkloadDescription) != ""
      )
    ])
    error_message = "Each resource_group_definitions entry must declare a non-empty workloadDescription, and subWorkloadDescription must be omitted or non-empty."
  }
}

variable "existing_log_analytics_id" {
  type        = string
  default     = null
  description = "Optional existing Log Analytics workspace resource ID. When omitted, Terraform creates the workspace in the operations resource group."

  validation {
    condition     = var.existing_log_analytics_id == null || trimspace(var.existing_log_analytics_id) != ""
    error_message = "existing_log_analytics_id must be null or a non-empty string."
  }
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
    vnetAddressSpace                           = string
    appSvcSubnetAddressSpace                   = string
    appSvcSubnetDefaultOutboundAccess          = optional(bool)
    privateEndpointSubnetAddressSpace          = string
    privateEndpointSubnetDefaultOutboundAccess = optional(bool)
    applicationGatewayConfig = optional(object({
      subnetAddressSpace    = string
      defaultOutboundAccess = optional(bool)
    }))
    postgreSqlPrivateAccessConfig = optional(object({
      subnetAddressSpace    = string
      defaultOutboundAccess = optional(bool)
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
    flowTimeoutInMinutes              = optional(number)
    bgpCommunity                      = optional(string)
    enablePrivateEndpointVNetPolicies = optional(string)
    lock = optional(object({
      kind  = string
      name  = optional(string)
      notes = optional(string)
    }))
    roleAssignments = optional(list(object({
      key                                = string
      roleDefinitionId                   = optional(string)
      roleDefinitionName                 = optional(string)
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
    nsgDiagnosticSettings = optional(list(object({
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

  validation {
    condition = (
      var.spoke_network_config.ingressOption != "applicationGateway" ||
      (
        var.spoke_network_config.applicationGatewayConfig != null &&
        trimspace(var.spoke_network_config.applicationGatewayConfig.subnetAddressSpace) != ""
      )
    )
    error_message = "spoke_network_config.applicationGatewayConfig.subnetAddressSpace must be provided when ingressOption is applicationGateway."
  }

  validation {
    condition = (
      !var.spoke_network_config.enableEgressLockdown ||
      (
        var.spoke_network_config.egressFirewallConfig != null &&
        trimspace(var.spoke_network_config.egressFirewallConfig.internalIp) != ""
      )
    )
    error_message = "spoke_network_config.egressFirewallConfig.internalIp must be provided when enableEgressLockdown is true."
  }

  validation {
    condition = (
      var.spoke_network_config.enablePrivateEndpointVNetPolicies == null ||
      contains(["Basic", "Disabled"], var.spoke_network_config.enablePrivateEndpointVNetPolicies)
    )
    error_message = "spoke_network_config.enablePrivateEndpointVNetPolicies must be Basic, Disabled, or omitted."
  }
}

variable "service_plan_config" {
  type = object({
    sku                       = string
    skuCapacity               = number
    zoneRedundant             = bool
    kind                      = string
    existingPlanId            = optional(string)
    elasticScaleEnabled       = bool
    maximumElasticWorkerCount = number
    perSiteScaling            = bool
    isCustomMode              = bool
    lock = optional(object({
      kind  = string
      name  = optional(string)
      notes = optional(string)
    }))
    roleAssignments = optional(list(object({
      key                                = string
      roleDefinitionId                   = optional(string)
      roleDefinitionName                 = optional(string)
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

  validation {
    condition     = contains(["windows", "linux"], var.service_plan_config.kind)
    error_message = "service_plan_config.kind must be either windows or linux."
  }

  validation {
    condition     = var.service_plan_config.existingPlanId == null || trimspace(var.service_plan_config.existingPlanId) != ""
    error_message = "service_plan_config.existingPlanId must be null or a non-empty string."
  }
}

variable "app_service_config" {
  type = object({
    workloadMode                      = string
    enabled                           = bool
    httpsOnly                         = bool
    clientAffinityEnabled             = bool
    disableBasicPublishingCredentials = bool
    publicNetworkAccess               = optional(string)
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
    appSettings                    = optional(map(string), {})
    useSolutionApplicationInsights = optional(bool, false)
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
      key                                = string
      roleDefinitionId                   = optional(string)
      roleDefinitionName                 = optional(string)
      principalId                        = string
      principalType                      = optional(string)
      description                        = optional(string)
      condition                          = optional(string)
      conditionVersion                   = optional(string)
      delegatedManagedIdentityResourceId = optional(string)
      name                               = optional(string)
    })), [])
    lock = optional(object({
      kind  = string
      name  = optional(string)
      notes = optional(string)
    }))
  })
  description = "Azure native App Service configuration object."

  validation {
    condition = contains([
      "windowsWebApp",
      "linuxWebApp",
      "windowsFunctionApp",
      "linuxFunctionApp",
    ], var.app_service_config.workloadMode)
    error_message = "app_service_config.workloadMode must be one of: windowsWebApp, linuxWebApp, windowsFunctionApp, linuxFunctionApp."
  }

  validation {
    condition = (
      !contains(["windowsFunctionApp", "linuxFunctionApp"], var.app_service_config.workloadMode) ||
      var.app_service_config.functionHostStorageAccount != null
    )
    error_message = "app_service_config.functionHostStorageAccount must be provided explicitly when app_service_config.workloadMode is a function app."
  }

  validation {
    condition = (
      contains(["windowsFunctionApp", "linuxFunctionApp"], var.app_service_config.workloadMode) ||
      var.app_service_config.functionHostStorageAccount == null
    )
    error_message = "app_service_config.functionHostStorageAccount must be omitted for web apps."
  }

  validation {
    condition = (
      var.app_service_config.publicNetworkAccess == null ||
      contains(["Enabled", "Disabled"], var.app_service_config.publicNetworkAccess)
    )
    error_message = "app_service_config.publicNetworkAccess must be Enabled, Disabled, or omitted."
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
      key                                = string
      roleDefinitionId                   = optional(string)
      roleDefinitionName                 = optional(string)
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
    lock = optional(object({
      kind  = string
      name  = optional(string)
      notes = optional(string)
    }))
    roleAssignments = optional(list(object({
      key                                = string
      roleDefinitionId                   = optional(string)
      roleDefinitionName                 = optional(string)
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

  validation {
    condition     = contains(["web", "other"], var.app_insights_config.applicationType)
    error_message = "app_insights_config.applicationType must be one of: web, other. Use lowercase values in tfvars."
  }

  validation {
    condition = (
      contains(["Enabled", "Disabled"], var.app_insights_config.publicNetworkAccessForIngestion) &&
      contains(["Enabled", "Disabled"], var.app_insights_config.publicNetworkAccessForQuery)
    )
    error_message = "app_insights_config public network access values must be either Enabled or Disabled."
  }

  validation {
    condition     = var.app_insights_config.samplingPercentage >= 0 && var.app_insights_config.samplingPercentage <= 100
    error_message = "app_insights_config.samplingPercentage must be between 0 and 100."
  }
}

variable "app_gateway_config" {
  type = object({
    sku                  = string
    scaleMode            = string
    capacity             = optional(number)
    autoscaleMinCapacity = optional(number)
    autoscaleMaxCapacity = optional(number)
    availabilityZones    = list(number)
    managedIdentities = object({
      systemAssigned = bool
    })
    enableHttp2 = bool
    enableFips  = bool
    gatewayIPConfigurations = list(object({
      name             = string
      subnetResourceId = string
    }))
    frontendIPConfigurations = list(object({
      name                      = string
      subnetResourceId          = optional(string)
      publicIpAddressResourceId = optional(string)
      privateIpAddress          = optional(string)
      privateIpAllocationMethod = optional(string)
    }))
    frontendPorts = list(object({
      name = string
      port = number
    }))
    backendAddressPools = list(object({
      name = string
      backendAddresses = optional(list(object({
        fqdn      = optional(string)
        ipAddress = optional(string)
      })), [])
    }))
    backendHttpSettingsCollection = list(object({
      name                           = string
      cookieBasedAffinity            = optional(string)
      path                           = optional(string)
      port                           = number
      protocol                       = string
      requestTimeout                 = optional(number)
      probeName                      = optional(string)
      hostName                       = optional(string)
      pickHostNameFromBackendAddress = optional(bool)
    }))
    probes = list(object({
      name                                = string
      protocol                            = string
      path                                = string
      interval                            = number
      timeout                             = number
      unhealthyThreshold                  = number
      host                                = optional(string)
      pickHostNameFromBackendHttpSettings = optional(bool)
      minimumServers                      = optional(number)
    }))
    httpListeners = list(object({
      name                        = string
      frontendIpConfigurationName = string
      frontendPortName            = string
      protocol                    = string
      hostName                    = optional(string)
      hostNames                   = optional(list(string))
      requireServerNameIndication = optional(bool)
      sslCertificateName          = optional(string)
    }))
    requestRoutingRules = list(object({
      name                    = string
      priority                = number
      httpListenerName        = string
      backendAddressPoolName  = string
      backendHttpSettingsName = string
    }))
    roleAssignments = optional(list(object({
      key                                = string
      roleDefinitionId                   = optional(string)
      roleDefinitionName                 = optional(string)
      principalId                        = string
      principalType                      = optional(string)
      description                        = optional(string)
      condition                          = optional(string)
      conditionVersion                   = optional(string)
      delegatedManagedIdentityResourceId = optional(string)
      name                               = optional(string)
    })), [])
    diagnosticSettings = optional(list(object({
      name                                = string
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
  })
  description = "Azure native Application Gateway configuration object."

  validation {
    condition     = contains(["fixed", "autoscale"], var.app_gateway_config.scaleMode)
    error_message = "app_gateway_config.scaleMode must be fixed or autoscale."
  }

  validation {
    condition = (
      var.app_gateway_config.scaleMode == "fixed" &&
      var.app_gateway_config.capacity != null &&
      var.app_gateway_config.autoscaleMinCapacity == null &&
      var.app_gateway_config.autoscaleMaxCapacity == null
      ) || (
      var.app_gateway_config.scaleMode == "autoscale" &&
      var.app_gateway_config.capacity == null &&
      var.app_gateway_config.autoscaleMinCapacity != null &&
      var.app_gateway_config.autoscaleMaxCapacity != null &&
      var.app_gateway_config.autoscaleMaxCapacity >= var.app_gateway_config.autoscaleMinCapacity
    )
    error_message = "app_gateway_config must declare one explicit scale mode: fixed requires capacity only, and autoscale requires autoscaleMinCapacity and autoscaleMaxCapacity only."
  }
}

variable "front_door_config" {
  type = object({
    managedIdentities = object({
      systemAssigned = bool
    })
    enableDefaultWafMethodBlock = bool
    wafCustomRules = optional(list(object({
      name                       = string
      action                     = string
      enabledState               = optional(string)
      priority                   = number
      type                       = string
      rateLimitDurationInMinutes = optional(number)
      rateLimitThreshold         = optional(number)
      matchConditions = optional(list(object({
        matchVariable   = string
        operator        = string
        negateCondition = optional(bool)
        matchValue      = optional(list(string), [])
        selector        = optional(string)
        transforms      = optional(list(string))
      })), [])
    })), [])
    roleAssignments = optional(list(object({
      key                                = string
      roleDefinitionId                   = optional(string)
      roleDefinitionName                 = optional(string)
      principalId                        = string
      principalType                      = optional(string)
      description                        = optional(string)
      condition                          = optional(string)
      conditionVersion                   = optional(string)
      delegatedManagedIdentityResourceId = optional(string)
      name                               = optional(string)
    })), [])
    originResponseTimeoutSeconds = number
    sku                          = string
    wafPolicySettings = object({
      enabledState     = string
      mode             = string
      requestBodyCheck = string
    })
    wafManagedRuleSets = optional(list(object({
      ruleSetType    = string
      ruleSetVersion = string
      ruleSetAction  = optional(string)
    })), [])
    originGroups = list(object({
      name = string
      healthProbeSettings = optional(object({
        probePath              = string
        probeIntervalInSeconds = number
        probeRequestType       = string
        probeProtocol          = string
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
      name         = string
      enabledState = string
      tags         = optional(map(string))
      routes = list(object({
        name                = string
        enabledState        = string
        forwardingProtocol  = string
        httpsRedirect       = string
        linkToDefaultDomain = string
        originGroupName     = string
        originPath          = optional(string)
        patternsToMatch     = list(string)
        supportedProtocols  = list(string)
      }))
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

  validation {
    condition = (
      length(var.front_door_config.originGroups) > 0 &&
      length(var.front_door_config.originGroups) == length(distinct([
        for origin_group in var.front_door_config.originGroups :
        origin_group.name
      ]))
    )
    error_message = "front_door_config.originGroups must contain at least one uniquely named origin group."
  }

  validation {
    condition = alltrue([
      for origin_group in var.front_door_config.originGroups :
      length(origin_group.origins) > 0
    ])
    error_message = "Each front_door_config.originGroups entry must contain at least one origin."
  }

  validation {
    condition = (
      length(var.front_door_config.afdEndpoints) > 0 &&
      length(var.front_door_config.afdEndpoints) == length(distinct([
        for endpoint in var.front_door_config.afdEndpoints :
        endpoint.name
      ]))
    )
    error_message = "front_door_config.afdEndpoints must contain at least one uniquely named endpoint."
  }

  validation {
    condition = alltrue(flatten([
      for endpoint in var.front_door_config.afdEndpoints : [
        for route in endpoint.routes :
        contains([
          for origin_group in var.front_door_config.originGroups :
          origin_group.name
        ], route.originGroupName)
      ]
    ]))
    error_message = "Each Front Door route must reference an origin group declared in front_door_config.originGroups."
  }
}

variable "ase_config" {
  type = object({
    clusterSettings = list(object({
      name  = string
      value = string
    }))
    dedicatedHostCount                 = number
    internalLoadBalancingMode          = string
    zoneRedundant                      = bool
    allowNewPrivateEndpointConnections = bool
    remoteDebugEnabled                 = bool
    lock = optional(object({
      kind  = string
      name  = optional(string)
      notes = optional(string)
    }))
    roleAssignments = optional(list(object({
      key                                = string
      roleDefinitionId                   = optional(string)
      roleDefinitionName                 = optional(string)
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
  description = "AzureRM-supported App Service Environment configuration object."
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
    availabilityZone                  = optional(number)
    highAvailabilityZone              = optional(number)
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
      key                                = string
      roleDefinitionId                   = optional(string)
      roleDefinitionName                 = optional(string)
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

  validation {
    condition     = contains(["delegatedSubnet", "none"], var.postgresql_config.privateAccessMode)
    error_message = "postgresql_config.privateAccessMode must be delegatedSubnet or none."
  }

  validation {
    condition     = contains(["Disabled", "SameZone", "ZoneRedundant"], var.postgresql_config.highAvailability)
    error_message = "postgresql_config.highAvailability must be Disabled, SameZone, or ZoneRedundant."
  }

  validation {
    condition     = contains(["Enabled", "Disabled"], var.postgresql_config.geoRedundantBackup)
    error_message = "postgresql_config.geoRedundantBackup must be Enabled or Disabled."
  }

  validation {
    condition     = contains(["Enabled", "Disabled"], var.postgresql_config.autoGrow)
    error_message = "postgresql_config.autoGrow must be Enabled or Disabled."
  }

  validation {
    condition     = contains(["Enabled", "Disabled"], var.postgresql_config.publicNetworkAccess)
    error_message = "postgresql_config.publicNetworkAccess must be Enabled or Disabled."
  }

  validation {
    condition = (
      var.postgresql_config.highAvailability == "Disabled" ||
      var.postgresql_config.availabilityZone != null
    )
    error_message = "postgresql_config.availabilityZone must be provided when highAvailability is enabled."
  }

  validation {
    condition = (
      var.postgresql_config.highAvailability != "ZoneRedundant" ||
      var.postgresql_config.highAvailabilityZone != null
    )
    error_message = "postgresql_config.highAvailabilityZone must be provided when highAvailability is ZoneRedundant."
  }
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
      key                                = string
      roleDefinitionId                   = optional(string)
      roleDefinitionName                 = optional(string)
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
