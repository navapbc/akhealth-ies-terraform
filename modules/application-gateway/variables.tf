variable "resource_group_name" {
  type = string
}

variable "system_abbreviation" {
  type = string
}

variable "environment_abbreviation" {
  type = string
}

variable "instance_number" {
  type = string
}

variable "region_abbreviation" {
  type = string
}

variable "workload_description" {
  type    = string
  default = null

  validation {
    condition     = var.workload_description == null || trimspace(var.workload_description) != ""
    error_message = "workload_description must be null or a non-empty string."
  }
}

variable "location" {
  type = string
}

variable "sku" {
  type = string
}

variable "scale_mode" {
  type = string

  validation {
    condition     = contains(["fixed", "autoscale"], var.scale_mode)
    error_message = "scale_mode must be either fixed or autoscale."
  }
}

variable "capacity" {
  type    = number
  default = null
}

variable "autoscale_min_capacity" {
  type    = number
  default = null
}

variable "autoscale_max_capacity" {
  type    = number
  default = null
}

variable "enable_http2" {
  type = bool
}

variable "enable_fips" {
  type = bool
}

variable "availability_zones" {
  type = list(number)
}

variable "firewall_policy_resource_id" {
  type    = string
  default = null
}

variable "gateway_ip_configurations" {
  type = list(object({
    name             = string
    subnetResourceId = string
  }))
  default = []

  validation {
    condition     = length(var.gateway_ip_configurations) > 0
    error_message = "gateway_ip_configurations must declare at least one gateway subnet configuration."
  }
}

variable "frontend_ip_configurations" {
  type = list(object({
    name                      = string
    subnetResourceId          = optional(string)
    publicIpAddressResourceId = optional(string)
    privateIpAddress          = optional(string)
    privateIpAllocationMethod = optional(string)
  }))
  default = []

  validation {
    condition = alltrue([
      for configuration in var.frontend_ip_configurations :
      ((configuration.subnetResourceId != null) != (configuration.publicIpAddressResourceId != null))
    ])
    error_message = "Each frontend_ip_configuration must set exactly one of subnetResourceId or publicIpAddressResourceId."
  }
}

variable "frontend_ports" {
  type = list(object({
    name = string
    port = number
  }))
  default = []
}

variable "backend_address_pools" {
  type = list(object({
    name = string
    backendAddresses = optional(list(object({
      fqdn      = optional(string)
      ipAddress = optional(string)
    })), [])
  }))
  default = []

  validation {
    condition = alltrue(flatten([
      for pool in var.backend_address_pools : [
        for address in pool.backendAddresses :
        length(compact([
          address.fqdn,
          address.ipAddress,
        ])) == 1
      ]
    ]))
    error_message = "Each backend address must set exactly one of fqdn or ipAddress."
  }
}

variable "backend_http_settings_collection" {
  type = list(object({
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
  default = []
}

variable "probes" {
  type = list(object({
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
  default = []
}

variable "http_listeners" {
  type = list(object({
    name                        = string
    frontendIpConfigurationName = string
    frontendPortName            = string
    protocol                    = string
    hostName                    = optional(string)
    hostNames                   = optional(list(string))
    requireServerNameIndication = optional(bool)
    sslCertificateName          = optional(string)
  }))
  default = []

  validation {
    condition = alltrue([
      for listener in var.http_listeners :
      !(listener.hostName != null && listener.hostNames != null)
    ])
    error_message = "Each http_listener may set hostName or hostNames, but not both."
  }
}

variable "request_routing_rules" {
  type = list(object({
    name                      = string
    priority                  = optional(number)
    ruleType                  = string
    httpListenerName          = string
    backendAddressPoolName    = optional(string)
    backendHttpSettingsName   = optional(string)
    redirectConfigurationName = optional(string)
    urlPathMapName            = optional(string)
  }))
  default = []

  validation {
    condition = alltrue([
      for rule in var.request_routing_rules :
      (
        rule.ruleType == "Basic" &&
        (
          (
            rule.backendAddressPoolName != null &&
            rule.backendHttpSettingsName != null &&
            rule.redirectConfigurationName == null &&
            rule.urlPathMapName == null
          ) ||
          (
            rule.backendAddressPoolName == null &&
            rule.backendHttpSettingsName == null &&
            rule.redirectConfigurationName != null &&
            rule.urlPathMapName == null
          )
        )
      ) || (
        rule.ruleType == "PathBasedRouting" &&
        rule.urlPathMapName != null &&
        rule.backendAddressPoolName == null &&
        rule.backendHttpSettingsName == null &&
        rule.redirectConfigurationName == null
      )
    ])
    error_message = "request_routing_rules must declare one explicit routing shape: Basic rules need backendAddressPoolName/backendHttpSettingsName or redirectConfigurationName, and PathBasedRouting rules need urlPathMapName."
  }
}

variable "managed_identities" {
  type = object({
    systemAssigned = bool
  })
}

variable "role_assignments" {
  type = list(object({
    key                                = string
    roleDefinitionId                   = optional(string)
    roleDefinitionName                 = optional(string)
    principalId                        = string
    principalType                      = optional(string)
    description                        = optional(string)
    condition                          = optional(string)
    conditionVersion                   = optional(string)
    delegatedManagedIdentityResourceId = optional(string)
    name                                = string
  }))
  default = []
}

variable "diagnostic_settings" {
  type = list(object({
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
  }))
  default = []
}

variable "lock" {
  type = object({
    kind  = string
    name                                = string
    notes = optional(string)
  })
  default = null
}

variable "tags" {
  type    = map(string)
  default = {}
}
