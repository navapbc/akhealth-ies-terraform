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

variable "gateway_ip_configurations" {
  type = list(object({
    name             = string
    subnetResourceId = string
  }))
  default = []

  validation {
    condition = (
      length(var.gateway_ip_configurations) > 0 &&
      length(var.gateway_ip_configurations) == length(distinct([
        for configuration in var.gateway_ip_configurations :
        configuration.name
      ]))
    )
    error_message = "gateway_ip_configurations must declare at least one uniquely named gateway subnet configuration."
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

  validation {
    condition = (
      length(var.frontend_ip_configurations) > 0 &&
      length(var.frontend_ip_configurations) == length(distinct([
        for configuration in var.frontend_ip_configurations :
        configuration.name
      ]))
    )
    error_message = "frontend_ip_configurations must declare at least one uniquely named frontend IP configuration."
  }

  validation {
    condition = alltrue([
      for configuration in var.frontend_ip_configurations :
      configuration.publicIpAddressResourceId == null || (
        configuration.privateIpAddress == null &&
        configuration.privateIpAllocationMethod == null
      )
    ])
    error_message = "frontend_ip_configurations using publicIpAddressResourceId must not also set privateIpAddress or privateIpAllocationMethod."
  }
}

variable "frontend_ports" {
  type = list(object({
    name = string
    port = number
  }))
  default = []

  validation {
    condition = (
      length(var.frontend_ports) > 0 &&
      length(var.frontend_ports) == length(distinct([
        for port in var.frontend_ports :
        port.name
      ]))
    )
    error_message = "frontend_ports must declare at least one uniquely named frontend port."
  }

  validation {
    condition = alltrue([
      for port in var.frontend_ports :
      port.port >= 1 && port.port <= 65535
    ])
    error_message = "Each frontend_port.port must be between 1 and 65535."
  }
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
    condition = (
      length(var.backend_address_pools) > 0 &&
      length(var.backend_address_pools) == length(distinct([
        for pool in var.backend_address_pools :
        pool.name
      ]))
    )
    error_message = "backend_address_pools must declare at least one uniquely named backend address pool."
  }

  validation {
    condition = alltrue([
      for pool in var.backend_address_pools :
      length(pool.backendAddresses) > 0
    ])
    error_message = "Each backend_address_pool must declare at least one backend address."
  }

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

  validation {
    condition = (
      length(var.backend_http_settings_collection) > 0 &&
      length(var.backend_http_settings_collection) == length(distinct([
        for settings in var.backend_http_settings_collection :
        settings.name
      ]))
    )
    error_message = "backend_http_settings_collection must declare at least one uniquely named backend HTTP settings entry."
  }

  validation {
    condition = alltrue([
      for settings in var.backend_http_settings_collection :
      contains(["Http", "Https"], settings.protocol)
    ])
    error_message = "Each backend_http_settings_collection.protocol must be Http or Https."
  }

  validation {
    condition = alltrue([
      for settings in var.backend_http_settings_collection :
      !(settings.hostName != null && coalesce(settings.pickHostNameFromBackendAddress, false))
    ])
    error_message = "Each backend_http_settings_collection entry may set hostName or pickHostNameFromBackendAddress, but not both."
  }
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

  validation {
    condition = length(var.probes) == length(distinct([
      for probe in var.probes :
      probe.name
    ]))
    error_message = "probes must use unique names."
  }

  validation {
    condition = alltrue([
      for probe in var.probes :
      contains(["Http", "Https"], probe.protocol)
    ])
    error_message = "Each probe.protocol must be Http or Https."
  }

  validation {
    condition = alltrue([
      for probe in var.probes :
      probe.interval > 0 &&
      probe.timeout > 0 &&
      probe.unhealthyThreshold > 0 &&
      probe.timeout < probe.interval
    ])
    error_message = "Each probe must declare positive interval, timeout, and unhealthyThreshold values, and timeout must be less than interval."
  }
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

  validation {
    condition = (
      length(var.http_listeners) > 0 &&
      length(var.http_listeners) == length(distinct([
        for listener in var.http_listeners :
        listener.name
      ]))
    )
    error_message = "http_listeners must declare at least one uniquely named HTTP listener."
  }

  validation {
    condition = alltrue([
      for listener in var.http_listeners :
      listener.protocol == "Http" && listener.sslCertificateName == null
    ])
    error_message = "http_listeners currently support only Http listeners without sslCertificateName. Add explicit SSL certificate support before allowing Https listeners."
  }
}

variable "request_routing_rules" {
  type = list(object({
    name                    = string
    priority                = number
    httpListenerName        = string
    backendAddressPoolName  = string
    backendHttpSettingsName = string
  }))
  default = []

  validation {
    condition = (
      length(var.request_routing_rules) > 0 &&
      length(var.request_routing_rules) == length(distinct([
        for rule in var.request_routing_rules :
        rule.name
      ]))
    )
    error_message = "request_routing_rules must declare at least one uniquely named routing rule."
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
    name                               = string
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
    name  = string
    notes = optional(string)
  })
  default = null
}

variable "tags" {
  type    = map(string)
  default = {}
}
