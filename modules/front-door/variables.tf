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

variable "workload_description" {
  type    = string
  default = null

  validation {
    condition     = var.workload_description == null || trimspace(var.workload_description) != ""
    error_message = "workload_description must be null or a non-empty string."
  }
}

variable "sku" {
  type = string
}

variable "managed_identities" {
  type = object({
    systemAssigned = bool
  })
}

variable "origin_response_timeout_seconds" {
  type = number
}

variable "origin_groups" {
  type = list(object({
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

  validation {
    condition = (
      length(var.origin_groups) > 0 &&
      length(var.origin_groups) == length(distinct([
        for origin_group in var.origin_groups :
        origin_group.name
      ]))
    )
    error_message = "origin_groups must contain at least one uniquely named origin group."
  }

  validation {
    condition = alltrue([
      for origin_group in var.origin_groups :
      length(origin_group.origins) > 0
    ])
    error_message = "Each origin group must contain at least one origin."
  }
}

variable "afd_endpoints" {
  type = list(object({
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

  validation {
    condition = (
      length(var.afd_endpoints) > 0 &&
      length(var.afd_endpoints) == length(distinct([
        for endpoint in var.afd_endpoints :
        endpoint.name
      ]))
    )
    error_message = "afd_endpoints must contain at least one uniquely named endpoint."
  }

  validation {
    condition = alltrue(flatten([
      for endpoint in var.afd_endpoints : [
        for route in endpoint.routes :
        contains([
          for origin_group in var.origin_groups :
          origin_group.name
        ], route.originGroupName)
      ]
    ]))
    error_message = "Each route must reference an origin group declared in origin_groups."
  }
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
    name                               = optional(string)
  }))
  default = []
}

variable "lock" {
  type = object({
    kind  = string
    name  = optional(string)
    notes = optional(string)
  })
  default = null
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

variable "workload_origin_host_name" {
  type = string
}

variable "workload_origin_resource_id" {
  type = string
}

variable "workload_origin_location" {
  type = string
}

variable "tags" {
  type    = map(string)
  default = {}
}
