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
  default = ""
}

variable "location" {
  type = string
}

variable "sku" {
  type = string
}

variable "capacity" {
  type = number
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
  type    = bool
  default = false
}

variable "enable_fips" {
  type    = bool
  default = false
}

variable "availability_zones" {
  type    = list(number)
  default = []
}

variable "firewall_policy_resource_id" {
  type    = string
  default = null
}

variable "gateway_ip_configurations" {
  type = list(object({
    name = string
    properties = object({
      subnet = object({
        id = string
      })
    })
  }))
  default = []
}

variable "frontend_ip_configurations" {
  type = list(object({
    name       = string
    properties = any
  }))
  default = []
}

variable "frontend_ports" {
  type = list(object({
    name = string
    properties = object({
      port = number
    })
  }))
  default = []
}

variable "backend_address_pools" {
  type = list(object({
    name       = string
    properties = any
  }))
  default = []
}

variable "backend_http_settings_collection" {
  type = list(object({
    name       = string
    properties = any
  }))
  default = []
}

variable "probes" {
  type = list(object({
    name       = string
    properties = any
  }))
  default = []
}

variable "http_listeners" {
  type = list(object({
    name       = string
    properties = any
  }))
  default = []
}

variable "request_routing_rules" {
  type = list(object({
    name       = string
    properties = any
  }))
  default = []
}

variable "managed_identities" {
  type = object({
    systemAssigned = bool
  })
  default = null
}

variable "role_assignments" {
  type = list(object({
    roleDefinitionIdOrName             = string
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

variable "diagnostic_settings" {
  type = list(object({
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

variable "tags" {
  type    = map(string)
  default = {}
}
