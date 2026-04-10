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

variable "subnet_resource_id" {
  type = string
}

variable "cluster_settings" {
  type = list(object({
    name  = string
    value = string
  }))
  default = []
}

variable "dedicated_host_count" {
  type    = number
  default = null
}

variable "internal_load_balancing_mode" {
  type    = string
  default = null

  validation {
    condition = var.internal_load_balancing_mode == null || contains([
      "None",
      "Web",
      "Publishing",
      "Web, Publishing",
    ], var.internal_load_balancing_mode)
    error_message = "internal_load_balancing_mode must be one of None, Web, Publishing, or Web, Publishing."
  }
}

variable "allow_new_private_endpoint_connections" {
  type    = bool
  default = null
}

variable "remote_debugging_enabled" {
  type    = bool
  default = null
}

variable "zone_redundant" {
  type    = bool
  default = null
}

variable "role_assignments" {
  type = list(object({
    key                                = optional(string)
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
