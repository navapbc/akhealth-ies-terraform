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
  type = string

  validation {
    condition     = trimspace(var.workload_description) != ""
    error_message = "workload_description must be a non-empty string."
  }
}

variable "location" {
  type = string

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
      "global",
    ], var.location)
    error_message = "location must be one of the supported naming locations for this module."
  }
}

variable "administrator_group_object_id" {
  type = string
}

variable "administrator_group_display_name" {
  type = string
}

variable "administrator_group_tenant_id" {
  type = string
}

variable "sku_name" {
  type = string
}

variable "availability_zone" {
  type    = number
  default = null
}

variable "high_availability_zone" {
  type    = number
  default = null
}

variable "high_availability" {
  type = string

  validation {
    condition     = contains(["Disabled", "SameZone", "ZoneRedundant"], var.high_availability)
    error_message = "high_availability must be Disabled, SameZone, or ZoneRedundant."
  }
}

variable "backup_retention_days" {
  type = number
}

variable "geo_redundant_backup" {
  type = string

  validation {
    condition     = contains(["Enabled", "Disabled"], var.geo_redundant_backup)
    error_message = "geo_redundant_backup must be Enabled or Disabled."
  }
}

variable "storage_size_gb" {
  type = number
}

variable "auto_grow" {
  type = string

  validation {
    condition     = contains(["Enabled", "Disabled"], var.auto_grow)
    error_message = "auto_grow must be Enabled or Disabled."
  }
}

variable "engine_version" {
  type = string
}

variable "public_network_access" {
  type = string

  validation {
    condition     = contains(["Enabled", "Disabled"], var.public_network_access)
    error_message = "public_network_access must be Enabled or Disabled."
  }
}

variable "private_access_mode" {
  type = string

  validation {
    condition     = contains(["delegatedSubnet", "none"], var.private_access_mode)
    error_message = "private_access_mode must be delegatedSubnet or none."
  }
}

variable "delegated_subnet_resource_id" {
  type    = string
  default = null
}

variable "private_dns_zone_virtual_network_links" {
  type = list(object({
    name                     = string
    virtualNetworkResourceId = string
    registrationEnabled      = optional(bool)
    resolutionPolicy         = optional(string)
  }))
  default = []
}

variable "databases" {
  type = list(object({
    name      = string
    collation = optional(string)
    charset   = optional(string)
  }))
  default = []
}

variable "configurations" {
  type = list(object({
    name   = string
    source = optional(string)
    value  = optional(string)
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
    name  = optional(string)
    notes = optional(string)
  })
  default = null
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

variable "tags" {
  type    = map(string)
  default = {}
}
