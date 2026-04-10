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
  type = string
}

variable "location" {
  type = string
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

variable "tier" {
  type = string
}

variable "availability_zone" {
  type = number
}

variable "high_availability_zone" {
  type = number
}

variable "high_availability" {
  type = string
}

variable "backup_retention_days" {
  type = number
}

variable "geo_redundant_backup" {
  type = string
}

variable "storage_size_gb" {
  type = number
}

variable "auto_grow" {
  type = string
}

variable "engine_version" {
  type = string
}

variable "public_network_access" {
  type = string
}

variable "private_access_mode" {
  type = string
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

variable "tags" {
  type    = map(string)
  default = {}
}
