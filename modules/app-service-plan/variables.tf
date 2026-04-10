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

variable "sku_name" {
  type = string
}

variable "sku_capacity" {
  type = number
}

variable "service_plan_kind" {
  type = string

  validation {
    condition     = contains(["windows", "linux"], var.service_plan_kind)
    error_message = "service_plan_kind must be either windows or linux."
  }
}

variable "app_service_environment_resource_id" {
  type    = string
  default = null
}

variable "per_site_scaling" {
  type = bool
}

variable "maximum_elastic_worker_count" {
  type = number
}

variable "elastic_scale_enabled" {
  type = bool
}

variable "zone_redundant" {
  type = bool
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

variable "tags" {
  type    = map(string)
  default = {}
}
