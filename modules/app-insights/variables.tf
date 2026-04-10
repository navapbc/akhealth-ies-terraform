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

variable "workspace_resource_id" {
  type = string
}

variable "application_type" {
  type = string

  validation {
    condition     = contains(["web", "other"], var.application_type)
    error_message = "application_type must be one of: web, other. Use lowercase values."
  }
}

variable "disable_ip_masking" {
  type = bool
}

variable "disable_local_auth" {
  type = bool
}

variable "force_customer_storage_for_profiler" {
  type = bool
}

variable "public_network_access_for_ingestion" {
  type = string

  validation {
    condition     = contains(["Enabled", "Disabled"], var.public_network_access_for_ingestion)
    error_message = "public_network_access_for_ingestion must be either Enabled or Disabled."
  }
}

variable "public_network_access_for_query" {
  type = string

  validation {
    condition     = contains(["Enabled", "Disabled"], var.public_network_access_for_query)
    error_message = "public_network_access_for_query must be either Enabled or Disabled."
  }
}

variable "retention_in_days" {
  type = number
}

variable "sampling_percentage" {
  type = number

  validation {
    condition     = var.sampling_percentage >= 0 && var.sampling_percentage <= 100
    error_message = "sampling_percentage must be between 0 and 100."
  }
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
