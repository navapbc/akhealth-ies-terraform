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

variable "tags" {
  type    = map(string)
  default = {}
}

variable "sku" {
  type = string
}

variable "retention_in_days" {
  type = number
}

variable "enable_log_access_using_only_resource_permissions" {
  type = bool
}

variable "disable_local_auth" {
  type = bool
}

variable "public_network_access_for_ingestion" {
  type = string

  validation {
    condition     = contains(["Enabled", "Disabled"], var.public_network_access_for_ingestion)
    error_message = "public_network_access_for_ingestion must be Enabled or Disabled."
  }
}

variable "public_network_access_for_query" {
  type = string

  validation {
    condition     = contains(["Enabled", "Disabled"], var.public_network_access_for_query)
    error_message = "public_network_access_for_query must be Enabled or Disabled."
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
