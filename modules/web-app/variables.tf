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

variable "workload_mode" {
  type = string

  validation {
    condition = contains([
      "windowsWebApp",
      "linuxWebApp",
      "windowsFunctionApp",
      "linuxFunctionApp",
    ], var.workload_mode)
    error_message = "workload_mode must be one of: windowsWebApp, linuxWebApp, windowsFunctionApp, linuxFunctionApp."
  }
}

variable "server_farm_resource_id" {
  type = string
}

variable "https_only" {
  type = bool
}

variable "client_affinity_enabled" {
  type = bool
}

variable "public_network_access" {
  type    = string
  default = null
}

variable "site_config" {
  type = object({
    alwaysOn          = optional(bool)
    ftpsState         = optional(string)
    healthCheckPath   = optional(string)
    http20Enabled     = optional(bool)
    minTlsVersion     = optional(string)
    localMySqlEnabled = optional(bool)
  })
}

variable "outbound_vnet_routing" {
  type = object({
    allTraffic = optional(bool)
  })
  default = null
}

variable "managed_identities" {
  type = object({
    systemAssigned = bool
  })
  default = null
}

variable "key_vault_access_identity_resource_id" {
  type    = string
  default = null
}

variable "virtual_network_subnet_resource_id" {
  type    = string
  default = null
}

variable "enabled" {
  type = bool
}

variable "disable_basic_publishing_credentials" {
  type    = bool
  default = false
}

variable "app_settings" {
  type    = map(string)
  default = {}
}

variable "use_solution_application_insights" {
  type    = bool
  default = false
}

variable "solution_application_insights_connection_string" {
  type    = string
  default = null
}

variable "function_host_storage_account" {
  type = object({
    name = string
  })
  default = null
}

variable "enable_default_private_endpoint" {
  type    = bool
  default = false
}

variable "default_private_endpoint_subnet_resource_id" {
  type    = string
  default = null
}

variable "default_private_dns_zone_name" {
  type    = string
  default = "privatelink.azurewebsites.net"
}

variable "default_private_dns_zone_virtual_network_links" {
  type = list(object({
    name                     = string
    virtualNetworkResourceId = string
    registrationEnabled      = optional(bool)
    resolutionPolicy         = optional(string)
  }))
  default = []
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

variable "tags" {
  type    = map(string)
  default = {}
}
