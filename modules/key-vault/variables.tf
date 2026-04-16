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

variable "secrets" {
  type = list(object({
    name        = string
    value       = string
    contentType = optional(string)
    attributes = optional(object({
      exp = optional(number)
      nbf = optional(number)
    }))
    tags = optional(map(string))
  }))
  default = []
}

variable "keys" {
  type = list(object({
    name      = string
    kty       = optional(string)
    keySize   = optional(number)
    curveName = optional(string)
    keyOps    = optional(list(string))
    attributes = optional(object({
      exp = optional(number)
      nbf = optional(number)
    }))
    tags = optional(map(string))
  }))
  default = []
}

variable "enable_vault_for_deployment" {
  type = bool
}

variable "enable_vault_for_template_deployment" {
  type = bool
}

variable "enable_vault_for_disk_encryption" {
  type = bool
}

variable "soft_delete_retention_in_days" {
  type = number
}

variable "enable_purge_protection" {
  type = bool
}

variable "sku" {
  type = string
}

variable "network_acls" {
  type = object({
    bypass        = optional(string)
    defaultAction = optional(string)
    ipRules = optional(list(object({
      value = string
    })), [])
    virtualNetworkRules = optional(list(object({
      id = string
    })), [])
  })
  default = null
}

variable "public_network_access" {
  type = string
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

variable "enable_default_private_endpoint" {
  type    = bool
  default = false
}

variable "default_private_endpoint_subnet_resource_id" {
  type    = string
  default = null
}

variable "private_endpoint_resource_group_name" {
  type    = string
  default = null
}

variable "default_private_dns_zone_name" {
  type    = string
  default = "privatelink.vaultcore.azure.net"
}

variable "private_dns_zone_resource_group_name" {
  type    = string
  default = null
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

variable "tags" {
  type    = map(string)
  default = {}
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
