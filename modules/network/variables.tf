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

variable "vnet_spoke_address_space" {
  type = string
}

variable "subnet_plan" {
  type = list(object({
    key                               = string
    nameSuffix                        = string
    cidr                              = string
    create                            = bool
    purpose                           = optional(string)
    delegationProfile                 = string
    nsgProfile                        = string
    routeProfile                      = string
    privateEndpointNetworkPolicies    = optional(string)
    privateLinkServiceNetworkPolicies = optional(string)
    serviceEndpoints                  = optional(list(string), [])
    defaultOutboundAccess             = optional(bool)
    sharingScope                      = optional(string)
    roleAssignments = optional(list(object({
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
    })), [])
  }))
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "enable_egress_lockdown" {
  type = bool
}

variable "egress_firewall_internal_ip" {
  type    = string
  default = null
}

variable "nsg_diagnostic_settings" {
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

  validation {
    condition = (
      length(var.nsg_diagnostic_settings) <= 1 ||
      alltrue([
        for diagnostic_setting in var.nsg_diagnostic_settings :
        diagnostic_setting.name != null && trimspace(diagnostic_setting.name) != ""
      ])
    )
    error_message = "Multiple nsg_diagnostic_settings entries must each declare an explicit non-empty name."
  }
}

variable "nsg_diagnostic_default_workspace_resource_id" {
  type    = string
  default = null
}

variable "hub_peering_config" {
  type = object({
    virtualNetworkResourceId  = string
    virtualNetworkName        = string
    resourceGroupName         = string
    subscriptionId            = string
    allowForwardedTraffic     = bool
    allowGatewayTransit       = bool
    allowVirtualNetworkAccess = bool
    doNotVerifyRemoteGateways = bool
    useRemoteGateways         = bool
    reversePeeringConfig = optional(object({
      allowForwardedTraffic     = bool
      allowGatewayTransit       = bool
      allowVirtualNetworkAccess = bool
      doNotVerifyRemoteGateways = bool
      useRemoteGateways         = bool
    }))
  })
  default = null
}

variable "dns_servers" {
  type    = list(string)
  default = []
}

variable "ddos_protection_plan_resource_id" {
  type    = string
  default = null
}

variable "vnet_diagnostic_settings" {
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

variable "vnet_lock" {
  type = object({
    kind  = string
    name  = optional(string)
    notes = optional(string)
  })
  default = null
}

variable "disable_bgp_route_propagation" {
  type = bool
}

variable "vnet_role_assignments" {
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

variable "vnet_encryption" {
  type = bool
}

variable "vnet_encryption_enforcement" {
  type = string
}

variable "flow_timeout_in_minutes" {
  type    = number
  default = null
}

variable "virtual_network_bgp_community" {
  type    = string
  default = null
}

variable "private_endpoint_vnet_policies" {
  type    = string
  default = null

  validation {
    condition = (
      var.private_endpoint_vnet_policies == null ||
      contains(["Basic", "Disabled"], var.private_endpoint_vnet_policies)
    )
    error_message = "private_endpoint_vnet_policies must be Basic, Disabled, or null."
  }
}
