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

variable "deploy_ase_v3" {
  type = bool
}

variable "deploy_private_networking" {
  type = bool
}

variable "vnet_spoke_address_space" {
  type = string
}

variable "subnet_spoke_appsvc_address_space" {
  type = string
}

variable "subnet_spoke_private_endpoint_address_space" {
  type = string
}

variable "application_gateway_config" {
  type = object({
    subnetAddressSpace = string
  })
  default = null
}

variable "postgresql_private_access_config" {
  type = object({
    subnetAddressSpace = string
  })
  default = null
}

variable "egress_firewall_config" {
  type = object({
    internalIp = string
  })
  default = null
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "enable_egress_lockdown" {
  type = bool
}

variable "networking_option" {
  type = string
}

variable "deploy_postgresql_private_access" {
  type    = bool
  default = false
}

variable "log_analytics_workspace_id" {
  type = string
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

variable "vnet_encryption" {
  type = bool
}

variable "vnet_encryption_enforcement" {
  type = string
}

variable "flow_timeout_in_minutes" {
  type = number
}

variable "enable_vm_protection" {
  type = bool
}

variable "enable_private_endpoint_vnet_policies" {
  type = string
}

variable "virtual_network_bgp_community" {
  type    = string
  default = null
}
