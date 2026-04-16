locals {
  workload_segment   = var.workload_description == null ? "" : "-${var.workload_description}"
  shared_name_prefix = "${var.system_abbreviation}-${var.region_abbreviation}-${var.environment_abbreviation}"
  shared_name_suffix = "${local.workload_segment}-${var.instance_number}"

  names = {
    vnet_spoke  = substr("vnet-${local.shared_name_prefix}${local.shared_name_suffix}", 0, 80)
    nsg_appsvc  = substr("nsg-${local.shared_name_prefix}-appservice-${var.instance_number}", 0, 80)
    nsg_pe      = substr("nsg-${local.shared_name_prefix}-privateendpoint-${var.instance_number}", 0, 80)
    nsg_pgsql   = substr("nsg-${local.shared_name_prefix}-postgresql-${var.instance_number}", 0, 80)
    nsg_ase     = substr("nsg-${local.shared_name_prefix}-ase-${var.instance_number}", 0, 80)
    nsg_appgw   = substr("nsg-${local.shared_name_prefix}-appgateway-${var.instance_number}", 0, 80)
    route_table = substr("rt-${local.shared_name_prefix}${local.shared_name_suffix}", 0, 80)
    route_name  = substr("route-${local.shared_name_prefix}-egresslockdown-${var.instance_number}", 0, 80)
  }

  created_subnets = {
    for subnet in var.subnet_plan :
    subnet.key => subnet
    if subnet.create
  }

  created_subnet_names = {
    for key, subnet in local.created_subnets :
    key => substr("snet-${local.shared_name_prefix}-${subnet.nameSuffix}-${var.instance_number}", 0, 80)
  }

  created_nsg_profiles = toset(distinct([
    for subnet in values(local.created_subnets) :
    subnet.nsgProfile
    if subnet.nsgProfile != "none"
  ]))

  created_route_profiles = toset(distinct([
    for subnet in values(local.created_subnets) :
    subnet.routeProfile
    if subnet.routeProfile != "none"
  ]))

  subnet_delegation_names = {
    appServicePlan           = "Microsoft.Web/serverFarms"
    appServiceEnvironment    = "Microsoft.Web/hostingEnvironments"
    postgresqlFlexibleServer = "Microsoft.DBforPostgreSQL/flexibleServers"
  }

  subnet_nsg_names = {
    appService         = local.names.nsg_appsvc
    privateEndpoint    = local.names.nsg_pe
    postgresql         = local.names.nsg_pgsql
    ase                = local.names.nsg_ase
    applicationGateway = local.names.nsg_appgw
  }

  create_egress_route_table = contains(local.created_route_profiles, "egressLockdown")

  nsg_ids_by_profile = merge(
    contains(local.created_nsg_profiles, "appService") ? { appService = azurerm_network_security_group.appsvc[0].id } : {},
    contains(local.created_nsg_profiles, "privateEndpoint") ? { privateEndpoint = azurerm_network_security_group.private_endpoint[0].id } : {},
    contains(local.created_nsg_profiles, "postgresql") ? { postgresql = azurerm_network_security_group.postgresql[0].id } : {},
    contains(local.created_nsg_profiles, "ase") ? { ase = azurerm_network_security_group.ase[0].id } : {},
    contains(local.created_nsg_profiles, "applicationGateway") ? { applicationGateway = azurerm_network_security_group.app_gateway[0].id } : {}
  )

  nsg_diagnostic_targets = {
    for profile, id in local.nsg_ids_by_profile :
    local.subnet_nsg_names[profile] => id
  }
}

resource "azurerm_route_table" "egress" {
  count = local.create_egress_route_table && var.enable_egress_lockdown ? 1 : 0

  name                          = local.names.route_table
  location                      = var.location
  resource_group_name           = var.resource_group_name
  bgp_route_propagation_enabled = !var.disable_bgp_route_propagation
  tags                          = var.tags

  route {
    name                   = local.names.route_name
    address_prefix         = "0.0.0.0/0"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = var.egress_firewall_internal_ip
  }
}

resource "azurerm_network_security_group" "appsvc" {
  count = contains(local.created_nsg_profiles, "appService") ? 1 : 0

  name                = local.names.nsg_appsvc
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  security_rule {
    name                       = "deny-hop-outbound"
    priority                   = 200
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_ranges    = ["3389", "22"]
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_security_group" "private_endpoint" {
  count = contains(local.created_nsg_profiles, "privateEndpoint") ? 1 : 0

  name                = local.names.nsg_pe
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_network_security_group" "postgresql" {
  count = contains(local.created_nsg_profiles, "postgresql") ? 1 : 0

  name                = local.names.nsg_pgsql
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_network_security_group" "ase" {
  count = contains(local.created_nsg_profiles, "ase") ? 1 : 0

  name                = local.names.nsg_ase
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  security_rule {
    name                       = "SSL_WEB_443"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_security_group" "app_gateway" {
  count = contains(local.created_nsg_profiles, "applicationGateway") ? 1 : 0

  name                = local.names.nsg_appgw
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  security_rule {
    name                       = "AllowGatewayManager"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "65200-65535"
    source_address_prefix      = "GatewayManager"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowHTTPS"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowHTTP"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowAzureLoadBalancer"
    priority                   = 130
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "AzureLoadBalancer"
    destination_address_prefix = "*"
  }
}

resource "azurerm_virtual_network" "this" {
  name                           = local.names.vnet_spoke
  location                       = var.location
  resource_group_name            = var.resource_group_name
  address_space                  = [var.vnet_spoke_address_space]
  dns_servers                    = var.dns_servers
  flow_timeout_in_minutes        = var.flow_timeout_in_minutes == null || var.flow_timeout_in_minutes == 0 ? null : var.flow_timeout_in_minutes
  bgp_community                  = var.virtual_network_bgp_community
  private_endpoint_vnet_policies = var.private_endpoint_vnet_policies
  tags                           = var.tags

  dynamic "ddos_protection_plan" {
    for_each = var.ddos_protection_plan_resource_id == null ? [] : [var.ddos_protection_plan_resource_id]
    content {
      id     = ddos_protection_plan.value
      enable = true
    }
  }

  dynamic "encryption" {
    for_each = var.vnet_encryption ? [1] : []
    content {
      enforcement = var.vnet_encryption_enforcement
    }
  }
}

resource "azurerm_subnet" "this" {
  for_each = local.created_subnets

  name                              = local.created_subnet_names[each.key]
  resource_group_name               = var.resource_group_name
  virtual_network_name              = azurerm_virtual_network.this.name
  address_prefixes                  = [each.value.cidr]
  default_outbound_access_enabled   = try(each.value.defaultOutboundAccess, null)
  private_endpoint_network_policies = try(each.value.privateEndpointNetworkPolicies, null)
  private_link_service_network_policies_enabled = (
    try(each.value.privateLinkServiceNetworkPolicies, null) == null ?
    null :
    each.value.privateLinkServiceNetworkPolicies == "Enabled"
  )
  service_endpoints = try(each.value.serviceEndpoints, [])
  sharing_scope     = try(each.value.sharingScope, null)

  dynamic "delegation" {
    for_each = each.value.delegationProfile == "none" ? [] : [each.value.delegationProfile]
    content {
      name = local.subnet_delegation_names[delegation.value]

      service_delegation {
        name = local.subnet_delegation_names[delegation.value]
        actions = delegation.value == "postgresqlFlexibleServer" ? [
          "Microsoft.Network/virtualNetworks/subnets/join/action",
          ] : [
          "Microsoft.Network/virtualNetworks/subnets/action",
        ]
      }
    }
  }
}

resource "azurerm_subnet_network_security_group_association" "this" {
  for_each = {
    for key, subnet in local.created_subnets :
    key => subnet
    if subnet.nsgProfile != "none"
  }

  subnet_id                 = azurerm_subnet.this[each.key].id
  network_security_group_id = local.nsg_ids_by_profile[each.value.nsgProfile]
}

resource "azurerm_subnet_route_table_association" "this" {
  for_each = local.create_egress_route_table && var.enable_egress_lockdown ? {
    for key, subnet in local.created_subnets :
    key => subnet
    if subnet.routeProfile == "egressLockdown"
  } : {}

  subnet_id      = azurerm_subnet.this[each.key].id
  route_table_id = azurerm_route_table.egress[0].id
}

module "subnet_role_assignments" {
  for_each = {
    for key, subnet in local.created_subnets :
    key => subnet
    if length(try(subnet.roleAssignments, [])) > 0
  }

  source = "../common-role-assignments"

  scope            = azurerm_subnet.this[each.key].id
  role_assignments = each.value.roleAssignments
}

module "nsg_diagnostic_settings" {
  for_each = local.nsg_diagnostic_targets

  source = "../common-diagnostic-settings"

  target_resource_id = each.value
  diagnostic_settings = [
    for diagnostic_setting in var.nsg_diagnostic_settings :
    merge(diagnostic_setting, {
      name                = diagnostic_setting.name == null ? "${each.key}-diagnosticSettings" : diagnostic_setting.name
      workspaceResourceId = diagnostic_setting.workspaceResourceId == null ? var.nsg_diagnostic_default_workspace_resource_id : diagnostic_setting.workspaceResourceId
    })
  ]
}

resource "azurerm_virtual_network_peering" "spoke_to_hub" {
  count = var.hub_peering_config == null ? 0 : 1

  name                         = substr("peer-${local.shared_name_prefix}-hub-${var.instance_number}", 0, 80)
  resource_group_name          = var.resource_group_name
  virtual_network_name         = azurerm_virtual_network.this.name
  remote_virtual_network_id    = var.hub_peering_config.virtualNetworkResourceId
  allow_virtual_network_access = var.hub_peering_config.allowVirtualNetworkAccess
  allow_forwarded_traffic      = var.hub_peering_config.allowForwardedTraffic
  allow_gateway_transit        = var.hub_peering_config.allowGatewayTransit
  use_remote_gateways          = var.hub_peering_config.useRemoteGateways
}

module "vnet_role_assignments" {
  source = "../common-role-assignments"

  scope            = azurerm_virtual_network.this.id
  role_assignments = var.vnet_role_assignments
}

module "vnet_diagnostic_settings" {
  source = "../common-diagnostic-settings"

  target_resource_id  = azurerm_virtual_network.this.id
  diagnostic_settings = var.vnet_diagnostic_settings
}

module "vnet_management_lock" {
  source = "../common-management-lock"

  scope       = azurerm_virtual_network.this.id
  name_suffix = local.names.vnet_spoke
  lock        = var.vnet_lock
}
