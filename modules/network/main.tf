locals {
  region_abbreviations = {
    eastus         = "eus"
    eastus2        = "eus2"
    westus         = "wus"
    westus2        = "wus2"
    westus3        = "wus3"
    centralus      = "cus"
    northcentralus = "ncus"
    southcentralus = "scus"
    westcentralus  = "wcus"
    global         = "global"
  }

  region_abbreviation = lookup(local.region_abbreviations, var.location, replace(var.location, " ", ""))
  workload_segment    = trimspace(var.workload_description) == "" ? "" : "-${var.workload_description}"
  shared_name_prefix  = "${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}"
  shared_name_suffix  = "${local.workload_segment}-${var.instance_number}"

  names = {
    vnet_spoke      = substr("vnet-${local.shared_name_prefix}${local.shared_name_suffix}", 0, 80)
    snet_appsvc     = substr("snet-${local.shared_name_prefix}-appservice-${var.instance_number}", 0, 80)
    snet_pe         = substr("snet-${local.shared_name_prefix}-privateendpoint-${var.instance_number}", 0, 80)
    snet_postgresql = substr("snet-${local.shared_name_prefix}-postgresql-${var.instance_number}", 0, 80)
    snet_appgw      = substr("snet-${local.shared_name_prefix}-appgateway-${var.instance_number}", 0, 80)
    nsg_appsvc      = substr("nsg-${local.shared_name_prefix}-appservice-${var.instance_number}", 0, 80)
    nsg_pe          = substr("nsg-${local.shared_name_prefix}-privateendpoint-${var.instance_number}", 0, 80)
    nsg_postgresql  = substr("nsg-${local.shared_name_prefix}-postgresql-${var.instance_number}", 0, 80)
    nsg_ase         = substr("nsg-${local.shared_name_prefix}-ase-${var.instance_number}", 0, 80)
    nsg_appgw       = substr("nsg-${local.shared_name_prefix}-appgateway-${var.instance_number}", 0, 80)
    route_table     = substr("rt-${local.shared_name_prefix}${local.shared_name_suffix}", 0, 80)
    route_name      = substr("route-${local.shared_name_prefix}-egresslockdown-${var.instance_number}", 0, 80)
  }

  deploy_app_gateway                  = var.networking_option == "applicationGateway"
  create_private_endpoint_subnet      = var.deploy_private_networking
  create_postgresql_subnet            = var.deploy_postgresql_private_access
  create_app_gateway_subnet           = local.deploy_app_gateway && try(var.application_gateway_config.subnetAddressSpace, "") != ""
  app_service_delegation              = var.deploy_ase_v3 ? "Microsoft.Web/hostingEnvironments" : "Microsoft.Web/serverFarms"
  app_service_subnet_nsg_id           = var.deploy_ase_v3 ? azurerm_network_security_group.ase[0].id : azurerm_network_security_group.appsvc[0].id
  app_service_private_endpoint_policy = var.deploy_ase_v3 ? "Disabled" : "Enabled"
  nsg_diagnostic_settings = trimspace(var.log_analytics_workspace_id) == "" ? [] : [{
    workspaceResourceId = var.log_analytics_workspace_id
    logCategoriesAndGroups = [{
      categoryGroup = "allLogs"
    }]
  }]
  nsg_diagnostic_targets = merge(
    var.deploy_ase_v3 ? {
      (local.names.nsg_ase) = azurerm_network_security_group.ase[0].id
      } : {
      (local.names.nsg_appsvc) = azurerm_network_security_group.appsvc[0].id
    },
    local.create_private_endpoint_subnet ? {
      (local.names.nsg_pe) = azurerm_network_security_group.private_endpoint[0].id
    } : {},
    local.create_postgresql_subnet ? {
      (local.names.nsg_postgresql) = azurerm_network_security_group.postgresql[0].id
    } : {},
    local.create_app_gateway_subnet ? {
      (local.names.nsg_appgw) = azurerm_network_security_group.app_gateway[0].id
    } : {}
  )
}

resource "azurerm_route_table" "egress" {
  count = var.enable_egress_lockdown && try(var.egress_firewall_config.internalIp, null) != null ? 1 : 0

  name                          = local.names.route_table
  location                      = var.location
  resource_group_name           = var.resource_group_name
  bgp_route_propagation_enabled = !var.disable_bgp_route_propagation
  tags                          = var.tags

  route {
    name                   = local.names.route_name
    address_prefix         = "0.0.0.0/0"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = var.egress_firewall_config.internalIp
  }
}

resource "azurerm_network_security_group" "appsvc" {
  count = var.deploy_ase_v3 ? 0 : 1

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
  count = local.create_private_endpoint_subnet ? 1 : 0

  name                = local.names.nsg_pe
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_network_security_group" "postgresql" {
  count = local.create_postgresql_subnet ? 1 : 0

  name                = local.names.nsg_postgresql
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_network_security_group" "ase" {
  count = var.deploy_ase_v3 ? 1 : 0

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
  count = local.deploy_app_gateway ? 1 : 0

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
  name                    = local.names.vnet_spoke
  location                = var.location
  resource_group_name     = var.resource_group_name
  address_space           = [var.vnet_spoke_address_space]
  dns_servers             = var.dns_servers
  flow_timeout_in_minutes = var.flow_timeout_in_minutes > 0 ? var.flow_timeout_in_minutes : null
  bgp_community           = var.virtual_network_bgp_community
  tags                    = var.tags

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

resource "azurerm_subnet" "app_service" {
  name                              = local.names.snet_appsvc
  resource_group_name               = var.resource_group_name
  virtual_network_name              = azurerm_virtual_network.this.name
  address_prefixes                  = [var.subnet_spoke_appsvc_address_space]
  private_endpoint_network_policies = local.app_service_private_endpoint_policy

  delegation {
    name = "app-service-delegation"

    service_delegation {
      name    = local.app_service_delegation
      actions = ["Microsoft.Network/virtualNetworks/subnets/action"]
    }
  }
}

resource "azurerm_subnet" "private_endpoint" {
  count = local.create_private_endpoint_subnet ? 1 : 0

  name                              = local.names.snet_pe
  resource_group_name               = var.resource_group_name
  virtual_network_name              = azurerm_virtual_network.this.name
  address_prefixes                  = [var.subnet_spoke_private_endpoint_address_space]
  private_endpoint_network_policies = "Disabled"
}

resource "azurerm_subnet" "postgresql" {
  count = local.create_postgresql_subnet ? 1 : 0

  name                              = local.names.snet_postgresql
  resource_group_name               = var.resource_group_name
  virtual_network_name              = azurerm_virtual_network.this.name
  address_prefixes                  = [var.postgresql_private_access_config.subnetAddressSpace]
  private_endpoint_network_policies = "Enabled"

  delegation {
    name = "postgresql-flexible-server"

    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_subnet" "app_gateway" {
  count = local.create_app_gateway_subnet ? 1 : 0

  name                 = local.names.snet_appgw
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [var.application_gateway_config.subnetAddressSpace]
}

resource "azurerm_subnet_network_security_group_association" "app_service" {
  subnet_id                 = azurerm_subnet.app_service.id
  network_security_group_id = local.app_service_subnet_nsg_id
}

resource "azurerm_subnet_route_table_association" "app_service" {
  count = length(azurerm_route_table.egress) == 0 ? 0 : 1

  subnet_id      = azurerm_subnet.app_service.id
  route_table_id = azurerm_route_table.egress[0].id
}

resource "azurerm_subnet_network_security_group_association" "private_endpoint" {
  count = local.create_private_endpoint_subnet ? 1 : 0

  subnet_id                 = azurerm_subnet.private_endpoint[0].id
  network_security_group_id = azurerm_network_security_group.private_endpoint[0].id
}

resource "azurerm_subnet_network_security_group_association" "postgresql" {
  count = local.create_postgresql_subnet ? 1 : 0

  subnet_id                 = azurerm_subnet.postgresql[0].id
  network_security_group_id = azurerm_network_security_group.postgresql[0].id
}

resource "azurerm_subnet_network_security_group_association" "app_gateway" {
  count = local.create_app_gateway_subnet ? 1 : 0

  subnet_id                 = azurerm_subnet.app_gateway[0].id
  network_security_group_id = azurerm_network_security_group.app_gateway[0].id
}

module "nsg_diagnostic_settings" {
  for_each = local.nsg_diagnostic_targets

  source = "../common-diagnostic-settings"

  name_prefix        = each.key
  target_resource_id = each.value
  diagnostic_settings = [for diagnostic_setting in local.nsg_diagnostic_settings : merge(diagnostic_setting, {
    name = "${each.key}-diagnosticSettings"
  })]
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

  name_prefix         = local.names.vnet_spoke
  target_resource_id  = azurerm_virtual_network.this.id
  diagnostic_settings = var.vnet_diagnostic_settings
}

module "vnet_management_lock" {
  source = "../common-management-lock"

  scope       = azurerm_virtual_network.this.id
  name_suffix = local.names.vnet_spoke
  lock        = var.vnet_lock
}
