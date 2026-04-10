locals {
  workload_segment    = var.workload_description == null ? "" : "-${var.workload_description}"
  name                = substr("agw-${var.system_abbreviation}-${var.region_abbreviation}-${var.environment_abbreviation}${local.workload_segment}-${var.instance_number}", 0, 80)
  identity_enabled    = var.managed_identities.systemAssigned
}

resource "azurerm_application_gateway" "this" {
  name                = local.name
  resource_group_name = var.resource_group_name
  location            = var.location
  firewall_policy_id  = var.firewall_policy_resource_id
  enable_http2        = var.enable_http2
  fips_enabled        = var.enable_fips
  tags                = var.tags
  zones               = var.availability_zones

  sku {
    name     = var.sku
    tier     = var.sku
    capacity = var.capacity
  }

  dynamic "autoscale_configuration" {
    for_each = [1]
    content {
      min_capacity = var.autoscale_min_capacity
      max_capacity = var.autoscale_max_capacity
    }
  }

  dynamic "identity" {
    for_each = local.identity_enabled ? [1] : []
    content {
      type = "SystemAssigned"
    }
  }

  dynamic "gateway_ip_configuration" {
    for_each = var.gateway_ip_configurations
    content {
      name      = gateway_ip_configuration.value.name
      subnet_id = gateway_ip_configuration.value.subnetResourceId
    }
  }

  dynamic "frontend_ip_configuration" {
    for_each = var.frontend_ip_configurations
    content {
      name                          = frontend_ip_configuration.value.name
      subnet_id                     = frontend_ip_configuration.value.subnetResourceId
      public_ip_address_id          = frontend_ip_configuration.value.publicIpAddressResourceId
      private_ip_address            = frontend_ip_configuration.value.privateIpAddress
      private_ip_address_allocation = frontend_ip_configuration.value.privateIpAllocationMethod
    }
  }

  dynamic "frontend_port" {
    for_each = var.frontend_ports
    content {
      name = frontend_port.value.name
      port = frontend_port.value.port
    }
  }

  dynamic "backend_address_pool" {
    for_each = var.backend_address_pools
    content {
      name         = backend_address_pool.value.name
      fqdns        = [for item in backend_address_pool.value.backendAddresses : item.fqdn if item.fqdn != null]
      ip_addresses = [for item in backend_address_pool.value.backendAddresses : item.ipAddress if item.ipAddress != null]
    }
  }

  dynamic "backend_http_settings" {
    for_each = var.backend_http_settings_collection
    content {
      name                                = backend_http_settings.value.name
      cookie_based_affinity               = backend_http_settings.value.cookieBasedAffinity
      path                                = backend_http_settings.value.path
      port                                = backend_http_settings.value.port
      protocol                            = backend_http_settings.value.protocol
      request_timeout                     = backend_http_settings.value.requestTimeout
      probe_name                          = backend_http_settings.value.probeName
      host_name                           = backend_http_settings.value.hostName
      pick_host_name_from_backend_address = backend_http_settings.value.pickHostNameFromBackendAddress
    }
  }

  dynamic "probe" {
    for_each = var.probes
    content {
      name                                      = probe.value.name
      protocol                                  = probe.value.protocol
      path                                      = probe.value.path
      interval                                  = probe.value.interval
      timeout                                   = probe.value.timeout
      unhealthy_threshold                       = probe.value.unhealthyThreshold
      host                                      = probe.value.host
      pick_host_name_from_backend_http_settings = probe.value.pickHostNameFromBackendHttpSettings
      minimum_servers                           = probe.value.minimumServers
    }
  }

  dynamic "http_listener" {
    for_each = var.http_listeners
    content {
      name                           = http_listener.value.name
      frontend_ip_configuration_name = http_listener.value.frontendIpConfigurationName
      frontend_port_name             = http_listener.value.frontendPortName
      protocol                       = http_listener.value.protocol
      host_name                      = http_listener.value.hostName
      host_names                     = http_listener.value.hostNames
      require_sni                    = http_listener.value.requireServerNameIndication
      ssl_certificate_name           = http_listener.value.sslCertificateName
    }
  }

  dynamic "request_routing_rule" {
    for_each = var.request_routing_rules
    content {
      name                        = request_routing_rule.value.name
      priority                    = request_routing_rule.value.priority
      rule_type                   = request_routing_rule.value.ruleType
      http_listener_name          = request_routing_rule.value.httpListenerName
      backend_address_pool_name   = request_routing_rule.value.backendAddressPoolName
      backend_http_settings_name  = request_routing_rule.value.backendHttpSettingsName
      redirect_configuration_name = request_routing_rule.value.redirectConfigurationName
      url_path_map_name           = request_routing_rule.value.urlPathMapName
    }
  }
}

module "role_assignments" {
  source = "../common-role-assignments"

  scope            = azurerm_application_gateway.this.id
  role_assignments = var.role_assignments
}

module "diagnostic_settings" {
  source = "../common-diagnostic-settings"

  name_prefix         = local.name
  target_resource_id  = azurerm_application_gateway.this.id
  diagnostic_settings = var.diagnostic_settings
}

module "management_lock" {
  source = "../common-management-lock"

  scope       = azurerm_application_gateway.this.id
  name_suffix = local.name
  lock        = var.lock
}
