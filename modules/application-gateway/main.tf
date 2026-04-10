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
  name                = substr("agw-${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}${local.workload_segment}-${var.instance_number}", 0, 80)
  identity_enabled    = try(var.managed_identities.systemAssigned, false)
}

resource "azurerm_application_gateway" "this" {
  name                = local.name
  resource_group_name = var.resource_group_name
  location            = var.location
  firewall_policy_id  = var.firewall_policy_resource_id
  enable_http2        = try(var.enable_http2, false)
  fips_enabled        = try(var.enable_fips, false)
  tags                = var.tags
  zones               = try(var.availability_zones, [])

  sku {
    name     = var.sku
    tier     = var.sku
    capacity = var.capacity
  }

  dynamic "autoscale_configuration" {
    for_each = try(var.autoscale_min_capacity, null) == null || try(var.autoscale_max_capacity, null) == null ? [] : [1]
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
    for_each = try(var.gateway_ip_configurations, [])
    content {
      name      = gateway_ip_configuration.value.name
      subnet_id = gateway_ip_configuration.value.properties.subnet.id
    }
  }

  dynamic "frontend_ip_configuration" {
    for_each = try(var.frontend_ip_configurations, [])
    content {
      name                          = frontend_ip_configuration.value.name
      subnet_id                     = try(frontend_ip_configuration.value.properties.subnet.id, null)
      public_ip_address_id          = try(frontend_ip_configuration.value.properties.publicIPAddress.id, null)
      private_ip_address            = try(frontend_ip_configuration.value.properties.privateIPAddress, null)
      private_ip_address_allocation = try(frontend_ip_configuration.value.properties.privateIPAllocationMethod, null)
    }
  }

  dynamic "frontend_port" {
    for_each = try(var.frontend_ports, [])
    content {
      name = frontend_port.value.name
      port = frontend_port.value.properties.port
    }
  }

  dynamic "backend_address_pool" {
    for_each = try(var.backend_address_pools, [])
    content {
      name         = backend_address_pool.value.name
      fqdns        = [for item in try(backend_address_pool.value.properties.backendAddresses, []) : item.fqdn if try(item.fqdn, null) != null]
      ip_addresses = [for item in try(backend_address_pool.value.properties.backendAddresses, []) : item.ipAddress if try(item.ipAddress, null) != null]
    }
  }

  dynamic "backend_http_settings" {
    for_each = try(var.backend_http_settings_collection, [])
    content {
      name                                = backend_http_settings.value.name
      cookie_based_affinity               = try(backend_http_settings.value.properties.cookieBasedAffinity, "Disabled")
      path                                = try(backend_http_settings.value.properties.path, null)
      port                                = backend_http_settings.value.properties.port
      protocol                            = backend_http_settings.value.properties.protocol
      request_timeout                     = try(backend_http_settings.value.properties.requestTimeout, 30)
      probe_name                          = try(backend_http_settings.value.properties.probe.id, null) == null ? null : basename(backend_http_settings.value.properties.probe.id)
      host_name                           = try(backend_http_settings.value.properties.hostName, null)
      pick_host_name_from_backend_address = try(backend_http_settings.value.properties.pickHostNameFromBackendAddress, null)
    }
  }

  dynamic "probe" {
    for_each = try(var.probes, [])
    content {
      name                                      = probe.value.name
      protocol                                  = probe.value.properties.protocol
      path                                      = probe.value.properties.path
      interval                                  = probe.value.properties.interval
      timeout                                   = probe.value.properties.timeout
      unhealthy_threshold                       = probe.value.properties.unhealthyThreshold
      host                                      = try(probe.value.properties.host, null)
      pick_host_name_from_backend_http_settings = try(probe.value.properties.pickHostNameFromBackendHttpSettings, null)
      minimum_servers                           = try(probe.value.properties.minServers, null)
    }
  }

  dynamic "http_listener" {
    for_each = try(var.http_listeners, [])
    content {
      name                           = http_listener.value.name
      frontend_ip_configuration_name = basename(http_listener.value.properties.frontendIPConfiguration.id)
      frontend_port_name             = basename(http_listener.value.properties.frontendPort.id)
      protocol                       = http_listener.value.properties.protocol
      host_name                      = try(http_listener.value.properties.hostName, null)
      host_names                     = try(http_listener.value.properties.hostNames, null)
      require_sni                    = try(http_listener.value.properties.requireServerNameIndication, null)
      ssl_certificate_name           = try(http_listener.value.properties.sslCertificate.id, null) == null ? null : basename(http_listener.value.properties.sslCertificate.id)
    }
  }

  dynamic "request_routing_rule" {
    for_each = try(var.request_routing_rules, [])
    content {
      name                        = request_routing_rule.value.name
      priority                    = try(request_routing_rule.value.properties.priority, null)
      rule_type                   = request_routing_rule.value.properties.ruleType
      http_listener_name          = basename(request_routing_rule.value.properties.httpListener.id)
      backend_address_pool_name   = try(request_routing_rule.value.properties.backendAddressPool.id, null) == null ? null : basename(request_routing_rule.value.properties.backendAddressPool.id)
      backend_http_settings_name  = try(request_routing_rule.value.properties.backendHttpSettings.id, null) == null ? null : basename(request_routing_rule.value.properties.backendHttpSettings.id)
      redirect_configuration_name = try(request_routing_rule.value.properties.redirectConfiguration.id, null) == null ? null : basename(request_routing_rule.value.properties.redirectConfiguration.id)
      url_path_map_name           = try(request_routing_rule.value.properties.urlPathMap.id, null) == null ? null : basename(request_routing_rule.value.properties.urlPathMap.id)
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
