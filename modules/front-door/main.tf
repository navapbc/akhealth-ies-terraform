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
  name                = substr("afd-${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}${local.workload_segment}-${var.instance_number}", 0, 260)
  origin_groups = {
    for origin_group in try(var.config.originGroups, []) :
    origin_group.name => origin_group
  }
  endpoints = {
    for endpoint in try(var.config.afdEndpoints, []) :
    endpoint.name => merge(endpoint, {
      resolved_name = substr("fde-${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}-${endpoint.name}-${var.instance_number}", 0, 260)
    })
  }
  routes = merge([
    for endpoint_name, endpoint in local.endpoints : {
      for route in try(endpoint.routes, []) :
      "${endpoint_name}/${route.name}" => merge(route, {
        endpoint_name = endpoint_name
      })
    }
  ]...)
  front_door_identity_type = try(var.config.managedIdentities.systemAssigned, false) ? "SystemAssigned" : null
}

resource "azurerm_cdn_frontdoor_profile" "this" {
  name                     = local.name
  resource_group_name      = var.resource_group_name
  sku_name                 = var.config.sku
  response_timeout_seconds = try(var.config.originResponseTimeoutSeconds, 120)
  tags                     = var.tags

  dynamic "identity" {
    for_each = local.front_door_identity_type == null ? [] : [local.front_door_identity_type]
    content {
      type = identity.value
    }
  }
}

resource "azurerm_cdn_frontdoor_endpoint" "this" {
  for_each = local.endpoints

  name                     = each.value.resolved_name
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
  enabled                  = try(each.value.enabledState, "Enabled") == "Enabled"
  tags                     = coalesce(each.value.tags, var.tags)
}

resource "azurerm_cdn_frontdoor_origin_group" "this" {
  for_each = local.origin_groups

  name                                                      = each.value.name
  cdn_frontdoor_profile_id                                  = azurerm_cdn_frontdoor_profile.this.id
  session_affinity_enabled                                  = try(each.value.sessionAffinityState, "Disabled") == "Enabled"
  restore_traffic_time_to_healed_or_new_endpoint_in_minutes = try(each.value.trafficRestorationTimeToHealedOrNewEndpointsInMinutes, 10)

  load_balancing {
    additional_latency_in_milliseconds = coalesce(each.value.loadBalancingSettings.additionalLatencyInMilliseconds, 50)
    sample_size                        = try(each.value.loadBalancingSettings.sampleSize, 4)
    successful_samples_required        = try(each.value.loadBalancingSettings.successfulSamplesRequired, 3)
  }

  dynamic "health_probe" {
    for_each = try(each.value.healthProbeSettings, null) == null ? [] : [each.value.healthProbeSettings]
    content {
      interval_in_seconds = coalesce(health_probe.value.probeIntervalInSeconds, 100)
      path                = coalesce(health_probe.value.probePath, "/")
      protocol            = coalesce(health_probe.value.probeProtocol, "Https")
      request_type        = coalesce(health_probe.value.probeRequestType, "GET")
    }
  }
}

resource "azurerm_cdn_frontdoor_origin" "this" {
  for_each = merge([
    for group_name, group in local.origin_groups : {
      for origin in try(group.origins, []) :
      "${group_name}/${origin.name}" => merge(origin, {
        origin_group_name = group_name
      })
    }
  ]...)

  name                           = each.value.name
  cdn_frontdoor_origin_group_id  = azurerm_cdn_frontdoor_origin_group.this[each.value.origin_group_name].id
  enabled                        = try(each.value.enabledState, "Enabled") == "Enabled"
  host_name                      = var.workload_origin_host_name
  http_port                      = try(each.value.httpPort, 80)
  https_port                     = try(each.value.httpsPort, 443)
  origin_host_header             = var.workload_origin_host_name
  priority                       = try(each.value.priority, 1)
  weight                         = try(each.value.weight, 1000)
  certificate_name_check_enabled = try(each.value.enforceCertificateNameCheck, true)

  dynamic "private_link" {
    for_each = try(each.value.sharedPrivateLink, null) == null ? [] : [each.value.sharedPrivateLink]
    content {
      request_message        = try(private_link.value.requestMessage, null)
      target_type            = try(private_link.value.groupId, null)
      location               = var.workload_origin_location
      private_link_target_id = var.workload_origin_resource_id
    }
  }
}

resource "azurerm_cdn_frontdoor_route" "this" {
  for_each = local.routes

  name                          = each.value.name
  cdn_frontdoor_endpoint_id     = azurerm_cdn_frontdoor_endpoint.this[each.value.endpoint_name].id
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.this[each.value.originGroupName].id
  cdn_frontdoor_origin_ids = [
    for origin_key, origin in azurerm_cdn_frontdoor_origin.this :
    origin.id if startswith(origin_key, "${each.value.originGroupName}/")
  ]
  patterns_to_match      = each.value.patternsToMatch
  supported_protocols    = try(each.value.supportedProtocols, ["Http", "Https"])
  forwarding_protocol    = try(each.value.forwardingProtocol, "HttpsOnly")
  https_redirect_enabled = try(each.value.httpsRedirect, "Enabled") == "Enabled"
  link_to_default_domain = try(each.value.linkToDefaultDomain, "Enabled") == "Enabled"
  enabled                = try(each.value.enabledState, "Enabled") == "Enabled"
}

module "role_assignments" {
  source = "../common-role-assignments"

  scope            = azurerm_cdn_frontdoor_profile.this.id
  role_assignments = try(var.config.roleAssignments, [])
}

module "diagnostic_settings" {
  source = "../common-diagnostic-settings"

  name_prefix         = local.name
  target_resource_id  = azurerm_cdn_frontdoor_profile.this.id
  diagnostic_settings = try(var.config.diagnosticSettings, [])
}

module "management_lock" {
  source = "../common-management-lock"

  scope       = azurerm_cdn_frontdoor_profile.this.id
  name_suffix = local.name
  lock        = try(var.config.lock, null)
}
