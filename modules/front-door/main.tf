locals {
  workload_segment    = var.workload_description == null ? "" : "-${var.workload_description}"
  name                = substr("afd-${var.system_abbreviation}-${var.region_abbreviation}-${var.environment_abbreviation}${local.workload_segment}-${var.instance_number}", 0, 260)
  origin_groups = {
    for origin_group in var.origin_groups :
    origin_group.name => origin_group
  }
  endpoints = {
    for endpoint in var.afd_endpoints :
    endpoint.name => merge(endpoint, {
      resolved_name = substr("fde-${var.system_abbreviation}-${var.region_abbreviation}-${var.environment_abbreviation}-${endpoint.name}-${var.instance_number}", 0, 260)
    })
  }
  routes = merge([
    for endpoint_name, endpoint in local.endpoints : {
      for route in endpoint.routes :
      "${endpoint_name}/${route.name}" => merge(route, {
        endpoint_name = endpoint_name
      })
    }
  ]...)
  front_door_identity_type = var.managed_identities.systemAssigned ? "SystemAssigned" : null
}

resource "azurerm_cdn_frontdoor_profile" "this" {
  name                     = local.name
  resource_group_name      = var.resource_group_name
  sku_name                 = var.sku
  response_timeout_seconds = var.origin_response_timeout_seconds
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
  enabled                  = each.value.enabledState == "Enabled"
  tags                     = coalesce(each.value.tags, var.tags)
}

resource "azurerm_cdn_frontdoor_origin_group" "this" {
  for_each = local.origin_groups

  name                                                      = each.value.name
  cdn_frontdoor_profile_id                                  = azurerm_cdn_frontdoor_profile.this.id
  session_affinity_enabled                                  = each.value.sessionAffinityState == "Enabled"
  restore_traffic_time_to_healed_or_new_endpoint_in_minutes = each.value.trafficRestorationTimeToHealedOrNewEndpointsInMinutes

  load_balancing {
    additional_latency_in_milliseconds = coalesce(each.value.loadBalancingSettings.additionalLatencyInMilliseconds, 50)
    sample_size                        = each.value.loadBalancingSettings.sampleSize
    successful_samples_required        = each.value.loadBalancingSettings.successfulSamplesRequired
  }

  dynamic "health_probe" {
    for_each = each.value.healthProbeSettings == null ? [] : [each.value.healthProbeSettings]
    content {
      interval_in_seconds = health_probe.value.probeIntervalInSeconds
      path                = health_probe.value.probePath
      protocol            = health_probe.value.probeProtocol
      request_type        = health_probe.value.probeRequestType
    }
  }
}

resource "azurerm_cdn_frontdoor_origin" "this" {
  for_each = merge([
    for group_name, group in local.origin_groups : {
      for origin in group.origins :
      "${group_name}/${origin.name}" => merge(origin, {
        origin_group_name = group_name
      })
    }
  ]...)

  name                           = each.value.name
  cdn_frontdoor_origin_group_id  = azurerm_cdn_frontdoor_origin_group.this[each.value.origin_group_name].id
  enabled                        = each.value.enabledState == "Enabled"
  host_name                      = var.workload_origin_host_name
  http_port                      = each.value.httpPort
  https_port                     = each.value.httpsPort
  origin_host_header             = var.workload_origin_host_name
  priority                       = each.value.priority
  weight                         = each.value.weight
  certificate_name_check_enabled = each.value.enforceCertificateNameCheck

  dynamic "private_link" {
    for_each = each.value.sharedPrivateLink == null ? [] : [each.value.sharedPrivateLink]
    content {
      request_message        = private_link.value.requestMessage
      target_type            = private_link.value.groupId
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
  cdn_frontdoor_origin_path = each.value.originPath
  patterns_to_match         = each.value.patternsToMatch
  supported_protocols       = each.value.supportedProtocols
  forwarding_protocol       = each.value.forwardingProtocol
  https_redirect_enabled    = each.value.httpsRedirect == "Enabled"
  link_to_default_domain    = each.value.linkToDefaultDomain == "Enabled"
  enabled                   = each.value.enabledState == "Enabled"
}

module "role_assignments" {
  source = "../common-role-assignments"

  scope            = azurerm_cdn_frontdoor_profile.this.id
  role_assignments = var.role_assignments
}

module "diagnostic_settings" {
  source = "../common-diagnostic-settings"

  name_prefix         = local.name
  target_resource_id  = azurerm_cdn_frontdoor_profile.this.id
  diagnostic_settings = var.diagnostic_settings
}

module "management_lock" {
  source = "../common-management-lock"

  scope       = azurerm_cdn_frontdoor_profile.this.id
  name_suffix = local.name
  lock        = var.lock
}
