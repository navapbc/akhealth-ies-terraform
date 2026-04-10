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
  workload_segment    = var.workload_description == null ? "" : "-${var.workload_description}"
  name                = substr("ase-${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}${local.workload_segment}-${var.instance_number}", 0, 80)
}

resource "azurerm_app_service_environment_v3" "this" {
  name                                   = local.name
  resource_group_name                    = var.resource_group_name
  subnet_id                              = var.subnet_resource_id
  internal_load_balancing_mode           = var.internal_load_balancing_mode
  zone_redundant                         = var.zone_redundant
  dedicated_host_count                   = var.dedicated_host_count
  allow_new_private_endpoint_connections = var.allow_new_private_endpoint_connections
  remote_debugging_enabled               = var.remote_debugging_enabled
  tags                                   = var.tags

  dynamic "cluster_setting" {
    for_each = var.cluster_settings
    content {
      name  = cluster_setting.value.name
      value = cluster_setting.value.value
    }
  }
}

module "role_assignments" {
  source = "../common-role-assignments"

  scope            = azurerm_app_service_environment_v3.this.id
  role_assignments = var.role_assignments
}

module "diagnostic_settings" {
  source = "../common-diagnostic-settings"

  name_prefix         = local.name
  target_resource_id  = azurerm_app_service_environment_v3.this.id
  diagnostic_settings = var.diagnostic_settings
}

module "management_lock" {
  source = "../common-management-lock"

  scope       = azurerm_app_service_environment_v3.this.id
  name_suffix = local.name
  lock        = var.lock
}
