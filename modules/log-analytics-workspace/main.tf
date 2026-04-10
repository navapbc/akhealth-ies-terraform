locals {
  workload_segment    = var.workload_description == null ? "" : "-${var.workload_description}"
  name                = substr("log-${var.system_abbreviation}-${var.region_abbreviation}-${var.environment_abbreviation}${local.workload_segment}-${var.instance_number}", 0, 63)
}

resource "azurerm_log_analytics_workspace" "this" {
  name                            = local.name
  location                        = var.location
  resource_group_name             = var.resource_group_name
  sku                             = var.sku
  retention_in_days               = var.retention_in_days
  allow_resource_only_permissions = var.enable_log_access_using_only_resource_permissions
  local_authentication_enabled    = !var.disable_local_auth
  internet_ingestion_enabled      = var.public_network_access_for_ingestion == "Enabled"
  internet_query_enabled          = var.public_network_access_for_query == "Enabled"
  tags                            = var.tags
}

module "role_assignments" {
  source = "../common-role-assignments"

  scope            = azurerm_log_analytics_workspace.this.id
  role_assignments = var.role_assignments
}

module "diagnostic_settings" {
  source = "../common-diagnostic-settings"

  target_resource_id  = azurerm_log_analytics_workspace.this.id
  diagnostic_settings = var.diagnostic_settings
}

module "management_lock" {
  source = "../common-management-lock"

  scope       = azurerm_log_analytics_workspace.this.id
  name_suffix = local.name
  lock        = var.lock
}
