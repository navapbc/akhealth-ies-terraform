data "azurerm_client_config" "current" {}

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
  name                = substr("log-${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}${local.workload_segment}-${var.instance_number}", 0, 63)
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

  name_prefix         = local.name
  target_resource_id  = azurerm_log_analytics_workspace.this.id
  diagnostic_settings = var.diagnostic_settings
}

module "management_lock" {
  source = "../common-management-lock"

  scope       = azurerm_log_analytics_workspace.this.id
  name_suffix = local.name
  lock        = var.lock
}
