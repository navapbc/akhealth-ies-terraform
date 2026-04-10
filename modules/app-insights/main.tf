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
  name                = substr("appi-${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}${local.workload_segment}-${var.instance_number}", 0, 260)
}

resource "azurerm_application_insights" "this" {
  name                                = local.name
  location                            = var.location
  resource_group_name                 = var.resource_group_name
  workspace_id                        = var.workspace_resource_id
  application_type                    = lower(var.application_type)
  retention_in_days                   = var.retention_in_days
  sampling_percentage                 = var.sampling_percentage
  disable_ip_masking                  = var.disable_ip_masking
  local_authentication_disabled       = var.disable_local_auth
  internet_ingestion_enabled          = var.public_network_access_for_ingestion == "Enabled"
  internet_query_enabled              = var.public_network_access_for_query == "Enabled"
  force_customer_storage_for_profiler = var.force_customer_storage_for_profiler
  tags                                = var.tags
}

module "role_assignments" {
  source = "../common-role-assignments"

  scope            = azurerm_application_insights.this.id
  role_assignments = var.role_assignments
}

module "diagnostic_settings" {
  source = "../common-diagnostic-settings"

  name_prefix         = local.name
  target_resource_id  = azurerm_application_insights.this.id
  diagnostic_settings = var.diagnostic_settings
}

module "management_lock" {
  source = "../common-management-lock"

  scope       = azurerm_application_insights.this.id
  name_suffix = local.name
  lock        = var.lock
}
