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
  name                = substr("asp-${var.system_abbreviation}-${local.region_abbreviation}-${var.environment_abbreviation}${local.workload_segment}-${var.instance_number}", 0, 40)
  os_type             = var.service_plan_kind == "linux" ? "Linux" : "Windows"
}

resource "azurerm_service_plan" "this" {
  name                            = local.name
  location                        = var.location
  resource_group_name             = var.resource_group_name
  os_type                         = local.os_type
  sku_name                        = var.sku_name
  worker_count                    = var.sku_capacity
  app_service_environment_id      = var.app_service_environment_resource_id
  per_site_scaling_enabled        = var.per_site_scaling
  premium_plan_auto_scale_enabled = var.elastic_scale_enabled
  maximum_elastic_worker_count    = var.maximum_elastic_worker_count
  zone_balancing_enabled          = var.zone_redundant
  tags                            = var.tags
}

module "role_assignments" {
  source = "../common-role-assignments"

  scope            = azurerm_service_plan.this.id
  role_assignments = var.role_assignments
}

module "diagnostic_settings" {
  source = "../common-diagnostic-settings"

  name_prefix         = local.name
  target_resource_id  = azurerm_service_plan.this.id
  diagnostic_settings = var.diagnostic_settings
}

module "management_lock" {
  source = "../common-management-lock"

  scope       = azurerm_service_plan.this.id
  name_suffix = local.name
  lock        = var.lock
}
